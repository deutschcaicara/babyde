import os
import base64
import datetime
import csv
import json # Mantido
import logging
import time # Mantido
import io
from functools import wraps
from collections import defaultdict # Usaremos para contar as aprovações
import re # Para encontrar os inputs numerados

from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, session
from werkzeug.utils import secure_filename

# --- Configuração ---
# UPLOAD_FOLDER não é mais usado diretamente para salvar, os paths são definidos abaixo
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Variáveis de ambiente serão configuradas no Railway
SECRET_KEY = os.getenv('SECRET_KEY', 'DEFINA_UMA_SECRET_KEY_FORTE_NO_RAILWAY')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin_railway')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'senha_forte_railway')

if SECRET_KEY == 'DEFINA_UMA_SECRET_KEY_FORTE_NO_RAILWAY':
    logging.warning("Usando SECRET_KEY padrão. Defina uma chave segura nas variáveis de ambiente do Railway!")
if ADMIN_PASSWORD == 'senha_forte_railway':
    logging.warning("Usando ADMIN_PASSWORD padrão. Defina uma senha segura nas variáveis de ambiente do Railway!")


MAX_CONTENT_LENGTH = 16 * 1024 * 1024 # 16MB
BENEFICIARIO_APPROVAL_LIMIT = 30 # Limite de makers aprovados por beneficiário
MIN_MAKER_PAIRS_REQUIRED = 2 # Exige pelo menos 2 pares por submissão

# --- Inicialização do Flask ---
app = Flask(__name__)
# app.config['UPLOAD_FOLDER'] não é mais necessário aqui
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Configuração de logging - Nível DEBUG para mais detalhes
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] %(message)s')

# --- Caminhos para Dados Persistentes (Adaptados para Railway Volumes) ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
logging.info(f"BASE_DIR (diretório do app.py) detectado como: {BASE_DIR}")

# Diretório para os CSVs (será montado como um volume no Railway)
DATA_DIR = os.path.join(BASE_DIR, 'data_persistente')
os.makedirs(DATA_DIR, exist_ok=True)
logging.info(f"Diretório de dados persistentes (CSVs): {DATA_DIR}")

PROCESSADOS_CSV = os.path.join(DATA_DIR, 'processados.csv')
REVISAO_CSV = os.path.join(DATA_DIR, 'revisao_log.csv')
logging.info(f"Caminho para PROCESSADOS_CSV: {PROCESSADOS_CSV}")
logging.info(f"Caminho para REVISAO_CSV: {REVISAO_CSV}")

# Diretórios para uploads (será montado como um volume no Railway)
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads_persistentes')
os.makedirs(UPLOADS_DIR, exist_ok=True)
logging.info(f"Diretório de uploads persistentes: {UPLOADS_DIR}")

PROCESSADOS_DIR = os.path.join(UPLOADS_DIR, 'processados') # Para arquivos aprovados
SUSPEITOS_DIR = os.path.join(UPLOADS_DIR, 'suspeitos')   # Para arquivos pendentes de revisão
os.makedirs(PROCESSADOS_DIR, exist_ok=True)
os.makedirs(SUSPEITOS_DIR, exist_ok=True)
logging.info(f"Diretório de SUSPEITOS (para salvar uploads) definido como: {SUSPEITOS_DIR}")
logging.info(f"Diretório de PROCESSADOS (para aprovados) definido como: {PROCESSADOS_DIR}")


# --- Funções Auxiliares ---
def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def initialize_csv(file_path, fieldnames):
    """Cria o arquivo CSV com cabeçalho se não existir."""
    try:
        # O diretório DATA_DIR já deve ter sido criado
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
            logging.info(f"Arquivo CSV inicializado: {file_path}")
    except IOError as e: logging.error(f"Erro I/O ao inicializar CSV {file_path}: {e}")
    except Exception as e: logging.exception(f"Erro inesperado ao inicializar CSV {file_path}: {e}")

# --- Estrutura CSV ---
PROCESSADOS_FIELDS = [
    'timestamp', 'char_beneficiario', 'all_maker_inputs', 'all_filenames',
    'status_geral_submissao', 'revisado_por', 'timestamp_revisao', 'rejection_reason'
]
REVISAO_FIELDS = [
    'timestamp_revisao', 'nome_revisor', 'char_beneficiario_aprovado',
    'makers_aprovados', 'filenames_associados', 'acao', 'motivo_rejeicao_log'
]

def initialize_all_csvs():
    """Inicializa todos os arquivos CSV necessários."""
    logging.info(f"Inicializando CSVs em {DATA_DIR}...")
    initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS)
    initialize_csv(REVISAO_CSV, REVISAO_FIELDS)

# Chamada para inicializar os CSVs quando o app é carregado/importado
initialize_all_csvs()

def log_processamento(data):
    """Registra uma submissão no CSV principal."""
    try:
        # initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS) # Já chamado globalmente
        with open(PROCESSADOS_CSV, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=PROCESSADOS_FIELDS, extrasaction='ignore')
            row_data = {field: data.get(field, '') for field in PROCESSADOS_FIELDS}
            if isinstance(row_data.get('all_maker_inputs'), list):
                row_data['all_maker_inputs'] = ','.join(row_data['all_maker_inputs'])
            if isinstance(row_data.get('all_filenames'), list):
                row_data['all_filenames'] = ','.join(row_data['all_filenames'])
            writer.writerow(row_data)
        logging.info(f"Submissão logada para B: {data.get('char_beneficiario')} Status: {data.get('status_geral_submissao')} ID: {data.get('timestamp')}")
    except Exception as e: logging.exception(f"Erro ao logar processamento: {e}")

def log_revisao(timestamp_revisao, nome_revisor, char_beneficiario, makers_list, filenames_list, acao, motivo_rejeicao=''):
    """Registra uma ação de revisão manual no CSV de log."""
    try:
        # initialize_csv(REVISAO_CSV, REVISAO_FIELDS) # Já chamado globalmente
        with open(REVISAO_CSV, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=REVISAO_FIELDS, extrasaction='ignore')
            writer.writerow({
                'timestamp_revisao': timestamp_revisao,
                'nome_revisor': nome_revisor,
                'char_beneficiario_aprovado': char_beneficiario or '',
                'makers_aprovados': ','.join(makers_list) if isinstance(makers_list, list) else makers_list or '',
                'filenames_associados': ','.join(filenames_list) if isinstance(filenames_list, list) else filenames_list or '',
                'acao': acao,
                'motivo_rejeicao_log': motivo_rejeicao if acao == 'Rejeitado Manual' else '' # Corrigido para 'Rejeitado Manual'
            })
        logging.info(f"Revisão manual logada por {nome_revisor}. Ação: {acao} para B: {char_beneficiario}. Motivo: {motivo_rejeicao if motivo_rejeicao else 'N/A'}")
    except Exception as e: logging.exception(f"Erro ao logar revisão manual: {e}")

def get_validated_data():
    """Lê o CSV de processados e retorna contagem de makers aprovados por beneficiário e makers já usados globalmente."""
    # Retorna um dicionário:
    # 'beneficiarios_makers_count': {'nome_benef_lower': contagem_makers_aprovados}
    # 'used_makers_global': {set_de_makers_usados_globalmente_lower}
    
    beneficiarios_makers_count = defaultdict(int)
    used_makers_global = set()
    try:
        # initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS) # Já chamado
        if not os.path.exists(PROCESSADOS_CSV) or os.path.getsize(PROCESSADOS_CSV) == 0:
            logging.warning("get_validated_data: processados.csv vazio ou não encontrado.")
            return {'beneficiarios_makers_count': dict(beneficiarios_makers_count), 'used_makers_global': used_makers_global}

        with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            if not reader.fieldnames or not all(f in reader.fieldnames for f in ['char_beneficiario', 'all_maker_inputs', 'status_geral_submissao']):
                 logging.error(f"get_validated_data: CSV {PROCESSADOS_CSV} com cabeçalhos inválidos. Pulando leitura.")
                 return {'beneficiarios_makers_count': dict(beneficiarios_makers_count), 'used_makers_global': used_makers_global}

            for row in reader:
                if row.get('status_geral_submissao') == 'Aprovado Manual':
                    beneficiario_lower = row.get('char_beneficiario', '').strip().lower()
                    makers_str = row.get('all_maker_inputs', '')
                    
                    if makers_str:
                        current_makers_in_row = [m.strip().lower() for m in makers_str.split(',') if m.strip()]
                        # Adiciona à contagem de makers para este beneficiário
                        if beneficiario_lower:
                            beneficiarios_makers_count[beneficiario_lower] += len(current_makers_in_row)
                        # Adiciona ao conjunto global de makers usados
                        used_makers_global.update(current_makers_in_row)
                        
    except FileNotFoundError:
        logging.error(f"get_validated_data: Arquivo {PROCESSADOS_CSV} não encontrado.")
    except Exception as e: logging.exception(f"Erro ao ler dados validados de {PROCESSADOS_CSV}: {e}")
    
    logging.debug(f"Dados validados carregados: Beneficiarios Makers Counts={dict(beneficiarios_makers_count)}, Used Makers Global Count={len(used_makers_global)}")
    return {'beneficiarios_makers_count': dict(beneficiarios_makers_count), 'used_makers_global': used_makers_global}

# --- Decorador de Autenticação ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, faça login para acessar.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Rotas ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_attempt = request.form.get('username')
        password_attempt = request.form.get('password')
        logging.info(f"Tentativa de login para usuário: '{username_attempt}'")
        if username_attempt == ADMIN_USERNAME and password_attempt == ADMIN_PASSWORD:
            session['logged_in'] = True; session['username'] = username_attempt
            flash('Login realizado com sucesso!', 'success'); logging.info(f"Login OK: '{username_attempt}'")
            next_url = request.args.get('next'); return redirect(next_url or url_for('pagina_revisao'))
        else:
            flash('Nome de usuário ou senha inválidos.', 'danger'); logging.warning(f"Falha login: '{username_attempt}'")
    return render_template('login.html')


@app.route('/logout')
def logout():
    logged_out_user = session.pop('username', 'Desconhecido'); session.pop('logged_in', None)
    flash('Você foi desconectado.', 'info'); logging.info(f"Logout: '{logged_out_user}'")
    return redirect(url_for('index'))

@app.route('/', methods=['GET'])
def index(): return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    start_time = datetime.datetime.now()
    char_beneficiario = request.form.get('char_beneficiario', '').strip()
    logging.debug(f"Recebido upload para beneficiário: '{char_beneficiario}'")
    if not char_beneficiario:
        flash('Nome do Personagem Beneficiário é obrigatório!', 'warning'); return redirect(url_for('index'))

    submitted_pairs = []
    maker_names_in_submission = set()
    form_keys = list(request.form.keys())
    file_keys = list(request.files.keys())
    logging.debug(f"Form keys recebidos: {form_keys}")
    logging.debug(f"File keys recebidos: {file_keys}")

    i = 1
    while True:
        maker_name_key = f'maker_name_{i}'
        print_key = f'print_{i}'
        if maker_name_key not in form_keys and print_key not in file_keys:
             if i == 1: logging.warning("Nenhum par maker_name_X / print_X encontrado no formulário.")
             break
        maker_name = request.form.get(maker_name_key, '').strip()
        print_file = request.files.get(print_key)
        if not maker_name:
            flash(f'Nome do Maker {i} está vazio ou não foi encontrado!', 'warning'); logging.warning(f"Nome vazio/ausente para maker_{i}"); return redirect(url_for('index'))
        if not print_file or not print_file.filename:
            flash(f'Print {i} (para Maker {maker_name}) não foi enviado ou não foi encontrado!', 'warning'); logging.warning(f"Arquivo ausente/inválido para print_{i}"); return redirect(url_for('index'))
        if not allowed_file(print_file.filename):
            flash(f'Formato inválido para Print {i} ({print_file.filename})!', 'warning'); logging.warning(f"Arquivo inválido: {print_file.filename}"); return redirect(url_for('index'))
        logging.debug(f"Processando par índice {i}: Maker='{maker_name}', File='{print_file.filename}'")
        maker_name_lower = maker_name.lower()
        if maker_name_lower in maker_names_in_submission:
            flash(f'Nome do Maker "{maker_name}" repetido nesta submissão!', 'warning'); logging.warning(f"Maker repetido na submissão: {maker_name}"); return redirect(url_for('index'))
        maker_names_in_submission.add(maker_name_lower)
        submitted_pairs.append({'index': i, 'name': maker_name, 'file': print_file})
        i += 1

    if len(submitted_pairs) < MIN_MAKER_PAIRS_REQUIRED:
        flash(f'É necessário enviar pelo menos {MIN_MAKER_PAIRS_REQUIRED} pares válidos de Maker/Print.', 'warning'); logging.warning(f"Menos de {MIN_MAKER_PAIRS_REQUIRED} pares válidos enviados."); return redirect(url_for('index'))
    logging.info(f"Submissão válida recebida para B: '{char_beneficiario}' com {len(submitted_pairs)} pares.")

    validated_data = get_validated_data() # Obtém contagens e makers usados
    beneficiario_lower = char_beneficiario.lower()
    rejection_reason, rejection_message = None, None
    
    current_beneficiary_makers_count = validated_data['beneficiarios_makers_count'].get(beneficiario_lower, 0)
    needed_approvals = len(submitted_pairs) # Número de makers nesta submissão
    
    logging.debug(f"Verificando limites/duplicados para upload: B='{beneficiario_lower}' (Makers Aprovados={current_beneficiary_makers_count}, Limite={BENEFICIARIO_APPROVAL_LIMIT}), Makers nesta submissão={maker_names_in_submission}")
    
    if current_beneficiary_makers_count + needed_approvals > BENEFICIARIO_APPROVAL_LIMIT:
        rejection_reason = 'beneficiario_limit_exceeded'
        rejection_message = f"Rejeitado: Beneficiário '{char_beneficiario}' já tem {current_beneficiary_makers_count} makers aprovados. Esta submissão com {needed_approvals} makers excederia o limite de {BENEFICIARIO_APPROVAL_LIMIT}."
    else:
        # Verifica duplicidade global de makers
        for pair in submitted_pairs:
            maker_lower = pair['name'].lower()
            if maker_lower in validated_data['used_makers_global']:
                rejection_reason = f'maker_duplicate_global'; rejection_message = f"Rejeitado: O Maker '{pair['name']}' já foi utilizado em uma validação aprovada anteriormente."; break
    
    if rejection_reason:
        flash(rejection_message, 'warning'); logging.warning(f"Submissão rejeitada ({rejection_reason}): {rejection_message}")
        log_entry_rejected = {
            'timestamp': datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f"), 'char_beneficiario': char_beneficiario,
            'all_maker_inputs': ','.join([p['name'] for p in submitted_pairs]), 'all_filenames': ','.join([p['file'].filename for p in submitted_pairs]), # Nome original do arquivo
            'status_geral_submissao': 'Rejeitado Duplicado/Limite', 'revisado_por': 'Sistema', 'timestamp_revisao': datetime.datetime.now().isoformat(), 'rejection_reason': rejection_reason }
        log_processamento(log_entry_rejected)
        return render_template('resultado.html', message=rejection_message, status='warning', char_beneficiario=char_beneficiario, current_count=current_beneficiary_makers_count, limit=BENEFICIARIO_APPROVAL_LIMIT, rejection_reason=rejection_reason)

    now = datetime.datetime.now(); timestamp_str = now.strftime("%Y%m%d_%H%M%S_%f")
    safe_beneficiario_name = "".join(c for c in char_beneficiario if c.isalnum() or c == ' ').strip().replace(' ', '_')
    saved_filenames = []
    all_maker_names = []
    for pair in submitted_pairs:
        maker_name = pair['name']; file_obj = pair['file']; index = pair['index']
        all_maker_names.append(maker_name)
        safe_maker_name = "".join(c for c in maker_name if c.isalnum() or c == ' ').strip().replace(' ', '_')
        file_extension = file_obj.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"{timestamp_str}_B_{safe_beneficiario_name}_M{index}_{safe_maker_name}_img{index}.{file_extension}")
        save_path = os.path.join(SUSPEITOS_DIR, filename) # Salva na pasta de suspeitos
        logging.debug(f"Tentando salvar arquivo em: {save_path} (Caminho absoluto: {os.path.abspath(save_path)})")
        try:
            file_obj.seek(0); file_obj.save(save_path)
            if os.path.exists(save_path):
                logging.info(f"Arquivo salvo COM SUCESSO e ENCONTRADO: {filename} em {save_path}")
            else:
                logging.error(f"Arquivo salvo mas NÃO ENCONTRADO IMEDIATAMENTE: {filename} em {save_path}. Verifique permissões ou caminho.")
            saved_filenames.append(filename)
        except Exception as e:
            for fname in saved_filenames: # Tenta remover os já salvos desta submissão
                try: os.remove(os.path.join(SUSPEITOS_DIR, fname))
                except OSError: pass
            logging.exception(f"Erro CRÍTICO ao salvar {file_obj.filename} para {save_path}: {e}")
            flash(f"Erro CRÍTICO ao salvar arquivo para {maker_name}. Submissão cancelada.", "danger"); return redirect(url_for('index'))
    
    logging.info(f"Todos os {len(saved_filenames)} arquivos da submissão {timestamp_str} foram processados para salvamento em {SUSPEITOS_DIR}: {saved_filenames}")

    log_entry = {
        'timestamp': timestamp_str, 'char_beneficiario': char_beneficiario,
        'all_maker_inputs': ','.join(all_maker_names), 'all_filenames': ','.join(saved_filenames),
        'status_geral_submissao': 'Pendente Revisão', 'revisado_por': '', 'timestamp_revisao': '', 'rejection_reason': '' }
    logging.debug(f"Logando submissão pendente no CSV: {log_entry}")
    log_processamento(log_entry)

    processing_time = (datetime.datetime.now() - start_time).total_seconds()
    logging.info(f"Submissão para B:'{char_beneficiario}' com {len(all_maker_names)} makers enviada para revisão. Tempo: {processing_time:.2f}s.")
    final_message = (f"Submissão para '{char_beneficiario}' com {len(all_maker_names)} makers ({', '.join(all_maker_names)}) recebida e enviada para revisão. "
                     f"Este beneficiário tem {current_beneficiary_makers_count} makers aprovados e esta submissão adicionaria {len(all_maker_names)}, totalizando {current_beneficiary_makers_count + len(all_maker_names)} de {BENEFICIARIO_APPROVAL_LIMIT} permitidas se aprovada.")
    flash(final_message, 'success')
    return render_template('resultado.html', message=final_message, status='success', char_beneficiario=char_beneficiario, makers_submitted=all_maker_names, status_final1='Pendente Revisão', rejection_reason=None)


@app.route('/validados_pesquisa', methods=['GET'])
@login_required
def pagina_validados_pesquisa():
    query = request.args.get('q', '').strip().lower()
    error_msg = None
    validacoes_para_template = [] 
    try:
        # initialize_all_csvs() # Já chamado globalmente
        if not os.path.exists(PROCESSADOS_CSV) or os.path.getsize(PROCESSADOS_CSV) == 0:
            error_msg = "Arquivo de validações (processados.csv) não encontrado ou vazio."
        else:
            with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS):
                     error_msg = "Arquivo de validações (processados.csv) corrompido ou formato antigo."
                else:
                    temp_validacoes = [] 
                    for row in reader:
                        # Filtra por status e também pode filtrar por rejeitados se desejar
                        status_submissao = row.get('status_geral_submissao', '')
                        if status_submissao == 'Aprovado Manual' or status_submissao == 'Rejeitado Manual' or status_submissao == 'Rejeitado Duplicado/Limite':
                            beneficiario = row.get('char_beneficiario', 'N/A')
                            makers_str = row.get('all_maker_inputs', '')
                            makers_list = [m.strip() for m in makers_str.split(',') if m.strip()]
                            revisor = row.get('revisado_por', '')
                            timestamp_rev_iso = row.get('timestamp_revisao', '')
                            timestamp_original_submissao = row.get('timestamp', '') # Para ordenação
                            rejection_reason_text = row.get('rejection_reason', '')

                            timestamp_display = timestamp_rev_iso if timestamp_rev_iso else timestamp_original_submissao

                            try: # Tenta formatar o timestamp de revisão, se existir
                                if timestamp_rev_iso:
                                    timestamp_rev_dt = datetime.datetime.fromisoformat(timestamp_rev_iso)
                                    timestamp_display = timestamp_rev_dt.strftime("%Y-%m-%d %H:%M")
                                elif timestamp_original_submissao: # Fallback para timestamp da submissao
                                     timestamp_orig_dt = datetime.datetime.strptime(timestamp_original_submissao, "%Y%m%d_%H%M%S_%f")
                                     timestamp_display = timestamp_orig_dt.strftime("%Y-%m-%d %H:%M")
                            except ValueError:
                                logging.warning(f"Falha ao converter timestamp '{timestamp_display}' para B '{beneficiario}'. Usando string original.")

                            matches_query = (
                                not query or 
                                query in beneficiario.lower() or
                                (revisor and query in revisor.lower()) or
                                any(query in maker.lower() for maker in makers_list) or
                                (rejection_reason_text and query in rejection_reason_text.lower())
                            )

                            if matches_query:
                                status_completo = status_submissao
                                if status_submissao == 'Aprovado Manual' and revisor:
                                    status_completo = f'Aprovado por {revisor}'
                                elif status_submissao == 'Rejeitado Manual' and revisor:
                                    status_completo = f'Rejeitado por {revisor} (Motivo: {rejection_reason_text})'
                                elif status_submissao == 'Rejeitado Duplicado/Limite':
                                     status_completo = f'Rej. Automático (Motivo: {rejection_reason_text})'


                                temp_validacoes.append({
                                    'timestamp_sort': timestamp_rev_iso or timestamp_original_submissao, # para ordenação correta
                                    'timestamp_display': timestamp_display,
                                    'beneficiario': beneficiario,
                                    'makers_display': ', '.join(makers_list) if makers_list else 'N/A',
                                    'status': status_completo,
                                    'revisado_por': revisor if revisor else ( 'Sistema' if status_submissao == 'Rejeitado Duplicado/Limite' else '-'),
                                    'submission_id': timestamp_original_submissao 
                                })
                    # Ordena por data de revisão/submissão (mais recentes primeiro)
                    temp_validacoes.sort(key=lambda x: x.get('timestamp_sort', '0'), reverse=True)
                    validacoes_para_template = temp_validacoes 
    except Exception as e:
        error_msg = f"Erro ao carregar validações para pesquisa: {e}"
        logging.exception(error_msg)
    return render_template('validados_pesquisa.html', validacoes=validacoes_para_template, limit=BENEFICIARIO_APPROVAL_LIMIT, error=error_msg, search_query=query)


@app.route('/revisao', methods=['GET'])
@login_required
def pagina_revisao():
    submissions_pending = []
    error_msg = None
    logging.debug(f"--- INÍCIO ROTA /revisao ---")
    logging.debug(f"Tentando ler CSV: {PROCESSADOS_CSV} (Abs: {os.path.abspath(PROCESSADOS_CSV)})")
    logging.debug(f"Verificando arquivos em: {SUSPEITOS_DIR} (Abs: {os.path.abspath(SUSPEITOS_DIR)})")

    try:
        if not os.path.isdir(SUSPEITOS_DIR):
             logging.error(f"Diretório de suspeitos NÃO ENCONTRADO em {SUSPEITOS_DIR}")
             error_msg = f"Erro crítico: Diretório de arquivos pendentes ({SUSPEITOS_DIR}) não encontrado."
             return render_template('revisao.html', submissions=[], error=error_msg)
        # initialize_all_csvs() # Já chamado globalmente
        if not os.path.exists(PROCESSADOS_CSV) or os.path.getsize(PROCESSADOS_CSV) == 0:
            error_msg = "Arquivo de processamento (processados.csv) não encontrado ou vazio."
            logging.warning(f"/revisao: {error_msg}")
        else:
             logging.debug(f"/revisao: Lendo CSV: {PROCESSADOS_CSV}")
             with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS):
                     error_msg = "Arquivo de processamento (processados.csv) corrompido ou com formato inválido."
                     logging.error(f"/revisao: {error_msg}")
                else:
                    row_count = 0
                    for row in reader:
                        row_count += 1
                        status_atual = row.get('status_geral_submissao', '').strip()
                        submission_id_from_row = row.get('timestamp')
                        logging.debug(f"/revisao: Lendo linha {row_count} do CSV: ID='{submission_id_from_row}', Status='{status_atual}'")

                        if status_atual == 'Pendente Revisão': # Apenas pendentes para esta página
                            makers_str = row.get('all_maker_inputs', '')
                            filenames_str = row.get('all_filenames', '')
                            beneficiario = row.get('char_beneficiario', 'N/A')
                            logging.info(f"/revisao: Submissão PENDENTE encontrada: ID={submission_id_from_row}, B='{beneficiario}', Makers='{makers_str}', Files='{filenames_str}'")
                            makers_list = [m.strip() for m in makers_str.split(',') if m.strip()]
                            filenames_list = [f.strip() for f in filenames_str.split(',') if f.strip()]

                            if not submission_id_from_row or not makers_list or not filenames_list:
                                logging.warning(f"/revisao: Submissão pendente {submission_id_from_row} com dados faltando. Pulando.")
                                continue
                            if len(makers_list) != len(filenames_list):
                                logging.warning(f"/revisao: Submissão pendente {submission_id_from_row} com contagem M/F inconsistente. Pulando.")
                                continue
                            all_files_exist = True
                            missing_files_log = []
                            logging.debug(f"/revisao: Verificando {len(filenames_list)} arquivos para submissão {submission_id_from_row} em {SUSPEITOS_DIR}...")
                            for fname in filenames_list:
                                file_path_check = os.path.join(SUSPEITOS_DIR, fname)
                                file_path_abs = os.path.abspath(file_path_check) 
                                exists = os.path.exists(file_path_check)
                                logging.debug(f"/revisao:  -> Verificando '{fname}': Path='{file_path_check}', AbsPath='{file_path_abs}', Existe? {exists}")
                                if not exists:
                                    logging.error(f"/revisao: ARQUIVO NÃO ENCONTRADO! Nome: '{fname}', para submissão {submission_id_from_row}")
                                    all_files_exist = False
                                    missing_files_log.append(fname) # Não precisa de break para logar todos os faltantes
                            
                            if all_files_exist:
                                logging.info(f"/revisao: OK! Todos os {len(filenames_list)} arquivos encontrados para submissão {submission_id_from_row}.")
                                submissions_pending.append({
                                    'submission_id': submission_id_from_row,
                                    'char_beneficiario': beneficiario,
                                    'makers': makers_list,
                                    'filenames': filenames_list,
                                    'timestamp_original': submission_id_from_row 
                                })
                            else:
                                logging.warning(f"/revisao: Submissão {submission_id_from_row} IGNORADA para revisão: Arquivos ausentes: {missing_files_log}.")
                        # else: # Opcional: logar status não pendentes
                        #     logging.debug(f"/revisao: Linha {row_count} (ID: {submission_id_from_row}) não 'Pendente Revisão', status: '{status_atual}'.")
        
        submissions_pending.sort(key=lambda x: x.get('timestamp_original', '0'), reverse=True)
        logging.info(f"/revisao: Total de submissões pendentes para exibir: {len(submissions_pending)}")

    except FileNotFoundError:
        error_msg = f"Erro: Arquivo {PROCESSADOS_CSV} não encontrado."
        logging.error(f"/revisao: {error_msg}")
    except Exception as e:
        error_msg = f"Erro inesperado ao listar pendentes: {e}"
        logging.exception(error_msg)
        flash(error_msg, "danger") 
    
    logging.debug(f"--- FIM ROTA /revisao ---")
    return render_template('revisao.html', submissions=submissions_pending, error=error_msg)


@app.route('/suspeitos/<path:filename>')
@login_required
def serve_suspeito(filename):
    """Serve arquivos de imagem da pasta de suspeitos (ou processados como fallback)."""
    try:
        if '..' in filename or filename.startswith('/'):
            logging.warning(f"Tentativa de acesso inválido a arquivo: {filename}")
            return "Acesso inválido", 400
        safe_filename = secure_filename(filename)
        
        # Tenta servir da pasta SUSPEITOS_DIR (que está dentro de UPLOADS_DIR)
        suspeito_path_relativo_a_uploads = os.path.join('suspeitos', safe_filename) # Caminho relativo dentro de UPLOADS_DIR
        logging.debug(f"Tentando servir arquivo suspeito: {safe_filename} de {SUSPEITOS_DIR}")
        # send_from_directory espera o diretório PAI e o nome do arquivo DENTRO dele
        if os.path.exists(os.path.join(SUSPEITOS_DIR, safe_filename)):
             logging.debug(f"Servindo de SUSPEITOS: {safe_filename}")
             return send_from_directory(SUSPEITOS_DIR, safe_filename, as_attachment=False)

        # Fallback: Tenta servir da pasta PROCESSADOS_DIR
        processado_path_relativo_a_uploads = os.path.join('processados', safe_filename)
        logging.debug(f"Não encontrado em suspeitos. Tentando servir de processados: {safe_filename} de {PROCESSADOS_DIR}")
        if os.path.exists(os.path.join(PROCESSADOS_DIR, safe_filename)):
            logging.warning(f"Servindo arquivo de PROCESSADOS (fallback): {safe_filename}")
            return send_from_directory(PROCESSADOS_DIR, safe_filename, as_attachment=False)

        logging.error(f"Arquivo não encontrado para servir (nem suspeito, nem processado): {safe_filename}")
        return "Arquivo não encontrado", 404
    except Exception as e:
        logging.exception(f"Erro ao servir arquivo {filename}: {e}")
        return "Erro interno do servidor", 500


@app.route('/aprovar/<submission_id>', methods=['POST'])
@login_required
def aprovar_par(submission_id):
    nome_revisor_manual = request.form.get('revisor_name', '').strip()
    if not nome_revisor_manual:
        flash("Nome do revisor é obrigatório para aprovar.", "warning")
        return redirect(url_for('pagina_revisao'))
    logging.info(f"Tentativa de aprovação por '{nome_revisor_manual}' para Submissão ID: '{submission_id}'")
    original_rows = []
    row_index_to_update = -1
    submission_data = None
    try:
        # initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS) # Já chamado
        with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS):
                flash("Erro crítico: Formato do arquivo processados.csv inválido.", "danger")
                logging.error("Formato inválido do processados.csv ao tentar aprovar.")
                return redirect(url_for('pagina_revisao'))
            original_rows = list(reader) 
        
        for i, row in enumerate(original_rows):
            if row.get('timestamp') == submission_id and row.get('status_geral_submissao', '').strip() == 'Pendente Revisão':
                submission_data = row 
                row_index_to_update = i 
                logging.debug(f"Encontrada submissão pendente no CSV para ID {submission_id} na linha {i}.")
                break 
        
        if not submission_data:
            flash(f"Erro: Submissão com ID '{submission_id}' não encontrada ou já processada.", "danger")
            logging.error(f"Tentativa de aprovar submissão {submission_id} falhou: Não encontrada ou não está pendente.")
            return redirect(url_for('pagina_revisao'))

        char_beneficiario_original = submission_data.get('char_beneficiario', '')
        makers_str = submission_data.get('all_maker_inputs', '')
        filenames_str = submission_data.get('all_filenames', '')
        makers_list_original = [m.strip() for m in makers_str.split(',') if m.strip()]
        filenames_list_original = [f.strip() for f in filenames_str.split(',') if f.strip()]

        if not char_beneficiario_original or not makers_list_original or not filenames_list_original:
            flash(f"Erro: Dados incompletos na submissão {submission_id} no CSV.", "danger")
            logging.error(f"Dados incompletos na linha do CSV para submissão {submission_id}.")
            return redirect(url_for('pagina_revisao'))
        if len(makers_list_original) != len(filenames_list_original):
             flash(f"Erro: Inconsistência de dados na submissão {submission_id} (contagem maker/file).", "danger")
             logging.error(f"Inconsistência M/F na linha do CSV para submissão {submission_id}.")
             return redirect(url_for('pagina_revisao'))
        
        # Revalida usando os dados mais atuais
        validated_data_atual = get_validated_data()
        beneficiario_lower = char_beneficiario_original.lower()
        rejection_reason, rejection_message = None, None

        current_beneficiary_makers_count = validated_data_atual['beneficiarios_makers_count'].get(beneficiario_lower, 0)
        approvals_in_this_submission = len(makers_list_original)
        
        logging.info(f"Revalidando aprovação para B:'{char_beneficiario_original}'. Makers Aprovados atualmente:{current_beneficiary_makers_count}/{BENEFICIARIO_APPROVAL_LIMIT}. Esta submissão adicionaria +{approvals_in_this_submission}")

        if current_beneficiary_makers_count + approvals_in_this_submission > BENEFICIARIO_APPROVAL_LIMIT:
            rejection_reason = 'beneficiario_limit_reached_aprovacao'
            rejection_message = f"Aprovação Bloqueada: Beneficiário '{char_beneficiario_original}' já tem {current_beneficiary_makers_count} makers aprovados. Aprovar esta submissão com {approvals_in_this_submission} makers excederia o limite de {BENEFICIARIO_APPROVAL_LIMIT}."
        else:
            for maker_name in makers_list_original:
                maker_lower = maker_name.lower()
                # Verifica se o maker já está no conjunto global de makers aprovados
                if maker_lower in validated_data_atual['used_makers_global']: 
                    rejection_reason = 'maker_duplicate_aprovacao'
                    rejection_message = f"Aprovação Bloqueada: O Maker '{maker_name}' já foi utilizado em uma validação aprovada anteriormente."; break
        
        if rejection_reason:
            flash(rejection_message, 'warning')
            logging.warning(f"Aprovação da submissão {submission_id} bloqueada na revalidação ({rejection_reason}): {rejection_message}")
            return redirect(url_for('pagina_revisao'))

        all_moved = True; moved_files = []
        logging.debug(f"Tentando mover {len(filenames_list_original)} arquivos de {SUSPEITOS_DIR} para {PROCESSADOS_DIR}...")
        for filename in filenames_list_original:
            path_suspeito = os.path.join(SUSPEITOS_DIR, filename)
            path_processado = os.path.join(PROCESSADOS_DIR, filename)
            if os.path.exists(path_suspeito):
                try: 
                    os.rename(path_suspeito, path_processado)
                    moved_files.append(filename)
                    logging.info(f"Arquivo movido: {filename} de {SUSPEITOS_DIR} para {PROCESSADOS_DIR}")
                except OSError as e: 
                    logging.error(f"Erro CRÍTICO ao mover arquivo {filename}: {e}")
                    all_moved = False; break
            else: 
                logging.error(f"Arquivo {filename} NÃO encontrado em {SUSPEITOS_DIR} durante a tentativa de movê-lo! Aprovação cancelada.")
                all_moved = False; break
        
        if not all_moved:
            logging.warning(f"Falha ao mover um ou mais arquivos para {submission_id}. Revertendo movimentações...")
            for fname in moved_files: # Tenta mover de volta os que foram movidos
                try: 
                    os.rename(os.path.join(PROCESSADOS_DIR, fname), os.path.join(SUSPEITOS_DIR, fname))
                    logging.info(f"Arquivo revertido: {fname} de volta para {SUSPEITOS_DIR}")
                except OSError as e_revert: 
                    logging.error(f"Erro ao tentar reverter a movimentação do arquivo {fname}: {e_revert}")
            flash(f"Erro crítico ao mover os arquivos da submissão {submission_id}. A aprovação foi cancelada. Verifique os logs.", "danger")
            return redirect(url_for('pagina_revisao'))

        ts_revisao = datetime.datetime.now().isoformat()
        original_rows[row_index_to_update]['status_geral_submissao'] = 'Aprovado Manual'
        original_rows[row_index_to_update]['revisado_por'] = nome_revisor_manual
        original_rows[row_index_to_update]['timestamp_revisao'] = ts_revisao
        original_rows[row_index_to_update]['rejection_reason'] = '' 
        
        logging.debug(f"Reescrevendo {PROCESSADOS_CSV} com linha {row_index_to_update} atualizada para 'Aprovado Manual'.")
        with open(PROCESSADOS_CSV, 'w', newline='', encoding='utf-8') as outfile:
             writer = csv.DictWriter(outfile, fieldnames=PROCESSADOS_FIELDS); writer.writeheader(); writer.writerows(original_rows)
        
        log_revisao(ts_revisao, nome_revisor_manual, char_beneficiario_original, makers_list_original, filenames_list_original, "Aprovado Manual") # Ação como Aprovado Manual
        
        flash(f"Submissão para '{char_beneficiario_original}' (Makers: {', '.join(makers_list_original)}) aprovada com sucesso por '{nome_revisor_manual}'.", "success")
        flash(f"'{char_beneficiario_original}' agora tem {current_beneficiary_makers_count + approvals_in_this_submission} makers aprovados de {BENEFICIARIO_APPROVAL_LIMIT}.", "info")
        logging.info(f"Submissão {submission_id} aprovada por {nome_revisor_manual}.")

    except FileNotFoundError:
        flash(f"Erro crítico: Arquivo {PROCESSADOS_CSV} não encontrado durante a aprovação.", "danger")
        logging.error(f"FileNotFoundError ao tentar aprovar {submission_id}.")
    except Exception as e:
        flash(f"Erro inesperado ao tentar aprovar a submissão {submission_id}: {e}", "danger")
        logging.exception(f"Erro inesperado na rota /aprovar para {submission_id}: {e}")
    
    return redirect(url_for('pagina_revisao'))

@app.route('/rejeitar/<submission_id>', methods=['POST'])
@login_required
def rejeitar_submissao(submission_id):
    nome_revisor = request.form.get('revisor_name', '').strip()
    motivo_rejeicao = request.form.get('rejection_reason', '').strip()

    if not nome_revisor:
        flash("Nome do revisor é obrigatório para rejeitar.", "warning")
        return redirect(url_for('pagina_revisao'))
    if not motivo_rejeicao:
        flash("Motivo da rejeição é obrigatório.", "warning")
        return redirect(url_for('pagina_revisao'))

    logging.info(f"Tentativa de rejeição por '{nome_revisor}' para Submissão ID: '{submission_id}' com motivo: '{motivo_rejeicao}'")

    original_rows = []
    row_index_to_update = -1
    submission_data = None

    try:
        # initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS) # Já chamado
        with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS):
                flash("Erro crítico: Formato do arquivo processados.csv inválido.", "danger")
                logging.error("Formato inválido do processados.csv ao tentar rejeitar.")
                return redirect(url_for('pagina_revisao'))
            original_rows = list(reader)

        for i, row in enumerate(original_rows):
            if row.get('timestamp') == submission_id and row.get('status_geral_submissao', '').strip() == 'Pendente Revisão':
                submission_data = row
                row_index_to_update = i
                logging.debug(f"Encontrada submissão pendente no CSV para rejeição. ID {submission_id} na linha {i}.")
                break
        
        if not submission_data:
            flash(f"Erro: Submissão com ID '{submission_id}' não encontrada ou já processada.", "danger")
            logging.error(f"Tentativa de rejeitar submissão {submission_id} falhou: Não encontrada ou não está pendente.")
            return redirect(url_for('pagina_revisao'))

        char_beneficiario = submission_data.get('char_beneficiario', '')
        makers_str = submission_data.get('all_maker_inputs', '')
        filenames_str = submission_data.get('all_filenames', '') # Nomes dos arquivos não são alterados
        makers_list = [m.strip() for m in makers_str.split(',') if m.strip()]
        filenames_list = [f.strip() for f in filenames_str.split(',') if f.strip()]

        ts_revisao = datetime.datetime.now().isoformat()
        original_rows[row_index_to_update]['status_geral_submissao'] = 'Rejeitado Manual'
        original_rows[row_index_to_update]['revisado_por'] = nome_revisor
        original_rows[row_index_to_update]['timestamp_revisao'] = ts_revisao
        original_rows[row_index_to_update]['rejection_reason'] = motivo_rejeicao

        logging.debug(f"Reescrevendo {PROCESSADOS_CSV} com linha {row_index_to_update} atualizada para 'Rejeitado Manual'.")
        with open(PROCESSADOS_CSV, 'w', newline='', encoding='utf-8') as outfile:
             writer = csv.DictWriter(outfile, fieldnames=PROCESSADOS_FIELDS)
             writer.writeheader()
             writer.writerows(original_rows)
        
        log_revisao(ts_revisao, nome_revisor, char_beneficiario, makers_list, filenames_list, "Rejeitado Manual", motivo_rejeicao)
        
        flash(f"Submissão para '{char_beneficiario}' (Makers: {', '.join(makers_list)}) REJEITADA por '{nome_revisor}'. Motivo: {motivo_rejeicao}", "warning")
        logging.info(f"Submissão {submission_id} rejeitada por {nome_revisor}. Motivo: {motivo_rejeicao}")

    except FileNotFoundError:
        flash(f"Erro crítico: Arquivo {PROCESSADOS_CSV} não encontrado durante a rejeição.", "danger")
        logging.error(f"FileNotFoundError ao tentar rejeitar {submission_id}.")
    except Exception as e:
        flash(f"Erro inesperado ao rejeitar a submissão {submission_id}: {e}", "danger")
        logging.exception(f"Erro inesperado na rota /rejeitar para {submission_id}: {e}")
    
    return redirect(url_for('pagina_revisao'))


@app.route('/validados_publico', methods=['GET'])
def validados_publico():
    validacoes_publicas_agg = defaultdict(lambda: {'submissoes_aprovadas': 0, 'makers_aprovados_count': 0})
    error_msg = None
    try:
        # initialize_all_csvs() # Já chamado
        if not os.path.exists(PROCESSADOS_CSV) or os.path.getsize(PROCESSADOS_CSV) == 0: 
            error_msg = "Nenhuma validação registrada ainda."
        else:
            with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS): 
                    error_msg = "Erro ao ler formato do arquivo de validações."
                else:
                    for row in reader:
                        if row.get('status_geral_submissao') == 'Aprovado Manual':
                            beneficiario_nome = row.get('char_beneficiario', 'N/A').strip()
                            if beneficiario_nome != 'N/A' and beneficiario_nome:
                                validacoes_publicas_agg[beneficiario_nome]['submissoes_aprovadas'] += 1
                                makers_in_row = row.get('all_maker_inputs','').split(',')
                                validacoes_publicas_agg[beneficiario_nome]['makers_aprovados_count'] += len([m for m in makers_in_row if m.strip()])
        
        validacoes_para_template = []
        for nome, data in validacoes_publicas_agg.items():
            validacoes_para_template.append({
                'beneficiario': nome,
                'submissoes_aprovadas': data['submissoes_aprovadas'], # Mantido se precisar
                'makers_aprovados': data['makers_aprovados_count'] # Principal métrica
            })
        
        validacoes_ordenadas = sorted(validacoes_para_template, key=lambda x: (-x['makers_aprovados'], x['beneficiario']))

    except Exception as e: 
        error_msg = f"Erro ao carregar validações públicas: {e}"
        logging.exception(error_msg)
    
    return render_template('validados_publico.html', validacoes=validacoes_ordenadas, limit=BENEFICIARIO_APPROVAL_LIMIT, error=error_msg)


