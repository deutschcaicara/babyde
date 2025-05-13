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
# PIL e requests não são mais necessários
# from PIL import Image
# import requests

# --- Configuração ---
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '.') # Não usado diretamente para salvar, mas mantido por padrão Flask
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

SECRET_KEY = os.getenv('SECRET_KEY', 'SUA_CHAVE_SECRETA_FORTE_E_UNICA_AQUI_VAL11') # IMPORTANTE! Troque
if SECRET_KEY == 'SUA_CHAVE_SECRETA_FORTE_E_UNICA_AQUI_VAL11':
    logging.warning("Usando SECRET_KEY padrão. Defina uma chave segura!")

MAX_CONTENT_LENGTH = 16 * 1024 * 1024 # 16MB
BENEFICIARIO_APPROVAL_LIMIT = 30
MIN_MAKER_PAIRS_REQUIRED = 2 # Exige pelo menos 2 pares por submissão

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'ollamaNgrokSenha123$$$Maestra') # ALTERE!

# --- Inicialização do Flask ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Configuração de logging - Nível DEBUG para mais detalhes
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] %(message)s')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
logging.info(f"BASE_DIR (diretório do app.py) detectado como: {BASE_DIR}")

PROCESSADOS_DIR = os.path.join(BASE_DIR, 'processados')
SUSPEITOS_DIR = os.path.join(BASE_DIR, 'suspeitos')
os.makedirs(PROCESSADOS_DIR, exist_ok=True)
os.makedirs(SUSPEITOS_DIR, exist_ok=True)
logging.info(f"Diretório de SUSPEITOS (para salvar uploads) definido como: {SUSPEITOS_DIR}")
logging.info(f"Diretório de PROCESSADOS (para aprovados) definido como: {PROCESSADOS_DIR}")

PROCESSADOS_CSV = os.path.join(BASE_DIR, 'processados.csv')
REVISAO_CSV = os.path.join(BASE_DIR, 'revisao_log.csv')
logging.info(f"Caminho para PROCESSADOS_CSV: {PROCESSADOS_CSV}")

# --- Funções Auxiliares ---
def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def initialize_csv(file_path, fieldnames):
    """Cria o arquivo CSV com cabeçalho se não existir."""
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
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
    'makers_aprovados', 'filenames_associados', 'acao'
]

def initialize_all_csvs():
    """Inicializa todos os arquivos CSV necessários."""
    initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS)
    initialize_csv(REVISAO_CSV, REVISAO_FIELDS)

def log_processamento(data):
    """Registra uma submissão no CSV principal."""
    try:
        initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS)
        with open(PROCESSADOS_CSV, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=PROCESSADOS_FIELDS, extrasaction='ignore')
            # Garante que todos os campos definidos existam no dicionário, mesmo que vazios
            row_data = {field: data.get(field, '') for field in PROCESSADOS_FIELDS}
            # Converte listas para strings separadas por vírgula, se necessário
            if isinstance(row_data.get('all_maker_inputs'), list):
                row_data['all_maker_inputs'] = ','.join(row_data['all_maker_inputs'])
            if isinstance(row_data.get('all_filenames'), list):
                row_data['all_filenames'] = ','.join(row_data['all_filenames'])
            writer.writerow(row_data)
        logging.info(f"Submissão logada para B: {data.get('char_beneficiario')} Status: {data.get('status_geral_submissao')} ID: {data.get('timestamp')}")
    except Exception as e: logging.exception(f"Erro ao logar processamento: {e}")

def log_revisao(timestamp_revisao, nome_revisor, char_beneficiario, makers_list, filenames_list, acao):
    """Registra uma ação de revisão manual no CSV de log."""
    try:
        initialize_csv(REVISAO_CSV, REVISAO_FIELDS)
        with open(REVISAO_CSV, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=REVISAO_FIELDS, extrasaction='ignore')
            writer.writerow({
                'timestamp_revisao': timestamp_revisao,
                'nome_revisor': nome_revisor,
                'char_beneficiario_aprovado': char_beneficiario or '',
                'makers_aprovados': ','.join(makers_list) if isinstance(makers_list, list) else makers_list or '',
                'filenames_associados': ','.join(filenames_list) if isinstance(filenames_list, list) else filenames_list or '',
                'acao': acao
            })
        logging.info(f"Revisão manual logada por {nome_revisor}. Ação: {acao} para B: {char_beneficiario}")
    except Exception as e: logging.exception(f"Erro ao logar revisão manual: {e}")

def get_validated_data():
    """Lê o CSV de processados e retorna contagem de aprovações por beneficiário e makers já usados."""
    beneficiarios_count = defaultdict(int)
    used_makers = set()
    try:
        initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS) # Garante que existe
        if not os.path.exists(PROCESSADOS_CSV) or os.path.getsize(PROCESSADOS_CSV) == 0:
            logging.warning("get_validated_data: processados.csv vazio ou não encontrado.")
            return {'beneficiarios_count': dict(beneficiarios_count), 'makers': used_makers}

        with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            # Validação básica do cabeçalho
            if not reader.fieldnames or not all(f in reader.fieldnames for f in ['char_beneficiario', 'all_maker_inputs', 'status_geral_submissao']):
                 logging.error(f"get_validated_data: CSV {PROCESSADOS_CSV} com cabeçalhos inválidos ou faltando colunas essenciais. Pulando leitura.")
                 return {'beneficiarios_count': dict(beneficiarios_count), 'makers': used_makers}

            for row in reader:
                # Considera apenas aprovações manuais para contagem e makers usados
                if row.get('status_geral_submissao') == 'Aprovado Manual':
                    beneficiario = row.get('char_beneficiario', '').strip().lower()
                    if beneficiario:
                        # Incrementa a contagem para este beneficiário
                        beneficiarios_count[beneficiario] += 1

                    makers_str = row.get('all_maker_inputs', '')
                    if makers_str:
                        # Adiciona os makers desta linha (já aprovados) ao conjunto de makers usados
                        current_makers = [m.strip().lower() for m in makers_str.split(',') if m.strip()]
                        used_makers.update(current_makers)

    except FileNotFoundError:
        logging.error(f"get_validated_data: Arquivo {PROCESSADOS_CSV} não encontrado.")
    except Exception as e: logging.exception(f"Erro ao ler dados validados de {PROCESSADOS_CSV}: {e}")

    logging.debug(f"Dados validados carregados: Beneficiarios Counts={dict(beneficiarios_count)}, Used Makers Count={len(used_makers)}")
    return {'beneficiarios_count': dict(beneficiarios_count), 'makers': used_makers}

# --- Decorador de Autenticação ---
def login_required(f):
    """Garante que o usuário esteja logado para acessar a rota."""
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
    """Página de login."""
    if request.method == 'POST':
        username_attempt = request.form.get('username')
        password_attempt = request.form.get('password')
        logging.info(f"Tentativa de login para usuário: '{username_attempt}'")
        # Comparação segura de credenciais (idealmente usar hash de senha)
        if username_attempt == ADMIN_USERNAME and password_attempt == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['username'] = username_attempt
            flash('Login realizado com sucesso!', 'success')
            logging.info(f"Login bem-sucedido para usuário: '{username_attempt}'")
            next_url = request.args.get('next')
            return redirect(next_url or url_for('pagina_revisao'))
        else:
            flash('Nome de usuário ou senha inválidos.', 'danger')
            logging.warning(f"Falha na tentativa de login para usuário: '{username_attempt}'")
    # Se GET ou falha no POST, renderiza o formulário de login
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Desconecta o usuário."""
    logged_out_user = session.pop('username', 'Desconhecido')
    session.pop('logged_in', None)
    flash('Você foi desconectado.', 'info')
    logging.info(f"Usuário desconectado: '{logged_out_user}'")
    return redirect(url_for('index'))

@app.route('/', methods=['GET'])
def index():
    """Página inicial com o formulário de upload."""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    """Processa o envio do formulário com múltiplos pares maker/print."""
    start_time = datetime.datetime.now()
    char_beneficiario = request.form.get('char_beneficiario', '').strip()
    logging.debug(f"Recebido upload para beneficiário: '{char_beneficiario}'")

    if not char_beneficiario:
        flash('Nome do Personagem Beneficiário é obrigatório!', 'warning')
        return redirect(url_for('index'))

    submitted_pairs = [] # Lista para armazenar os pares válidos (maker, file)
    maker_names_in_submission = set() # Para checar duplicatas dentro da mesma submissão
    form_keys = list(request.form.keys())
    file_keys = list(request.files.keys())
    logging.debug(f"Form keys recebidos: {form_keys}")
    logging.debug(f"File keys recebidos: {file_keys}")

    # Loop para encontrar pares maker_name_X e print_X
    i = 1
    while True:
        maker_name_key = f'maker_name_{i}'
        print_key = f'print_{i}'

        # Condição de parada: se não encontrar nem o nome nem o arquivo para o índice atual
        if maker_name_key not in form_keys and print_key not in file_keys:
             # Se for o primeiro índice e não encontrou nada, loga um aviso
             if i == 1: logging.warning("Nenhum par maker_name_X / print_X encontrado no formulário.")
             break # Sai do loop

        maker_name = request.form.get(maker_name_key, '').strip()
        print_file = request.files.get(print_key)

        # Validações para o par atual
        if not maker_name:
            flash(f'Nome do Maker {i} está vazio ou não foi encontrado!', 'warning')
            logging.warning(f"Nome vazio/ausente para maker_{i}")
            return redirect(url_for('index'))
        if not print_file or not print_file.filename:
            flash(f'Print {i} (para Maker {maker_name}) não foi enviado ou não foi encontrado!', 'warning')
            logging.warning(f"Arquivo ausente/inválido para print_{i}")
            return redirect(url_for('index'))
        if not allowed_file(print_file.filename):
            flash(f'Formato inválido para Print {i} ({print_file.filename})!', 'warning')
            logging.warning(f"Arquivo inválido: {print_file.filename}")
            return redirect(url_for('index'))

        logging.debug(f"Processando par índice {i}: Maker='{maker_name}', File='{print_file.filename}'")

        # Verifica duplicidade de maker DENTRO desta submissão
        maker_name_lower = maker_name.lower()
        if maker_name_lower in maker_names_in_submission:
            flash(f'Nome do Maker "{maker_name}" repetido nesta submissão!', 'warning')
            logging.warning(f"Maker repetido na submissão: {maker_name}")
            return redirect(url_for('index'))
        maker_names_in_submission.add(maker_name_lower)

        # Adiciona o par válido à lista
        submitted_pairs.append({'index': i, 'name': maker_name, 'file': print_file})
        i += 1 # Incrementa para buscar o próximo par

    # Verifica se o número mínimo de pares foi enviado
    if len(submitted_pairs) < MIN_MAKER_PAIRS_REQUIRED:
        flash(f'É necessário enviar pelo menos {MIN_MAKER_PAIRS_REQUIRED} pares válidos de Maker/Print.', 'warning')
        logging.warning(f"Menos de {MIN_MAKER_PAIRS_REQUIRED} pares válidos enviados.")
        return redirect(url_for('index'))

    logging.info(f"Submissão válida recebida para B: '{char_beneficiario}' com {len(submitted_pairs)} pares.")

    # --- Validação contra dados já existentes ---
    validated_data = get_validated_data()
    beneficiario_lower = char_beneficiario.lower()
    rejection_reason, rejection_message = None, None

    # Verifica limite do beneficiário
    current_beneficiary_count = validated_data['beneficiarios_count'].get(beneficiario_lower, 0)
    needed_approvals = len(submitted_pairs) # Cada par conta como uma aprovação potencial
    logging.debug(f"Verificando limites/duplicados: B='{beneficiario_lower}' (Count={current_beneficiary_count}, Limit={BENEFICIARIO_APPROVAL_LIMIT}), Makers nesta submissão={maker_names_in_submission}")
    if current_beneficiary_count + needed_approvals > BENEFICIARIO_APPROVAL_LIMIT:
        rejection_reason = 'beneficiario_limit_exceeded'
        rejection_message = f"Rejeitado: Beneficiário '{char_beneficiario}' já possui {current_beneficiary_count} aprovações e esta submissão com {needed_approvals} excederia o limite de {BENEFICIARIO_APPROVAL_LIMIT}."
    else:
        # Verifica duplicidade global de makers
        for pair in submitted_pairs:
            maker_lower = pair['name'].lower()
            if maker_lower in validated_data['makers']:
                rejection_reason = f'maker_duplicate_global'
                rejection_message = f"Rejeitado: O Maker '{pair['name']}' já foi utilizado em uma validação anterior."
                break # Para na primeira duplicata encontrada

    # Se houve rejeição, loga e informa o usuário
    if rejection_reason:
        flash(rejection_message, 'warning')
        logging.warning(f"Submissão rejeitada ({rejection_reason}): {rejection_message}")
        # Loga a tentativa rejeitada
        log_entry_rejected = {
            'timestamp': datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f"),
            'char_beneficiario': char_beneficiario,
            'all_maker_inputs': ','.join([p['name'] for p in submitted_pairs]),
            'all_filenames': ','.join([p['file'].filename for p in submitted_pairs]), # Usa nome original aqui
            'status_geral_submissao': 'Rejeitado Duplicado/Limite',
            'revisado_por': 'Sistema',
            'timestamp_revisao': datetime.datetime.now().isoformat(),
            'rejection_reason': rejection_reason
        }
        log_processamento(log_entry_rejected)
        # Renderiza página de resultado informando a rejeição
        return render_template('resultado.html',
                               message=rejection_message,
                               status='warning',
                               char_beneficiario=char_beneficiario,
                               current_count=current_beneficiary_count, # Passa a contagem atual
                               limit=BENEFICIARIO_APPROVAL_LIMIT,       # Passa o limite
                               rejection_reason=rejection_reason)       # Passa o motivo

    # --- Processamento e Salvamento dos Arquivos (se passou nas validações) ---
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y%m%d_%H%M%S_%f") # Timestamp único para a submissão
    # Nome seguro para o beneficiário (para usar no nome do arquivo)
    safe_beneficiario_name = "".join(c for c in char_beneficiario if c.isalnum() or c == ' ').strip().replace(' ', '_')

    saved_filenames = [] # Lista para guardar os nomes dos arquivos salvos
    all_maker_names = [] # Lista para guardar os nomes dos makers desta submissão

    for pair in submitted_pairs:
        maker_name = pair['name']
        file_obj = pair['file']
        index = pair['index'] # Índice original do formulário

        all_maker_names.append(maker_name) # Adiciona nome à lista de makers da submissão

        # Cria um nome de arquivo seguro e informativo
        safe_maker_name = "".join(c for c in maker_name if c.isalnum() or c == ' ').strip().replace(' ', '_')
        file_extension = file_obj.filename.rsplit('.', 1)[1].lower()
        # Estrutura do nome do arquivo: timestamp_B_beneficiario_M<indice>_maker_img<indice>.extensao
        filename = secure_filename(f"{timestamp_str}_B_{safe_beneficiario_name}_M{index}_{safe_maker_name}_img{index}.{file_extension}")
        save_path = os.path.join(SUSPEITOS_DIR, filename)
        logging.debug(f"Tentando salvar arquivo em: {save_path} (Caminho absoluto: {os.path.abspath(save_path)})")

        try:
            file_obj.seek(0) # Garante que a leitura comece do início do arquivo
            file_obj.save(save_path)
            # Verifica se o arquivo realmente foi salvo
            if os.path.exists(save_path):
                logging.info(f"Arquivo salvo COM SUCESSO e ENCONTRADO: {filename} em {save_path}")
            else:
                # Isso não deveria acontecer se save() não deu erro, mas é uma checagem extra
                logging.error(f"Arquivo salvo mas NÃO ENCONTRADO IMEDIATAMENTE: {filename} em {save_path}. Verifique permissões ou caminho.")
                # Considerar lançar um erro aqui ou tratar como falha crítica
            saved_filenames.append(filename) # Adiciona nome do arquivo salvo à lista
        except Exception as e:
            # Se der erro ao salvar um arquivo, remove os que já foram salvos desta submissão
            for fname in saved_filenames:
                try:
                    os.remove(os.path.join(SUSPEITOS_DIR, fname))
                except OSError:
                    pass # Ignora erro ao remover (pode já não existir)
            logging.exception(f"Erro CRÍTICO ao salvar {file_obj.filename} para {save_path}: {e}")
            flash(f"Erro CRÍTICO ao salvar arquivo para o maker '{maker_name}'. A submissão foi cancelada.", "danger")
            return redirect(url_for('index'))

    # Se chegou aqui, todos os arquivos foram salvos com sucesso
    logging.info(f"Todos os {len(saved_filenames)} arquivos da submissão {timestamp_str} foram processados para salvamento em {SUSPEITOS_DIR}: {saved_filenames}")

    # --- Loga a submissão como pendente no CSV ---
    log_entry = {
        'timestamp': timestamp_str, # ID único da submissão
        'char_beneficiario': char_beneficiario,
        'all_maker_inputs': ','.join(all_maker_names), # Nomes dos makers separados por vírgula
        'all_filenames': ','.join(saved_filenames),   # Nomes dos arquivos salvos separados por vírgula
        'status_geral_submissao': 'Pendente Revisão', # Status inicial
        'revisado_por': '',
        'timestamp_revisao': '',
        'rejection_reason': ''
    }
    logging.debug(f"Logando submissão pendente no CSV: {log_entry}")
    log_processamento(log_entry)

    # --- Informa o usuário sobre o sucesso e status pendente ---
    processing_time = (datetime.datetime.now() - start_time).total_seconds()
    logging.info(f"Submissão para B:'{char_beneficiario}' com {len(all_maker_names)} makers enviada para revisão. Tempo: {processing_time:.2f}s.")

    final_message = (f"Submissão para '{char_beneficiario}' com {len(all_maker_names)} makers ({', '.join(all_maker_names)}) recebida e enviada para revisão. "
                     f"Este beneficiário tem {current_beneficiary_count} aprovações e esta submissão adicionaria {len(all_maker_names)}, totalizando {current_beneficiary_count + len(all_maker_names)} de {BENEFICIARIO_APPROVAL_LIMIT} permitidas se aprovada.")
    flash(final_message, 'success')

    # Renderiza a página de resultado
    return render_template('resultado.html',
                           message=final_message,
                           status='success', # Indica sucesso no envio
                           char_beneficiario=char_beneficiario,
                           makers_submitted=all_maker_names, # Passa a lista de makers enviados
                           status_final1='Pendente Revisão', # Status explícito
                           rejection_reason=None) # Sem rejeição nesta fase


@app.route('/validados_pesquisa', methods=['GET'])
@login_required
def pagina_validados_pesquisa():
    """Página para administradores pesquisarem validações aprovadas."""
    query = request.args.get('q', '').strip().lower() # Termo de busca
    error_msg = None
    validacoes_agrupadas = [] # Lista final para o template

    try:
        initialize_all_csvs() # Garante que CSVs existem
        if not os.path.exists(PROCESSADOS_CSV) or os.path.getsize(PROCESSADOS_CSV) == 0:
            error_msg = "Arquivo de validações (processados.csv) não encontrado ou vazio."
        else:
            with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                # Validação do cabeçalho
                if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS):
                     error_msg = "Arquivo de validações (processados.csv) corrompido ou formato antigo."
                else:
                    temp_validacoes = [] # Lista temporária para guardar as linhas aprovadas
                    for row in reader:
                        # Filtra apenas as linhas aprovadas manualmente
                        if row.get('status_geral_submissao') == 'Aprovado Manual':
                            beneficiario = row.get('char_beneficiario', 'N/A')
                            makers_str = row.get('all_maker_inputs', '')
                            makers_list = [m.strip() for m in makers_str.split(',') if m.strip()]
                            revisor = row.get('revisado_por', '')
                            timestamp_rev_iso = row.get('timestamp_revisao', '')
                            timestamp_display = timestamp_rev_iso # Fallback

                            # Tenta formatar o timestamp para exibição
                            try:
                                if timestamp_rev_iso:
                                    timestamp_rev_dt = datetime.datetime.fromisoformat(timestamp_rev_iso)
                                    timestamp_display = timestamp_rev_dt.strftime("%Y-%m-%d %H:%M")
                            except ValueError:
                                logging.warning(f"Falha ao converter timestamp '{timestamp_rev_iso}' para B '{beneficiario}'. Usando ISO string.")

                            # Verifica se a linha corresponde à query (se houver)
                            matches_query = (
                                not query or # Se não há query, todos combinam
                                query in beneficiario.lower() or
                                (revisor and query in revisor.lower()) or
                                any(query in maker.lower() for maker in makers_list)
                            )

                            if matches_query:
                                temp_validacoes.append({
                                    'timestamp': timestamp_display,
                                    'beneficiario': beneficiario,
                                    'makers_display': ', '.join(makers_list) if makers_list else 'N/A',
                                    'status': f'Aprovado por {revisor}' if revisor else 'Aprovado Manualmente',
                                    'revisado_por': revisor,
                                    'submission_id': row.get('timestamp') # ID original da submissão
                                })

                    # Ordena as validações encontradas pela data/hora (mais recentes primeiro)
                    temp_validacoes.sort(key=lambda x: x.get('timestamp', '0'), reverse=True)
                    validacoes_agrupadas = temp_validacoes # Neste caso, não estamos agrupando, apenas listando

    except Exception as e:
        error_msg = f"Erro ao carregar validações para pesquisa: {e}"
        logging.exception(error_msg)

    # Renderiza a página de pesquisa com os resultados
    return render_template('validados_pesquisa.html',
                           validacoes=validacoes_agrupadas, # Passa a lista de validações
                           limit=BENEFICIARIO_APPROVAL_LIMIT,
                           error=error_msg,
                           search_query=query) # Passa a query de volta para o input


@app.route('/revisao', methods=['GET'])
@login_required
def pagina_revisao():
    """Página para revisar submissões pendentes."""
    submissions_pending = []
    error_msg = None
    logging.debug(f"--- INÍCIO ROTA /revisao ---")
    logging.debug(f"Tentando ler CSV: {PROCESSADOS_CSV} (Abs: {os.path.abspath(PROCESSADOS_CSV)})")
    logging.debug(f"Verificando arquivos em: {SUSPEITOS_DIR} (Abs: {os.path.abspath(SUSPEITOS_DIR)})")

    try:
        # Garante que o diretório de suspeitos existe (embora já deva existir)
        if not os.path.isdir(SUSPEITOS_DIR):
             logging.error(f"Diretório de suspeitos NÃO ENCONTRADO em {SUSPEITOS_DIR}")
             error_msg = f"Erro crítico: Diretório de arquivos pendentes ({SUSPEITOS_DIR}) não encontrado."
             # Não adianta continuar se a pasta não existe
             return render_template('revisao.html', submissions=[], error=error_msg)

        initialize_all_csvs() # Garante que o CSV existe

        if not os.path.exists(PROCESSADOS_CSV) or os.path.getsize(PROCESSADOS_CSV) == 0:
            error_msg = "Arquivo de processamento (processados.csv) não encontrado ou vazio."
            logging.warning(f"/revisao: {error_msg}")
        else:
             logging.debug(f"/revisao: Lendo CSV: {PROCESSADOS_CSV}")
             with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)

                # Validação do cabeçalho do CSV
                if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS):
                     error_msg = "Arquivo de processamento (processados.csv) corrompido ou com formato inválido."
                     logging.error(f"/revisao: {error_msg}")
                else:
                    row_count = 0
                    for row in reader:
                        row_count += 1
                        status_atual = row.get('status_geral_submissao', '').strip()
                        submission_id_from_row = row.get('timestamp')

                        # LOG DETALHADO DA LINHA SENDO LIDA
                        logging.debug(f"/revisao: Lendo linha {row_count} do CSV: ID='{submission_id_from_row}', Status='{status_atual}'")

                        # Processa apenas as linhas com status 'Pendente Revisão'
                        if status_atual == 'Pendente Revisão':
                            makers_str = row.get('all_maker_inputs', '')
                            filenames_str = row.get('all_filenames', '')
                            beneficiario = row.get('char_beneficiario', 'N/A')

                            logging.info(f"/revisao: Submissão PENDENTE encontrada: ID={submission_id_from_row}, B='{beneficiario}', Makers='{makers_str}', Files='{filenames_str}'")

                            # Converte as strings de volta para listas
                            makers_list = [m.strip() for m in makers_str.split(',') if m.strip()]
                            filenames_list = [f.strip() for f in filenames_str.split(',') if f.strip()]

                            # Validação básica dos dados da linha
                            if not submission_id_from_row or not makers_list or not filenames_list:
                                logging.warning(f"/revisao: Submissão pendente {submission_id_from_row} com dados faltando (ID, makers ou filenames vazios no CSV). Pulando.")
                                continue
                            if len(makers_list) != len(filenames_list):
                                logging.warning(f"/revisao: Submissão pendente {submission_id_from_row} com contagem inconsistente de makers ({len(makers_list)}) e filenames ({len(filenames_list)}). Pulando.")
                                continue

                            # --- VERIFICAÇÃO DA EXISTÊNCIA DOS ARQUIVOS ---
                            all_files_exist = True
                            missing_files_log = []
                            logging.debug(f"/revisao: Verificando {len(filenames_list)} arquivos para submissão {submission_id_from_row} em {SUSPEITOS_DIR}...")
                            for fname in filenames_list:
                                file_path_check = os.path.join(SUSPEITOS_DIR, fname)
                                file_path_abs = os.path.abspath(file_path_check) # Log do caminho absoluto

                                exists = os.path.exists(file_path_check)

                                # LOG DETALHADO DA VERIFICAÇÃO DE CADA ARQUIVO
                                logging.debug(f"/revisao:  -> Verificando '{fname}': Path='{file_path_check}', AbsPath='{file_path_abs}', Existe? {exists}")

                                if not exists:
                                    logging.error(f"/revisao: ARQUIVO NÃO ENCONTRADO! Nome: '{fname}', Caminho verificado: '{file_path_check}' (Abs: '{file_path_abs}') para submissão {submission_id_from_row}")
                                    all_files_exist = False
                                    missing_files_log.append(fname)
                                    # Não precisa continuar verificando os outros arquivos desta submissão se um já faltou
                                    # break # Removido break para logar TODOS os arquivos faltantes

                            # Se TODOS os arquivos existirem, adiciona à lista para exibição
                            if all_files_exist:
                                logging.info(f"/revisao: OK! Todos os {len(filenames_list)} arquivos encontrados para submissão {submission_id_from_row}. Adicionando à lista de revisão.")
                                submissions_pending.append({
                                    'submission_id': submission_id_from_row,
                                    'char_beneficiario': beneficiario,
                                    'makers': makers_list,
                                    'filenames': filenames_list,
                                    'timestamp_original': submission_id_from_row # Usado para ordenação
                                })
                            else:
                                # Se algum arquivo não foi encontrado, loga e ignora a submissão
                                logging.warning(f"/revisao: Submissão {submission_id_from_row} IGNORADA para revisão devido a arquivos ausentes: {missing_files_log}.")

                        else:
                            # Loga as linhas que não estão pendentes (apenas para debug)
                            logging.debug(f"/revisao: Linha {row_count} (ID: {submission_id_from_row}) não está 'Pendente Revisão', status é '{status_atual}'. Pulando.")

        # Ordena as submissões pendentes pela data/hora original (mais recentes primeiro)
        submissions_pending.sort(key=lambda x: x.get('timestamp_original', '0'), reverse=True)
        logging.info(f"/revisao: Total de submissões pendentes para exibir: {len(submissions_pending)}")

    except FileNotFoundError:
        error_msg = f"Erro: Arquivo {PROCESSADOS_CSV} não encontrado."
        logging.error(f"/revisao: {error_msg}")
    except Exception as e:
        error_msg = f"Erro inesperado ao listar pendentes: {e}"
        logging.exception(error_msg)
        flash(error_msg, "danger") # Mostra erro genérico na interface

    logging.debug(f"--- FIM ROTA /revisao ---")
    # Renderiza a página de revisão passando a lista de submissões pendentes
    return render_template('revisao.html', submissions=submissions_pending, error=error_msg)


@app.route('/suspeitos/<path:filename>')
@login_required
def serve_suspeito(filename):
    """Serve arquivos de imagem da pasta de suspeitos (ou processados como fallback)."""
    try:
        # Medida de segurança básica contra path traversal
        if '..' in filename or filename.startswith('/'):
            logging.warning(f"Tentativa de acesso inválido a arquivo: {filename}")
            return "Acesso inválido", 400

        # Limpa o nome do arquivo para segurança
        safe_filename = secure_filename(filename)

        # Caminho para o arquivo na pasta de suspeitos
        suspeito_path = os.path.join(SUSPEITOS_DIR, safe_filename)
        logging.debug(f"Tentando servir arquivo suspeito: {suspeito_path} (Abs: {os.path.abspath(suspeito_path)})")

        # Verifica se existe em 'suspeitos' e serve
        if os.path.exists(suspeito_path):
            logging.debug(f"Servindo de SUSPEITOS: {safe_filename}")
            return send_from_directory(SUSPEITOS_DIR, safe_filename, as_attachment=False)

        # Fallback: Verifica se existe em 'processados' (caso já tenha sido aprovado mas o link ainda é antigo)
        processado_path = os.path.join(PROCESSADOS_DIR, safe_filename)
        logging.debug(f"Não encontrado em suspeitos. Tentando servir de processados: {processado_path} (Abs: {os.path.abspath(processado_path)})")
        if os.path.exists(processado_path):
            logging.warning(f"Servindo arquivo de PROCESSADOS (fallback): {safe_filename}")
            return send_from_directory(PROCESSADOS_DIR, safe_filename, as_attachment=False)

        # Se não encontrou em nenhum dos locais
        logging.error(f"Arquivo não encontrado para servir (nem suspeito, nem processado): {safe_filename}")
        return "Arquivo não encontrado", 404

    except Exception as e:
        logging.exception(f"Erro ao servir arquivo {filename}: {e}")
        return "Erro interno do servidor", 500


@app.route('/aprovar/<submission_id>', methods=['POST'])
@login_required
def aprovar_par(submission_id):
    """Processa a aprovação de uma submissão pendente."""
    nome_revisor_manual = request.form.get('revisor_name', '').strip()
    if not nome_revisor_manual:
        flash("Nome do revisor é obrigatório para aprovar.", "warning")
        return redirect(url_for('pagina_revisao'))

    logging.info(f"Tentativa de aprovação por '{nome_revisor_manual}' para Submissão ID: '{submission_id}'")

    original_rows = []
    row_index_to_update = -1
    submission_data = None

    try:
        # --- 1. Ler todo o CSV original ---
        initialize_csv(PROCESSADOS_CSV, PROCESSADOS_FIELDS) # Garante que existe
        with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS):
                flash("Erro crítico: Formato do arquivo processados.csv inválido.", "danger")
                logging.error("Formato inválido do processados.csv ao tentar aprovar.")
                return redirect(url_for('pagina_revisao'))
            original_rows = list(reader) # Carrega todas as linhas na memória

        # --- 2. Encontrar a linha a ser atualizada ---
        for i, row in enumerate(original_rows):
            # Compara o timestamp (ID) e verifica se o status é 'Pendente Revisão'
            if row.get('timestamp') == submission_id and row.get('status_geral_submissao', '').strip() == 'Pendente Revisão':
                submission_data = row # Guarda os dados da linha encontrada
                row_index_to_update = i # Guarda o índice da linha
                logging.debug(f"Encontrada submissão pendente no CSV para ID {submission_id} na linha {i}.")
                break # Para a busca

        # --- 3. Validar se a submissão foi encontrada e está pendente ---
        if not submission_data:
            flash(f"Erro: Submissão com ID '{submission_id}' não encontrada ou já processada.", "danger")
            logging.error(f"Tentativa de aprovar submissão {submission_id} falhou: Não encontrada ou não está pendente no CSV.")
            return redirect(url_for('pagina_revisao'))

        # --- 4. Extrair dados da submissão encontrada ---
        char_beneficiario_original = submission_data.get('char_beneficiario', '')
        makers_str = submission_data.get('all_maker_inputs', '')
        filenames_str = submission_data.get('all_filenames', '')
        makers_list_original = [m.strip() for m in makers_str.split(',') if m.strip()]
        filenames_list_original = [f.strip() for f in filenames_str.split(',') if f.strip()]

        # Validação básica dos dados extraídos
        if not char_beneficiario_original or not makers_list_original or not filenames_list_original:
            flash(f"Erro: Dados incompletos na submissão {submission_id} no CSV.", "danger")
            logging.error(f"Dados incompletos (beneficiário, makers ou filenames) na linha do CSV para submissão {submission_id}.")
            return redirect(url_for('pagina_revisao'))
        if len(makers_list_original) != len(filenames_list_original):
             flash(f"Erro: Inconsistência de dados na submissão {submission_id} (contagem maker/file).", "danger")
             logging.error(f"Inconsistência M/F na linha do CSV para submissão {submission_id}.")
             return redirect(url_for('pagina_revisao'))

        # --- 5. Revalidar Limites e Duplicatas (importante!) ---
        # Busca os dados validados ATUALIZADOS (pode ter mudado desde o upload)
        validated_data = get_validated_data()
        beneficiario_lower = char_beneficiario_original.lower()
        rejection_reason, rejection_message = None, None

        # Re-verifica limite do beneficiário
        current_beneficiary_count = validated_data['beneficiarios_count'].get(beneficiario_lower, 0)
        approvals_in_this_submission = len(makers_list_original) # Cada maker conta como uma aprovação
        logging.info(f"Revalidando aprovação para B:'{char_beneficiario_original}'. Aprovados atualmente:{current_beneficiary_count}/{BENEFICIARIO_APPROVAL_LIMIT}. Esta submissão adicionaria +{approvals_in_this_submission}")

        if current_beneficiary_count + approvals_in_this_submission > BENEFICIARIO_APPROVAL_LIMIT:
            rejection_reason = 'beneficiario_limit_reached_aprovacao'
            rejection_message = f"Aprovação Bloqueada: Beneficiário '{char_beneficiario_original}' já tem {current_beneficiary_count} aprovações. Aprovar esta submissão com {approvals_in_this_submission} makers excederia o limite de {BENEFICIARIO_APPROVAL_LIMIT}."
        else:
            # Re-verifica duplicidade global de makers
            for maker_name in makers_list_original:
                maker_lower = maker_name.lower()
                # Verifica se algum maker desta submissão JÁ EXISTE no conjunto de makers aprovados
                if maker_lower in validated_data['makers']:
                    rejection_reason = 'maker_duplicate_aprovacao'
                    rejection_message = f"Aprovação Bloqueada: O Maker '{maker_name}' já foi utilizado em uma validação aprovada anteriormente."
                    break # Para na primeira duplicata

        # Se houve bloqueio na revalidação, informa e retorna
        if rejection_reason:
            flash(rejection_message, 'warning')
            logging.warning(f"Aprovação da submissão {submission_id} bloqueada na revalidação ({rejection_reason}): {rejection_message}")
            # NÃO atualiza o CSV nem move arquivos
            return redirect(url_for('pagina_revisao'))

        # --- 6. Mover Arquivos de 'suspeitos' para 'processados' ---
        all_moved = True
        moved_files = [] # Para rastrear arquivos movidos e poder reverter
        logging.debug(f"Tentando mover {len(filenames_list_original)} arquivos para {PROCESSADOS_DIR}...")
        for filename in filenames_list_original:
            path_suspeito = os.path.join(SUSPEITOS_DIR, filename)
            path_processado = os.path.join(PROCESSADOS_DIR, filename)

            # Verifica se o arquivo existe em 'suspeitos' antes de mover
            if os.path.exists(path_suspeito):
                try:
                    os.rename(path_suspeito, path_processado) # Tenta mover
                    moved_files.append(filename) # Adiciona à lista de movidos
                    logging.info(f"Arquivo movido com sucesso: {filename} de {SUSPEITOS_DIR} para {PROCESSADOS_DIR}")
                except OSError as e:
                    logging.error(f"Erro CRÍTICO ao mover arquivo {filename} de {SUSPEITOS_DIR} para {PROCESSADOS_DIR}: {e}")
                    all_moved = False
                    break # Para a operação de mover
            else:
                # Isso é um problema sério - o arquivo existia na verificação da página, mas não agora?
                logging.error(f"Arquivo {filename} NÃO encontrado em {SUSPEITOS_DIR} durante a tentativa de movê-lo! A aprovação será cancelada.")
                all_moved = False
                break # Para a operação de mover

        # --- 7. Reverter Movimentação se Algo Falhou ---
        if not all_moved:
            logging.warning(f"Falha ao mover um ou mais arquivos para {submission_id}. Revertendo movimentações...")
            for fname in moved_files: # Tenta mover de volta os que foram movidos
                try:
                    os.rename(os.path.join(PROCESSADOS_DIR, fname), os.path.join(SUSPEITOS_DIR, fname))
                    logging.info(f"Arquivo revertido: {fname} de volta para {SUSPEITOS_DIR}")
                except OSError as e_revert:
                    # Se falhar ao reverter, apenas loga, pois a situação já é de erro
                    logging.error(f"Erro ao tentar reverter a movimentação do arquivo {fname}: {e_revert}")
            flash(f"Erro crítico ao mover os arquivos da submissão {submission_id}. A aprovação foi cancelada. Verifique os logs.", "danger")
            # NÃO atualiza o CSV
            return redirect(url_for('pagina_revisao'))

        # --- 8. Atualizar a Linha no CSV (na memória) ---
        ts_revisao = datetime.datetime.now().isoformat() # Timestamp da revisão
        original_rows[row_index_to_update]['status_geral_submissao'] = 'Aprovado Manual'
        original_rows[row_index_to_update]['revisado_por'] = nome_revisor_manual
        original_rows[row_index_to_update]['timestamp_revisao'] = ts_revisao
        original_rows[row_index_to_update]['rejection_reason'] = '' # Limpa motivo de rejeição anterior, se houver

        # --- 9. Reescrever TODO o arquivo CSV com a linha atualizada ---
        # Isso é mais seguro do que tentar editar in-loco
        logging.debug(f"Reescrevendo {PROCESSADOS_CSV} com a linha {row_index_to_update} atualizada para 'Aprovado Manual'.")
        with open(PROCESSADOS_CSV, 'w', newline='', encoding='utf-8') as outfile:
             writer = csv.DictWriter(outfile, fieldnames=PROCESSADOS_FIELDS)
             writer.writeheader()
             writer.writerows(original_rows) # Escreve todas as linhas (a modificada e as outras)

        # --- 10. Logar a Ação de Revisão ---
        log_revisao(ts_revisao, nome_revisor_manual, char_beneficiario_original, makers_list_original, filenames_list_original, "Aprovado")

        # --- 11. Informar Sucesso ---
        flash(f"Submissão para '{char_beneficiario_original}' (Makers: {', '.join(makers_list_original)}) aprovada com sucesso por '{nome_revisor_manual}'.", "success")
        # Informa a contagem atualizada
        flash(f"'{char_beneficiario_original}' agora tem {current_beneficiary_count + approvals_in_this_submission} aprovações de {BENEFICIARIO_APPROVAL_LIMIT}.", "info")
        logging.info(f"Submissão {submission_id} aprovada por {nome_revisor_manual}.")

    except FileNotFoundError:
        flash(f"Erro crítico: Arquivo {PROCESSADOS_CSV} não encontrado durante a aprovação.", "danger")
        logging.error(f"FileNotFoundError ao tentar aprovar {submission_id}.")
    except Exception as e:
        flash(f"Erro inesperado ao tentar aprovar a submissão {submission_id}: {e}", "danger")
        logging.exception(f"Erro inesperado na rota /aprovar para {submission_id}: {e}")
        # Tentar reverter movimentações aqui também pode ser uma boa prática,
        # mas a lógica de 'moved_files' pode não estar acessível dependendo de onde o erro ocorreu.

    # Redireciona de volta para a página de revisão em qualquer caso (sucesso ou falha tratada)
    return redirect(url_for('pagina_revisao'))


@app.route('/validados_publico', methods=['GET'])
def validados_publico():
    """Página pública que mostra a contagem de aprovações por beneficiário."""
    validacoes_publicas = defaultdict(int) # Dicionário para contar aprovações por beneficiário
    error_msg = None
    try:
        initialize_all_csvs() # Garante que CSV existe
        if not os.path.exists(PROCESSADOS_CSV) or os.path.getsize(PROCESSADOS_CSV) == 0:
            error_msg = "Nenhuma validação registrada ainda."
        else:
            with open(PROCESSADOS_CSV, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                # Validação do cabeçalho
                if not reader.fieldnames or not all(f in reader.fieldnames for f in PROCESSADOS_FIELDS):
                    error_msg = "Erro ao ler o formato do arquivo de validações."
                else:
                    for row in reader:
                        # Conta apenas as linhas que foram 'Aprovado Manual'
                        if row.get('status_geral_submissao') == 'Aprovado Manual':
                            beneficiario = row.get('char_beneficiario', 'N/A')
                            # Só conta se o nome do beneficiário for válido
                            if beneficiario != 'N/A' and beneficiario.strip():
                                # Incrementa a contagem para este beneficiário
                                # Usamos o nome original (com case) para exibição, mas a contagem é por nome
                                validacoes_publicas[beneficiario.strip()] += 1

        # Ordena os resultados pelo nome do beneficiário para exibição
        validacoes_ordenadas = sorted(validacoes_publicas.items())

    except Exception as e:
        error_msg = f"Erro ao carregar validações públicas: {e}"
        logging.exception(error_msg)

    # Renderiza a página pública
    return render_template('validados_publico.html',
                           validacoes=validacoes_ordenadas, # Passa a lista de tuplas (nome, contagem)
                           limit=BENEFICIARIO_APPROVAL_LIMIT,
                           error=error_msg)

# --- Inicialização ---
if __name__ == '__main__':
    initialize_all_csvs() # Garante que os CSVs sejam criados ao iniciar
    logging.info("-----------------------------------------")
    logging.info(f"Iniciando Validador Tibia (Manual - Múltiplos Pares - Limite {BENEFICIARIO_APPROVAL_LIMIT}/Beneficiário)...")
    # Aviso sobre credenciais padrão
    if ADMIN_USERNAME == 'admin' or ADMIN_PASSWORD == 'ollamaNgrokSenha123$$$Maestra':
        logging.warning("ATENÇÃO: Usando credenciais de ADMIN padrão! Altere ADMIN_USERNAME e ADMIN_PASSWORD.")
    # Executa o servidor Flask
    # Use 'debug=True' apenas em desenvolvimento. Para produção, use um servidor WSGI como Gunicorn ou Waitress.
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')