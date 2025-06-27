# Detecção de Ameaças em APIs com Aprendizado de Máquina: 
# Foco Exclusivo no Caminho da URL

# Objetivo:
#   Treinar um modelo leve e robusto, usando apenas features
#   extraídas do caminho da URL e do método HTTP.

# %%
# CARREGAR O DATASET E BIBLIOTECAS
# ----------------------------------------------------------------
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix
)
import seaborn as sns
import matplotlib.pyplot as plt
import joblib

# 1. CARREGAR OS DADOS
csic_data = pd.read_csv('csic_database.csv')
feature_names = ['Method', 'classification', 'URL']
X = csic_data[feature_names].copy()
X.dropna(subset=['URL'], inplace=True)
X['URL'] = X['URL'].astype(str)

# %%
# 2. DEFINIR FUNÇÕES DE FEATURES
# ----------------------------------------------------------------
# Funções que não serão usadas (hostname_length, count_http) foram removidas para maior clareza.
def count_dot(url): return url.count('.')
def no_of_dir(url): return urlparse(url).path.count('/')
def no_of_embed(url): return urlparse(url).path.count('//')
def count_per(url): return url.count('%')
def count_ques(url): return url.count('?')
def count_hyphen(url): return url.count('-')
def count_equal(url): return url.count('=')
def url_length(url): return len(str(url))
def suspicious_words(url):
    score_map = { 'error': 30, 'SELECT': 50, 'FROM': 50, 'WHERE': 50, 'DELETE': 50, 'USERS': 50, 'DROP': 50, 'CREATE': 50, 'INJECTED': 50, 'TABLE': 50, 'alert': 30, 'javascript': 20, 'cookie': 25, '--': 30, '.exe': 30, '.php': 20, '.js': 10, 'admin': 10, 'administrator': 10, '\'': 30, 'password': 15, 'login': 15, 'incorrect': 20, 'pwd': 15, 'tamper': 25, 'vaciar': 20, 'carrito': 25, 'wait': 30, 'delay': 35, 'set': 20, 'steal': 35, 'hacker': 35, 'proxy': 35, 'location': 30, 'document.cookie': 40, 'document': 20, 'set-cookie': 40, 'create': 40, 'cmd': 40, 'dir': 30, 'shell': 40, 'reverse': 30, 'bin': 20, 'cookiesteal': 40, 'LIKE': 30, 'UNION': 35, 'include': 30, 'file': 20, 'tmp': 25, 'ssh': 40, 'exec': 30, 'cat': 25, 'etc': 30, 'fetch': 25, 'eval': 30, 'malware': 45, 'ransomware': 45, 'phishing': 45, 'exploit': 45, 'virus': 45, 'trojan': 45, 'backdoor': 45, 'spyware': 45, 'rootkit': 45, 'credential': 30, 'inject': 30, 'script': 25, 'iframe': 25, 'src=': 25, 'onerror': 30, 'prompt': 20, 'confirm': 20, 'expression': 30, r'function\(': 20, 'xmlhttprequest': 30, 'xhr': 20, 'window.': 20, 'document.': 20, 'click': 15, 'mouseover': 15, 'onload': 20, 'onunload': 20 }
    matches = re.findall(r'(?i)' + '|'.join(score_map.keys()), url)
    return sum(score_map.get(match.lower(), 0) for match in matches)
def digit_count(url): return sum(c.isdigit() for c in url)
def letter_count(url): return sum(c.isalpha() for c in url)
def count_special_characters(url): return len(re.sub(r'[a-zA-Z0-9\s]', '', url))
def number_of_parameters(url):
    params = urlparse(url).query
    return 0 if not params else len(params.split('&'))
def is_encoded(url): return 1 if '%' in url.lower() else 0
def unusual_character_ratio(url):
    total_characters = len(url)
    if total_characters == 0: return 0
    unusual_characters = re.sub(r'[a-zA-Z0-9\s\-._]', '', url)
    return len(unusual_characters) / total_characters
# Adicione esta nova função para extrair apenas a query
def get_query(url):
    try:
        return urlparse(url).query
    except:
        return ""
# %%
# --- ETAPA 1: Limpar a coluna URL para remover o " HTTP/1.1" no final ---
print("Limpando a coluna de URL...")
# Isso divide a string no espaço antes de "HTTP/" e pega a primeira parte (a URL real)
X['URL_limpa'] = X['URL'].str.split(' HTTP/').str[0]

# --- ETAPA 2: Extrair o PATH da URL limpa ---
print("Extraindo o 'path' da URL...")
# Função para extrair o path de forma segura, tratando possíveis erros
def get_path(url):
    try:
        # A função urlparse faz exatamente o que você precisa: separa as partes da URL
        return urlparse(url).path
    except TypeError:
        # Retorna uma string vazia se a URL for inválida (ex: NaN)
        return ""

X['path'] = X['URL_limpa'].apply(get_path)
# %%
# 4. EXTRAÇÃO DE FEATURES A PARTIR DO PATH
print("A extrair features exclusivamente do path da URL...")

# AGORA, APLIQUE TODAS AS FUNÇÕES NA NOVA COLUNA 'path'
# Recomendo renomear as features para refletir que vêm do path (ex: path_length)
X['count_dot_path'] = X['path'].apply(count_dot)
X['count_dir_path'] = X['path'].apply(no_of_dir)
X['count_embed_domain_path'] = X['path'].apply(no_of_embed)
X['count%_path'] = X['path'].apply(count_per)
X['count?_path'] = X['path'].apply(count_ques)
X['count-_path'] = X['path'].apply(count_hyphen)
X['count=_path'] = X['path'].apply(count_equal)
X['sus_path'] = X['path'].apply(suspicious_words)
X['count-digits_path'] = X['path'].apply(digit_count)
X['count-letters_path'] = X['path'].apply(letter_count)
X['path_length'] = X['path'].apply(url_length)
X['special_count_path'] = X['path'].apply(count_special_characters)
X['unusual_character_ratio_path'] = X['path'].apply(unusual_character_ratio)

# Estas features abaixo dependem da URL completa (query string), então usamos a URL_limpa
X['number_of_parameters_url'] = X['URL_limpa'].apply(number_of_parameters)
X['is_encoded_url'] = X['URL_limpa'].apply(is_encoded)

# query strings
X['query'] = X['URL_limpa'].apply(get_query)
X['sus_query'] = X['query'].apply(suspicious_words)

print("Extração de features concluída.")

# %%
# 4. TRANSFORMAÇÃO DE DADOS CATEGÓRICOS
# ----------------------------------------------------------------
print("A codificar o método HTTP...")
le_method = LabelEncoder()
X["Method_enc"] = le_method.fit_transform(X["Method"])

# %%
# 5. CRIAÇÃO DO DATASET FINAL (PATH-ONLY)
# -----------------------------------------------------------------
# --- MUDANÇA ---
# A lista de 'labels' foi simplificada. hostname_length e count-http foram removidas.
labels = [
    'count_dot_path', 'count_dir_path', 'count_embed_domain_path', 
    'count%_path', 'count?_path', 'count-_path', 'count=_path', 'path_length',
    'sus_path', 'count-digits_path', 'count-letters_path', 
    'number_of_parameters_url', 'is_encoded_url', 'special_count_path',
    'unusual_character_ratio_path', 'sus_query', 'Method_enc'
]
y = X['classification']
X_final = X[labels]
print("\nFeatures selecionadas para o novo modelo:", X_final.columns.tolist())

# %%
# 6. TREINO DO MODELO
# -----------------------------------------------------------------
x_tr, x_ts, y_tr, y_ts = train_test_split(X_final, y, test_size=0.3, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
print('\nA treinar o modelo Random Forest (Path-Only)...')
model.fit(x_tr, y_tr)
print('Treino concluído!')

# %%
# 7. SALVAR ARTEFATOS
# -----------------------------------------------------------------
# Nomes de ficheiro específicos para este modelo para evitar confusão.
MODEL_FILE = 'path_only_model.pkl'
METHOD_ENCODER_FILE = 'path_only_method_encoder.pkl'
joblib.dump(model, MODEL_FILE)
joblib.dump(le_method, METHOD_ENCODER_FILE)
print(f"\nModelo guardado em: {MODEL_FILE}")
print(f"Codificador guardado em: {METHOD_ENCODER_FILE}")

# %%
# 8. AVALIAÇÃO
# -----------------------------------------------------------------
predictions = model.predict(x_ts)
print("\n--- Avaliação do Modelo Path-Only ---")
print("Acurácia:", accuracy_score(y_ts, predictions))
print("\nRelatório de Classificação:\n", classification_report(y_ts, predictions, target_names=['Normal', 'Anomalous']))

plt.figure(figsize=(8, 6))
sns.heatmap(confusion_matrix(y_ts, predictions), annot=True, fmt='d', cmap="Greens")
plt.title("Matriz de Confusão - Modelo Path-Only")
plt.xlabel("Previsto")
plt.ylabel("Real")
plt.show()

# %%
# Feature Importance RANDOM FOREST
# -----------------------------------------------------------------

importance = model.feature_importances_
feature_names = x_tr.columns

# feat_imp = pd.Series(importance, index=feature_names)
# feat_imp.nlargest(10).plot(kind='barh')

feat_imp_df = pd.DataFrame({
    'Feature': feature_names,
    'Importance': importance
}).sort_values(by='Importance', ascending=False)

feat_imp_df.plot(kind='barh', x='Feature', y='Importance', figsize=(10, 6))
# %%
