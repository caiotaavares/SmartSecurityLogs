# Detecção de Ameaças em APIs com Aprendizado de Máquina: 
# Estudo Comparativo de Modelos Supervisionados e Não Supervisionados

# Objetivo:
#   Avaliar a eficácia de algoritmos como Decision Tree, Random Forest, SVM (supervisionados) e Isolation Forest, Autoencoder (não supervisionados) na detecção de ataques em APIs.
# Resultado esperado: 
#   Taxas de precisão, recall e falsos positivos comparadas em ambiente simulado com tráfego de API.
# %%
# CARREGAR O DATASET
# ----------------------------------------------------------------
import pandas as pd
csic_data = pd.read_csv('/home/caiotavares/Documents/unesp/tcc/git/smartlogs/data/csic_database.csv')
# csic_data.head()

# %%
# VERIFICAÇÃO DOS TIPOS DE DADOS
# ----------------------------------------------------------------
import seaborn as sns

# Visualização de dados
sns.set_style('darkgrid')
sns.countplot(data=csic_data, x='Unnamed: 0')

# Verificando os tipos de dados
feature_names=[ 'Unnamed: 0', 'Method', 'User-Agent', 'Pragma', 'Cache-Control',
       'Accept', 'Accept-encoding', 'Accept-charset', 'language', 'host',
       'cookie', 'content-type', 'connection', 'lenght', 'content','classification',
        'URL']

X = csic_data[feature_names]
X = X.rename(columns={'Unnamed: 0': 'Class'})
X = X.rename(columns={'lenght': 'content_length'})

# Ajuste nas colunas
feature_names=[ 'Class','Method','host','cookie','Accept', 'content_length', 'content','classification','URL']
X = X[feature_names]
Y = X['Class']

# %%
# VARIÁVEIS CATEGÓRICAS
# ---------------------------------------------------------------
# identificar quais colunas em X são variáveis categóricas,
# ou seja, colunas com valores que não são numéricos, 
# geralmente do tipo string (texto), como "GET", "POST", 
# "Mozilla/5.0", etc.

# Número de colunas de X
size = X.shape[1]

# Verifica se o tipo de dado é string
# s é uma série booleana que indica se cada coluna é do tipo string
# O resultado é uma série booleana onde True indica que a coluna é do tipo string
# e False indica que a coluna é de outro tipo.
s = (X.dtypes == 'object') 

# s[s] filtra só os itens onde s é True (ou seja, só as colunas categóricas)
# .index retorna os nomes das colunas
# list(...) transforma isso em uma lista
object_cols = list(s[s].index)
print("Categorical variables:")
print(object_cols)

# 📌 Por que isso é importante?
# Modelos de ML como RandomForest, SVC, XGBoost não aceitam strings diretamente.
# As variáveis categóricas precisam ser:
#     Codificadas com números:
#         LabelEncoder (se for ordinal)
#         OneHotEncoder (se for nominal/categórica)

# %%
# TRATAMENTO DE DADOS DA URL
# ----------------------------------------------------------------
from urllib.parse import urlparse

# Conta o número de pontos
# Muitos subdomínios = phishing
def count_dot(url):
    count_dot = url.count('.')
    return count_dot

# Quantos diretórios (/) tem no path
def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

# Se tem // dentro do path
def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

# Verifica se a URL usa serviços de encurtamento como bit.ly, t.co, tinyurl, etc.
# Esses serviços são frequentemente usados para mascarar URLs maliciosas.
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

# Repetições podem indicar manipulação
def count_http(url):
    return url.count('http')

# URLs codificadas, comuns em XSS
def count_per(url):
    return url.count('%')

# Início de parâmetros – pode ser manipulado
def count_ques(url):
    return url.count('?')

# Comum em URLs de phishing
def count_hyphen(url):
    return url.count('-')

# Comum em parâmetros maliciosos
def count_equal(url):
    return url.count('=')

# Tamanho total da URL
def url_length(url):
    return len(str(url))

#Tamanho do domínio
def hostname_length(url):
    return len(urlparse(url).netloc)


import re
# Verifica se a URL contém palavras suspeitas
# Palavras suspeitas podem indicar tentativas de injeção de SQL, XSS, etc.
def suspicious_words(url):
    score_map = {
        'error': 30,
        'errorMsg': 30,
        'id': 10,
        'errorID': 30,
        'SELECT': 50,
        'FROM': 50,
        'WHERE': 50,
        'DELETE': 50,
        'USERS': 50,
        'DROP': 50,
        'CREATE': 50,
        'INJECTED': 50,
        'TABLE': 50,
        'alert': 30,
        'javascript': 20,
        'cookie': 25,
        '--': 30,
        '.exe': 30,
        '.php': 20,
        '.js': 10,
        'admin': 10,
        'administrator': 10,
        '\'': 30,
        'password': 15,
        'login': 15,
        'incorrect': 20,
        'pwd': 15,
        'tamper': 25,
        'vaciar': 20,
        'carrito': 25,
        'wait': 30,
        'delay': 35,
        'set': 20,
        'steal': 35,
        'hacker': 35,
        'proxy': 35,
        'location': 30,
        'document.cookie': 40,
        'document': 20,
        'set-cookie': 40,
        'create': 40,
        'cmd': 40,
        'dir': 30,
        'shell': 40,
        'reverse': 30,
        'bin': 20,
        'cookiesteal': 40,
        'LIKE': 30,
        'UNION': 35,
        'include': 30,
        'file': 20,
        'tmp': 25,
        'ssh': 40,
        'exec': 30,
        'cat': 25,
        'etc': 30,
        'fetch': 25,
        'eval': 30,
        'wait': 30,
        'malware': 45,
        'ransomware': 45,
        'phishing': 45,
        'exploit': 45,
        'virus': 45,
        'trojan': 45,
        'backdoor': 45,
        'spyware': 45,
        'rootkit': 45,
        'credential': 30,
        'inject': 30,
        'script': 25,
        'iframe': 25,
        'src=': 25,
        'onerror': 30,
        'prompt': 20,
        'confirm': 20,
        'eval': 25,
        'expression': 30,
        'function\(': 20,
        'xmlhttprequest': 30,
        'xhr': 20,
        'window.': 20,
        'document.': 20,
        'cookie': 25,
        'click': 15,
        'mouseover': 15,
        'onload': 20,
        'onunload': 20,
    }

    matches = re.findall(r'(?i)' + '|'.join(score_map.keys()), url)

    total_score = sum(score_map.get(match.lower(), 0) for match in matches)
    return total_score

# Quantos números tem na URL
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

# Quantas letras tem na URL
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters += 1
    return letters

# Quantos caracteres especiais (@, #, $, etc.)
def count_special_characters(url):
    special_characters = re.sub(r'[a-zA-Z0-9\s]', '', url)
    count = len(special_characters)
    return count


# Numero de parâmetros na URL
def number_of_parameters(url):
    params = urlparse(url).query
    return 0 if params == '' else len(params.split('&'))

# Numero de fragmentos na URL
def number_of_fragments(url):
    frags = urlparse(url).fragment
    return len(frags.split('#')) - 1 if frags == '' else 0

# URL é codificada
def is_encoded(url):
    return int('%' in url.lower())

# Proporção de caracteres incomuns
def unusual_character_ratio(url):
    total_characters = len(url)
    unusual_characters = re.sub(r'[a-zA-Z0-9\s\-._]', '', url)
    unusual_count = len(unusual_characters)
    ratio = unusual_count / total_characters if total_characters > 0 else 0
    return ratio


# %%
# JUNTA TUDO NAS NOVAS COLUNAS
# ----------------------------------------------------------------

X['count_dot_url']                      = X['URL'].apply(count_dot)
X['count_dir_url']                      = X['URL'].apply(no_of_dir)
X['count_embed_domain_url']             = X['URL'].apply(no_of_embed)
X['short_url']                          = X['URL'].apply(shortening_service)
X['count-http']                         = X['URL'].apply(count_http)
X['count%_url']                         = X['URL'].apply(count_per)
X['count?_url']                         = X['URL'].apply(count_ques)
X['count-_url']                         = X['URL'].apply(count_hyphen)
X['count=_url']                         = X['URL'].apply(count_equal)
X['hostname_length_url']                = X['URL'].apply(hostname_length)
X['sus_url']                            = X['URL'].apply(suspicious_words)
X['count-digits_url']                   = X['URL'].apply(digit_count)
X['count-letters_url']                  = X['URL'].apply(letter_count)
X['url_length']                         = X['URL'].apply(url_length)
X['number_of_parameters_url']           = X['URL'].apply(number_of_parameters)
X['number_of_fragments_url']            = X['URL'].apply(number_of_fragments)
X['is_encoded_url']                     = X['URL'].apply(is_encoded)
X['special_count_url']                  = X['URL'].apply(count_special_characters)
X['unusual_character_ratio_url']        = X['URL'].apply(unusual_character_ratio)

new_features = ['count_dot_url', 'count_dir_url', 'count_embed_domain_url', 'count-http',
                'count%_url', 'count?_url', 'count-_url', 'count=_url', 'url_length', 'hostname_length_url',
                'sus_url', 'count-digits_url', 'count-letters_url', 'number_of_parameters_url',
                'number_of_fragments_url', 'is_encoded_url','special_count_url','unusual_character_ratio_url']

set = X[new_features]
X.head()

# %%
# ----------------------------------------------------------------
# TRANSFORMAÇÃO DE DADOS CATEGÓRICOS
# ----------------------------------------------------------------
# Por que transformar o campo Accept assim?
# A coluna Accept normalmente contém tipos MIME (ex: text/html, application/json, etc.), mas aqui o objetivo é:
#     Extrair qualquer valor numérico presente (geralmente em parâmetros como q=0.9)
#     Ignorar o resto da string
#     Padronizar para valores numéricos que possam ser usados em modelos de ML
from sklearn.preprocessing import LabelEncoder

X['Accept'] = X['Accept'].astype(str)
X['Accept'] = X['Accept'].str.extract(r'(\d+)')
X['Accept'] = pd.to_numeric(X['Accept'], errors='coerce').fillna(1)

# LabelEncoder é uma classe da biblioteca sklearn.preprocessing 
# usada para converter valores categóricos (textuais) em valores
# numéricos inteiros.
le_method = LabelEncoder()
X["Method_enc"] = le_method.fit_transform(X["Method"])

le_host = LabelEncoder()
X["host_enc"] = le_host.fit_transform(X["host"])

le_accept = LabelEncoder()
X["Accept_enc"] = le_accept.fit_transform(X["Accept"])

unique_count_met        = X["Method_enc"].nunique()
unique_count_host       = X["host_enc"].nunique()
unique_count_acc        = X["Accept_enc"].nunique()

print(f"Número de valores únicos para 'Method_enc': {unique_count_met}")
print(f"Número de valores únicos para 'host_enc': {unique_count_host}")
print(f"Número de valores únicos para 'Accept_enc': {unique_count_acc}")

X.head()
X.tail()

# %%
# APLICANDO AS FUNÇÕES DE PROCESSAMENTO ao content
# ----------------------------------------------------------------
def apply_to_content(content,function):
    if pd.isna(content):
        return 0
    elif isinstance(content, str):
        return function(content)

X['count_dot_content']                  = X['content'].apply(apply_to_content, function=count_dot)
X['count_dir_content']                  = X['content'].apply(apply_to_content, function=no_of_dir)
X['count_embed_domain_content']         = X['content'].apply(apply_to_content, function=no_of_embed)
X['count%_content']                     = X['content'].apply(apply_to_content, function=count_per)
X['count?_content']                     = X['content'].apply(apply_to_content, function=count_ques)
X['count-_content']                     = X['content'].apply(apply_to_content, function=count_hyphen)
X['count=_content']                     = X['content'].apply(apply_to_content, function=count_equal)
X['content_length']                     = X['content'].apply(apply_to_content, function=url_length)
X['sus_content']                        = X['content'].apply(apply_to_content, function=suspicious_words)
X['count_digits_content']               = X['content'].apply(apply_to_content, function=digit_count)
X['count_letters_content']              = X['content'].apply(apply_to_content, function=letter_count)
X['special_count_content']              = X['content'].apply(apply_to_content, function=count_special_characters)
X['is_encoded_content']                 = X['content'].apply(apply_to_content, function=is_encoded)

# Verificando os tipos de dados
import seaborn as sns
import matplotlib.pyplot as plt

# Selecionando as features e a variável de classe para o gráfico
new_content_features = ['count_dot_content', 'count_dir_content', 'count_embed_domain_content', 'count%_content', 'count?_content',
                        'count-_content', 'count=_content', 'sus_content', 'count_digits_content',
                        'count_letters_content', 'content_length', 'is_encoded_content', 'special_count_content']

# Cria um DataFrame com as features selecionadas
selected_features_df = X[new_content_features]

for feature_name in selected_features_df.columns:
    if feature_name in X.columns:
        unique_count = selected_features_df[feature_name].nunique()
        print(f"Number of unique values for {feature_name}: {unique_count}")
    else:
        print(f"Column '{feature_name}' does not exist in the DataFrame.")

# %%
X.columns
# %%
# CRIAÇÃO DO DATASET FINAL
# -----------------------------------------------------------------

labels = [      'count_dot_url', 'count_dir_url', 'count_embed_domain_url', 'count-http',
                'count%_url', 'count?_url', 'count-_url', 'count=_url', 'url_length', 'hostname_length_url',
                'sus_url', 'count-digits_url', 'count-letters_url', 'number_of_parameters_url',
                'is_encoded_url','special_count_url','unusual_character_ratio_url',
                # Method
                'Method_enc',
                # Content
                'count_dot_content','count%_content',
                'count-_content','count=_content','sus_content','count_digits_content',
                'count_letters_content','content_length',
                'is_encoded_content','special_count_content']
X[labels]

# y receberá a variável de classificação
y = X['classification']

# %%
# SEPARAÇÃO DO DATASET EM TREINO E TESTE
# -----------------------------------------------------------------
from sklearn.model_selection import train_test_split

# Separar o dataset em treino e teste
x_tr, x_ts, y_tr, y_ts = train_test_split(X[labels], y, test_size=0.3, random_state=0)
# x_tr contém 70% dos dados de entrada para treino
# x_ts contém 30% dos dados de entrada para teste
# y_tr contém 70% dos rótulos (ataque ou não) correspondentes para treino
# y_ts contém 30% dos rótulos (ataque ou não) correspondentes para teste

# %%
# RANDOM FOREST
# -----------------------------------------------------------------
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score
from sklearn.metrics import accuracy_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
from sklearn.metrics import roc_auc_score
from sklearn.metrics import mean_absolute_error
import numpy as np

random_forest_model = RandomForestClassifier(random_state=1000)
print('Treinando o modelo Random Forest....')
# Treinando o modelo Random Forest usando 
# os dados de treino (x_tr, y_tr).
random_forest_model.fit(x_tr,y_tr)
print('Feito!')

# Usa o modelo SVC_model para prever as classes de cada exemplo 
# em x_ts (dados de teste). O resultado é um array com as classes previstas.
# Aqui o modelo tenta adivinhar a classe (ataque ou não) de cada entrada
# nos dados de teste x_ts.
RT_predictions = random_forest_model.predict(x_ts)

# %%
# Avaliando o modelo RANDOM FOREST
# -----------------------------------------------------------------
# Erro médio absoluto (Diferença entre previsto e real)
print('Erro Médio Absoluto:', mean_absolute_error(y_ts, RT_predictions))
# Acurácia (% de acertos totais)
print("Acurácia:", accuracy_score(y_ts, RT_predictions))
# Precisão (Entre os ataques detectados, quantos eram de verdade?)
print("Precisão:", precision_score(y_ts, RT_predictions, average='weighted', labels=np.unique(RT_predictions)))
# Recall / Sensibilidade (Entre os ataques reais, quantos o modelo detectou?)
print("Recall/Sensibilidade:", recall_score(y_ts, RT_predictions, average='weighted', labels=np.unique(RT_predictions)))
# F1 (balanceia precisão e recall) (Importante em dados desbalanceados)
print("F1 (balanceia precisão e recall):", f1_score(y_ts, RT_predictions, average='weighted', labels=np.unique(RT_predictions)))
# Capacidade de distinguir entre classes (Quanto maior (próximo de 1), melhor)
print("ROC AUC:", roc_auc_score(y_ts, RT_predictions, average='weighted', labels=np.unique(RT_predictions)))
# Proporção de erros (Mostra a proporção de erros cometidos pelo modelo nas previsões.)
error_rt = (RT_predictions != y_ts).mean()
print("Proporção de erros: {:.1%}".format(error_rt))
print("Relatório de desempenho:")
from sklearn.metrics import classification_report
report = classification_report(y_ts, RT_predictions, target_names=['Normal', 'Anomalous'], output_dict=True)
report_df = pd.DataFrame(report).transpose()
report_df = report_df.loc[['Normal', 'Anomalous']]
report_df
# %%
# Matriz de Confusão RANDOM FOREST
# -----------------------------------------------------------------
from sklearn.metrics import confusion_matrix
label = ['Normal', 'Anomalous']
cm = confusion_matrix(y_ts, RT_predictions)
cm = pd.DataFrame(cm, index=['0', '1'], columns=['0', '1'])

plt.figure(figsize=(10, 10))
sns.heatmap(cm, cmap="Blues", linecolor='black', linewidth=1, annot=True, fmt='', xticklabels=label, yticklabels=label)
plt.title("Random Forest")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.show()

# %%
# Feature Importance RANDOM FOREST
# -----------------------------------------------------------------
import pandas as pd
import matplotlib.pyplot as plt

importance = random_forest_model.feature_importances_
feature_names = x_tr.columns

# feat_imp = pd.Series(importance, index=feature_names)
# feat_imp.nlargest(10).plot(kind='barh')

feat_imp_df = pd.DataFrame({
    'Feature': feature_names,
    'Importance': importance
}).sort_values(by='Importance', ascending=False)

feat_imp_df.plot(kind='barh', x='Feature', y='Importance', figsize=(10, 6))

# %%
# LIME
# -----------------------------------------------------------------
from lime.lime_tabular import LimeTabularExplainer

# Explicador LIME
explainer = LimeTabularExplainer(
    training_data=x_tr.values,
    feature_names=x_tr.columns,
    class_names=['Normal', 'Anomalous'],
    mode='classification'
)

i=0
exp = explainer.explain_instance(   x_ts.iloc[i], 
                                    random_forest_model.predict_proba)
print(exp.as_list())
x_ts.iloc[i]
# [
#     ('count_embed_domain_url <= 0.00', 0.09893277465424392), 
#     ('count-_url > 0.00', 0.07151532225463739), 
#     ('count%_content <= 0.00', -0.06383856011166143), 
#     ('count_dot_url > 2.00', 0.06010114070404867), 
#     ('is_encoded_content <= 0.00', -0.0548380231028701), 
#     ('special_count_url > 13.00', 0.05470434013571856), 
#     ('count-digits_url > 8.00', 0.052412352247600394), 
#     ('is_encoded_url > 0.00', 0.04971785525615355), 
#     ('count%_url > 0.00', 0.048248627923435435), 
#     ('number_of_parameters_url > 1.00', -0.04004551471890278)
# ]
# EXPLICAÇÂO
# ('<condição da feature>' '<numero de parametros>', <peso da influência na previsão>)
# O valor numérico (peso) mostra o quanto aquela condição puxou a previsão para a classe predita.
#     Valor positivo → puxou a previsão para "Anomalous" (ataque).
#     Valor negativo → puxou a previsão para "Normal" (sem ataque).

# %%
# K-NEAREST NEIGHBOR
# -----------------------------------------------------------------
from sklearn.neighbors import KNeighborsClassifier

final_model = KNeighborsClassifier(n_neighbors = 9)
final_model.fit(x_tr, y_tr)
knn_predictions = final_model.predict(x_ts)

print('MAE', mean_absolute_error(y_ts, knn_predictions))
print("Accuracy", accuracy_score(y_ts, knn_predictions))
print("Precision", precision_score(y_ts, knn_predictions, average='weighted', labels=np.unique(knn_predictions)))
print("Recall", recall_score(y_ts, knn_predictions, average='weighted', labels=np.unique(knn_predictions)))
print("F1", f1_score(y_ts, knn_predictions, average='weighted', labels=np.unique(knn_predictions)))
print("ROC AUC", roc_auc_score(y_ts, knn_predictions, average='weighted', labels=np.unique(knn_predictions)))
error_knn = (knn_predictions != y_ts).mean()
print("Test error: {:.1%}".format(error_knn))

# Matriz de Confusão K-NEAREST NEIGHBOR
# -----------------------------------------------------------------
cm = confusion_matrix(y_ts,knn_predictions)
cm = pd.DataFrame(cm , index = ['0','1'] , columns = ['0','1'])
plt.figure(figsize = (10,10))
sns.heatmap(cm,cmap= "Blues", linecolor = 'black' , linewidth = 1 , annot = True, fmt='',xticklabels = label,yticklabels = label)
plt.title("KN Neighbors")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt
# %%
# DECISION TREE
# -----------------------------------------------------------------
from sklearn.tree import DecisionTreeClassifier

# Treinando o modelo Decision Tree
decision_tree_model = DecisionTreeClassifier(random_state=1000)
decision_tree_model.fit(x_tr, y_tr)
dt_predictions = decision_tree_model.predict(x_ts)

# %%
# Avaliando DECISION TREE
# -----------------------------------------------------------------
print('MAE', mean_absolute_error(y_ts, dt_predictions))
print("Accuracy", accuracy_score(y_ts, dt_predictions))
print("Precision", precision_score(y_ts, dt_predictions, average='weighted', labels=np.unique(knn_predictions)))
print("Recall", recall_score(y_ts, dt_predictions, average='weighted', labels=np.unique(knn_predictions)))
print("F1", f1_score(y_ts, dt_predictions, average='weighted', labels=np.unique(knn_predictions)))
print("ROC AUC", roc_auc_score(y_ts, dt_predictions, average='weighted', labels=np.unique(knn_predictions)))
error_knn = (dt_predictions != y_ts).mean()
print("Test error: {:.1%}".format(error_knn))

# Matriz de Confusão DECISION TREE
# -----------------------------------------------------------------
cm = confusion_matrix(y_ts,dt_predictions)
cm = pd.DataFrame(cm , index = ['0','1'] , columns = ['0','1'])
plt.figure(figsize = (10,10))
sns.heatmap(cm,cmap= "Blues", linecolor = 'black' , linewidth = 1 , annot = True, fmt='',xticklabels = label,yticklabels = label)
plt.title("KN Neighbors")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt

# %%
# Logistic Regression
# Support Vector Machine (SVM)
# Naïves Bayes
# Recurrent Neural Network(RNN)
# Artificial Neural Network(ANN)
# Convolutional Neural Network(CNN)
# Long Short-Term Memory(LSTM)
# %%
import joblib
joblib.dump(random_forest_model, 'random_forest_model.pkl')

# %%
