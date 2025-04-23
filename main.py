import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Carregar o dataset
file_path = '/home/caiotavares/Documents/unesp/tcc/git/smartlogs/csic_database.csv'
data = pd.read_csv(file_path)

# Inspecionar o dataset
print(data.head())
print(data.info())

# Pré-processamento
# Remover colunas irrelevantes
columns_to_drop = ['URL', 'host', 'cookie']  # Ajuste conforme necessário
data = data.drop(columns=columns_to_drop)

# Converter colunas categóricas para numéricas
data = pd.get_dummies(data, drop_first=True)

# Separar features (X) e target (y)
X = data.drop(columns=['label_Normal'])  # 'label_Normal' é a coluna alvo após one-hot encoding
y = data['label_Normal']  # 1 para Normal, 0 para Intrusão

# Dividir o dataset em treino e teste
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Treinar o modelo
clf = RandomForestClassifier(random_state=42)
clf.fit(X_train, y_train)

# Fazer previsões
y_pred = clf.predict(X_test)

# Avaliar o modelo
print(classification_report(y_test, y_pred))