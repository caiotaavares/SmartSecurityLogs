import pandas as pd

# Define o nome do arquivo para facilitar a alteração
NOME_ARQUIVO_CSV = 'csic_database.csv'

try:
    # Carrega o dataset a partir do arquivo CSV
    # A primeira coluna sem nome será lida pelo pandas como 'Unnamed: 0'
    df = pd.read_csv(NOME_ARQUIVO_CSV)

    # --- Tratamento da Coluna Sem Nome ---
    # Verifica se a primeira coluna tem o nome padrão 'Unnamed: 0' e a renomeia
    if 'Unnamed: 0' in df.columns:
        df.rename(columns={'Unnamed: 0': 'Tipo_Requisicao'}, inplace=True)
    else:
        print("Aviso: A primeira coluna não se chama 'Unnamed: 0'. Verifique o nome da coluna de classificação.")

    # Define as colunas que queremos visualizar
    colunas_para_visualizar = ['Tipo_Requisicao', 'URL']

    # Verifica se as colunas necessárias existem no DataFrame
    if all(coluna in df.columns for coluna in colunas_para_visualizar):
        
        # Seleciona apenas as colunas de interesse
        df_visualizacao = df[colunas_para_visualizar]
        
        # --- Análise Quantitativa ---
        print("--- Contagem Total de Requisições por Tipo ---")
        print(df_visualizacao['Tipo_Requisicao'].value_counts())
        print("-" * 50)
        
        # --- Visualização de Exemplos ---

        # Filtra e exibe exemplos de URLs Normais
        print("\n--- 10 Exemplos de URLs consideradas NORMAIS ---")
        # Usamos .sample(10) para obter uma amostra aleatória, ou .head(10) para as 10 primeiras
        urls_normais = df_visualizacao[df_visualizacao['Tipo_Requisicao'] == 'Normal'].head(10)
        for index, row in urls_normais.iterrows():
            print(f"URL: {row['URL']}")
        
        print("\n" + "-" * 50)

        # Filtra e exibe exemplos de URLs Anômalas
        print("\n--- 10 Exemplos de URLs consideradas ANÔMALAS ---")
        urls_anomalas = df_visualizacao[df_visualizacao['Tipo_Requisicao'] == 'Anomalo'].head(10)
        for index, row in urls_anomalas.iterrows():
            print(f"URL: {row['URL']}")

    else:
        print("Erro: Uma ou mais colunas ('Tipo_Requisicao', 'URL') não foram encontradas no arquivo.")
        print(f"Colunas disponíveis: {df.columns.tolist()}")

except FileNotFoundError:
    print(f"ERRO: O arquivo '{NOME_ARQUIVO_CSV}' não foi encontrado. Verifique se ele está na mesma pasta que este script.")
except Exception as e:
    print(f"Ocorreu um erro inesperado: {e}")

