# Importamos a classe que queremos testar
from worker.analyzer.AttackAnalyzer import AttackAnalyzer

# Criamos um objeto de requisição falso para o teste
class MockRequest:
    def __init__(self, url, method='GET'):
        self.url = url
        self.method = method
    def get_data(self, as_text=False):
        return ""

print("--- INICIANDO TESTE LOCAL DO ANALYZER ---")

# Caminhos relativos a partir da raiz do projeto
MODEL_FILE = 'data/path_only_model.pkl'
ENCODER_FILE = 'data/path_only_method_encoder.pkl'

try:
    # Tentamos inicializar o analisador com os caminhos locais
    analyzer = AttackAnalyzer(model_path=MODEL_FILE, method_encoder_path=ENCODER_FILE)
    print("\n[SUCESSO] O AttackAnalyzer foi inicializado corretamente!")

    # Criamos uma requisição de teste
    test_req = MockRequest("http://exemplo.com/login.php?user=' or 1=1--")
    
    # Tentamos executar a análise
    result = analyzer.analyze(test_req)
    print("\n[SUCESSO] O método analyze() foi executado!")
    print("Resultado da Análise:")
    print(result)

except Exception as e:
    print(f"\n[FALHA] Ocorreu um erro durante o teste: {e}")

print("\n--- TESTE LOCAL DO ANALYZER CONCLUÍDO ---")