import pandas as pd
from analyzer.analyzer import AttackAnalyzer
from urllib.parse import urlparse

# Define a largura máxima de exibição do pandas para evitar quebras de linha indesejadas
pd.set_option('display.width', 200)

# Mock/Simulação de um objeto de requisição Flask
class MockRequest:
    def __init__(self, url, method='GET', host='localhost:8080', content=''):
        self.method = method
        self.host = host
        self._content = content.encode('utf-8')
        if url.startswith('http'):
            parsed = urlparse(url)
            self.url, self.path, self.query_string = url, parsed.path, parsed.query.encode('utf-8')
        else:
            self.url = f"http://{host}{url}"
            parsed = urlparse(url)
            self.path, self.query_string = parsed.path, parsed.query.encode('utf-8')

    def get_data(self, as_text=False):
        return self._content.decode('utf-8') if as_text else self._content

def formatar_features(features_df: pd.DataFrame):
    """
    Formata um DataFrame de uma única linha para uma exibição vertical legível.
    """
    if features_df.empty:
        return "Nenhuma feature extraída."
    
    features_dict = features_df.iloc[0].to_dict()
    max_len = max(len(key) for key in features_dict.keys()) if features_dict else 0
    
    output_lines = ["--- Features Extraídas ---"]
    for feature, value in features_dict.items():
        output_lines.append(f"  {feature:<{max_len}} : {value}")
    output_lines.append("---------------------------------")
    
    return "\n".join(output_lines)

def run_tests():
    print("--- TESTE DO MODELO ---")
    try:
        analyzer = AttackAnalyzer()
        print("ANALYZER (Path-Only) - Modelo e codificador carregados.")
        print("ANALYZER (Path-Only) - Pronto.")
    except FileNotFoundError as e:
        print(f"\nERRO: Não foi possível encontrar os ficheiros do modelo 'path_only_model.pkl'.")
        print(f"Certifique-se de que executou o notebook de treino finalizado.")
        print(f"Detalhe: {e}")
        return

    test_cases = [
        {"desc": "Navegação", "method": "GET", "url": "/tienda1/publico/carrito.jsp"},
        {"desc": "Navegação", "method": "GET", "url": "/tienda1/publico/entrar.jsp?errorMsg=Credenciales+incorrectas"},
        {"desc": "Navegação", "method": "GET", "url": "/tienda1/publico/miembros.jsp"},
        {"desc": "Navegação", "method": "GET", "url": "/tienda1/publico/pagar.jsp?modo=insertar&precio=2672&B1=Pasar+por+caja"},
        {"desc": "Navegação", "method": "GET", "url": "/tienda1/publico/productos.jsp"},
        {"desc": "Navegação", "method": "GET", "url": "/tienda1/global/menum.jsp"},
        {"desc": "Navegação - Ver produtos", "method": "GET", "url": "/tienda1/publico/productos.jsp"},
        {"desc": "Navegação - Adicionar item com query", "method": "GET", "url": "/tienda1/publico/anadir.jsp?id=4&nombre=ZAPATILLAS&precio=90"},
        {"desc": "Ataque - SQL Injection", "method": "GET", "url": "/tienda1/publico/productos.jsp?id=' or '1'='1"},
        {"desc": "Ataque - XSS", "method": "GET", "url": "/tienda1/publico/productos.jsp?id=<script>alert('xss')</script>"},
        {"desc": "Ataque - Path Traversal", "method": "GET", "url": "/tienda1/publico/ficheros/../../../../etc/passwd"},
    ]

    print(f"\nA analisar {len(test_cases)} casos de uso...\n" + "="*80)
    for i, case in enumerate(test_cases):
        mock_request = MockRequest(url=case["url"], method=case["method"])
        
        # 1. Extrair as features para visualização
        features_df = analyzer.feature_extractor.extract_df(mock_request.url, mock_request.method)
        
        # 2. Analisar a requisição
        result = analyzer.analyze(mock_request)
        classificacao = result['classificacao']
        
        # --- CORREÇÃO 1: Normalizar a chave removendo o acento ---
        # A chave no dicionário é 'anomalo' (sem acento), mas a classificação é 'Anómalo' (com acento).
        key_confianca = classificacao.lower().replace('ó', 'o')
        confianca = result['confianca'][key_confianca] * 100
        
        # 3. Imprimir tudo de forma organizada
        print(f"A analisar o caso: {case['desc']}")
        print(f"URL: {mock_request.url}")
        
        # Imprime as features formatadas
        print(formatar_features(features_df))

        # Imprime o resultado final
        # --- CORREÇÃO 2: Comparar com a string correta 'Anómalo' (com acento) ---
        if classificacao == "Anómalo":
            print(f"\033[91m[ANÓMALO]\033[0m - Conf: {confianca:6.2f}% - Teste: {case['desc']:<35} | {mock_request.method} {mock_request.url}")
        else:
            print(f"\033[92m[NORMAL]\033[0m  - Conf: {confianca:6.2f}% - Teste: {case['desc']:<35} | {mock_request.method} {mock_request.url}")
        
        # Adiciona uma linha separadora, exceto para o último caso
        if i < len(test_cases) - 1:
            print("-" * 80)

    print("="*80 + "\n--- TESTE CONCLUÍDO ---\n")

if __name__ == "__main__":
    run_tests()