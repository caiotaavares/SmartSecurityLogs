from analyzer.analyzer import AttackAnalyzer
from urllib.parse import urlparse

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

def run_tests():
    print("--- A INICIAR TESTE FINAL DO MODELO PATH-ONLY ---")
    try:
        analyzer = AttackAnalyzer()
    except FileNotFoundError as e:
        print(f"\nERRO: Não foi possível encontrar os ficheiros do modelo 'path_only_model.pkl'.")
        print(f"Certifique-se de que executou o notebook de treino finalizado.")
        print(f"Detalhe: {e}")
        return

    test_cases = [
        {"desc": "Navegação - Página inicial", "method": "GET", "url": "/tienda1/"},
        {"desc": "Navegação - Ver produtos", "method": "GET", "url": "/tienda1/publico/productos.jsp"},
        {"desc": "Navegação - Adicionar item", "method": "GET", "url": "/tienda1/publico/anadir.jsp?id=4&nombre=ZAPATILLAS&precio=90"},
        {"desc": "Ataque - SQL Injection", "method": "GET", "url": "/tienda1/publico/productos.jsp?id=' o '1'='1"},
        {"desc": "Ataque - XSS", "method": "GET", "url": "/tienda1/publico/productos.jsp?id=<script>alert('xss')</script>"},
        {"desc": "Ataque - Path Traversal", "method": "GET", "url": "/tienda1/publico/ficheros/../../../../etc/passwd"},
    ]

    print(f"\nA analisar {len(test_cases)} casos de uso...\n" + "="*80)
    for case in test_cases:
        mock_request = MockRequest(url=case["url"], method=case["method"])
        result = analyzer.analyze(mock_request)
        classificacao, confianca = result['classificacao'], result['confianca']['anomalo'] * 100
        
        if classificacao == "Anómalo":
            print(f"\033[91m[ANÓMALO]\033[0m - Conf: {confianca:6.2f}% - Teste: {case['desc']:<30} | {mock_request.method} {result.get('url')}")
        else:
            print(f"\033[92m[NORMAL]\033[0m  - Conf: {confianca:6.2f}% - Teste: {case['desc']:<30} | {mock_request.method} {result.get('url')}")
    print("="*80 + "\n--- TESTE CONCLUÍDO ---\n")

if __name__ == "__main__":
    run_tests()
