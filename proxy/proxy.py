from flask import Flask, request, Response, jsonify
import requests
# Importação da classe principal do analisador
from analyzer.analyzer import AttackAnalyzer

class ProxyServer:
    """
    Classe principal do Proxy HTTP que utiliza o AttackAnalyzer em modo de monitoramento.
    """
    def __init__(self, backend_host='localhost', backend_port=8081):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.logs = []
        # Instancia o analisador. Ele carregará os modelos apenas uma vez.
        self.analyzer = AttackAnalyzer()
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        """
        Configura as rotas do Flask para o proxy e o dashboard.
        """
        # Rota principal que captura todas as URLs e métodos
        self.app.add_url_rule(
            '/', defaults={'path': ''}, view_func=self.handle_proxy,
            methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
        self.app.add_url_rule(
            '/<path:path>', view_func=self.handle_proxy,
            methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
        
        # Rota para o dashboard de logs
        # Renomeei para /log para corresponder ao seu código original
        self.app.add_url_rule(
            '/log', view_func=self.handle_log, methods=["GET"])

    def handle_proxy(self, path):
        """
        Rota que intercepta, analisa e encaminha TODAS as requisições, sem bloqueio.
        """
        # O objeto 'request' do Flask é passado diretamente para o analisador
        analise = self.analyzer.analyze(request)
        self.logs.append(analise)

        print(f"PROXY - Análise para {request.method} {request.url}: {analise['classificacao']}")

        # --- LÓGICA DE BLOQUEIO REMOVIDA ---
        # A requisição agora SEMPRE será encaminhada, independentemente do resultado.
        # if analise['classificacao'] == "Anômalo":
        #     print(f"PROXY - Requisição ANÔMALA DETECTADA (mas não bloqueada) de {request.remote_addr}")
        #     # A linha abaixo que bloqueava a requisição foi removida.
        #     # return jsonify({"error": "Request blocked due to anomalous activity"}), 403
        
        # O código abaixo agora executa para todas as requisições.
        try:
            backend_url = f"http://{self.backend_host}:{self.backend_port}/{path}"
            resp = requests.request(
                method=request.method,
                url=backend_url,
                headers={key: value for (key, value) in request.headers if key.lower() != 'host'},
                params=request.args,
                data=request.get_data(),
                allow_redirects=False,
                timeout=5 # Adiciona um timeout para evitar que o proxy fique preso
            )
            # Retorna a resposta do backend para o cliente
            return Response(resp.content, resp.status_code, resp.raw.headers.items())
        except requests.exceptions.RequestException as e:
            print(f"PROXY - Erro ao conectar ao backend: {e}")
            return jsonify({"error": "Could not connect to the backend service"}), 502


    def handle_log(self):
        """
        Dashboard simples para exibir as análises em tempo real.
        """
        html = """
        <html>
            <head>
                <title>Logs de Análise</title>
                <style>
                    body { font-family: sans-serif; margin: 2em; background-color: #f4f4f9; }
                    h2 { color: #333; }
                    table { border-collapse: collapse; width: 100%; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                    th { background-color: #4CAF50; color: white; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                    tr:hover { background-color: #f1f1f1; }
                    .anomalo { color: #D8000C; font-weight: bold; background-color: #FFBABA; }
                    .normal { color: #2a7d2a; }
                    pre { white-space: pre-wrap; word-wrap: break-word; }
                </style>
            </head>
            <body>
                <h2>Requisições Analisadas</h2>
                <table>
                    <tr><th>Método</th><th>URL</th><th>Resultado</th><th>Confiança (Anômalo)</th><th>Payload</th></tr>
        """
        # Itera sobre os logs em ordem reversa para mostrar os mais recentes primeiro
        for item in reversed(self.logs):
            class_name = item['classificacao'].lower()
            confianca_anomalo = item['confianca']['anomalo']
            # Escapa caracteres HTML no payload para segurança
            import html as html_escape
            payload_escaped = html_escape.escape(item['payload'])

            html += f"""
                    <tr>
                        <td>{item['metodo']}</td>
                        <td>{item['url']}</td>
                        <td class='{class_name}'>{item['classificacao']}</td>
                        <td>{confianca_anomalo:.2%}</td>
                        <td><pre>{payload_escaped}</pre></td>
                    </tr>
            """
        html += "</table></body></html>"
        return html

    def run(self, port=8080):
        # use_reloader=False é importante para não carregar o modelo duas vezes no modo debug
        self.app.run(port=port, debug=True, use_reloader=False)