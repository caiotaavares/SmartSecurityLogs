from flask import Flask, request, Response
import requests
from analyzer.analyzer import AttackAnalyzer

class ProxyServer:
    """
    Classe principal do Proxy HTTP.
    """
    def __init__(self, backend_host='localhost', backend_port=8081):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.logs = []
        self.analyzer = AttackAnalyzer()
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        """
        Configura as rotas do Flask.
        """
        self.app.add_url_rule(
            '/', defaults={'path': ''}, view_func=self.handle_proxy, methods=["GET", "POST"])
        self.app.add_url_rule(
            '/<path:path>', view_func=self.handle_proxy, methods=["GET", "POST"])
        self.app.add_url_rule(
            '/log', view_func=self.handle_log, methods=["GET"])

    def handle_proxy(self, path):
        """
        Rota que intercepta e encaminha as requisições.
        """
        method = request.method
        headers = dict(request.headers)
        body = request.get_data()
        params = request.args

        # Analisa a requisição
        analise = self.analyzer.analyze(request)
        self.logs.append(analise)

        # Monta a URL do backend real
        backend_url = f"http://{self.backend_host}:{self.backend_port}/{path}"

        # Encaminha a requisição para o backend original
        resp = requests.request(
            method=method,
            url=backend_url,
            headers=headers,
            params=params,
            data=body,
            allow_redirects=False
        )

        # Retorna a resposta para o cliente
        return Response(resp.content, resp.status_code, resp.headers.items())

    def handle_log(self):
        """
        Dashboard simples para exibir as análises.
        """
        html = "<h2>Requisições analisadas</h2><table border='1'><tr><th>Método</th><th>URL</th><th>Resultado</th></tr>"
        for item in self.logs:
            html += f"<tr><td>{item['metodo']}</td><td>{item['url']}</td><td>{item['resultado']}</td></tr>"
        html += "</table>"
        return html

    def run(self, port=8080):
        self.app.run(port=port)
