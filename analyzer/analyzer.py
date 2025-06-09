class AttackAnalyzer:
    """
    Classe responsável pela análise da requisição (integração com ML).
    """
    def __init__(self):
        # Exemplo: aqui você pode carregar seu modelo ML, se necessário
        pass

    def analyze(self, req):
        """
        Recebe um objeto request do Flask e retorna o resultado da análise.
        """
        url = req.url
        method = req.method
        headers = dict(req.headers)
        body = req.get_data(as_text=True)

        # Chame aqui o seu modelo de ML
        resultado = "Normal"  # ou "Ataque"
        return {
            "url": url,
            "metodo": method,
            "resultado": resultado,
            "body": body
        }
