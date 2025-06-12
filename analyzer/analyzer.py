import analyzer.features as features
import joblib
import pandas as pd

class AttackAnalyzer:
    def __init__(self, model_path='data/random_forest_model.pkl'):
        # Carrega o modelo treinado
        self.model = joblib.load(model_path)
        # Aqui, adicione atributos, listas de features e codificadores se necessário
        self.feature_extractor = features.FeatureExtractor()

    def extract_features(self, req):
        """
        Extrai as features da requisição, com o mesmo pré-processamento usado no notebook.
        """
        # Exemplo básico: você deve replicar toda sua pipeline de features!
        method = req.method
        url = req.url
        headers = dict(req.headers)
        content = "modo=registro&login=amant&password=coyotera&nombre=Aleardo&apellidos=Sellares+Brihuega&email=AND+1%3D1&dni=15074727K&direccion=Calle+Rodrigo+De+Triana+189%2C+6E&ciudad=Ametlla+del+Vall%E8s%2C+L%27&cp=44597&provincia=Guadalajara&ntc=2988316222731904&B1=Registrar"
        
        # Extrai as features usando a classe FeatureExtractor
        features = self.feature_extractor.extract(url, method, content)
        features_df = pd.DataFrame([features])  
        return features_df

    def analyze(self, req):
        """
        Recebe o request do Flask, processa, faz a predição e retorna resultado.
        """
        features_df = self.extract_features(req)
        pred = self.model.predict(features_df)[0]
        resultado = "Normal" if pred == 0 else "Ataque"  # Ajuste para sua codificação de classe

        # Para logging/dash:
        return {
            "url": req.url,
            "metodo": req.method,
            "resultado": resultado,
            "body": req.get_data(as_text=True)
        }
