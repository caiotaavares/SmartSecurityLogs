import joblib
import pandas as pd
from . import features

class AttackAnalyzer:
    def __init__(self,
                 # Carrega os ficheiros corretos por defeito
                 model_path='data/path_only_model.pkl',
                 method_encoder_path='data/path_only_method_encoder.pkl'):
        
        print("ANALYZER (Path-Only) - A carregar modelo e codificador...")
        self.model = joblib.load(model_path)
        le_method = joblib.load(method_encoder_path)
        
        self.feature_extractor = features.FeatureExtractor(le_method)
        print("ANALYZER (Path-Only) - Pronto.")

    # No método analyze da classe AttackAnalyzer
    def analyze(self, req):
        """
        Analisa a requisição focando exclusivamente no path da URL e no método.
        """
        method = req.method
        
        # --- MUDANÇA ---
        # O extrator agora precisa da URL completa para replicar a lógica do treino.
        # Vamos assumir que req.url já contém a URL completa (sem " HTTP/1.1").
        # Se req.url puder ter o sufixo, limpe-o aqui também.
        full_url = req.url 

        # A chamada para o extrator agora passa a URL completa.
        features_df = self.feature_extractor.extract_df(full_url, method)
        
        prediction_code = self.model.predict(features_df)[0]
        probabilities = self.model.predict_proba(features_df)[0]
        resultado = "Anómalo" if prediction_code == 1 else "Normal"
        
        return {
            "url": req.url,
            "metodo": method,
            "classificacao": resultado,
            "confianca": { "normal": round(probabilities[0], 4), "anomalo": round(probabilities[1], 4) },
            "payload": req.get_data(as_text=True) 
        }
