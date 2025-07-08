import joblib
import pandas as pd
from . import FeatureExtractor

class AttackAnalyzer:
    def __init__(self,
        model_path='data/path_only_model.pkl',
        method_encoder_path='data/path_only_method_encoder.pkl'):

        print("ANALYZER (Path-Only) - A carregar modelo e codificador...")
        self.model = joblib.load(model_path)
        le_method = joblib.load(method_encoder_path)
        
        self.feature_extractor = FeatureExtractor.FeatureExtractor(le_method)
        print("ANALYZER (Path-Only) - Pronto.")

    def analyze(self, req):
        """
        Analisa a requisição focando exclusivamente no path da URL e no método.
        """
        method = req.method
        
        full_url = req.url 

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