import pandas as pd
from urllib.parse import urlparse
from .urlfeatures import urlfeatures as urlfeat

class FeatureExtractor:
    def __init__(self, le_method):
        self.le_method = le_method

        # --- CORREÇÃO CRÍTICA ---
        # Esta lista DEVE ser idêntica, em nomes e ordem, à lista de colunas
        # usada para treinar o modelo no seu notebook.
        self.feature_names = [
            'count_dot_path', 'count_dir_path', 'count_embed_domain_path', 
            'count%_path', 'count?_path', 'count-_path', 'count=_path', 'path_length',
            'sus_path', 'count-digits_path', 'count-letters_path', 
            'number_of_parameters_url', 'is_encoded_url',
            # Features da URL completa (para query, etc.)
            'special_count_path', 'unusual_character_ratio_path',
            # Feature do método
            'sus_query',
            'Method_enc'
        ]

    def extract(self, full_url, method):
        """
        Extrai um dicionário de features replicando a lógica do notebook de treino.
        """
        path = urlparse(full_url).path
        features = {}
        query = urlparse(full_url).query

        # --- CORREÇÃO CRÍTICA ---
        # As chaves do dicionário devem corresponder EXATAMENTE aos nomes em self.feature_names
        
        # Features que dependem APENAS do path
        features['count_dot_path'] = urlfeat.count_dot(path)
        features['count_dir_path'] = urlfeat.no_of_dir(path)
        features['count_embed_domain_path'] = urlfeat.no_of_embed(path)
        features['count%_path'] = urlfeat.count_per(path)
        features['count?_path'] = urlfeat.count_ques(path)
        features['count-_path'] = urlfeat.count_hyphen(path)
        features['count=_path'] = urlfeat.count_equal(path)
        features['path_length'] = urlfeat.url_length(path)
        features['sus_path'] = urlfeat.suspicious_words(path)
        features['count-digits_path'] = urlfeat.digit_count(path)
        features['count-letters_path'] = urlfeat.letter_count(path)
        features['special_count_path'] = urlfeat.count_special_characters(path)
        features['unusual_character_ratio_path'] = urlfeat.unusual_character_ratio(path)

        # Features que dependem da URL COMPLETA (incluindo query)
        features['number_of_parameters_url'] = urlfeat.number_of_parameters(full_url)
        features['is_encoded_url'] = urlfeat.is_encoded(full_url)

        # query
        features['sus_path'] = urlfeat.suspicious_words(path)
        features['sus_query'] = urlfeat.suspicious_words(query)
        
        # Feature do método
        try:
            features['Method_enc'] = self.le_method.transform([method])[0]
        except ValueError:
            features['Method_enc'] = -1
            
        return features

    def extract_df(self, full_url, method):
        """
        Retorna um DataFrame pronto para o modelo, garantindo a ordem das colunas.
        """
        features_dict = self.extract(full_url, method)
        # O reindex garante que as colunas estarão na mesma ordem do treino.
        return pd.DataFrame([features_dict]).reindex(columns=self.feature_names, fill_value=0)