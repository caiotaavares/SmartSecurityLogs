import analyzer.urlfeatures.urlfeatures as urlfeat
import pandas as pd

class FeatureExtractor:
    def __init__(self):
        # Lista de nomes de features, sempre na mesma ordem do modelo!
        self.feature_names = [
            'count_dot_url',
            'count_dir_url', 
            'count_embed_domain_url', 
            'count-http',
            'count%_url', 
            'count?_url', 
            'count-_url', 
            'count=_url', 
            'url_length', 
            'hostname_length_url',
            'sus_url', 
            'count-digits_url', 
            'count-letters_url', 
            'number_of_parameters_url',
            'is_encoded_url',
            'special_count_url',
            'unusual_character_ratio_url',
            # Method
            'Method_enc',
            # Content
            'count_dot_content',
            'count%_content',
            'count-_content',
            'count=_content',
            'sus_content',
            'count_digits_content',
            'count_letters_content',
            'content_length',
            'is_encoded_content',
            'special_count_content'
        ]

    # ----- Função principal -----
    def extract(self, url, method, content):
        print(f"FEATUREEXTRACTOR(extract) - Extraindo features da URL: {url} com método: {method}")
        features = {}
        # Preencha tudo com zero
        for name in self.feature_names:
            features[name] = 0

        # Preencha cada campo corretamente
        features['count_dot_url']               = urlfeat.count_dot(url)
        features['count_dir_url']               = urlfeat.no_of_dir(url)
        features['count_embed_domain_url']      = urlfeat.no_of_embed(url)
        features['count-http']                  = urlfeat.count_http(url)
        features['count%_url']                  = urlfeat.count_per(url)
        features['count?_url']                  = urlfeat.count_ques(url)
        features['count-_url']                  = urlfeat.count_hyphen(url)
        features['count=_url']                  = urlfeat.count_equal(url)
        features['url_length']                  = urlfeat.url_length(url)
        features['hostname_length_url']         = urlfeat.hostname_length(url)
        features['sus_url']                     = urlfeat.suspicious_words(url)
        features['count-digits_url']            = urlfeat.digit_count(url)
        features['count-letters_url']           = urlfeat.letter_count(url)
        features['number_of_parameters_url']    = urlfeat.number_of_parameters(url)
        features['is_encoded_url']              = urlfeat.is_encoded(url)
        features['special_count_url']           = urlfeat.count_special_characters(url)
        features['unusual_character_ratio_url'] = urlfeat.unusual_character_ratio(url)

        # Method_enc: Faça igual no treino! Exemplo:
        if method == "GET":
            features['Method_enc'] = 0
        elif method == "POST":
            features['Method_enc'] = 1
        else:
            features['Method_enc'] = 2  # Ou conforme seu LabelEncoder

        # Content features (repita o mesmo para content)
        features['count_dot_content'] = urlfeat.count_dot(content)
        features['count%_content'] = urlfeat.count_per(content)
        features['count-_content'] = urlfeat.count_hyphen(content)
        features['count=_content'] = urlfeat.count_equal(content)
        features['sus_content'] = urlfeat.suspicious_words(content)
        features['count_digits_content'] = urlfeat.digit_count(content)
        features['count_letters_content'] = urlfeat.letter_count(content)
        features['content_length'] = urlfeat.url_length(content)
        features['is_encoded_content'] = urlfeat.is_encoded(content)
        features['special_count_content'] = urlfeat.count_special_characters(content)

        # Retorne na ordem correta!
        print(f"FEATUREEXTRACTOR(extract) - Features extraídas: {features}")
        return features

    def extract_df(self, url, method, content):
        """
        Retorna um DataFrame pronto para o modelo.
        """
        print(f"PORRA")
        features = self.extract(url, method, content)
        print(f"FEATUREEXTRACTOR(extract_df) - {features}")
        return pd.DataFrame([features], columns=self.feature_names)

