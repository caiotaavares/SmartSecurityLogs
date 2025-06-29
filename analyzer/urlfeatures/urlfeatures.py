import re
from urllib.parse import urlparse

# ==============================================================================
#  FUNÇÕES DE TRATAMENTO DE URL E CONTEÚDO
# ==============================================================================

def count_dot(text):
    if not isinstance(text, str): return 0
    return text.count('.')

def no_of_dir(url):
    if not isinstance(url, str): return 0
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    if not isinstance(url, str): return 0
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    if not isinstance(url, str): return 0
    # CORRIGIDO: Usando raw string (r'') para a expressão regular
    match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      r'tr\.im|link\.zip\.net',
                      url)
    return 1 if match else 0

def count_http(text):
    if not isinstance(text, str): return 0
    return text.count('http')

def count_per(text):
    if not isinstance(text, str): return 0
    return text.count('%')

def count_ques(text):
    if not isinstance(text, str): return 0
    return text.count('?')

def count_hyphen(text):
    if not isinstance(text, str): return 0
    return text.count('-')

def count_equal(text):
    if not isinstance(text, str): return 0
    return text.count('=')

def url_length(text):
    return len(str(text))

def hostname_length(url):
    if not isinstance(url, str): return 0
    return len(urlparse(url).netloc)

def suspicious_words(text):
    if not isinstance(text, str): return 0
    score_map = {
        'error': 30, 'errorMsg': 30, 'id': 10, 'errorID': 30, 'SELECT': 50,
        'FROM': 50, 'WHERE': 50, 'DELETE': 50, 'USERS': 50, 'DROP': 50, 'CREATE': 50,
        'INJECTED': 50, 'TABLE': 50, 'alert': 30, 'javascript': 20, 'cookie': 25,
        '--': 30, '.exe': 30, '.php': 20, '.js': 10, 'admin': 10, 'administrator': 10,
        '\'': 30, 'password': 15, 'login': 15, 'incorrect': 20, 'pwd': 15, 'tamper': 25,
        'vaciar': 20, 'carrito': 25, 'wait': 30, 'delay': 35, 'set': 20, 'steal': 35,
        'hacker': 35, 'proxy': 35, 'location': 30, 'document.cookie': 40, 'document': 20,
        'set-cookie': 40, 'create': 40, 'cmd': 40, 'dir': 30, 'shell': 40, 'reverse': 30,
        'bin': 20, 'cookiesteal': 40, 'LIKE': 30, 'UNION': 35, 'include': 30, 'file': 20,
        'tmp': 25, 'ssh': 40, 'exec': 30, 'cat': 25, 'etc': 30, 'fetch': 25, 'eval': 30,
        'malware': 45, 'ransomware': 45, 'phishing': 45, 'exploit': 45, 'virus': 45,
        'trojan': 45, 'backdoor': 45, 'spyware': 45, 'rootkit': 45, 'credential': 30,
        'inject': 30, 'script': 25, 'iframe': 25, 'src=': 25, 'onerror': 30,
        'prompt': 20, 'confirm': 20, 'expression': 30,
        r'function\(': 20, # CORRIGIDO: Usando raw string aqui também
        'xmlhttprequest': 30, 'xhr': 20, 'window.': 20, 'document.': 20, 'click': 15,
        'mouseover': 15, 'onload': 20, 'onunload': 20
    }
    # Usando raw string para a expressão regular principal
    matches = re.findall(r'(?i)' + '|'.join(score_map.keys()), text)
    total_score = sum(score_map.get(match.lower(), 0) for match in matches)
    return total_score

def digit_count(text):
    if not isinstance(text, str): return 0
    return sum(c.isdigit() for c in text)

def letter_count(text):
    if not isinstance(text, str): return 0
    return sum(c.isalpha() for c in text)

def count_special_characters(text):
    if not isinstance(text, str): return 0
    special_characters = re.sub(r'[a-zA-Z0-9\s]', '', text)
    return len(special_characters)

def number_of_parameters(url):
    if not isinstance(url, str): return 0
    params = urlparse(url).query
    return 0 if not params else len(params.split('&'))

def number_of_fragments(url):
    if not isinstance(url, str): return 0
    frags = urlparse(url).fragment
    return 0 if not frags else len(frags.split('#')) - 1

def is_encoded(text):
    if not isinstance(text, str): return 0
    return 1 if '%' in text.lower() else 0

def unusual_character_ratio(url):
    if not isinstance(url, str) or not url: return 0
    total_characters = len(url)
    unusual_characters = re.sub(r'[a-zA-Z0-9\s\-._]', '', url)
    unusual_count = len(unusual_characters)
    return unusual_count / total_characters

# def count_dot(url): return url.count('.')
# def no_of_dir(url): return urlparse(url).path.count('/')
# def no_of_embed(url): return urlparse(url).path.count('//')
# def count_per(url): return url.count('%')
# def count_ques(url): return url.count('?')
# def count_hyphen(url): return url.count('-')
# def count_equal(url): return url.count('=')
# def url_length(url): return len(str(url))
# def suspicious_words(url):
#     score_map = { 'error': 30, 'SELECT': 50, 'FROM': 50, 'WHERE': 50, 'DELETE': 50, 'USERS': 50, 'DROP': 50, 'CREATE': 50, 'INJECTED': 50, 'TABLE': 50, 'alert': 30, 'javascript': 20, 'cookie': 25, '--': 30, '.exe': 30, '.php': 20, '.js': 10, 'admin': 10, 'administrator': 10, '\'': 30, 'password': 15, 'login': 15, 'incorrect': 20, 'pwd': 15, 'tamper': 25, 'vaciar': 20, 'carrito': 25, 'wait': 30, 'delay': 35, 'set': 20, 'steal': 35, 'hacker': 35, 'proxy': 35, 'location': 30, 'document.cookie': 40, 'document': 20, 'set-cookie': 40, 'create': 40, 'cmd': 40, 'dir': 30, 'shell': 40, 'reverse': 30, 'bin': 20, 'cookiesteal': 40, 'LIKE': 30, 'UNION': 35, 'include': 30, 'file': 20, 'tmp': 25, 'ssh': 40, 'exec': 30, 'cat': 25, 'etc': 30, 'fetch': 25, 'eval': 30, 'malware': 45, 'ransomware': 45, 'phishing': 45, 'exploit': 45, 'virus': 45, 'trojan': 45, 'backdoor': 45, 'spyware': 45, 'rootkit': 45, 'credential': 30, 'inject': 30, 'script': 25, 'iframe': 25, 'src=': 25, 'onerror': 30, 'prompt': 20, 'confirm': 20, 'expression': 30, r'function\(': 20, 'xmlhttprequest': 30, 'xhr': 20, 'window.': 20, 'document.': 20, 'click': 15, 'mouseover': 15, 'onload': 20, 'onunload': 20 }
#     matches = re.findall(r'(?i)' + '|'.join(score_map.keys()), url)
#     return sum(score_map.get(match.lower(), 0) for match in matches)
# def digit_count(url): return sum(c.isdigit() for c in url)
# def letter_count(url): return sum(c.isalpha() for c in url)
# def count_special_characters(url): return len(re.sub(r'[a-zA-Z0-9\s]', '', url))
# def number_of_parameters(url):
#     params = urlparse(url).query
#     return 0 if not params else len(params.split('&'))
# def is_encoded(url): return 1 if '%' in url.lower() else 0
# def unusual_character_ratio(url):
#     total_characters = len(url)
#     if total_characters == 0: return 0
#     unusual_characters = re.sub(r'[a-zA-Z0-9\s\-._]', '', url)
#     return len(unusual_characters) / total_characters