import os
import json
import redis
import time
from analyzer.analyzer import AttackAnalyzer # Importa seu analisador

# Mock/Simulação de um objeto de requisição, pois o analyzer espera um
class SimpleRequest:
    def __init__(self, data):
        self.method = data.get("method", "GET")
        # O analyzer precisa de uma URL completa, então montamos uma
        self.url = f"http://localhost{data.get('url', '/')}" 
    
    def get_data(self, as_text=False): # Método dummy
        return ""

# Conecta ao Redis
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
redis_conn = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)

TASK_QUEUE_NAME = "attack_analysis_queue"

def main():
    print("--- Starting Worker ---")
    print("Loading ML model...")
    analyzer = AttackAnalyzer(
        model_path='../data/path_only_model.pkl',
        method_encoder_path='../data/path_only_method_encoder.pkl'
    )
    print("Model loaded. Waiting for tasks in the queue...")

    while True:
        try:
            # BRPOP é uma operação de bloqueio. Ele espera eficientemente por uma tarefa.
            # O '0' significa esperar indefinidamente.
            _, task_json = redis_conn.brpop(TASK_QUEUE_NAME, 0)
            
            task_data = json.loads(task_json)
            print(f"\n[NOVA TAREFA RECEBIDA] URL: {task_data.get('url')}")

            # Simula um objeto de requisição e analisa
            request_to_analyze = SimpleRequest(task_data)
            result = analyzer.analyze(request_to_analyze)
            
            # Em um sistema real, você salvaria `result` no Elasticsearch/DB.
            # Por agora, apenas imprimimos no console.
            print(f"[ANÁLISE COMPLETA] Classificação: {result['classificacao']}, Confiança Anômalo: {result['confianca']['anomalo']:.2%}")

        except redis.exceptions.ConnectionError as e:
            print(f"Erro de conexão com o Redis, tentando novamente em 5s... {e}")
            time.sleep(5)
        except Exception as e:
            print(f"Erro ao processar tarefa: {e}")

if __name__ == "__main__":
    main()