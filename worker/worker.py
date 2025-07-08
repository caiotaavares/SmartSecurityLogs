import os
import json
import redis
import time
import traceback
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from worker.analyzer.AttackAnalyzer import AttackAnalyzer

PATH_ONLY_MODEL = '/app/data/path_only_model.pkl'
PATH_ONLY_METHOD_ENCODER = '/app/data/path_only_method_encoder.pkl'
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
ELASTIC_HOST = os.environ.get("ELASTIC_HOST", "localhost")
TASK_QUEUE_NAME = "attack_analysis_queue"
RESULTS_INDEX_NAME = "security_analysis_results"

class SimpleRequest:
    def __init__(self, data):
        self.method = data.get("method", "GET")
        self.url = f"http://localhost{data.get('url', '/')}"
    def get_data(self, as_text=False): return ""

redis_conn = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)
es_conn = Elasticsearch(f"http://{ELASTIC_HOST}:9200")

def main():
    print("--- Worker de Análise Iniciado ---")
    analyzer = AttackAnalyzer(
        model_path=PATH_ONLY_MODEL,
        method_encoder_path=PATH_ONLY_METHOD_ENCODER
    )
    
    while not es_conn.ping():
        print("Aguardando conexão com o Elasticsearch...")
        time.sleep(3)
    print("Conectado ao Elasticsearch. Aguardando tarefas na fila...")

    while True:
        try:
            # brpop retorna uma string, não bytes
            _, task_json = redis_conn.brpop(TASK_QUEUE_NAME, 0)
            
            print(f"\n[NOVA TAREFA RECEBIDA] Dados brutos: {task_json}")
            
            task_data = json.loads(task_json)
            
            request_to_analyze = SimpleRequest(task_data)
            result = analyzer.analyze(request_to_analyze)

            document_to_save = {
                "@timestamp": datetime.now(timezone.utc),
                "url": result["url"],
                "method": result["metodo"],
                "classification": result["classificacao"],
                "is_anomalous": 1 if result["classificacao"] == "Anómalo" else 0,
                "anomaly_confidence": result["confianca"]["anomalo"],
                "client_ip": task_data.get("client_ip")
            }

            es_conn.index(index=RESULTS_INDEX_NAME, document=document_to_save)
            print(f"[ANÁLISE COMPLETA E SALVA] URL: {result['url']}")

        except Exception as e:
            print(f"--- WORKER: ERRO AO PROCESSAR TAREFA: {e} ---")
            # Imprime o traceback completo do erro
            traceback.print_exc()
            time.sleep(5)

if __name__ == "__main__":
    main()