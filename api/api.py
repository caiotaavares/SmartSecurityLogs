import os
import json
import redis
from flask import Flask, request

app = Flask(__name__)

# --- CONFIGURAÇÃO DOS SERVIÇOS ---
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
TASK_QUEUE_NAME = "attack_analysis_queue"

# A conexão agora será criada dentro da função de request
# para garantir que ela seja sempre nova e válida para cada processo worker.

@app.route("/log", methods=["POST"])
def log_request():
    """
    Recebe os dados do Nginx, conecta-se ao Redis, 
    e enfileira a tarefa para processamento assíncrono.
    """
    try:
        # --- MUDANÇA CRÍTICA: Conexão criada aqui ---
        redis_conn = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
        redis_conn.ping() # Testa a conexão
        
        data_to_analyze = {
            "url": request.headers.get("X-Original-URI", ""),
            "method": request.headers.get("X-Original-Method", "GET"),
            "client_ip": request.headers.get("X-Client-IP", ""),
        }
        
        task_json = json.dumps(data_to_analyze)
        
        redis_conn.lpush(TASK_QUEUE_NAME, task_json)
        
        return "Accepted", 202
    
    except redis.exceptions.ConnectionError as e:
        # Erro específico para falha de conexão com o Redis
        print(f"API Error: Could not connect to Redis. {e}")
        return "Internal Server Error - Redis connection failed", 500
    except Exception as e:
        # Outros erros
        print(f"API Error: An unexpected error occurred. {e}")
        return "Internal Server Error", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)