import os
import json
import redis
from flask import Flask, request

app = Flask(__name__)

# Conecta ao Redis. O nome 'redis' será resolvido pelo Docker Compose.
# Usar variáveis de ambiente é a prática profissional.
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
redis_conn = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)

# Nome da nossa fila de tarefas no Redis
TASK_QUEUE_NAME = "attack_analysis_queue"

@app.route("/log", methods=["POST"])
def log_request():
    """
    Recebe os dados do Nginx e os enfileira no Redis para processamento assíncrono.
    """
    try:
        # Extrai os dados dos headers customizados que o Nginx enviou
        data_to_analyze = {
            "url": request.headers.get("X-Original-URI", ""),
            "method": request.headers.get("X-Original-Method", "GET"),
            "client_ip": request.headers.get("X-Client-IP", ""),
        }
        
        # Converte o dicionário para uma string JSON e o coloca na fila (LPUSH)
        redis_conn.lpush(TASK_QUEUE_NAME, json.dumps(data_to_analyze))
        
        # Retorna 202 Accepted para indicar que a requisição foi aceita
        # mas o processamento ainda não foi concluído.
        return "Accepted", 202
    
    except Exception as e:
        print(f"Erro ao enfileirar tarefa: {e}")
        return "Internal Server Error", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)