from flask import Flask, request, jsonify

app = Flask(__name__)

# Dados de exemplo (usuários)
users_data = [
    {'id': 1, 'name': 'Alice', 'email': 'alice@example.com', 'age': 25, 'role': 'admin'},
    {'id': 2, 'name': 'Bob', 'email': 'bob@example.com', 'age': 30, 'role': 'user'},
    {'id': 3, 'name': 'Charlie', 'email': 'charlie@example.com', 'age': 35, 'role': 'user'},
    {'id': 4, 'name': 'David', 'email': 'david@example.com', 'age': 28, 'role': 'admin'},
    {'id': 5, 'name': 'Eve', 'email': 'eve@example.com', 'age': 22, 'role': 'user'},
    {'id': 6, 'name': 'Frank', 'email': 'frank@example.com', 'age': 40, 'role': 'admin'},
    {'id': 7, 'name': 'Grace', 'email': 'grace@example.com', 'age': 24, 'role': 'user'}
]

@app.route('/')
def hello():
    return "Backend de teste rodando!"

# 1. Endpoint de busca para todos os usuários
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')  # Parâmetro de consulta 'q'
    role = request.args.get('role', '')  # Parâmetro de consulta 'role'
    min_age = request.args.get('min_age', type=int)  # Parâmetro de consulta 'min_age'
    max_age = request.args.get('max_age', type=int)  # Parâmetro de consulta 'max_age'

    # Filtra os usuários com base nos parâmetros de consulta
    filtered_users = users_data

    if query:
        filtered_users = [user for user in filtered_users if query.lower() in user['name'].lower() or query.lower() in user['email'].lower()]
    
    if role:
        filtered_users = [user for user in filtered_users if user['role'] == role]
    
    if min_age is not None:
        filtered_users = [user for user in filtered_users if user['age'] >= min_age]
    
    if max_age is not None:
        filtered_users = [user for user in filtered_users if user['age'] <= max_age]

    return jsonify(filtered_users)

if __name__ == "__main__":
    app.run(port=8081)

# GET http://127.0.0.1:8081/search?q=alice
# GET http://127.0.0.1:8081/search?role=admin
# GET http://127.0.0.1:8081/search?min_age=25&max_age=35
# GET http://127.0.0.1:8081/search?q=Bob&role=user
