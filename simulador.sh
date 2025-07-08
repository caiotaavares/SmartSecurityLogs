#!/bin/bash

# Lista de URLs de teste (apenas o caminho e a query)
URLS=(
    # "/index.html"
    # "/produtos/ver?id=12"
    # "/carrinho/adicionar"
    "/tienda1/publico/carrito.jsp"
    "/tienda1/publico/entrar.jsp?errorMsg=Credenciales+incorrectas"
    "/tienda1/publico/miembros.jsp"
    "/tienda1/publico/pagar.jsp?modo=insertar&precio=2672&B1=Pasar+por+caja"
    "/tienda1/publico/registro.jsp?errorMsg=El+usuario+ya+existe"
    "/login.php?user=' OR 1=1 --"
    "/search?q=<script>alert('xss')</script>"
    "/admin/../../etc/passwd"
    "/tienda1/publico/miembros.jsp"
    "/api/v1/products/delete?id=1;%20DROP%20TABLE%20users"
)

# O endpoint fixo da nossa API de coleta
API_ENDPOINT="http://localhost:5001/log"

echo "--- Iniciando Simulação de Tráfego (Formato Correto) ---"

while true; do
    # Escolhe uma URL aleatória da lista para ser analisada
    URL_PARA_ANALISAR=${URLS[$RANDOM % ${#URLS[@]}]}
    
    echo "Enviando para análise a URL: ${URL_PARA_ANALISAR}"
    
    # --- COMANDO CURL CORRIGIDO ---
    # Sempre faz um POST para o mesmo endpoint da API,
    # passando a URL a ser analisada dentro do header X-Original-URI.
    curl -X POST -s -o /dev/null \
      -H "X-Original-URI: ${URL_PARA_ANALISAR}" \
      -H "X-Original-Method: GET" \
      -H "X-Client-IP: 127.0.0.1" \
      "${API_ENDPOINT}"
    
    # Espera um tempo antes da próxima requisição
    sleep 1
done