from proxy.proxy import ProxyServer

if __name__ == "__main__":
    proxy = ProxyServer(backend_host='localhost', backend_port=8081)
    proxy.run(port=8080)
