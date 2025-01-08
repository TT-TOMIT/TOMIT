from flask import Flask, request, jsonify
import requests
import threading
import time
import ipaddress

app = Flask(__name__)

# Globalna lista dozwolonych adresów IP
allowed_ips = set()

# URL do pobierania danych adresacji AWS
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

# Region AWS, który chcemy dopuścić
ALLOWED_REGION = "eu-west-1"


def update_allowed_ips():
    """Funkcja odświeżająca listę dozwolonych adresów IP."""
    global allowed_ips
    try:
        response = requests.get(AWS_IP_RANGES_URL)
        response.raise_for_status()
        data = response.json()

        # Filtrujemy zakresy IP dla regionu Europe West
        new_allowed_ips = {
            prefix["ip_prefix"]
            for prefix in data["prefixes"]
            if prefix["region"] == ALLOWED_REGION
        }
        allowed_ips = {ipaddress.ip_network(ip) for ip in new_allowed_ips}
        print(f"[INFO] Zaktualizowano dozwolone adresy IP: {allowed_ips}")
    except Exception as e:
        print(f"[ERROR] Nie udało się zaktualizować adresów IP: {e}")


def start_scheduled_update(interval=86400):
    """Uruchamia wątek odświeżający adresy IP co określony czas."""
    def updater():
        while True:
            update_allowed_ips()
            time.sleep(interval)

    thread = threading.Thread(target=updater, daemon=True)
    thread.start()


@app.route("/verify", methods=["POST"])
def verify_request():
    """Endpoint do weryfikacji adresu IP."""
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    try:
        client_ip = ipaddress.ip_address(client_ip)
        # Sprawdzamy, czy IP klienta mieści się w którymkolwiek dozwolonym zakresie
        if any(client_ip in network for network in allowed_ips):
            return "OK", 200
        else:
            return "Unauthorized", 401
    except ValueError:
        return "Invalid IP", 400


if __name__ == "__main__":
    # Początkowe odświeżenie adresów IP
    update_allowed_ips()
    # Start planowego odświeżania
    start_scheduled_update()
    # Uruchomienie serwera Flask
    app.run(host="0.0.0.0", port=5000)
