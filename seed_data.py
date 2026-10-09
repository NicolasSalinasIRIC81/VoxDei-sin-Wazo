"""
Carga datos de PRUEBA en OpenSearch para ver el dashboard VOXDEI completo.

Uso (con el .venv activo, y OpenSearch corriendo en localhost:9200):

    python seed_data.py          # carga ~48 h de datos y termina
    python seed_data.py --live   # carga y luego sigue mandando datos nuevos
                                 # cada 20 s (mantiene a los agentes "online").
                                 # Ctrl + C para detener.

Crea estos índices (los mismos patrones que lee app.py):
  - suricata-alert-AAAA.MM.DD   -> alertas (vistas Resumen, Alertas, Mapa)
  - suricata-event-AAAA.MM.DD   -> tráfico crudo (línea "eventos" del Resumen)
  - agent-logs-AAAA.MM.DD       -> logs de agentes (vista Agentes)

Las IPs "atacantes" son IPs públicas conocidas (DNS públicos, etc.), usadas
solo para que ip-api.com pueda geolocalizarlas en el mapa. No son atacantes
reales: todo el contenido es inventado.
"""

import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

from opensearchpy import OpenSearch, helpers

HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
PORT = int(os.environ.get("OPENSEARCH_PORT", "9200"))
client = OpenSearch(hosts=[{"host": HOST, "port": PORT}], use_ssl=False, verify_certs=False)

HOURS_BACK = 48

# IP pública -> peso (qué tanto "ataca")
ATTACKERS = {
    "8.8.8.8": 10, "1.1.1.1": 6, "114.114.114.114": 14, "77.88.8.8": 9,
    "180.76.76.76": 12, "200.160.2.3": 5, "9.9.9.9": 4, "208.67.222.222": 3,
    "10.0.0.45": 3, "192.168.1.77": 2,  # internas (no salen en el mapa)
}
VICTIMS = ["10.0.0.10", "10.0.0.11", "10.0.0.20", "10.0.0.25", "192.168.1.5"]

# (firma, categoría, severidad 1=crítica 2=media 3=baja, puerto destino, proto)
SIGNATURES = [
    ("ET SCAN Potential SSH Scan", "Attempted Information Leak", 2, 22, "TCP"),
    ("ET EXPLOIT Apache Log4j RCE Attempt", "Attempted Administrator Privilege Gain", 1, 8080, "TCP"),
    ("ET POLICY RDP Brute Force Attempt", "Attempted User Privilege Gain", 1, 3389, "TCP"),
    ("ET SCAN Nmap Scripting Engine User-Agent", "Web Application Attack", 2, 80, "TCP"),
    ("ET MALWARE Possible Crypto Miner Stratum", "A Network Trojan was detected", 1, 3333, "TCP"),
    ("ET SCAN MySQL Probe", "Attempted Information Leak", 2, 3306, "TCP"),
    ("GPL DNS Query for Unusual TLD", "Potentially Bad Traffic", 3, 53, "UDP"),
    ("ET POLICY Outbound Telnet Connection", "Potential Corporate Privacy Violation", 3, 23, "TCP"),
    ("ET WEB_SERVER SQL Injection Attempt", "Web Application Attack", 1, 443, "TCP"),
    ("ET SCAN Redis Unauthenticated Access", "Attempted Information Leak", 2, 6379, "TCP"),
    ("ET SCAN SMB Enumeration", "Attempted Information Leak", 2, 445, "TCP"),
]

AGENTS = [
    # hostname, tipos de log, minutos desde su último log (0 = online)
    ("srv-web-01", ["nginx", "syslog"], 0),
    ("srv-db-01", ["postgres", "syslog"], 0),
    ("fw-perimetro", ["firewall", "syslog"], 0),
    ("srv-mail-01", ["postfix", "syslog"], 6),    # degradado
    ("pc-contabilidad", ["windows-event"], 180),  # offline
]


def ts(dt):
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def idx(prefix, dt):
    return f"{prefix}-{dt:%Y.%m.%d}"


def make_alert(dt):
    sig, cat, sev, dport, proto = random.choice(SIGNATURES)
    src = random.choices(list(ATTACKERS), weights=ATTACKERS.values())[0]
    return {
        "_index": idx("suricata-alert", dt),
        "_source": {
            "@timestamp": ts(dt),
            "event_type": "alert",
            "src_ip": src,
            "src_port": random.randint(1025, 65000),
            "dest_ip": random.choice(VICTIMS),
            "dest_port": dport,
            "proto": proto,
            "alert": {"signature": sig, "category": cat, "severity": sev},
        },
    }


def make_event(dt):
    return {
        "_index": idx("suricata-event", dt),
        "_source": {
            "@timestamp": ts(dt),
            "event_type": random.choice(["flow", "dns", "http", "tls"]),
            "src_ip": random.choice(VICTIMS),
            "dest_ip": random.choice(list(ATTACKERS)),
            "dest_port": random.choice([53, 80, 443]),
            "proto": random.choice(["TCP", "UDP"]),
        },
    }


def make_agent_log(dt, host, log_types):
    return {
        "_index": idx("agent-logs", dt),
        "_source": {
            "@timestamp": ts(dt),
            "hostname": host,
            "log_type": random.choice(log_types),
            "message": "log de prueba",
        },
    }


def seed_history():
    now = datetime.now(timezone.utc)
    docs = []
    for h in range(HOURS_BACK):
        hour_start = now - timedelta(hours=h + 1)
        # Más actividad "de día" para que la gráfica no sea plana
        busy = 1.6 if 8 <= hour_start.hour <= 20 else 0.6
        for _ in range(int(random.randint(8, 35) * busy)):
            docs.append(make_alert(hour_start + timedelta(seconds=random.randint(0, 3599))))
        for _ in range(int(random.randint(120, 400) * busy)):
            docs.append(make_event(hour_start + timedelta(seconds=random.randint(0, 3599))))

    # Algunas alertas recién llegadas (últimos minutos)
    for _ in range(25):
        docs.append(make_alert(now - timedelta(seconds=random.randint(0, 600))))

    # Agentes: logs hasta su "último visto"
    for host, types, mins_ago in AGENTS:
        last = now - timedelta(minutes=mins_ago)
        for _ in range(60):
            docs.append(make_agent_log(last - timedelta(minutes=random.randint(0, 55 * 24)), host, types))
        docs.append(make_agent_log(last - timedelta(seconds=5), host, types))

    ok, _ = helpers.bulk(client, docs, refresh=True)
    print(f"[seed] {ok} documentos cargados.")


def live_loop():
    print("[seed] Modo --live: enviando datos nuevos cada 20 s (Ctrl + C para salir)")
    while True:
        now = datetime.now(timezone.utc)
        docs = [make_alert(now) for _ in range(random.randint(1, 5))]
        docs += [make_event(now) for _ in range(random.randint(30, 80))]
        for host, types, mins_ago in AGENTS:
            if mins_ago == 0:  # solo los "online" siguen reportando
                docs.append(make_agent_log(now, host, types))
        helpers.bulk(client, docs, refresh=True)
        print(f"[seed] {now:%H:%M:%S} +{len(docs)} docs")
        time.sleep(20)


if __name__ == "__main__":
    try:
        client.info()
    except Exception as e:
        sys.exit(f"No pude conectar a OpenSearch en {HOST}:{PORT}. ¿Está corriendo?\nDetalle: {e}")
    seed_history()
    if "--live" in sys.argv:
        try:
            live_loop()
        except KeyboardInterrupt:
            print("\n[seed] Detenido.")
