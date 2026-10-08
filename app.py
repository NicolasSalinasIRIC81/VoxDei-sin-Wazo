"""
SOC Dashboard — backend Flask
Conecta con OpenSearch (índices suricata-alert-*) para servir
la vista de Alertas con datos reales del pipeline Suricata ->
Fluent Bit -> OpenSearch.

El campo "estado" (abierta / revisión / cerrada) no existe en los
datos crudos de Suricata -- lo llevamos nosotros en un índice
auxiliar (soc-annotations), keyed por el _id del documento de
alerta, para no tener que modificar el pipeline de ingestión.
"""

import ipaddress
import os
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from opensearchpy import OpenSearch

from auth import check_login, current_role, current_user, require_role, role_at_least

app = Flask(__name__)
# Necesario para que las cookies de sesión (login) sean seguras.
# En producción, define SECRET_KEY como variable de entorno real.
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me-before-deploying")

OS_HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
OS_PORT = int(os.environ.get("OPENSEARCH_PORT", "9200"))

# Coordenadas que representan "tu red" en el mapa de amenazas.
# AJUSTA ESTO a la ubicación real de tu servidor/oficina --
# se usan solo como ancla visual para dibujar las líneas de ataque.
DEST_LAT = float(os.environ.get("DEST_LAT", "19.4326"))
DEST_LON = float(os.environ.get("DEST_LON", "-99.1332"))
DEST_LABEL = os.environ.get("DEST_LABEL", "Tu red (SOC)")

client = OpenSearch(
    hosts=[{"host": OS_HOST, "port": OS_PORT}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
)

ALERT_INDEX = "suricata-alert-*"
ANNOTATIONS_INDEX = "soc-annotations"

_field_cache = {}


def resolve_agg_field(field):
    """Algunos campos de texto (src_ip, alert.signature) pueden estar
    mapeados como 'text' con un sub-campo '.keyword' para agregaciones
    exactas. Esto detecta cuál usar, en vez de asumirlo a ciegas, y
    cachea el resultado para no consultar el mapping en cada request."""
    if field in _field_cache:
        return _field_cache[field]
    resolved = field
    try:
        mapping = client.indices.get_field_mapping(index=ALERT_INDEX, fields=field)
        for _, idx_data in mapping.items():
            m = idx_data.get("mappings", {}).get(field, {}).get("mapping", {})
            for _, fdef in m.items():
                if fdef.get("type") == "text" and "keyword" in fdef.get("fields", {}):
                    resolved = f"{field}.keyword"
                break
            break
    except Exception:
        pass
    _field_cache[field] = resolved
    return resolved


def ensure_annotations_index():
    """Crea el índice de anotaciones si no existe. Se llama al arrancar.
    Envuelto en try/except: si OpenSearch no está disponible en el
    momento exacto en que arranca Flask (por ejemplo, en un docker-compose
    donde el contenedor de Flask sube antes que el de OpenSearch), la app
    ya no se cae por completo -- solo avisa y sigue. El índice se crea
    en el primer intento exitoso de guardar una anotación."""
    try:
        if not client.indices.exists(index=ANNOTATIONS_INDEX):
            client.indices.create(
                index=ANNOTATIONS_INDEX,
                body={
                    "mappings": {
                        "properties": {
                            "alert_id": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "updated_at": {"type": "date"},
                            "note": {"type": "text"},
                        }
                    }
                },
            )
    except Exception as e:
        print(f"[VOXDEI] Aviso: no se pudo verificar/crear '{ANNOTATIONS_INDEX}' al arrancar "
              f"(¿OpenSearch no está disponible todavía?). Detalle: {e}")


def severity_label(sev):
    """Mapea la severidad numérica de Suricata (1=alta) a las
    etiquetas que usa el dashboard."""
    if sev == 1:
        return "critica"
    if sev == 2:
        return "media"
    return "baja"


# --------------------------------------------------------------
# Geolocalización de IPs vía ip-api.com (gratis, sin API key,
# límite de 45 requests/minuto en el tier gratuito). Cacheamos en
# memoria por 6 horas para no rebasar ese límite -- la mayoría de
# las alertas repiten las mismas pocas IPs atacantes.
# --------------------------------------------------------------
_geo_cache = {}
_GEO_CACHE_TTL = 6 * 3600


def is_private_ip(ip):
    """IPs privadas/locales (RFC1918, loopback) no se pueden
    geolocalizar y normalmente son tu propia red interna -- se
    excluyen del mapa."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


def geolocate_ips(ips):
    """Resuelve país/ciudad/lat/lon para una lista de IPs públicas,
    usando el endpoint batch de ip-api.com (hasta 100 IPs por
    request) y cacheando el resultado."""
    now = time.time()
    to_fetch = [
        ip
        for ip in ips
        if ip not in _geo_cache or (now - _geo_cache[ip]["ts"]) > _GEO_CACHE_TTL
    ]

    if to_fetch:
        try:
            resp = requests.post(
                "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,query",
                json=to_fetch[:100],
                timeout=5,
            )
            for r in resp.json():
                ip = r.get("query")
                if not ip:
                    continue
                _geo_cache[ip] = {
                    "ts": now,
                    "data": r if r.get("status") == "success" else None,
                }
        except Exception:
            # Si ip-api.com no responde, seguimos con lo que haya
            # en caché; las IPs sin caché simplemente no aparecen
            # en el mapa esta vez.
            pass

    return {ip: _geo_cache.get(ip, {}).get("data") for ip in ips}


def get_annotations(ids):
    """Trae el estado guardado (si existe) para una lista de IDs
    de alerta. Devuelve {} si el índice está vacío o no existe."""
    if not ids:
        return {}
    try:
        res = client.mget(index=ANNOTATIONS_INDEX, body={"ids": ids})
    except Exception:
        return {}
    out = {}
    for doc in res.get("docs", []):
        if doc.get("found"):
            out[doc["_id"]] = doc["_source"]
    return out


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = check_login(username, password)
        if role:
            session["username"] = username
            session["role"] = role
            next_url = request.args.get("next") or url_for("resumen_page")
            return redirect(next_url)
        error = "Usuario o contraseña incorrectos."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.context_processor
def inject_role():
    """Disponible en todos los templates sin tener que pasarlo cada
    vez: current_role, current_user, y role_at_least('Admin') etc."""
    return {
        "current_role": current_role(),
        "current_user": current_user(),
        "role_at_least": role_at_least,
    }


@app.route("/")
@require_role("Operador")
def resumen_page():
    return render_template("resumen.html", active="resumen")


@app.route("/alertas")
@require_role("Operador")
def alertas_page():
    return render_template("alertas.html", active="alertas")


@app.route("/api/summary")
@require_role("Operador")
def api_summary():
    hours = int(request.args.get("hours", 24))
    compare = request.args.get("compare") == "1"

    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 0,
                }
            },
            "by_severity": {"terms": {"field": "alert.severity"}},
            "unique_src": {"cardinality": {"field": resolve_agg_field("src_ip")}},
            "top_src": {"terms": {"field": resolve_agg_field("src_ip"), "size": 5}},
            "top_sig": {
                "terms": {"field": resolve_agg_field("alert.signature"), "size": 5}
            },
            "top_ports": {
                "terms": {
                    "field": "dest_port",
                    "size": 15,
                    "order": {"last_seen": "desc"},
                },
                "aggs": {
                    "min_sev": {"min": {"field": "alert.severity"}},
                    "unique_src": {"cardinality": {"field": resolve_agg_field("src_ip")}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "top_sig": {
                        "terms": {
                            "field": resolve_agg_field("alert.signature"),
                            "size": 1,
                            "order": {"_count": "desc"},
                        }
                    },
                },
            },
        },
    }

    try:
        res = client.search(index=ALERT_INDEX, body=body)
    except Exception as e:
        return jsonify({"error": str(e), "empty": True})

    aggs = res.get("aggregations", {})

    alerts_by_hour = [
        {"hour": b["key_as_string"][11:16], "count": b["doc_count"]}
        for b in aggs.get("by_hour", {}).get("buckets", [])
    ]

    severity_counts = {"critica": 0, "media": 0, "baja": 0}
    for b in aggs.get("by_severity", {}).get("buckets", []):
        severity_counts[severity_label(b["key"])] += b["doc_count"]

    top_src = [
        {"ip": b["key"], "count": b["doc_count"]}
        for b in aggs.get("top_src", {}).get("buckets", [])
    ]
    top_sig = [
        {"signature": b["key"], "count": b["doc_count"]}
        for b in aggs.get("top_sig", {}).get("buckets", [])
    ]

    # Eventos/seg aproximado: todos los eventos (no solo alertas) en
    # los últimos 60 segundos, sobre todos los índices suricata-*
    try:
        eps_count = client.count(
            index="suricata-*",
            body={"query": {"range": {"@timestamp": {"gte": "now-60s"}}}},
        )["count"]
        events_per_sec = round(eps_count / 60, 1)
    except Exception:
        events_per_sec = None

    # ---- Serie de "eventos totales por hora" (tráfico crudo, no solo
    # alertas) sobre suricata-* -- es la segunda línea de la gráfica de
    # conectividad adaptada (equivalente al "RSSI vs Latencia" de ORIX:
    # aquí es "volumen de tráfico total" vs "volumen de alertas"). ----
    def hourly_histogram(index, extra_query=None):
        q = {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
        body = {
            "size": 0,
            "query": q if not extra_query else {"bool": {"must": [q, extra_query]}},
            "aggs": {
                "by_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                    }
                }
            },
        }
        try:
            r = client.search(index=index, body=body)
            return [
                {"hour": b["key_as_string"][11:16], "count": b["doc_count"]}
                for b in r["aggregations"]["by_hour"]["buckets"]
            ]
        except Exception:
            return []

    events_by_hour = hourly_histogram("suricata-*")

    # ---- Comparación opcional contra el periodo anterior (ej. "ayer"),
    # para el selector "Comparar con" que solo ve SuperAdmin/Admin. Se
    # desplaza la ventana `hours` hacia atrás otras `hours` horas. ----
    alerts_by_hour_prev = []
    if compare:
        prev_body = {
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {"gte": f"now-{hours*2}h", "lt": f"now-{hours}h"}
                }
            },
            "aggs": {
                "by_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                    }
                }
            },
        }
        try:
            prev_res = client.search(index=ALERT_INDEX, body=prev_body)
            alerts_by_hour_prev = [
                {"hour": b["key_as_string"][11:16], "count": b["doc_count"]}
                for b in prev_res["aggregations"]["by_hour"]["buckets"]
            ]
        except Exception:
            alerts_by_hour_prev = []

    # Últimas 5 alertas para la tabla de la parte inferior
    latest_body = {
        "size": 5,
        "sort": [{"@timestamp": "desc"}],
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
    }
    latest = []
    try:
        latest_res = client.search(index=ALERT_INDEX, body=latest_body)
        for h in latest_res["hits"]["hits"]:
            src = h["_source"]
            alert = src.get("alert", {})
            latest.append(
                {
                    "timestamp": src.get("@timestamp"),
                    "src_ip": src.get("src_ip"),
                    "dest_ip": src.get("dest_ip"),
                    "signature": alert.get("signature", ""),
                    "severity": severity_label(alert.get("severity", 3)),
                }
            )
    except Exception:
        pass

    port_buckets = aggs.get("top_ports", {}).get("buckets", [])
    top_ports = []
    for b in port_buckets:
        sig_buckets = b.get("top_sig", {}).get("buckets", [])
        top_ports.append(
            {
                "port": b["key"],
                "service": port_label(b["key"]),
                "count": b["doc_count"],
                "unique_src": b.get("unique_src", {}).get("value", 0),
                "severity": severity_label(round(b["min_sev"]["value"])),
                "top_signature": sig_buckets[0]["key"] if sig_buckets else "",
                "last_seen": b.get("last_seen", {}).get("value_as_string"),
            }
        )

    return jsonify(
        {
            "alerts_by_hour": alerts_by_hour,
            "events_by_hour": events_by_hour,
            "alerts_by_hour_prev": alerts_by_hour_prev,
            "severity_counts": severity_counts,
            "unique_src_ips": aggs.get("unique_src", {}).get("value", 0),
            "top_src": top_src,
            "top_sig": top_sig,
            "top_ports": top_ports,
            "events_per_sec": events_per_sec,
            "latest_alerts": latest,
        }
    )


# Nombres legibles para los puertos más comunes, solo para
# mostrar algo más útil que un número suelto en la tabla
KNOWN_PORTS = {
    20: "FTP (datos)", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP alterno", 8443: "HTTPS alterno",
    9001: "Tor", 27017: "MongoDB", 3333: "Crypto mining",
}


def port_label(port):
    return KNOWN_PORTS.get(port, "desconocido")


@app.route("/mapa")
@require_role("Admin")
def mapa_page():
    return render_template("mapa.html", active="mapa")


@app.route("/api/threat-map")
@require_role("Admin")
def api_threat_map():
    hours = int(request.args.get("hours", 24))

    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {
            "top_src": {
                "terms": {"field": resolve_agg_field("src_ip"), "size": 25},
                "aggs": {
                    "min_sev": {"min": {"field": "alert.severity"}},
                    "latest": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": "desc"}],
                            "_source": ["alert.signature", "@timestamp"],
                        }
                    },
                },
            },
        },
    }

    try:
        res = client.search(index=ALERT_INDEX, body=body)
    except Exception as e:
        return jsonify(
            {
                "destination": {"lat": DEST_LAT, "lon": DEST_LON, "label": DEST_LABEL},
                "sources": [],
                "error": str(e),
            }
        )

    buckets = res.get("aggregations", {}).get("top_src", {}).get("buckets", [])

    # Solo nos interesan IPs públicas (las privadas son tu propia red)
    public_buckets = [b for b in buckets if not is_private_ip(b["key"])][:15]
    ips = [b["key"] for b in public_buckets]
    geo = geolocate_ips(ips)

    sources = []
    for b in public_buckets:
        ip = b["key"]
        g = geo.get(ip)
        if not g:
            continue  # no se pudo geolocalizar esta vez, se omite

        latest_hits = b["latest"]["hits"]["hits"]
        signature = (
            latest_hits[0]["_source"].get("alert", {}).get("signature", "")
            if latest_hits
            else ""
        )

        sources.append(
            {
                "ip": ip,
                "country": g.get("country"),
                "country_code": g.get("countryCode"),
                "city": g.get("city"),
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "count": b["doc_count"],
                "severity": severity_label(round(b["min_sev"]["value"])),
                "signature": signature,
            }
        )

    return jsonify(
        {
            "destination": {"lat": DEST_LAT, "lon": DEST_LON, "label": DEST_LABEL},
            "sources": sources,
        }
    )
@app.route("/agentes")
@require_role("Admin")
def agentes_page():
    return render_template("agentes.html", active="agentes")


@app.route("/api/agents")
@require_role("Admin")
def api_agents():
    """Un 'agente' aquí es cualquier hostname distinto que haya
    mandado logs al índice agent-logs-*. No hay heartbeat aparte --
    el estado se infiere de qué tan reciente es su último log."""
    AGENT_INDEX = "agent-logs-*"

    body = {
        "size": 0,
        "aggs": {
            "by_host": {
                "terms": {"field": resolve_agg_field_on(AGENT_INDEX, "hostname"), "size": 50},
                "aggs": {
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "log_types": {"terms": {"field": resolve_agg_field_on(AGENT_INDEX, "log_type"), "size": 10}},
                },
            }
        },
    }

    try:
        res = client.search(index=AGENT_INDEX, body=body)
    except Exception:
        # El índice todavía no existe -- ningún agente ha mandado nada
        return jsonify({"agents": [], "total_events_1h": 0})

    now_ms = time.time() * 1000
    agents = []
    for b in res.get("aggregations", {}).get("by_host", {}).get("buckets", []):
        last_seen_ms = b["last_seen"]["value"]
        age_seconds = (now_ms - last_seen_ms) / 1000 if last_seen_ms else None

        if age_seconds is None:
            status = "offline"
        elif age_seconds < 120:
            status = "online"
        elif age_seconds < 900:
            status = "degradado"
        else:
            status = "offline"

        agents.append(
            {
                "hostname": b["key"],
                "event_count": b["doc_count"],
                "last_seen": b["last_seen"]["value_as_string"],
                "age_seconds": round(age_seconds) if age_seconds is not None else None,
                "log_types": [t["key"] for t in b.get("log_types", {}).get("buckets", [])],
                "status": status,
            }
        )

    try:
        total_1h = client.count(
            index=AGENT_INDEX,
            body={"query": {"range": {"@timestamp": {"gte": "now-1h"}}}},
        )["count"]
    except Exception:
        total_1h = 0

    return jsonify({"agents": agents, "total_events_1h": total_1h})


def resolve_agg_field_on(index, field):
    """Igual que resolve_agg_field, pero para un índice distinto a
    ALERT_INDEX (usado por agent-logs-*)."""
    cache_key = f"{index}:{field}"
    if cache_key in _field_cache:
        return _field_cache[cache_key]
    resolved = field
    try:
        mapping = client.indices.get_field_mapping(index=index, fields=field)
        for _, idx_data in mapping.items():
            m = idx_data.get("mappings", {}).get(field, {}).get("mapping", {})
            for _, fdef in m.items():
                if fdef.get("type") == "text" and "keyword" in fdef.get("fields", {}):
                    resolved = f"{field}.keyword"
                break
            break
    except Exception:
        pass
    _field_cache[cache_key] = resolved
    return resolved


@app.route("/api/alerts")
@require_role("Operador")
def api_alerts():
    q = request.args.get("q", "").strip()
    severity = request.args.get("severity", "todas")
    hours = int(request.args.get("hours", 24))
    page = max(1, int(request.args.get("page", 1)))
    size = min(100, int(request.args.get("size", 20)))

    must = [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]

    if q:
        must.append(
            {
                "multi_match": {
                    "query": q,
                    "fields": ["src_ip", "dest_ip", "alert.signature", "alert.category"],
                }
            }
        )

    sev_map = {"critica": 1, "media": 2}
    if severity == "baja":
        must.append({"range": {"alert.severity": {"gte": 3}}})
    elif severity in sev_map:
        must.append({"term": {"alert.severity": sev_map[severity]}})

    body = {
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": "desc"}],
        "from": (page - 1) * size,
        "size": size,
        "aggs": {"by_severity": {"terms": {"field": "alert.severity"}}},
    }

    try:
        res = client.search(index=ALERT_INDEX, body=body)
    except Exception as e:
        # Índice puede no existir todavía si no ha habido alertas hoy
        return jsonify(
            {
                "alerts": [],
                "total": 0,
                "severity_counts": {"critica": 0, "media": 0, "baja": 0},
                "page": page,
                "size": size,
                "error": str(e),
            }
        )

    hits = res["hits"]["hits"]
    total = res["hits"]["total"]["value"]

    ids = [h["_id"] for h in hits]
    annotations = get_annotations(ids)

    alerts = []
    for h in hits:
        src = h["_source"]
        alert = src.get("alert", {})
        sev = alert.get("severity", 3)
        ann = annotations.get(h["_id"], {})
        alerts.append(
            {
                "id": h["_id"],
                "timestamp": src.get("@timestamp"),
                "src_ip": src.get("src_ip"),
                "dest_ip": src.get("dest_ip"),
                "src_port": src.get("src_port"),
                "dest_port": src.get("dest_port"),
                "proto": src.get("proto"),
                "signature": alert.get("signature", ""),
                "category": alert.get("category") or "sin categoría",
                "severity": severity_label(sev),
                "status": ann.get("status", "abierta"),
            }
        )

    sev_counts = {"critica": 0, "media": 0, "baja": 0}
    for b in res.get("aggregations", {}).get("by_severity", {}).get("buckets", []):
        sev_counts[severity_label(b["key"])] += b["doc_count"]

    return jsonify(
        {
            "alerts": alerts,
            "total": total,
            "severity_counts": sev_counts,
            "page": page,
            "size": size,
        }
    )


@app.route("/api/alerts/<alert_id>/status", methods=["POST"])
@require_role("Operador")
def update_status(alert_id):
    data = request.get_json(force=True, silent=True) or {}
    status = data.get("status")
    if status not in ("abierta", "revision", "cerrada"):
        return jsonify({"error": "estado inválido"}), 400

    client.index(
        index=ANNOTATIONS_INDEX,
        id=alert_id,
        body={
            "alert_id": alert_id,
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        refresh=True,
    )
    return jsonify({"ok": True, "status": status})


if __name__ == "__main__":
    ensure_annotations_index()
    app.run(host="0.0.0.0", port=5000, debug=True)