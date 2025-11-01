# src/analyzer.py
import os
import re
import socket
import ssl
import requests
import datetime
import sqlite3
from urllib.parse import urlparse
from difflib import SequenceMatcher
import whois
import base64
import json

# ------------ Config / brand list -------------
BRAND_LIST = ["paypal", "google", "facebook", "amazon", "microsoft", "apple", "bank"]
OPENPHISH_FEED_PATH_DEFAULT = "src/openphish_feed.txt"
VT_BASE = "https://www.virustotal.com/api/v3"

# ------------ Core analyze function -------------
def analyze_url(url, config=None):
    if config is None:
        config = {}
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.lower()
    if ":" in domain:
        domain = domain.split(":")[0]

    results = {}
    # basic heuristics
    results.update(heuristic_checks(url, domain))
    # whois
    results["whois"] = whois_check(domain)
    # ssl
    results["ssl"] = ssl_check(domain)
    # redirects
    results["redirects"] = redirect_check(url)
    # content
    results["content"] = content_check(url)
    # brand similarity
    results["brand_similarity"] = brand_similarity(domain)
    # OpenPhish feed (local)
    if config.get("USE_OPENPHISH", True):
        feed_path = config.get("OPENPHISH_FEED", OPENPHISH_FEED_PATH_DEFAULT)
        results["openphish"] = check_openphish(domain, feed_path)
    else:
        results["openphish"] = "skipped"
    # URLhaus
    if config.get("USE_URLHAUS", True):
        results["urlhaus"] = check_urlhaus(url)
    else:
        results["urlhaus"] = "skipped"
    # VirusTotal
    if config.get("USE_VIRUSTOTAL", False):
        vt_key = config.get("VIRUSTOTAL_KEY")
        results["virustotal"] = check_virustotal(url, vt_key)
    else:
        results["virustotal"] = "skipped"
    # Safe Browsing
    if config.get("USE_SAFE_BROWSING", False):
        sb_key = config.get("SAFE_BROWSING_KEY")
        results["safe_browsing"] = check_safe_browsing(url, sb_key)
    else:
        results["safe_browsing"] = "skipped"

    results["risk"] = compute_score(results)
    try:
        save_history(url, results)
    except Exception:
        pass
    return results

# ------------ Checks -------------
def heuristic_checks(url, domain):
    out = {}
    out["url_length"] = len(url)
    # num_subdomains counting everything except TLD and SLD approx
    out["num_subdomains"] = max(0, domain.count(".") - 1)
    out["has_ip"] = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain))
    out["contains_digits"] = bool(re.search(r"\d", domain))
    out["special_chars"] = bool(re.search(r"[^a-z0-9\.-]", domain))
    out["has_at_symbol"] = "@" in url
    out["has_double_slash_path"] = urlparse(url).path.count("//") > 0
    return out

def whois_check(domain):
    import datetime
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            # remove timezone para evitar erro offset-naive/aware
            creation_naive = creation.replace(tzinfo=None) if hasattr(creation, "tzinfo") else creation
            now_naive = datetime.datetime.now()
            age_days = (now_naive - creation_naive).days
            creation_str = creation_naive.strftime("%Y-%m-%d %H:%M:%S")
        else:
            age_days = None
            creation_str = None
        return {"status": "ok", "domain": domain, "creation_date": creation_str, "age_days": age_days}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def ssl_check(domain):
    if not domain:
        return {"status": "error", "message": "domain empty"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "status": "valid",
                    "not_after": cert.get("notAfter"),
                    "issuer": cert.get("issuer"),
                    "subject": cert.get("subject")
                }
    except (ssl.SSLError, socket.timeout) as e:
        return {"status": "invalid", "message": f"SSL timeout/erro: {e}"}
    except ConnectionResetError:
        return {"status": "invalid", "message": "Conexão encerrada pelo host remoto"}
    except Exception as e:
        return {"status": "invalid", "message": str(e)}



def redirect_check(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=6, headers={"User-Agent": "phish-detector/1.0"})
        chain = [resp.url for resp in r.history] + [r.url]
        return {"status": "ok", "final_url": r.url, "status_code": r.status_code, "redirect_chain": chain}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": f"Falha na requisição: {e}"}
    except ConnectionResetError:
        return {"status": "error", "message": "Conexão encerrada pelo host remoto"}

def content_check(url):
    try:
        r = requests.get(url, timeout=6, headers={"User-Agent": "phish-detector/1.0"})
        text = r.text.lower()
        has_login_form = ("type=\"password\"" in text) or ("input name=\"password\"" in text)
        has_forms = "<form" in text
        logo_like = any(k in text for k in ["paypal", "login", "bank", "account", "apple", "google"])
        return {
            "status": "ok",
            "status_code": r.status_code,
            "has_forms": has_forms,
            "has_login_form": has_login_form,
            "logo_like": logo_like
        }
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": f"Falha ao obter conteúdo: {e}"}
    except ConnectionResetError:
        return {"status": "error", "message": "Conexão encerrada pelo host remoto"}


def brand_similarity(domain):
    best = {"brand": None, "ratio": 0.0}
    d = domain.split(".")[0]
    for b in BRAND_LIST:
        r = SequenceMatcher(None, d, b).ratio()
        if r > best["ratio"]:
            best = {"brand": b, "ratio": r}
    return best

# ------------ External feeds / APIs -------------
def check_openphish(domain_or_url, feed_path):
    """Retorna friendly output: found True/False e a linha correspondente se encontrada."""
    if not os.path.exists(feed_path):
        return {"status": "error", "message": f"feed not found at {feed_path}"}
    try:
        with open(feed_path, "r", encoding="utf-8") as f:
            data = f.read().splitlines()
        for line in data:
            if domain_or_url in line or line in domain_or_url:
                return {"status": "found", "source": "OpenPhish", "line": line}
        return {"status": "not_found", "source": "OpenPhish"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_urlhaus(url):
    """
    Verifica se a URL aparece no feed público do URLhaus.
    Não requer API key nem autenticação.
    """
    try:
        feed_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        resp = requests.get(feed_url, headers={"User-Agent": "phish-detector/1.0"}, timeout=10)
        if resp.status_code != 200:
            return {"status": "error", "message": f"Erro HTTP {resp.status_code} ao baixar feed."}
        
        # o feed é CSV, cada linha contém a URL (geralmente na 2ª coluna)
        lines = resp.text.splitlines()
        matches = [line for line in lines if url.replace("https://", "").replace("http://", "") in line]
        if matches:
            return {"status": "found", "source": "URLhaus", "matches": matches[:3]}  # mostra até 3 ocorrências
        else:
            return {"status": "not_found", "source": "URLhaus"}
    except Exception as e:
        return {"status": "error", "message": str(e)}



def vt_url_id_from_url(url):
    b = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    return b

def check_virustotal(url, api_key):
    """Consulta VirusTotal e resume last_analysis_stats em um dict legível."""
    if not api_key:
        return {"status": "skipped", "message": "no api key provided"}
    try:
        headers = {"x-apikey": api_key}
        url_id = vt_url_id_from_url(url)
        r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=10)
        if r.status_code == 200:
            j = r.json()
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            # transformar em total de detecções
            positives = sum(v for v in stats.values()) if isinstance(stats, dict) else 0
            return {"status": "found", "source": "VirusTotal", "positives": positives, "last_analysis_stats": stats}
        else:
            # 404 ou outro
            return {"status": "not_found", "source": "VirusTotal", "status_code": r.status_code, "text": r.text}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_safe_browsing(url, api_key):
    """Consulta o Google Safe Browsing e detalha o tipo de ameaça detectada."""
    if not api_key:
        return {"status": "skipped", "message": "no api key provided"}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        body = {
            "client": {"clientId": "phish-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(endpoint, json=body, timeout=10)
        if r.status_code == 200:
            j = r.json()
            matches = j.get("matches", [])
            if matches:
                threats = []
                for m in matches:
                    threats.append({
                        "tipo_ameaça": m.get("threatType"),
                        "plataforma": m.get("platformType"),
                        "entrada": m.get("threat", {}).get("url"),
                        "cache_duracao": m.get("cacheDuration")
                    })
                return {
                    "status": "found",
                    "source": "Google Safe Browsing",
                    "quantidade": len(threats),
                    "detalhes": threats
                }
            else:
                return {"status": "not_found", "source": "Google Safe Browsing"}
        else:
            return {"status": "error", "message": f"HTTP {r.status_code}: {r.text}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

    
# ------------ Scoring & history -------------
def compute_score(results):
    score = 0
    reasons = []
    if results.get("url_length", 0) > 100:
        score += 1; reasons.append("URL muito longa")
    if results.get("num_subdomains", 0) > 3:
        score += 1; reasons.append("muitos subdomínios")
    if results.get("has_ip"):
        score += 1; reasons.append("uso de IP")
    if results.get("contains_digits"):
        score += 1; reasons.append("números no domínio")
    who = results.get("whois", {})
    age = who.get("age_days") if isinstance(who, dict) else None
    if isinstance(age, int) and age < 90:
        score += 1; reasons.append("domínio muito novo")
    op = results.get("openphish", {})
    if isinstance(op, dict) and op.get("found"):
        score += 3; reasons.append("encontrado no OpenPhish")
    uh = results.get("urlhaus", {})
    if isinstance(uh, dict) and uh.get("query_status") == "ok":
        score += 3; reasons.append("encontrado no URLhaus")
    vt = results.get("virustotal", {})
    if isinstance(vt, dict) and vt.get("last_analysis_stats"):
        # count engines that flagged (heuristic)
        stats = vt["last_analysis_stats"]
        positives = sum(stats.get(k, 0) for k in stats if k in stats)
        # if any engine flagged, increase score
        if positives > 0:
            score += 3; reasons.append("VirusTotal detectou sinal")
    sb = results.get("safe_browsing", {})
    if isinstance(sb, dict) and sb.get("matches"):
        score += 3; reasons.append("Google Safe Browsing")
    sim = results.get("brand_similarity", {})
    if sim and sim.get("ratio", 0) > 0.7:
        score += 1; reasons.append(f"similaridade de marca: {sim.get('brand')}")
    return {"score": score, "reasons": reasons}

def summarize_results(results):
    r = results.get("risk", {})
    score = r.get("score", 0)
    veredito = "🚨 Suspeito" if score >= 3 else "⚠️ Potencial" if score >= 1 else "✅ Provavelmente seguro"
    return {"score": score, "score_text": f"{score}", "veredito": veredito}

def save_history(url, results, db_path="phish_history.db"):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS history (
                 id INTEGER PRIMARY KEY,
                 url TEXT,
                 timestamp DATETIME,
                 score INTEGER,
                 raw TEXT)""")
    ts = datetime.datetime.now().isoformat()
    score = results.get("risk", {}).get("score", 0)
    raw = json.dumps(results)
    c.execute("INSERT INTO history (url, timestamp, score, raw) VALUES (?, ?, ?, ?)",
              (url, ts, score, raw))
    conn.commit()
    conn.close()
