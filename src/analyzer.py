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

    # dynamic DNS
    results["dynamic_dns"] = detect_dynamic_dns(domain)
    # Levenshtein brand similarity (mais robusto)
    results["brand_similarity_lev"] = brand_similarity_lev(domain)
    # SSL domain match: use cert subject + SANs if available (we returned cert subject earlier)
    cert = results.get("ssl", {})
    # only attempt if ssl returned cert info
    try:
        subj = cert.get("subject")
        san = None
        # some certs might include subjectAltName in different key. We can't always get SAN from getpeercert without retrieving it differently,
        # but we try to use what ssl_check returned (subject). Use ssl_matches_domain best-effort:
        results["ssl_matches_domain"] = ssl_matches_domain(subj, cert.get("subjectAltName"), domain)
    except Exception:
        results["ssl_matches_domain"] = False

    # suspicious redirects
    red = results.get("redirects", {})
    if isinstance(red, dict) and red.get("redirect_chain"):
        results["redirects_suspicious"] = detect_suspicious_redirects(red.get("redirect_chain"), domain)
    else:
        results["redirects_suspicious"] = {"suspicious": False, "reasons": [], "chain_domains": []}

    # sensitive content checks: only if content fetch succeeded
    cont = results.get("content", {})
    if isinstance(cont, dict) and cont.get("status") == "ok":
        # we have r.text in content_check? If not, modify content_check to return a 'text' snippet.
        # To avoid changing working code too much, fetch again lightly (but short timeout)
        try:
            r = requests.get(url, timeout=6, headers={"User-Agent": "phish-detector/1.0"})
            results["content_sensitive"] = content_sensitive_checks(r.text.lower())
        except Exception:
            results["content_sensitive"] = {"has_sensitive": False, "sensitive_terms": []}
    else:
        results["content_sensitive"] = {"has_sensitive": False, "sensitive_terms": []}


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

# Lista curta de provedores de DNS dinâmico comuns
DYN_DNS_PROVIDERS = [
    "no-ip.org", "noip.com", "dyndns.org", "dynu.net", "duckdns.org", "freedns.afraid.org",
    "changeip.com", "serveftp.com", "hopto.org"
]

def detect_dynamic_dns(domain):
    """
    Detecta se o domínio pertence a providers DNS dinâmico (string matching).
    Retorna dict {"dynamic": True/False, "provider": name or None}
    """
    d = domain.lower()
    for p in DYN_DNS_PROVIDERS:
        if p in d:
            return {"dynamic": True, "provider": p}
    return {"dynamic": False, "provider": None}


def levenshtein(a, b):
    """Implementação simples de distância de Levenshtein (retorna int)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    # matrix
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * lb
        for j, cb in enumerate(b, start=1):
            add = prev[j] + 1
            delete = cur[j-1] + 1
            change = prev[j-1] + (0 if ca == cb else 1)
            cur[j] = min(add, delete, change)
        prev = cur
    return prev[-1]

def brand_similarity_lev(domain, brands=BRAND_LIST):
    """
    Usa Levenshtein normalizado para medir similaridade ao invés de SequenceMatcher.
    Retorna {'brand': best_brand, 'ratio': float (0..1), 'distance': int}
    """
    label = domain.split(".")[0]
    best = {"brand": None, "ratio": 0.0, "distance": None}
    for b in brands:
        dist = levenshtein(label, b)
        # normalizar: 1 - dist / max_len
        maxl = max(len(label), len(b))
        ratio = 1 - (dist / maxl) if maxl > 0 else 0
        if ratio > best["ratio"]:
            best = {"brand": b, "ratio": ratio, "distance": dist}
    return best

def ssl_matches_domain(cert_subject, cert_subject_alt_names, domain):
    """
    Verifica se o CN or SANs do certificado correspondem ao domínio (inclui wildcard match).
    cert_subject: data from cert.get('subject') (list of tuples)
    cert_subject_alt_names: tuple list from cert.get('subjectAltName') if present
    """
    # extract CN
    cn = None
    try:
        if cert_subject:
            # subject is list of tuples; find commonName
            for part in cert_subject:
                for entry in part:
                    if entry and isinstance(entry, tuple) and entry[0].lower() == 'commonname':
                        cn = entry[1]
                        break
                if cn:
                    break
    except Exception:
        cn = None

    # collect SANs
    sans = []
    try:
        if cert_subject_alt_names:
            # subjectAltName is like (('DNS', 'example.com'), ...)
            for t in cert_subject_alt_names:
                if isinstance(t, tuple) and t[0].lower() == 'dns':
                    sans.append(t[1])
    except Exception:
        sans = []

    def match_name(name, domain):
        # handle wildcard *.example.com
        if not name:
            return False
        name = name.lower()
        d = domain.lower()
        if name.startswith("*."):
            base = name[2:]
            return d == base or d.endswith("." + base)
        return d == name

    # exact match in CN or SANs
    if cn and match_name(cn, domain):
        return True
    for s in sans:
        if match_name(s, domain):
            return True
    return False

def detect_suspicious_redirects(redirect_chain, original_domain):
    """
    Analisa redirect_chain (lista de URLs) e sinaliza se houve mudança de domínio ou uso de IP.
    Retorna {'suspicious': bool, 'reasons': [..], 'chain_domains': [...]}
    """
    try:
        domains = []
        for u in redirect_chain:
            p = urlparse(u)
            d = p.netloc.split(':')[0].lower()
            domains.append(d)
        reasons = []
        # se mais de 3 hops -> suspeito
        if len(domains) > 4:
            reasons.append("muitos redirects")
        # se final domain != original domain
        if domains and original_domain not in domains[-1]:
            reasons.append("domínio final diferente do original")
        # se qualquer domínio no chain for um IP
        for d in domains:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
                reasons.append("redirect para IP")
                break
        return {"suspicious": len(reasons) > 0, "reasons": reasons, "chain_domains": domains}
    except Exception as e:
        return {"suspicious": False, "reasons": ["error:"+str(e)], "chain_domains": []}

def content_sensitive_checks(text):
    """
    Recebe o HTML/text da página (lowercase) e retorna flags sobre inputs sensíveis.
    """
    sensitive_terms = ["password", "passwd", "senha", "ssn", "social-security", "creditcard", "cardnumber", "cvv", "cvv2", "credit card", "card number", "cpf", "cartao", "email"]
    found = []
    for t in sensitive_terms:
        if t in text:
            found.append(t)
    return {"sensitive_terms": list(set(found)), "has_sensitive": len(found) > 0}


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
    # existing heuristics
    if results.get("url_length", 0) > 100:
        score += 1; reasons.append("URL muito longa")
    if results.get("num_subdomains", 0) > 3:
        score += 1; reasons.append("muitos subdomínios")
    if results.get("has_ip"):
        score += 1; reasons.append("uso de IP")
    if results.get("contains_digits"):
        score += 1; reasons.append("números no domínio")
    # whois age
    who = results.get("whois", {})
    age = who.get("age_days") if isinstance(who, dict) else None
    if isinstance(age, int) and age < 90:
        score += 1; reasons.append("domínio muito novo")
    # new: dynamic DNS
    dd = results.get("dynamic_dns", {})
    if isinstance(dd, dict) and dd.get("dynamic"):
        score += 1; reasons.append(f"provedor DNS dinâmico ({dd.get('provider')})")
    # new: ssl domain mismatch
    if results.get("ssl_matches_domain") is False:
        # penalize if ssl exists but doesn't match domain
        sslinfo = results.get("ssl", {})
        if sslinfo and sslinfo.get("status") in ["valid","invalid"]:
            score += 1; reasons.append("certificado SSL não corresponde ao domínio")
    # new: suspicious redirects
    rd = results.get("redirects_suspicious", {})
    if isinstance(rd, dict) and rd.get("suspicious"):
        score += 1; reasons.append("redirects suspeitos: " + ", ".join(rd.get("reasons", [])))
    # openphish
    op = results.get("openphish", {})
    if isinstance(op, dict) and op.get("status") == "found":
        score += 3; reasons.append("encontrado no OpenPhish")
    # urlhaus
    uh = results.get("urlhaus", {})
    if isinstance(uh, dict) and uh.get("status") == "found":
        score += 3; reasons.append("encontrado no URLhaus")
    # virustotal
    vt = results.get("virustotal", {})
    if isinstance(vt, dict) and vt.get("status") == "found":
        positives = vt.get("positives", 0)
        if positives > 0:
            score += 3; reasons.append("VirusTotal detectou sinal")
    # Safe Browsing
    sb = results.get("safe_browsing", {})
    if isinstance(sb, dict) and sb.get("status") == "found":
        score += 3; reasons.append("Google Safe Browsing")
    # brand similarity (Levenshtein)
    sim = results.get("brand_similarity_lev", {})
    if isinstance(sim, dict) and sim.get("ratio", 0) > 0.75:
        score += 1; reasons.append(f"similaridade de marca: {sim.get('brand')} ({sim.get('ratio'):.2f})")
    # content sensitive
    cs = results.get("content_sensitive", {})
    if isinstance(cs, dict) and cs.get("has_sensitive"):
        score += 1; reasons.append("conteúdo solicita informações sensíveis")
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
