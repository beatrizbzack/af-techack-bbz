# src/analyzer.py
import re, socket, ssl, requests, datetime
import whois
from urllib.parse import urlparse

def analyze_url(url):
    results = {}
    parsed = urlparse(url)
    domain = parsed.netloc

    # --- Heurísticas simples ---
    results["Comprimento da URL"] = len(url)
    results["Número de subdomínios"] = domain.count(".")
    results["Uso de números no domínio"] = bool(re.search(r"\d", domain))
    results["Caracteres especiais"] = bool(re.search(r"[^a-zA-Z0-9.-]", domain))

    # --- WHOIS ---
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age_days = (datetime.datetime.now() - creation).days if creation else None
        results["Idade do domínio (dias)"] = age_days or "Desconhecida"
    except Exception as e:
        results["WHOIS"] = f"Erro: {e}"

    # --- SSL Check ---
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                results["Emissor SSL"] = dict(cert.get("issuer")[0]).get("organizationName", "Desconhecido")
                results["Validade SSL até"] = cert.get("notAfter", "N/A")
    except Exception as e:
        results["SSL"] = f"Erro: {e}"

    # --- PhishTank (placeholder) ---
    results["PhishTank"] = "⚠️ Não verificado (API pendente)"

    # --- Classificação simples ---
    suspicious_score = 0
    if results["Número de subdomínios"] > 3: suspicious_score += 1
    if results["Uso de números no domínio"]: suspicious_score += 1
    if results["Caracteres especiais"]: suspicious_score += 1
    if isinstance(results.get("Idade do domínio (dias)"), int) and results["Idade do domínio (dias)"] < 90:
        suspicious_score += 1

    results["Score de risco"] = f"{suspicious_score}/4"
    results["Veredito"] = "🚨 Suspeito" if suspicious_score >= 2 else "✅ Provavelmente seguro"
    return results
