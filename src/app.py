# src/app.py
from dotenv import load_dotenv
load_dotenv() 
import os
import streamlit as st
from analyzer import analyze_url, summarize_results
import pandas as pd

st.set_page_config(page_title="Detector de Phishing", page_icon="🎣")
st.title("🎣 Detector de Phishing — MVP")
st.subheader("Avaliação de Tecnologias Hacker — Beatriz Borges Zackiewicz")

st.markdown("""
Insira uma URL para análise. Habilite as integrações desejadas (integração uma-a-uma se preferir).
""")

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_KEY")
OPENPHISH_FEED = os.getenv("OPENPHISH_FEED", "src/openphish_feed.txt")

def make_tag(text, color):
    return f"<span style='background-color:{color}; color:white; padding:2px 8px; border-radius:10px; font-size:0.8em;'>{text}</span>"

tags_html = " ".join([
    make_tag("Safe Browsing ✅" if SAFE_BROWSING_KEY else "Safe Browsing ⚠️", "#2c7a7b" if SAFE_BROWSING_KEY else "#b7791f"),
    make_tag("VirusTotal ✅" if VIRUSTOTAL_KEY else "VirusTotal ⚠️", "#2c7a7b" if VIRUSTOTAL_KEY else "#b7791f"),
    make_tag("OpenPhish disponível" if os.path.exists(OPENPHISH_FEED) else "OpenPhish ausente", "#3182ce" if os.path.exists(OPENPHISH_FEED) else "#b7791f"),
])
st.markdown(f"<div style='text-align:center; margin-bottom:15px;'>{tags_html}</div>", unsafe_allow_html=True)

st.write("---")

# --- ENTRADA ---
url = st.text_input("Digite a URL para analisar:", placeholder="https://exemplo.com")

st.markdown("### 🔍 Escolha as verificações a executar:")
col1, col2, col3, col4 = st.columns(4)
with col1:
    use_openphish = st.checkbox("OpenPhish", True)
with col2:
    use_urlhaus = st.checkbox("URLhaus", True)
with col3:
    use_virustotal = st.checkbox("VirusTotal", False)
with col4:
    use_safebrowsing = st.checkbox("Google Safe Browsing", True)

run = st.button("🚀 Analisar URL")

# --- EXECUÇÃO ---
if run:
    if not url:
        st.warning("Por favor insira uma URL válida.")
    else:
        st.info("Executando verificações... (pode levar alguns segundos)")
        config = {
            "USE_OPENPHISH": use_openphish,
            "USE_URLHAUS": use_urlhaus,
            "USE_VIRUSTOTAL": use_virustotal,
            "USE_SAFE_BROWSING": use_safebrowsing,
            "OPENPHISH_FEED": OPENPHISH_FEED,
            "VIRUSTOTAL_KEY": VIRUSTOTAL_KEY,
            "SAFE_BROWSING_KEY": SAFE_BROWSING_KEY
        }

        results = analyze_url(url, config=config)
        verdict = summarize_results(results)

        # --- RESUMO ---
        st.markdown("## 🧩 Resumo da Análise")
        score = verdict["score"]
        ver_text = verdict["veredito"]

        if score >= 3:
            st.error(f"**{ver_text}** — Score: {score}")
        elif score >= 1:
            st.warning(f"**{ver_text}** — Score: {score}")
        else:
            st.success(f"**{ver_text}** — Score: {score}")

        reasons = results.get("risk", {}).get("reasons", [])
        if reasons:
            st.markdown("**Principais sinais detectados:**")
            for r in reasons:
                st.markdown(f"- {r}")

        # --- MÉTRICAS CHAVE ---
        m1, m2, m3 = st.columns(3)
        m1.metric("Tamanho da URL", results.get("url_length", "—"))
        who_age = results.get("whois", {}).get("age_days", "—")
        m2.metric("Idade do domínio (dias)", who_age if who_age is not None else "—")
        ssl_status = results.get("ssl", {}).get("status", results.get("ssl", {}).get("valid", "—"))
        m3.metric("Status SSL", ssl_status)

        st.write("---")

        # --- DETALHES ---
        st.markdown("### 🔎 Detalhes das verificações")

        # Heurísticas
        with st.expander("Heurísticas (URL) — interpretação detalhada"):
            # Explicação de cada heurística
            heur_explanations = {
                "url_length": "Comprimento total da URL. URLs muito longas podem esconder parâmetros suspeitos.",
                "num_subdomains": "Número de subdomínios. Muitos subdomínios (ex: login.secure.paypal.com.fake.site) indicam falsificação.",
                "has_ip": "Uso de endereço IP em vez de nome de domínio. Sites legítimos raramente usam IP diretamente.",
                "contains_digits": "Presença de números no domínio. Exemplos como 'paypa1.com' ou 'g00gle.com' imitam marcas.",
                "special_chars": "Caracteres especiais no domínio. Podem ser usados para enganar visualmente (ex: 'amazón.com').",
                "has_at_symbol": "Símbolo '@' encontrado. Pode redirecionar o navegador para outro domínio.",
                "has_double_slash_path": "Múltiplos '//' após o domínio. Podem ser usados para enganar o usuário sobre a verdadeira URL."
            }

            # Captura os valores retornados pelo analisador
            heur_values = {
                key: results.get(key, "—")
                for key in heur_explanations.keys()
            }

            # Monta tabela com interpretação
            rows = []
            for key, desc in heur_explanations.items():
                val = heur_values.get(key, "—")
                emoji = "⚠️" if val not in [False, "—", 0, None] else "✅"
                # texto adicional conforme tipo
                if key == "url_length":
                    risk_text = "Longa" if isinstance(val, int) and val > 100 else "Normal"
                elif key == "num_subdomains":
                    risk_text = "Alto" if isinstance(val, int) and val > 3 else "Normal"
                else:
                    risk_text = "Risco" if val not in [False, "—", 0, None] else "OK"

                rows.append([
                    key,
                    str(val),
                    f"{emoji} {risk_text}",
                    desc
                ])

            df_heur = pd.DataFrame(rows, columns=["Heurística", "Valor encontrado", "Indicação", "Interpretação"])
            st.table(df_heur)



        # WHOIS
        with st.expander("Informações WHOIS"):
            who = results.get("whois", {})
            if who.get("status") == "error":
                st.error(f"Erro no WHOIS: {who.get('message')}")
            else:
                st.write(f"- Domínio: {who.get('domain')}")
                st.write(f"- Criado em: {who.get('creation_date')}")
                st.write(f"- Idade (dias): {who.get('age_days')}")

        # SSL
        with st.expander("Certificado SSL"):
            sslv = results.get("ssl", {})
            if sslv.get("status") == "valid":
                st.success(f"Certificado válido até: {sslv.get('not_after')}")
            elif sslv.get("status") == "invalid":
                st.error(f"SSL inválido / erro: {sslv.get('message')}")
            else:
                st.write(sslv)

        # Feeds e APIs
        with st.expander("Feeds e APIs"):
            def show_source(name, data):
                st.subheader(name)
                if isinstance(data, dict):
                    status = data.get("status")
                    if status == "found":
                        st.error(f"{name}: encontrado!")
                    elif status == "not_found":
                        st.success(f"{name}: não encontrado.")
                    elif status == "skipped":
                        st.info(f"{name}: verificação não realizada (sem chave).")
                    elif status == "error":
                        st.warning(f"{name}: erro — {data.get('message')}")
                    else:
                        st.write(data)
                else:
                    st.write(data)

            show_source("OpenPhish", results.get("openphish"))
            show_source("URLhaus", results.get("urlhaus"))
            show_source("VirusTotal", results.get("virustotal"))
            show_source("Google Safe Browsing", results.get("safe_browsing"))

        with st.expander("Dados brutos (JSON)"):
            st.json(results)

        # Exportar CSV
        flat = {
            "url": url,
            "veredito": verdict["veredito"],
            "score": verdict["score_text"],
            "reasons": "; ".join(results.get("risk", {}).get("reasons", [])),
            "whois_age_days": results.get("whois", {}).get("age_days"),
            "ssl_status": results.get("ssl", {}).get("status")
        }
        csv = pd.DataFrame([flat]).to_csv(index=False).encode("utf-8")
        st.download_button("📥 Baixar relatório (CSV)", csv, "phish_report.csv", "text/csv")