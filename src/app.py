# src/app.py
import os
import streamlit as st
from analyzer import analyze_url, summarize_results

st.set_page_config(page_title="Detector de Phishing", page_icon="🎣")
st.title("🎣 Detector de Phishing — MVP")
st.subheader("Avaliação de Tecnologias Hacker — Beatriz Borges Zackiewicz")

st.markdown("""
Insira uma URL para análise. Habilite as integrações desejadas (integração uma-a-uma se preferir).
""")

url = st.text_input("URL para analisar", placeholder="https://exemplo.com")
col1, col2 = st.columns(2)
with col1:
    use_openphish = st.checkbox("Usar OpenPhish (feed local)", value=True)
    use_urlhaus = st.checkbox("Usar URLhaus (abuse.ch)", value=True)
    use_virustotal = st.checkbox("Usar VirusTotal API", value=False)
with col2:
    use_safebrowsing = st.checkbox("Usar Google Safe Browsing API", value=False)
    show_raw = st.checkbox("Mostrar resultados brutos", value=False)

if st.button("Analisar"):
    if not url:
        st.warning("Insira uma URL válida.")
    else:
        config = {
            "USE_OPENPHISH": use_openphish,
            "USE_URLHAUS": use_urlhaus,
            "USE_VIRUSTOTAL": use_virustotal,
            "USE_SAFE_BROWSING": use_safebrowsing,
            "OPENPHISH_FEED": os.getenv("OPENPHISH_FEED", "src/openphish_feed.txt"),
            "VIRUSTOTAL_KEY": os.getenv("VIRUSTOTAL_KEY"),
            "SAFE_BROWSING_KEY": os.getenv("SAFE_BROWSING_KEY")
        }
        st.info("Executando verificações... (pode levar alguns segundos)")
        results = analyze_url(url, config=config)
        st.subheader("Resumo")
        verdict = summarize_results(results)
        st.markdown(f"**Veredito:** {verdict['veredito']}")
        st.markdown(f"**Score:** {verdict['score_text']}")
        st.subheader("Detalhes")
        for k, v in results.items():
            st.write(f"**{k}**: {v}")
        if show_raw:
            st.subheader("Raw (dict)")
            st.write(results)
