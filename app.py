# src/app.py
import streamlit as st
from analyzer import analyze_url

st.set_page_config(page_title="AF TecHack - Detector de Phishing", page_icon="🎣")

st.title("🎣 Ferramenta de Detecção de Phishing")
st.subheader("Por: Beatriz Borges Zackiewicz")
st.write("Insira uma URL para verificar possíveis sinais de phishing:")

url = st.text_input("URL:", placeholder="https://exemplo.com")
if st.button("Analisar"):
    if url:
        results = analyze_url(url)
        st.subheader("Resultados da análise")
        for key, value in results.items():
            st.write(f"**{key}:** {value}")
    else:
        st.warning("Por favor, insira uma URL válida.")
