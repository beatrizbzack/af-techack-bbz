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


        # Top metrics (visuais semelhantes ao Score)
        col_a, col_b, col_c = st.columns([1,1,1])
        col_a.metric("Tamanho da URL", f"{results.get('url_length', '—')}")
        who_age = results.get("whois", {}).get("age_days")
        col_b.metric("Idade do domínio (dias)", who_age if who_age is not None else "—")
        ssl_status = results.get("ssl", {}).get("status", results.get("ssl", {}).get("valid", "—"))
        col_c.metric("Status SSL", ssl_status)

        st.write("")  # espaçamento

        # Cards para checks — 2 colunas responsivas (ajusta conforme largura)
        card_cols = st.columns(2)

        def render_card(col, title, text, tone="info"):
            """
            tone: one of 'success','warning','error','info'
            """
            colors = {
                "success": "#1f7a3a",
                "warning": "#b7791f",
                "error": "#8b2d2d",
                "info": "#234e6b"
            }
            bg = colors.get(tone, "#234e6b")
            html = f"""
            <div style="
                background:{bg};
                padding:12px 16px;
                border-radius:10px;
                color: #ffffff;
                box-shadow: rgba(0,0,0,0.15) 0px 4px 8px;
                margin-bottom:8px;
            ">
            <div style="font-size:14px; opacity:0.95; margin-bottom:6px;"><strong>{title}</strong></div>
            <div style="font-size:13px; opacity:0.95;">{text}</div>
            </div>
            """
            col.markdown(html, unsafe_allow_html=True)

        # Primeiro par de cartões
        c1, c2 = card_cols
        # DNS dinâmico
        dyn = results.get("dynamic_dns", {})
        if dyn.get("dynamic"):
            render_card(c1, "DNS dinâmico detectado", f"Provedor: {dyn.get('provider')}. Domínios dinâmicos são frequentemente usados para evasão.", "warning")
        else:
            render_card(c1, "DNS dinâmico", "Não detectado.", "info")

        # Similaridade Levenshtein
        sim = results.get("brand_similarity_lev", {})
        ratio = sim.get("ratio", 0.0)
        brand = sim.get("brand") or "—"
        dist = sim.get("distance") if sim.get("distance") is not None else "—"
        if ratio > 0.75:
            render_card(c2, "Alta similaridade com marca", f"Marca: {brand} (ratio={ratio:.2f}, dist={dist}). Possível domínio clonador.", "error")
        elif ratio > 0.45:
            render_card(c2, "Similaridade moderada", f"Marca mais parecida: {brand} (ratio={ratio:.2f}).", "warning")
        else:
            render_card(c2, "Similaridade com marca", f"Sem similaridade de alto risco (melhor match: {brand}, ratio={ratio:.2f}).", "success")

        # Segundo par de cartões
        c3, c4 = st.columns(2)
        # SSL match
        ssl_match = results.get("ssl_matches_domain", None)
        if ssl_match is True:
            render_card(c3, "Certificado SSL", "Certificado corresponde ao domínio (CN/SAN).", "success")
        elif ssl_match is False:
            render_card(c3, "Certificado SSL", "NÃO corresponde ao domínio — comportamento suspeito.", "error")
        else:
            render_card(c3, "Certificado SSL", "Verificação não disponível.", "info")

        # Redirects
        rds = results.get("redirects_suspicious", {})
        if rds.get("suspicious"):
            reasons = ", ".join(rds.get("reasons", [])) or "suspeito"
            chain = " → ".join(rds.get("chain_domains", [])[:6])
            render_card(c4, "Redirects suspeitos", f"{reasons}. Cadeia: {chain}", "warning")
        else:
            render_card(c4, "Redirects", "Sem redirects suspeitos detectados.", "success")

        # Terceiro par de cartões
        c5, c6 = st.columns(2)
        # Conteúdo sensível
        cs = results.get("content_sensitive", {})
        if cs.get("has_sensitive"):
            terms = ", ".join(cs.get("sensitive_terms", [])[:8])
            render_card(c5, "Conteúdo sensível", f"Termos detectados: {terms}. Verifique formulários que solicitam dados.", "warning")
        else:
            render_card(c5, "Conteúdo sensível", "Nenhum termo sensível detectado no conteúdo.", "success")

        # Dynamic info: show chain domains if present (small card)
        chain_info = ""
        if isinstance(rds, dict) and rds.get("chain_domains"):
            chain_info = " → ".join(rds.get("chain_domains", [])[:8])
        if chain_info:
            render_card(c6, "Cadeia de redirects (amostragem)", chain_info, "info")
        else:
            render_card(c6, "Cadeia de redirects (amostragem)", "Nenhuma cadeia encontrada.", "info")




        st.write("---")

        # --- DETALHES ---
        st.markdown("### 🔎 Detalhes das verificações")

        st.markdown("## 📊 Histórico e Estatísticas")

        db_path = "phish_history.db"
        if os.path.exists(db_path):
            try:
                import sqlite3
                conn = sqlite3.connect(db_path)
                df_hist = pd.read_sql_query(
                    "SELECT id, url, timestamp, score FROM history ORDER BY timestamp DESC LIMIT 500",
                    conn
                )
                st.markdown("### Últimas análises realizadas")
                st.dataframe(df_hist, use_container_width=True, hide_index=True)

                # Exportar histórico completo
                csv_hist = df_hist.to_csv(index=False).encode("utf-8")
                st.download_button("📥 Baixar histórico completo (CSV)", csv_hist, "history.csv", "text/csv")

                # Gráfico de distribuição de scores
                st.markdown("### Distribuição de Scores")
                chart = df_hist["score"].value_counts().sort_index()
                st.bar_chart(chart)

                # Gráfico dos últimos 10 resultados
                st.markdown("### Últimas 10 URLs analisadas (Score)")
                if not df_hist.empty:
                    st.bar_chart(df_hist.head(10).set_index("url")["score"])
                else:
                    st.info("Ainda não há dados suficientes para gerar gráficos.")

                conn.close()
            except Exception as e:
                st.error(f"Erro ao carregar histórico: {e}")
        else:
            st.info("Nenhuma análise registrada ainda. Execute uma verificação para começar a gerar histórico.")

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
        with st.expander("Feeds e APIs — Detalhes e interpretação"):
            def explain_found(source_name):
                st.error(f"{source_name}: encontrado!")
                if source_name == "OpenPhish":
                    st.markdown("**O que isso significa:** Esta URL foi reportada publicamente como phishing pelo OpenPhish — alto grau de confiança.")
                    st.markdown("**Ação recomendada:** Não acesse a URL em navegadores comuns; marque como phishing e denuncie se necessário.")
                elif source_name == "URLhaus":
                    st.markdown("**O que isso significa:** URLhaus mantém um feed de URLs maliciosas (malware/phishing). Encontrado indica registro público recente.")
                    st.markdown("**Ação recomendada:** Trate como malicioso; evite interação e remova e-mails/links que apontem para ela.")
                elif source_name == "VirusTotal":
                    st.markdown("**O que isso significa:** Diversos mecanismos de segurança analisaram essa URL/artefato. Deteções indicam risco.")
                    st.markdown("**Ação recomendada:** confirmar com múltiplas fontes e evitar clicar; agregue evidências antes de ação corretiva.")
                elif source_name == "Google Safe Browsing":
                    st.markdown("**O que isso significa:** O Google identificou esta URL como um vetor de engenharia social (phishing) ou software indesejado.")
                    st.markdown("**Ação recomendada:** bloquear, não visitar, e avisar usuários que receberam o link.")

            def explain_not_found(source_name):
                st.success(f"{source_name}: não encontrado.")
                st.markdown("**O que isso significa:** A fonte pesquisada não tem registro conhecido dessa URL. Isso **não garante** que a URL é segura — apenas que não há registro nessa base.")
                st.markdown("**Ação recomendada:** combine com heurísticas e outras fontes; se heurísticas forem suspeitas, trate com cautela.")

            def explain_skipped(source_name):
                st.info(f"{source_name}: verificação pulada (chave não configurada).")
                st.markdown("**O que isso significa:** A checagem não foi realizada — configure a chave/API para obter verificação adicional.")
                st.markdown("**Como configurar:** ver README → `.env` → variáveis `SAFE_BROWSING_KEY`, `VIRUSTOTAL_KEY`.")

            def explain_error(source_name, message):
                st.warning(f"{source_name}: erro — {message}")
                st.markdown("**O que isso significa:** houve um problema técnico consultando a fonte. Isso pode ser temporário.")
                st.markdown("**Ação recomendada:** tente novamente mais tarde ou verifique sua conexão / quotas / formato da URL.")

            # ---- OpenPhish ----
            op = results.get("openphish")
            st.subheader("OpenPhish")
            if isinstance(op, dict):
                s = op.get("status")
                if s == "found":
                    explain_found("OpenPhish")
                    st.markdown("> Fonte: OpenPhish feed público")
                elif s == "not_found":
                    explain_not_found("OpenPhish")
                elif s == "error":
                    explain_error("OpenPhish", op.get("message"))
                else:
                    st.write(op)
            else:
                st.write(op)

            st.markdown("---")

            # ---- URLhaus ----
            uh = results.get("urlhaus")
            st.subheader("URLhaus")
            if isinstance(uh, dict):
                s = uh.get("status")
                if s == "found":
                    explain_found("URLhaus")
                    matches = uh.get("matches", [])
                    st.markdown("**Ocorrências (exemplo):**")
                    for m in matches:
                        st.text(m)
                    st.markdown("> Nota: usamos o feed CSV público do URLhaus para esta verificação.")
                elif s == "not_found":
                    explain_not_found("URLhaus")
                elif s == "error":
                    explain_error("URLhaus", uh.get("message"))
                else:
                    st.write(uh)
            else:
                st.write(uh)

            st.markdown("---")

            # ---- VirusTotal ----
            vt = results.get("virustotal")
            st.subheader("VirusTotal")
            if isinstance(vt, dict):
                s = vt.get("status")
                if s == "found":
                    explain_found("VirusTotal")
                    positives = vt.get("positives", 0)
                    st.markdown(f"- **Detecções totais (positives):** {positives}")
                    stats = vt.get("last_analysis_stats", {})
                    if isinstance(stats, dict):
                        st.markdown("**Resumo por categoria:**")
                        st.table(pd.DataFrame(list(stats.items()), columns=["Categoria","Contagem"]))
                    else:
                        st.write(stats)
                    st.markdown("> Observação: a contagem é a soma de engines que marcaram a URL; verifique `Dados brutos (JSON)` para detalhes por engine.")
                elif s == "not_found":
                    explain_not_found("VirusTotal")
                elif s == "skipped":
                    explain_skipped("VirusTotal")
                elif s == "error":
                    explain_error("VirusTotal", vt.get("message"))
                else:
                    st.write(vt)
            else:
                st.write(vt)

            st.markdown("---")

            # ---- Google Safe Browsing ----
            sb = results.get("safe_browsing")
            st.subheader("Google Safe Browsing")
            if isinstance(sb, dict):
                s = sb.get("status")
                if s == "found":
                    explain_found("Google Safe Browsing")
                    st.markdown(f"- **Quantidade de matches:** {sb.get('quantidade')}")
                    st.markdown("**Detalhes das correspondências:**")
                    for d in sb.get("detalhes", sb.get("threat_types", [])):
                        # d pode ser string ou dict dependendo da função; tratamos dict
                        if isinstance(d, dict):
                            st.write(f"- Tipo de ameaça: **{d.get('tipo_ameaça')}**")
                            st.write(f"  - Plataforma: {d.get('plataforma')}")
                            st.write(f"  - Cache duration: {d.get('cache_duracao')}")
                            st.write("---")
                        else:
                            st.write(f"- {d}")
                    st.markdown("Observação: `SOCIAL_ENGINEERING` indica classificação típica de phishing (eng. social).")
                elif s == "not_found":
                    explain_not_found("Google Safe Browsing")
                elif s == "skipped":
                    explain_skipped("Google Safe Browsing")
                elif s == "error":
                    explain_error("Google Safe Browsing", sb.get("message"))
                else:
                    st.write(sb)
            else:
                st.write(sb)

            st.markdown("---")
            st.markdown("**Guia rápido de interpretação:**")
            st.markdown("- **Encontrado** em qualquer feed/API → trate como malicioso até prova em contrário. Evite abrir o link.")
            st.markdown("- **Não encontrado** → pode ser legítimo ou novo; combine com heurísticas (idade do domínio, formulários de login, similaridade de marca).")
            st.markdown("- **Pulou verificação** → configure as chaves em `.env` para habilitar mais checagens.")
            st.markdown("- **Erro técnico** → pode ser temporário; tente novamente ou consulte o `Dados brutos (JSON)` para depuração.")


        with st.expander("Dados brutos (JSON)"):
            st.json(results)

        # Exportar CSV
        # flat = {
        #     "url": url,
        #     "veredito": verdict["veredito"],
        #     "score": verdict["score_text"],
        #     "reasons": "; ".join(results.get("risk", {}).get("reasons", [])),
        #     "whois_age_days": results.get("whois", {}).get("age_days"),
        #     "ssl_status": results.get("ssl", {}).get("status")
        # }
        # csv = pd.DataFrame([flat]).to_csv(index=False).encode("utf-8")
        # st.download_button("📥 Baixar relatório (CSV)", csv, "phish_report.csv", "text/csv")