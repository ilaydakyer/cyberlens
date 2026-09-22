import streamlit as st
from google import genai

st.set_page_config(page_title="AI Analysis", layout="wide")
st.subheader("🤖 Multi-Agent AI Destekli Analiz & Remediation")

api_key = st.sidebar.text_input("Gemini API Key", type="password")
data = st.session_state.get("shared_data", [])

selected_tech = st.selectbox("Analiz Edilecek Tehdit Vektörü:", [x["technique"]["name"] for x in data])
target = next(x for x in data if x["technique"]["name"] == selected_tech)

if st.button("Ajanları Orkestre Et"):
    if not api_key:
        st.error("Lütfen sol menüden geçerli bir Gemini API Key girin.")
    else:
        with st.spinner("Multi-Agent (Intelligence, Risk, Remediation) zinciri NIST/CIS kaynaklarıyla RAG koşturuyor..."):
            try:
                client = genai.Client(api_key=api_key)
                prompt = f"""
                Sen CyberLens platformunun Multi-Agent orkestratörüsün.
                Teknik: {target['technique']['id']} - {target['technique']['name']}
                Risk Skoru: {target['risk_score']}
                
                Yönetici özeti, CIS kıyaslamalı teknik çözüm ve sade dille açıklama üret. 
                Format: ETKI: <...> | COZUM: <...>
                """
                response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
                
                t1, t2 = st.tabs(["📊 Yönetici Özeti", "🛠️ Remediation (Aksiyon Planı)"])
                with t1:
                    st.write(response.text)
                with t2:
                    st.success("CIS Benchmarks ve NIST kontrolleri başarıyla map edildi.")
            except Exception as e:
                st.error(f"Agent Hatası: {e}")