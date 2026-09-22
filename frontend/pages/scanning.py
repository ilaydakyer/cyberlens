import streamlit as st
import pandas as pd
import subprocess

st.set_page_config(page_title="Asset Scanning", layout="wide")
st.subheader("🔍 Ağ ve Kurumsal Varlık Tarama Modülü")

if st.button("Go Backend Tarama Motorunu Tetikle"):
    with st.spinner("Go Goroutines ağ ve endpoint envanterini çıkartıyor..."):
        try:
            # Go Engine'i subprocess ile çalıştır
            subprocess.run(["go", "run", "../backend/main.go"], check=True)
            st.success("Tarama Başarılı! Veri havuzu güncellendi.")
        except Exception as e:
            st.warning(f"Yerel Go ortamı bulunamadı, simüle ediliyor. Hata: {e}")

data = st.session_state.get("shared_data", [])
df = pd.DataFrame([
    {
        "ID": x["technique"]["id"],
        "Zafiyet / Teknik": x["technique"]["name"],
        "Durum": "🔴 KÖR NOKTA" if not x["technique"]["data_sources"] else "🟢 Izleniyor"
    } for x in data
])
st.table(df)