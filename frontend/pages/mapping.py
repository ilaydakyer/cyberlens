import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="MITRE ATT&CK Mapping", layout="wide")
st.subheader("🗺️ Dinamik MITRE ATT&CK TTP Heatmap Matrisi")

data = st.session_state.get("shared_data", [])

matrix_rows = []
for x in data:
    for tactic in x["technique"]["tactics"]:
        matrix_rows.append({
            "Taktik (Phase)": tactic,
            "Teknik ID": x["technique"]["id"],
            "Risk Puanı": x["risk_score"]
        })

if matrix_rows:
    df = pd.DataFrame(matrix_rows)
    fig = px.density_heatmap(df, x="Taktik (Phase)", y="Teknik ID", z="Risk Puanı",
                             text_auto=True, color_continuous_scale="Reds",
                             title="Canlı TTP Eşleşme Matrisi")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("Matris verisi yüklenemedi.")