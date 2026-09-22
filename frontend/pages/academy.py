import streamlit as st

st.set_page_config(page_title="CyberLens Academy", layout="wide")
st.subheader("🎓 CyberLens Academy — İnteraktif Tehdit Avı")
st.caption("Yöneticiler ve Yeni Başlayanlar İçin Siber Güvenlik Oyunlaştırma Katmanı")

st.markdown("### 🏹 Senaryo: Antivirüs Devre Dışı Kaldı!")
st.write("Sisteminizde `T1562.001 (Disable or Modify Tools)` tekniğiyle Windows Defender'ın kapatıldığı alarmı düştü. İlk aksiyonunuz ne olmalıdır?")

choice = st.radio("Karar Mekanizmanız:", [
    "A) Logları silip sunucuyu görmezden gelmek.",
    "B) Hemen ağ trafiğini izole etmek, aktif oturumları kapatıp endpoint ajanını güvenli modda tetiklemek.",
    "C) Bilgisayara restart atmak."
])

if st.button("Kararı Gönder"):
    if "B)" in choice:
        st.balloons()
        st.success("Doğru Karar! +100 CyberScore Puanı. [Badge: Mavi Takım Analisti]")
        st.markdown("> **Yapay Zeka Açıklaması:** Bir saldırgan savunma araçlarını kapattıysa içeride kalıcı olmaya çalışıyor demektir. Makineyi izole etmek yayılımı (lateral movement) durdurur.")
    else:
        st.error("Yanlış Karar! Saldırgan şirketin aktif verilerini sızdırmaya devam ediyor.")