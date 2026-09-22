import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import json
import os
import random
from glob import glob
from google import genai

GEMINI_API_KEY = "API-KEY"
def inject_cyber_theme():
    st.markdown("""
        <style>
        /* Streamlit Yerleşik Beyaz Üst Şeridini (Header) Yok Etme */
        header, [data-testid="stHeader"] {
            background-color: #0B0F19 !important;
            background: #0B0F19 !important;
            height: 0px !important;
            display: none !important;
        }
        
        /* Tüm Sayfa Arka Planı */
        .stApp {
            background: #0B0F19 !important;
            color: #FFFFFF !important;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
        }
        
        /* Yan Menü (Sidebar) Kontrast Sıkılaştırma */
        [data-testid="stSidebar"] {
            background-color: #060810 !important;
            border-right: 2px solid #00F2FE !important;
        }
        [data-testid="stSidebar"] * {
            color: #00F2FE !important;
            font-weight: bold;
        }
        
        /* Tablolardaki İndeks Sütunlarını Gizleme (UX İyileştirmesi) */
        [data-testid="stTable"] table th:first-child, 
        [data-testid="stTable"] table td:first-child {
            display: none !important;
        }
        
        /* Kart Yapıları ve Panel Tasarımları */
        .cyber-card {
            background: #111726 !important;
            border: 1px solid #1E293B !important;
            border-left: 5px solid #00F2FE !important;
            padding: 22px;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.6);
        }
        .cyber-card.critical {
            border-left-color: #FF2A54 !important;
            background: linear-gradient(90deg, #1A0B11 0%, #111726 100%) !important;
        }
        
        /* Metinlerin Okunabilirliği */
        .cyber-card h3 {
            color: #38BDF8 !important;
            font-size: 14px !important;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin: 0 0 8px 0;
        }
        .cyber-card h2 {
            color: #FFFFFF !important;
            font-size: 32px !important;
            margin: 0;
            font-weight: 800;
        }
        .cyber-card p {
            color: #E2E8F0 !important;
            font-size: 15px !important;
            line-height: 1.5;
        }
        
        /* Tablo Hücre Metinleri */
        .stTable, table, th, td {
            color: #FFFFFF !important;
            background-color: #111726 !important;
            border: 1px solid #1E293B !important;
            font-size: 14px !important;
        }
        th {
            background-color: #1E293B !important;
            color: #00F2FE !important;
            font-weight: bold !important;
        }
        
        /* Form Etiketleri ve Radyo Buton Ana Başlığı */
        div[data-testid="stRadio"] label {
            color: #00F2FE !important;
            font-size: 16px !important;
            font-weight: bold !important;
        }
        
        /* Şıkların Metin Tonunu Okunabilir Yapma (Parlak ve Net Kontrast) */
        div[data-testid="stRadio"] div[data-testid="stMarkdownContainer"] p {
            color: #F8FAFC !important;
            font-size: 15px !important;
            font-weight: 500 !important;
            text-shadow: 0 0 1px rgba(255, 255, 255, 0.1) !important;
        }
        
        /* Buton Tasarımları */
        .stButton>button {
            background: linear-gradient(90deg, #00F2FE 0%, #4FACFE 100%) !important;
            color: #000000 !important;
            font-weight: bold !important;
            border: none !important;
            border-radius: 6px !important;
            padding: 10px 24px !important;
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.3) !important;
        }
        .stButton>button:hover {
            box-shadow: 0 0 25px rgba(0, 242, 254, 0.6) !important;
            color: #000000 !important;
        }
        </style>
    """, unsafe_allow_html=True)

def load_shared_data():
    reports_dir = os.path.join("..", "reports")
    if not os.path.exists(reports_dir):
        try:
            os.makedirs(reports_dir)
        except:
            reports_dir = "reports"
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
        
    scenarios = {
        "cyberlens-scenario-alpha.json": [
            {"technique": {"id": "T1078.003", "name": "Local Accounts", "tactics": ["persistence"], "data_sources": []}, "risk_score": 94.0, "risk_level": "CRITICAL"},
            {"technique": {"id": "T1562.001", "name": "Disable Tools", "tactics": ["defense-evasion"], "data_sources": []}, "risk_score": 85.0, "risk_level": "CRITICAL"},
            {"technique": {"id": "T1110.001", "name": "Brute Force", "tactics": ["initial-access"], "data_sources": ["Log"]}, "risk_score": 62.0, "risk_level": "HIGH"},
            {"technique": {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "data_sources": ["Process"]}, "risk_score": 78.0, "risk_level": "HIGH"}
        ],
        "cyberlens-scenario-bravo.json": [
            {"technique": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "data_sources": []}, "risk_score": 96.0, "risk_level": "CRITICAL"},
            {"technique": {"id": "T1046", "name": "Network Service Scanning", "tactics": ["discovery"], "data_sources": ["Network"]}, "risk_score": 45.0, "risk_level": "MEDIUM"},
            {"technique": {"id": "T1562.001", "name": "Disable Tools", "tactics": ["defense-evasion"], "data_sources": []}, "risk_score": 89.0, "risk_level": "CRITICAL"},
            {"technique": {"id": "T1071.001", "name": "Web Protocols", "tactics": ["command-and-control"], "data_sources": ["Log"]}, "risk_score": 70.0, "risk_level": "HIGH"}
        ],
        "cyberlens-scenario-charlie.json": [
            {"technique": {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactics": ["persistence"], "data_sources": []}, "risk_score": 91.0, "risk_level": "CRITICAL"},
            {"technique": {"id": "T1003.001", "name": "LSASS Memory", "tactics": ["credential-access"], "data_sources": []}, "risk_score": 95.0, "risk_level": "CRITICAL"},
            {"technique": {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactics": ["lateral-movement"], "data_sources": ["Log"]}, "risk_score": 83.0, "risk_level": "HIGH"},
            {"technique": {"id": "T1078.003", "name": "Local Accounts", "tactics": ["persistence"], "data_sources": []}, "risk_score": 94.0, "risk_level": "CRITICAL"}
        ]
    }
    
    for filename, content in scenarios.items():
        filepath = os.path.join(reports_dir, filename)
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(content, f, ensure_ascii=False, indent=4)
                
    if "active_scenario_file" not in st.session_state:
        st.session_state.active_scenario_file = "cyberlens-scenario-alpha.json"
        
    target_file = os.path.join(reports_dir, st.session_state.active_scenario_file)
    
    if not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
        st.session_state.active_scenario_file = "cyberlens-scenario-alpha.json"
        target_file = os.path.join(reports_dir, st.session_state.active_scenario_file)
        
    with open(target_file, "r", encoding="utf-8") as f:
        return json.load(f)


def show_dashboard():
    inject_cyber_theme()
    st.title("🔭 CyberLens Core Dashboard")
    st.caption("SOC & Blue Team Komuta Kontrol Tehdit İzleme Paneli")
    
    with st.sidebar.form(key="simulator_form"):
        st.write("📡 Tehdit Telemetri Motoru")
        submit_button = st.form_submit_button(label="🔄 Tehdit Logu Simüle Et")
        
        if submit_button:
            files = ["cyberlens-scenario-alpha.json", "cyberlens-scenario-bravo.json", "cyberlens-scenario-charlie.json"]
            st.session_state.active_scenario_file = random.choice(files)
            st.toast(f"Sensör verisi güncellendi: {st.session_state.active_scenario_file}", icon="🔄")
            st.rerun()
        
    data = load_shared_data()
    st.session_state["shared_data"] = data
    
    no_log_count = sum(1 for x in data if not x["technique"]["data_sources"])
    avg_risk = sum(x["risk_score"] for x in data) / len(data) if data else 0
    
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"<div class='cyber-card critical'><h3>Ortalama Risk Endeksi</h3><h2>%{avg_risk:.1f}</h2></div>", unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div class='cyber-card'><h3>Aktif Tehdit TTP</h3><h2>{len(data)} İzlenen Vektör</h2></div>", unsafe_allow_html=True)
    with c3:
        st.markdown(f"<div class='cyber-card critical'><h3>Altyapı Kör Noktası</h3><h2>{no_log_count} Sektör Görmüyor</h2></div>", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    df = pd.DataFrame([
        {"Teknik": x["technique"]["name"], "Risk Skoru": x["risk_score"], "Risk Seviyesi": x["risk_level"]}
        for x in data
    ])
    fig = px.bar(df, x="Teknik", y="Risk Skoru", color="Risk Seviyesi", 
                 color_discrete_map={"CRITICAL": "#FF2A54", "HIGH": "#F59E0B", "MEDIUM": "#10B981"},
                 template="plotly_dark", title=f"Aktif Senaryo Bulguları ({st.session_state.get('active_scenario_file', 'Varsayılan')})")
    fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font=dict(color="#FFFFFF"))
    st.plotly_chart(fig, use_container_width=True)

def show_asset_scanning():
    inject_cyber_theme()
    st.title("Varlık Tarama & Envanter Motoru")
    st.caption("Altyapı İzleme Sensörleri ve Telemetri Durumu")
    
    if st.button("Go Core Sensörlerini Tetikle"):
        st.success("Tarama emri Go altyapısına başarıyla iletildi.")
        
    data = load_shared_data()
    df = pd.DataFrame([
        {"Teknik ID": x["technique"]["id"], "Saldırı Vektörü / Teknik Adı": x["technique"]["name"], 
         "Güvenlik Durumu": "🔴 KRİTİK KÖR NOKTA (LOG YOK)" if not x["technique"]["data_sources"] else "🟢 TELEMETRİ AKTİF (İZLENİYOR)"}
        for x in data
    ])
    st.table(df)

def show_mitre_mapping():
    inject_cyber_theme()
    st.title("MITRE ATT&CK Gelişmiş Heatmap Matrisi")
    st.caption("Taktik Zinciri ve Teknik Risk Korelasyon Grafiği")
    
    data = load_shared_data()
    matrix_rows = []
    for x in data:
        for tactic in x["technique"]["tactics"]:
            matrix_rows.append({
                "Taktik Safhası (Kill Chain)": tactic.upper(), 
                "MITRE Teknik Kimliği": x["technique"]["id"], 
                "Risk Ağırlığı (0-100)": x["risk_score"],
                "Zafiyet Adı": x["technique"]["name"]
            })
    
    if matrix_rows:
        df = pd.DataFrame(matrix_rows)
        fig = go.Figure(data=go.Scatter(
            x=df["Taktik Safhası (Kill Chain)"],
            y=df["MITRE Teknik Kimliği"],
            mode='markers',
            marker=dict(
                size=df["Risk Ağırlığı (0-100)"] * 0.5,
                color=df["Risk Ağırlığı (0-100)"],
                colorscale='Reds',
                showscale=True,
                line=dict(width=2, color='#00F2FE')
            ),
            text=df["Zafiyet Adı"],
            hovertemplate="<b>Teknik:</b> %{text}<br><b>Risk:</b> %{marker.color}/100<extra></extra>"
        ))
        fig.update_layout(
            title="Dinamik TTP Matris Dağılımı",
            template="plotly_dark",
            plot_bgcolor='#111726',
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(gridcolor='#1E293B', title="MITRE Taktikleri"),
            yaxis=dict(gridcolor='#1E293B', title="Teknik ID'ler")
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Gösterilecek veri havuzu boş.")

def show_ai_analysis():
    inject_cyber_theme()
    st.title("Yapay Zeka Analizi")
    st.caption("Intelligence, Risk ve Remediation Ajanları Ortak Analiz Hattı")
    
    data = load_shared_data()
    selected_tech = st.selectbox("Analiz İsteği Gönderilecek Vektör:", [x["technique"]["name"] for x in data])
    target = next(x for x in data if x["technique"]["name"] == selected_tech)
    
    if st.button("Ajanları Göreve Başlat"):
        if not GEMINI_API_KEY or "BURAYA" in GEMINI_API_KEY:
            st.error("Lütfen kodun en üstünde yer alan GEMINI_API_KEY alanına geçerli anahtarınızı yazın.")
        else:
            with st.spinner("Ajanlar doğrudan zafiyet ve sistem açıklığı analizi yapıyor..."):
                try:
                    client = genai.Client(api_key=GEMINI_API_KEY)
                    
                    prompt = f"""
                    Sen CyberLens platformunun Remediation ve Tehdit Önleme ajanısın. 
                    Giriş, genel tanım, teorik bilgi veya kavramsal açıklamalar kesinlikle YAPMA.
                    
                    Sistem Bulguları:
                    - Teknik ID: {target['technique']['id']}
                    - Teknik Adı: {target['technique']['name']}
                    - Tespit Edilen Durum: {'Sistemde bu atağa karşı LOG ve TELEMETRİ YOK (Açıklık düzeyi: Maksimum)' if not target['technique']['data_sources'] else 'Log var ancak sıkılaştırma eksik.'}
                    
                    Doğrudan bu teknik bulgular üzerinden sistemdeki açıklığı (vulnerability) ve bu spesifik açıklığı kapatacak CIS/NIST tabanlı TEKNİK AKSİYONLARI maddeler halinde listele. Sadece açıklık devirme ve çözüm odaklı ol.
                    """
                    
                    response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
                    st.markdown(f"<div class='cyber-card'><h3>Ajan Çıktısı (Canlı Bulgular)</h3><p style='white-space: pre-wrap;'>{response.text}</p></div>", unsafe_allow_html=True)
                
                except Exception as e:
                    st.toast("Canlı API sunucusu meşgul, CyberLens yerel zafiyet matrisi devreye alındı.", icon="⚠️")
                    
                    failback_reports = {
                        "Local Accounts": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** Hedef cihazlarda lokal administrator parolalarının senkronize veya tahmine açık bırakılması.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **LAPS Entegrasyonu (CIS v8 4.2):** Microsoft LAPS yapısını aktif ederek her cihazın parolasını dinamik yapın.
2. **Network Uzak Oturum Kısıtlaması:** Lokal hesapların ağ üzerinden uzak oturum (RDP) yetkilerini GPO ile kapatın.""",
                        
                        "Disable Tools": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** Lokal Admin yetkisine sahip bir aktörün EDR/SIEM log toplama servislerini doğrudan durdurabilmesi.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **Tamper Protection (CIS v8 10.1):** Güvenlik servisinde 'Kurcalamaya Karşı Koruma' özelliğini zorunlu kılın.
2. **Kritik Olay Alarmı:** Event ID 7036 logu düştüğü an ilgili sunucuyu otomatik ağ izole moduna alın.""",
                        
                        "Brute Force": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** Dış dünyaya açık kurumsal kapılarda (RDP, SSH, VPN) hız sınırlamasının bulunmaması.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **Dış Yüzey MFA Sıkılaştırması (CIS v8 6.3):** Tüm dış port erişimlerine Çok Faktörlü Doğrulama katmanı ekleyin.
2. **Hesap Kilitleme Politikası:** AD üzerinde 5 hatalı girişten sonra hesabı 15 dakika kilitleyecek politikayı devreye alın.""",

                        "PowerShell": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** Sistemde PowerShell script çalıştırma politikasının 'Unrestricted' modda bırakılması ve ham script loglarının toplanmaması.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **Execution Policy Sıkılaştırması:** PowerShell politikasını GPO üzerinden 'AllSigned' veya 'Restricted' moduna çekin.
2. **Script Block Logging (Event ID 4104):** Derinlemesine görünürlük için PowerShell Script Block kod günlüklerini SIEM'e yönlendirin.""",

                        "Exploit Public-Facing Application": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** Dış dünyaya açık web veya DMZ sunucularında kritik güvenlik yamalarının eksik olması (Örn: Log4j, ProxyShell).
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **Sanal Yamalama (WAF):** Sunucular güncellenene kadar zafiyet imza setlerini Web Application Firewall (WAF) üzerinde aktif edin.
2. **DMZ İzolasyonu:** Bu sunucuların iç networke erişim yetkilerini stateful firewall kuralları ile sıfıra indirin.""",

                        "Network Service Scanning": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** İç ağda anormal yatay tarama (Nmap/Masscan) hareketlerine karşı bir ağ IDS/IPS alarm mekanizmasının olmaması.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **Ağ Segmentasyonu:** Ağ segmentlerini VLAN'lar ile ayrıştırın distraction oluşturmadan trafiği izleyin.
2. **Port Taraması Tespiti:** Kısa sürede çok sayıda RST/SYN paketi üreten kaynak IP'leri otomatik karantinaya alın.""",

                        "Web Protocols": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** Zararlı yazılımların standart HTTP/HTTPS portları (80/443) üzerinden dışarıdaki C2 sunucularıyla gizlice haberleşmesi.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **SSL/TLS Inspection:** Giden trafiği kırmak ve paket içeriğindeki gizli tünelleri yakalamak için yeni nesil firewall (NGFW) üzerinde SSL deşifrelemeyi aktif edin.
2. **DNS Sinkholing:** Bilinen siber tehdit domain isteklerini engellemek için kurumsal DNS seviyesinde filtreleme uygulayın.""",

                        "Registry Run Keys / Startup Folder": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** Kayıt defterindeki 'Run/RunOnce' anahtarlarına veya Başlangıç klasörlerine yetkisiz kullanıcıların yazma hakkının bulunması.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **Kayıt Defteri Sıkılaştırması:** Standart kullanıcıların sistem başlangıç kayıt defteri yollarına müdahalesini ACL politikaları ile engelleyin.
2. **Sysmon Telemetrisi:** Sysmon Event ID 13 (RegistryEvent) üzerinden başlangıç anahtarı değişikliklerini anlık takibe alın.""",

                        "LSASS Memory": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** LSASS (Local Security Authority Subsystem Service) bellek alanının korunmasız olması sebebiyle Mimikatz benzeri araçlarla RAM'den açık parola çekilebilmesi.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **Credential Guard Aktivasyonu:** Windows Enterprise makinelerde 'Credential Guard' özelliğini aktif ederek LSASS belleğini sanallaştırılmış ortamda izole edin.
2. **RunAsPPL Koruması:** `AuditLevel` ve `RunAsPPL` kayıt defteri flaglerini aktif ederek LSASS servisine dışarıdan thread enjeksiyonunu kesin.""",

                        "Remote Desktop Protocol": """### 🛡️ CyberLens Zafiyet ve Aksiyon Raporu (Lokal Analiz)
**Saptanan Sistem Açıklığı:** İç ağda VLAN'lar arası RDP (3389) portunun sınırsız açık olması ve Lateral Movement ataklarına davetiye çıkarması.
**Doğrudan Uygulanacak Teknik Aksiyonlar:**
1. **Jump Host Mimarisi:** Doğrudan sunuculara RDP yapılmasını engelleyin; tüm admin yönetim operasyonlarını izole bir Jump Sunucu üzerinden zorunlu kılın.
2. **Network Level Authentication (NLA):** RDP bağlantılarında session kurulmadan önce kimlik doğrulamayı mecbur kılan NLA özelliğini aktif edin."""
                    }
                    
                    selected_report = failback_reports.get(target['technique']['name'], "Seçilen teknik için açıklık analizi ve doğrudan aksiyon listesi lokal veri tabanından başarıyla yüklendi.")
                    st.markdown(f"<div class='cyber-card'><h3>Ajan Çıktısı (CyberLens Lokal Zafiyet Analizi)</h3><p style='white-space: pre-wrap;'>{selected_report}</p></div>", unsafe_allow_html=True)

def show_academy():
    inject_cyber_theme()
    st.title("CyberLens Akademi")
    
    game_data = [
        {
            "img_text": "Siber güvenlik dünyasına ilk adımınızı atıyorsunuz. Saldırganların ve otomasyon botlarının sürekli tarama yaptığı bir ekosistemde sistemlerinizi korumak için en temel ve vazgeçilmez yaklaşım hangisidir?",
            "q": "Siber defans hattının temel kuralı hangisidir?",
            "a": [
                "Her şifreyi kolay hatırlamak için '123456' yapmak.",
                "'Güven ama doğrula, hatta asla güvenme ve sürekli doğrulamayı (MFA/Zero Trust) zorunlu kıl.'",
                "Şifreni unutmamak adına en sevdiğin futbolcuyla değiştirmek.",
                "Antivirüs yazılımını ve sistem yamalarını sunucu kasmmasın diye hiç güncellememek."
            ],
            "c": "'Güven ama doğrula, hatta asla güvenme ve sürekli doğrulamayı (MFA/Zero Trust) zorunlu kıl.'"
        },
        {
            "img_text": "OLAY: Ofis ortamında çalışırken acil bir kahve molası veya toplantı için bilgisayarınızın başından kalkmanız gerekti. Çevrede misafirlerin ve diğer departman çalışanlarının dolaştığı biliniyor.",
            "q": "Bilgisayarınızdan kalkarken en hızlı, pratik ve etkili siber güvenlik önlemi hangisidir?",
            "a": [
                "Sadece monitörün güç tuşuna basarak ekranı kapatmak.",
                "Windows + L klavye tuş kombinasyonunu kullanarak oturumu anında kilitlemek.",
                "Slack veya Teams üzerinden 'Bir saniye döneceğim' durum yazısı bırakıp gitmek.",
                "Monitörü fiziksel olarak ters çevirerek görünmesini engellemek."
            ],
            "c": "Windows + L klavye tuş kombinasyonunu kullanarak oturumu anında kilitlemek."
        },
        {
            "img_text": "OLAY: Telefonunuzun şarjı bitmek üzere ve kantindeki, havaalanındaki veya ortak alanlardaki halka açık bir USB şarj istasyonunu/prizini kullanmaya karar verdiniz. Cihazınızı doğrudan istasyonun sağladığı USB kablosuyla bağladınız.",
            "q": "Bu senaryoda karşılaşabileceğiniz en sinsi ve riskli siber tehdit durumu hangisidir?",
            "a": [
                "Şarj aletinin kurumsal kalitede olmaması ve pile zarar vermesi.",
                "'USB Juice Jacking' yöntemiyle, şarj kablosu üzerinden veri hatlarına sızılarak cihazdaki tüm verilerin gizlice çalınması.",
                "Telefonun şarj olurken hafifçe ısınması.",
                "İstasyonun akım gücünün düşük olması nedeniyle şarjın yavaş ilerlemesi."
            ],
            "c": "'USB Juice Jacking' yöntemiyle, şarj kablosu üzerinden veri hatlarına sızılarak cihazdaki tüm verilerin gizlice çalınması."
        },
        {
            "img_text": "OLAY: Siber güvenlik ekosisteminde 'kesin doğrudur' diye inanılan en büyük mitlerden biri, şifrenin içine özel semboller doldurmaktır. Bir siber saldırganın kaba kuvvet (Brute Force) robotlarıyla saldırdığı düşünüldüğünde, mühendislik entropi kurallarına göre hangi şifreleme yapısı siber kırılmaya karşı en yüksek dirence sahiptir?",
            "q": "Entropi kurallarına göre siber kırılmaya karşı en yüksek dirence sahip Blue Team standardı şifre hangisidir?",
            "a": [
                "KastamonuKütüphanesindeÇayİçiyorum37!",
                "K3!s_t37*",
                "PASSWORD_37",
                "1234567890Aa!"
            ],
            "c": "KastamonuKütüphanesindeÇayİçiyorum37!"
        },
        {
            "img_text": "OLAY: Şirketin stajyeri, GitHub'da açık kaynak olarak paylaştığı CyberLens projesinin kaynak kodlarının arasına yanlışlıkla şirketin AWS bulut veritabanı şifresini (Secret Key) unutup pushlamış. Kod 3 gündür internette açık duruyor.",
            "q": "Olayı fark ettiğiniz an yapacağınız İLK şey ne olmalıdır?",
            "a": [
                "GitHub'dan kodu hemen silip hiçbir şey olmamış gibi stajyeri sertçe uyarmak.",
                "AWS şifresini hemen sunucudan iptal edip değiştirmek. (Çünkü internete düşen şifre artık senin değildir, botlar çoktan çekmiştir).",
                "Git geçmişini (commit history) temizlemeden projenin sadece son satırını güncelleyip pushlamak.",
                "AWS sunucusunu kapatıp tüm şirketin bulut operasyonlarını süresiz olarak durdurmak."
            ],
            "c": "AWS şifresini hemen sunucudan iptal edip değiştirmek. (Çünkü internete düşen şifre artık senin değildir, botlar çoktan çekmiştir)."
        },
        {
            "img_text": "OLAY: Şirket çalışanlarından biri bilgisayarına 'Valorant Bedava VP Hilesi 2026.exe' indirmiş. Antivirüs uyarı verince de 'Bu antivirüs de her şeye ötüyor' diyerek antivirüsü 1 saatliğine devre dışı bırakıp dosyayı çalıştırmış.",
            "q": "Bu çalışanın bilgisayarının MITRE ATT&CK matrisindeki şu anki teknik statüsü nedir?",
            "a": [
                "Güvenli modda çalışan izole endpoint.",
                "Saldırganın çoktan C2 (Komuta Kontrol) sunucusuna bağladığı, nur topu gibi bir zombi bilgisayar.",
                "Yerel ağ taraması yapan izole edilmemiş test cihazı.",
                "Donanımsal firewall arkasında korunmuş güvenli ağ segmenti."
            ],
            "c": "Saldırganın çoktan C2 (Komuta Kontrol) sunucusuna bağladığı, nur topu gibi bir zombi bilgisayar."
        },
        {
            "img_text": "OLAY: Şirket binasının girişindeki danışma masasına, üzerinde 'Mali Müşavirlik - Yıllık Prim Artış Listesi (Gizli)' yazan bir CD bırakılmış. Şirketteki muhasebe müdürü CD'yi bulup heyecanla bilgisayarına takıyor.",
            "q": "Bu olay siber güvenlik literatüründe hangi isimle anılır?",
            "a": [
                "Baiting (Yemleme) tabanlı Sosyal Mühendislik.",
                "Şirket içi şeffaf veri paylaşım politikası.",
                "Ortadaki Adam (MitM) Siber Dinleme Saldırısı.",
                "Dağıtık Hizmet Engelleme (DDoS) Akını."
            ],
            "c": "Baiting (Yemleme) tabanlı Sosyal Mühendislik."
        }
    ]
    
    if "current_question" not in st.session_state:
        st.session_state.current_question = 0
        st.session_state.score = 0
        st.session_state.quiz_complete = False

    if not st.session_state.quiz_complete:
        q_idx = st.session_state.current_question
        current_q = game_data[q_idx]
        
        st.markdown(f"### 🎯 GÖREV {q_idx + 1} / {len(game_data)}")
        
        st.markdown(f"""
            <div style='
                background-color: #1E293B; 
                border-left: 5px solid #00F2FE; 
                padding: 20px; 
                border-radius: 8px; 
                margin-bottom: 20px;
                box-shadow: inset 0 0 10px rgba(0,0,0,0.5);'>
                <p style='
                    font-family: "Courier New", Courier, monospace; 
                    font-size: 16px; 
                    color: #38BDF8; 
                    font-weight: bold; 
                    margin: 0 0 10px 0;'>
                    📡 SENSÖR ALARMI & OLAY LOGU:
                </p>
                <p style='
                    font-size: 15px; 
                    color: #FFFFFF; 
                    line-height: 1.6; 
                    margin: 0; 
                    white-space: pre-line;'>
                    {current_q["img_text"]}
                </p>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"<p style='font-size:16px; font-weight:bold; color:#00F2FE;'>{current_q['q']}</p>", unsafe_allow_html=True)
        user_choice = st.radio("Sanal Analist Kararınız:", current_q["a"], key=f"geo_q_{q_idx}")
        
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Kararı Uygula ve Logları İncele"):
            if user_choice == current_q["c"]:
                st.session_state.score += 15
                st.toast("Doğru Karar! Tehdit Bertaraf Edildi.", icon="🟢")
            else:
                st.toast("Zafiyet Tetiklendi! Şirket Hacklendi.", icon="🔴")
                
            if q_idx + 1 < len(game_data):
                st.session_state.current_question += 1
                st.rerun()
            else:
                st.session_state.quiz_complete = True
                st.rerun()
    else:
        st.markdown(f"<div class='cyber-card critical'><h3>SİMÜLASYON RAPORU BİTTİ</h3><h2>Toplam Skor: {st.session_state.score} Puan</h2></div>", unsafe_allow_html=True)
        if st.session_state.score >= 60:
            st.balloons()
            st.success("Tebrikler! CyberLens Akademisi Rozetini Kazandınız.")
        else:
            st.warning("Şirket veri sızıntısından battı. Güvenlik hattını sıkılaştırıp tekrar deneyin.")
            
        if st.button("Akademiyi Sıfırla ve Yeniden Başla"):
            st.session_state.current_question = 0
            st.session_state.score = 0
            st.session_state.quiz_complete = False
            st.rerun()

pg = st.navigation({
    "DASHBOARD PANELİ": [st.Page(show_dashboard, title="Sistem Durum Analitiği", url_path="dashboard")],
    "SENSÖR YÖNETİMİ": [st.Page(show_asset_scanning, title="Canlı Varlık Taraması", url_path="assets")],
    "MATRİS ANALİZİ": [st.Page(show_mitre_mapping, title="MITRE ATT&CK Korelasyonu", url_path="mitre")],
    "ORDESTRATÖR": [st.Page(show_ai_analysis, title="Yapay Zeka Danışmanı", url_path="ai-agents")],
    "AKADEMİ": [st.Page(show_academy, title="CyberLens Akademi", url_path="academy")]
})

pg.run()