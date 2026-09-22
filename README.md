# CyberLens 🔭

CyberLens, MITRE ATT&CK matrisi tabanlı, dinamik risk skorlaması ve yapay zeka destekli zafiyet analizi sunan bir SOC (Security Operations Center) komuta kontrol paneli simülasyonudur.

## Mimari
- **Backend (Go):** MITRE veri tabanını asenkron olarak çeken (`fetcher`), işleyen (`parser`) ve çok boyutlu algoritmalarla risk analizi yapan (`analyzer`) yüksek performanslı motor. Çıktıları JSON formatında raporlar.
- **Frontend (Python):** Veri motorunun ürettiği JSON raporlarını görselleştiren, Streamlit ve Plotly tabanlı etkileşimli arayüz.
- **Yapay Zeka Motoru:** Google Gemini entegrasyonu ile zafiyetlere yönelik anlık CIS/NIST tabanlı çözüm (remediation) senaryoları üretir.

## Özellikler
- Dinamik Tehdit Logu Simülasyonu
- MITRE TTP Korelasyonu ve Isı Haritası (Heatmap)
- Varlık Taraması ve "Kör Nokta" (Log Eksikliği) Tespiti
- CyberLens Akademi (İnteraktif Güvenlik Senaryoları)

### Backend
Terminalden backend dizinine geçin ve veri toplama/analiz motorunu başlatın:
```bash
cd backend
go run main.go
