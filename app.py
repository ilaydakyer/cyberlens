import sys
import re
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QListWidget, QTextBrowser, 
                             QProgressBar, QSplitter, QFrame)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

# Örnek Ham Veri (Giriş metniniz)
REPORT_DATA = """
═════════════════════════════════════════════════════════════════
  CYBERLENS
═════════════════════════════════════════════════════════════════
  Oluşturma  : 2026-06-04 15:13:35
  Platform   : windows,linux
  Taktik     : execution,persistence
  Kaynak     : MITRE ATT&CK Enterprise (Canlı)

─────────────────────────────────────────────────────────────────
  RİSK ÖZETİ
─────────────────────────────────────────────────────────────────
  Filtre Eşleşmesi     : 133 teknik
  CRITICAL              : 36
  HIGH                  : 84
  MEDIUM                : 13
  LOW                   : 0
  Ortalama Risk Skoru  : 64.1 / 100
  En Sık Taktik        : persistence

═════════════════════════════════════════════════════════════════
  TEKNİK DETAYLARI  (20 teknik)
═════════════════════════════════════════════════════════════════

  [1]  T1078.003 — Local Accounts
       Risk Skoru    : 100.0 / 100  [CRITICAL]
       Versiyon      : 2.0  |  Güncelleme: 2026-05-12T15:12:00.726Z
       Platformlar   : containers, esxi, linux, macos, network devices, windows
       Kill Chain    : initial-access → persistence → privilege-escalation → stealth
       Veri Kaynakları: ⚠ YOK — algılama kapasitesi sıfır
       Risk Faktörleri:
         +30  Çok platform hedefleme (4+): ağ genelinde yayılma potansiyeli
         +20  3+ taktik fazı: tam kampanya desteği (persistence → exfil)
         +10  Alt-teknik: genel algılama imzalarını atlatma kapasitesi
         +25  KRİTİK ALGI AÇIĞI: Bilinen veri kaynağı yok — analist kör
         +15  Kritik taktik [privilege-escalation]: doğrudan iş etkisi
·································································

  [2]  T1078.001 — Default Accounts
       Risk Skoru    : 100.0 / 100  [CRITICAL]
       Versiyon      : 2.0  |  Güncelleme: 2026-05-12T15:12:00.636Z
       Platformlar   : containers, esxi, iaas, identity provider, linux, macos, network devices, office suite, saas, windows
       Kill Chain    : initial-access → persistence → privilege-escalation → stealth
       Veri Kaynakları: ⚠ YOK — algılama kapasitesi sıfır
       Risk Faktörleri:
         +30  Çok platform hedefleme (4+): ağ genelinde yayılma potansiyeli
         +20  3+ taktik fazı: tam kampanya desteği (persistence → exfil)
         +10  Alt-teknik: genel algılama imzalarını atlatma kapasitesi
         +25  KRİTİK ALGI AÇIĞI: Bilinen veri kaynağı yok — analist kör
         +15  Kritik taktik [privilege-escalation]: doğrudan iş etkisi
"""

class MitreApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberLens Scout - Risk Dashboard")
        self.setGeometry(100, 100, 1100, 750)
        self.techniques = self.parse_report(REPORT_DATA)
        self.init_ui()

    def parse_report(self, text):
        """Basit regex ile teknik detayları parse eden motor."""
        techniques = []
        blocks = text.split("·································································")
        
        for block in blocks:
            if "[" not in block: continue
            tech = {}
            # Başlık ve ID yakalama
            title_match = re.search(r'\[\d+\]\s+(T\d+(?:\.\d+)?)\s+—\s+(.*)', block)
            if title_match:
                tech['id'] = title_match.group(1)
                tech['name'] = title_match.group(2).strip()
            
            # Skor ve Seviye
            score_match = re.search(r'Risk Skoru\s+:\s+([\d.]+)\s+/\s+100\s+\[(.*)\]', block)
            if score_match:
                tech['score'] = float(score_match.group(1))
                tech['level'] = score_match.group(2).strip()
            
            # Algılama Açığı Kontrolü
            tech['blind_spot'] = "⚠ Veri Kaynağı Yok (Sistem Kör Noktada)" in block or "algılama kapasitesi sıfır" in block
            
            # Risk Faktörleri metni ayıklama
            factors_start = block.find("Risk Faktörleri:")
            if factors_start != -1:
                tech['factors'] = block[factors_start:].strip()
            else:
                tech['factors'] = "Faktör belirtilmemiş."
                
            techniques.append(tech)
        return techniques

    def init_ui(self):
        # Ana Tema CSS (Cyberpunk Dark Mode)
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QLabel { color: #c9d1d9; font-family: 'Segoe UI', Arial; }
            QListWidget { 
                background-color: #161b22; 
                border: 1px solid #30363d; 
                border-radius: 6px; 
                color: #c9d1d9; 
                padding: 5px;
            }
            QListWidget::item { 
                padding: 10px; 
                border-bottom: 1px solid #21262d; 
                border-radius: 4px;
            }
            QListWidget::item:selected { 
                background-color: #1f6feb; 
                color: white; 
            }
            QTextBrowser { 
                background-color: #161b22; 
                border: 1px solid #30363d; 
                border-radius: 6px; 
                color: #c9d1d9; 
                padding: 15px;
            }
        """)

        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)

        # 1. ÜST PANEL (KPI Özet Kartları)
        summary_layout = QHBoxLayout()
        
        # Ortalama Skor Kartı
        score_card = QFrame()
        score_card.setStyleSheet("background-color: #21262d; border-radius: 8px; border: 1px solid #30363d;")
        sc_layout = QVBoxLayout(score_card)
        sc_title = QLabel("ORTALAMA TEHDİT SKORU")
        sc_title.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        sc_val = QLabel("64.1 / 100")
        sc_val.setStyleSheet("color: #ff7b72; font-size: 24px; font-weight: bold; border: none;")
        sc_layout.addWidget(sc_title)
        sc_layout.addWidget(sc_val)

        # Kritik Durum Kartı
        status_card = QFrame()
        status_card.setStyleSheet("background-color: #21262d; border-radius: 8px; border: 1px solid #30363d;")
        st_layout = QVBoxLayout(status_card)
        st_title = QLabel("KRİTİK TEHDİT ADEDİ")
        st_title.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        st_val = QLabel("36 Teknik")
        st_val.setStyleSheet("color: #f25944; font-size: 24px; font-weight: bold; border: none;")
        st_layout.addWidget(st_title)
        st_layout.addWidget(st_val)

        summary_layout.addWidget(score_card)
        summary_layout.addWidget(status_card)
        main_layout.addLayout(summary_layout)

        # 2. ORTA ALAN (Splitter ile Listeleme ve Detay)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Sol taraf: Teknik Listesi
        self.list_widget = QListWidget()
        for t in self.techniques:
            self.list_widget.addItem(f"[{t['id']}] {t['name']}")
        self.list_widget.currentRowChanged.connect(self.display_details)
        splitter.addWidget(self.list_widget)

        # Sağ taraf: Detay ve Yönetici Özeti Paneli
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(10, 0, 0, 0)

        # Dinamik Risk Barı
        self.risk_label = QLabel("Tehdit Seviyesi:")
        self.risk_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setStyleSheet("""
            QProgressBar { border: 1px solid #30363d; border-radius: 4px; text-align: center; color: white; background-color: #111; }
            QProgressBar::chunk { background-color: #da3633; }
        """)
        
        # Yönetici Açıklama Alanı (Siber güvenlik bilmeyenler için)
        self.explanation_box = QTextBrowser()
        self.explanation_box.setFont(QFont("Segoe UI", 10))

        right_layout.addWidget(self.risk_label)
        right_layout.addWidget(self.progress_bar)
        right_layout.addWidget(QLabel("<b>Detaylar ve Analiz Metni:</b>"))
        right_layout.addWidget(self.explanation_box)
        
        splitter.addWidget(right_container)
        splitter.setSizes([400, 700])
        main_layout.addWidget(splitter)

        self.setCentralWidget(main_widget)
        if self.techniques:
            self.list_widget.setCurrentRow(0)

    def display_details(self, index):
        """Seçilen tekniği sadeleştirerek ekrana basan fonksiyon."""
        if index < 0 or index >= len(self.techniques): return
        tech = self.techniques[index]

        # Risk Skoru ve Progress Bar Güncelleme
        self.progress_bar.setValue(int(tech['score']))
        self.risk_label.setText(f"Tehdit Seviyesi: {tech['level']} ({tech['score']}/100)")

        # Teknik olmayan kişiye özel özet metni (Yalınlaştırma)
        bg_color = "#381215" if tech['blind_spot'] else "#161b22"
        
        html_content = f"""
        <div style="line-height: 1.5;">
            <h2 style="color: #58a6ff; margin-bottom: 0;">{tech['id']} — {tech['name']}</h2>
            <hr style="border: 0; border-top: 1px solid #30363d;"/>
            
            <p style="font-size: 13px; color: #ff7b72; font-weight: bold;">
                ⚠️ YÖNETİCİ ÖZETİ:<br>
                <span style="color: #c9d1d9; font-weight: normal;">
                Bu teknik, saldırganların yetkisiz erişim sağlamak veya sistemde kalıcı olmak adına meşru hesapları taklit ettiğini/kullandığını gösterir.
                </span>
            </p>
        """
        
        if tech['blind_spot']:
            html_content += f"""
            <div style="background-color: {bg_color}; border: 1px solid #f25944; padding: 10px; border-radius: 4px; margin-top: 10px;">
                <b style="color: #f25944;">KORUMA AÇIĞI TESPİT EDİLDİ:</b><br>
                Sisteminizde bu hareketi izleyecek aktif bir log/veri kaynağı bulunmamaktadır. Saldırgan görünmez durumdadır.
            </div>
            """
        
        html_content += f"""
            <br>
            <b style="color: #8b949e;">Teknik Analiz ve Risk Faktörleri:</b>
            <pre style="color: #8b949e; font-family: Consolas, monospace; background-color: #0d1117; padding: 10px; border-radius: 4px;">{tech['factors']}</pre>
        </div>
        """
        
        self.explanation_box.setHtml(html_content)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MitreApp()
    window.show()
    sys.exit(app.exec())