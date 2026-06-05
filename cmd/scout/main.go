package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cypherlens/scout/internal/analyzer"
	"github.com/cypherlens/scout/internal/fetcher"
	"github.com/cypherlens/scout/internal/parser"
)

// ─────────────────────────────────────────────
//  Giriş Noktası
// ─────────────────────────────────────────────

func main() {
	cfg := parseFlags()
	printBanner(cfg)

	// Aşama 1 — Canlı veri çek
	rawData, fetchResult := mustFetch(cfg)
	printStep("1/3", "Veri çekme",
		fmt.Sprintf("%d KB | %d ms | %d deneme",
			fetchResult.SizeKB,
			fetchResult.Elapsed.Milliseconds(),
			fetchResult.Attempts,
		))

	// Aşama 2 — Parse et
	techniques, parseStats := mustParse(rawData)
	printStep("2/3", "Ayrıştırma",
		fmt.Sprintf("%d teknik yüklendi (%d deprecated atlandı)",
			parseStats.FinalTechniques,
			parseStats.SkippedRevoked,
		))

	// Aşama 3 — Analiz & Skora
	analyzerCfg := analyzer.Config{
		Platforms: splitFlag(cfg.platforms),
		Tactics:   splitFlag(cfg.tactics),
	}
	results, stats := analyzer.Run(techniques, analyzerCfg)
	printStep("3/3", "Risk analizi",
		fmt.Sprintf("%d eşleşme | Ort. skor: %.1f | En sık taktik: %s",
			stats.Matched, stats.AvgScore, orDash(stats.TopTactic),
		))

	fmt.Println()

	if len(results) == 0 {
		printWarn("Filtrelerle eşleşen teknik bulunamadı.")
		printWarn("Öneri: -platform ve -tactic değerlerini genişletin veya kaldırın.")
		os.Exit(0)
	}

	// Top-N kesimine al
	if len(results) > cfg.top {
		results = results[:cfg.top]
	}

	// Konsol özeti
	printConsoleSummary(results, stats)

	// Dosya raporu
	path := writeReport(results, stats, parseStats, cfg)
	fmt.Printf("\n  ✓ Rapor kaydedildi → %s\n\n", path)
}

// ─────────────────────────────────────────────
//  Flag Yönetimi
// ─────────────────────────────────────────────

type cliConfig struct {
	platforms string
	tactics   string
	output    string
	top       int
	verbose   bool
}

func parseFlags() cliConfig {
	var cfg cliConfig

	flag.StringVar(&cfg.platforms, "platform", "",
		"Platform filtresi (virgüllü). Örn: windows,linux,azure-ad")
	flag.StringVar(&cfg.tactics, "tactic", "",
		"Taktik filtresi (virgüllü). Örn: execution,persistence,exfiltration")
	flag.StringVar(&cfg.output, "output", "reports",
		"Rapor çıktı dizini")
	flag.IntVar(&cfg.top, "top", 25,
		"Rapora dahil edilecek maksimum teknik sayısı")
	flag.BoolVar(&cfg.verbose, "verbose", false,
		"HTTP retry ve ayrıntılı hata mesajlarını göster")

	flag.Usage = usage
	flag.Parse()
	return cfg
}

func usage() {
	fmt.Fprintf(os.Stderr, `
CypherLens Scout — MITRE ATT&CK Hibrit Risk Analiz Motoru

Kullanım:
  scout [seçenekler]

Seçenekler:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Örnekler:
  scout -platform=windows,linux -tactic=execution,persistence
  scout -platform=azure-ad,office-365 -tactic=credential-access -top=10
  scout -top=50 -output=./raporlar

ATT&CK Platform Değerleri:
  windows | linux | macos | azure-ad | office-365 |
  google-workspace | saas | iaas | containers | network

ATT&CK Taktik Değerleri:
  reconnaissance | resource-development | initial-access | execution |
  persistence | privilege-escalation | defense-evasion | credential-access |
  discovery | lateral-movement | collection | command-and-control |
  exfiltration | impact
`)
}

// ─────────────────────────────────────────────
//  Pipeline Adımları
// ─────────────────────────────────────────────

// 1. Fonksiyon imzasını değiştir
func mustFetch(cfg cliConfig) ([]byte, *fetcher.FetchResult) {
	opts := []fetcher.Option{}
	if cfg.verbose {
		opts = append(opts, fetcher.WithVerbose())
	}
	client := fetcher.New(opts...)

	result, err := client.Fetch(fetcher.MITRESource)
	if err != nil {
		fatal("Veri çekme hatası", err)
	}
	return result.Data, result
}

func mustParse(data []byte) ([]parser.Technique, *parser.ParseStats) {
	techniques, stats, err := parser.Parse(data)
	if err != nil {
		fatal("Parse hatası", err)
	}
	return techniques, stats
}

// ─────────────────────────────────────────────
//  Konsol Çıktısı
// ─────────────────────────────────────────────

func printBanner(cfg cliConfig) {
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════╗")
	fmt.Println("  ║          CyberLens Scout  ·  v2.0                  ║")
	fmt.Println("  ║     MITRE ATT&CK Hibrit Risk Analiz Motoru           ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Platform  : %s\n", orAll(cfg.platforms))
	fmt.Printf("  Taktik    : %s\n", orAll(cfg.tactics))
	fmt.Printf("  Maks. Top : %d\n", cfg.top)
	fmt.Printf("  Çıktı     : %s\n", cfg.output)
	fmt.Println()
}

func printStep(step, label, detail string) {
	fmt.Printf("  [%s] %-18s → %s\n", step, label, detail)
}

func printWarn(msg string) {
	fmt.Fprintf(os.Stderr, "  ⚠  %s\n", msg)
}

func printConsoleSummary(results []analyzer.Result, stats *analyzer.Stats) {
	bar := func(count, total int, char string) string {
		if total == 0 {
			return ""
		}
		n := (count * 20) / total
		return strings.Repeat(char, n)
	}

	total := stats.Matched
	fmt.Println("  ┌─────────────────────────────────────────────────────┐")
	fmt.Println("  │                   RİSK DAĞILIMI                     │")
	fmt.Println("  ├─────────────────────────────────────────────────────┤")
	fmt.Printf("  │  CRITICAL  %3d  %s\n", stats.Critical, bar(stats.Critical, total, "█"))
	fmt.Printf("  │  HIGH      %3d  %s\n", stats.High, bar(stats.High, total, "▓"))
	fmt.Printf("  │  MEDIUM    %3d  %s\n", stats.Medium, bar(stats.Medium, total, "░"))
	fmt.Printf("  │  LOW       %3d  %s\n", stats.Low, bar(stats.Low, total, "·"))
	fmt.Println("  ├─────────────────────────────────────────────────────┤")
	fmt.Printf("  │  Ortalama Skor: %.1f / 100\n", stats.AvgScore)
	fmt.Println("  └─────────────────────────────────────────────────────┘")
	fmt.Println()

	// İlk 5 tekniği konsola önizle
	fmt.Println("  TOP 5 KRİTİK TEKNİK:")
	fmt.Println("  ─────────────────────────────────────────────────────")
	for i, r := range results {
		if i >= 5 {
			break
		}
		fmt.Printf("  %d. [%6s] %-12s  %.0f puan  —  %s\n",
			i+1, r.RiskLevel, r.Technique.ID, r.RiskScore, r.Technique.Name)
	}
	fmt.Println()
}

// ─────────────────────────────────────────────
//  Rapor Yazıcı
// ─────────────────────────────────────────────

func writeReport(
	results []analyzer.Result,
	stats *analyzer.Stats,
	pStats *parser.ParseStats,
	cfg cliConfig,
) string {
	if err := os.MkdirAll(cfg.output, 0750); err != nil {
		fatal("Çıktı dizini oluşturulamadı", err)
	}

	ts := time.Now().Format("20060102-150405")
	path := filepath.Join(cfg.output, fmt.Sprintf("cyberlens-%s.txt", ts))

	f, err := os.Create(path)
	if err != nil {
		fatal("Rapor dosyası açılamadı", err)
	}
	defer f.Close()

	w := func(format string, a ...any) {
		fmt.Fprintf(f, format+"\n", a...)
	}
	line := func(ch string) { w(strings.Repeat(ch, 65)) }

	// ── Başlık ──
	line("═")
	w("  CYBERLENS")
	line("═")
	w("  Oluşturma  : %s", time.Now().Format("2006-01-02 15:04:05"))
	w("  Platform   : %s", orAll(cfg.platforms))
	w("  Taktik     : %s", orAll(cfg.tactics))
	w("  Kaynak     : MITRE ATT&CK Enterprise (Canlı)")
	w("")

	// ── Veri Kalitesi ──
	line("─")
	w("  VERİ KALİTESİ")
	line("─")
	w("  Toplam STIX Nesnesi  : %d", pStats.TotalObjects)
	w("  Attack-Pattern       : %d", pStats.AttackPatterns)
	w("  Deprecated/Revoked   : %d (elendi)", pStats.SkippedRevoked)
	w("  ID'siz               : %d (elendi)", pStats.SkippedNoID)
	w("  Analiz Edilen        : %d", pStats.FinalTechniques)
	w("")

	// ── Risk Özeti ──
	line("─")
	w("  RİSK ÖZETİ")
	line("─")
	w("  Filtre Eşleşmesi     : %d teknik", stats.Matched)
	w("  CRITICAL             : %d", stats.Critical)
	w("  HIGH                 : %d", stats.High)
	w("  MEDIUM               : %d", stats.Medium)
	w("  LOW                  : %d", stats.Low)
	w("  Ortalama Risk Skoru  : %.1f / 100", stats.AvgScore)
	w("  En Sık Taktik        : %s", orDash(stats.TopTactic))
	w("")

	// ── Teknik Detayları ──
	line("═")
	w("  TEKNİK DETAYLARI  (%d teknik)", len(results))
	line("═")

	for i, r := range results {
		t := r.Technique
		w("")
		w("  [%d]  %s — %s", i+1, t.ID, t.Name)
		w("       Risk Skoru    : %.1f / 100  [%s]", r.RiskScore, r.RiskLevel)
		w("       Versiyon      : %s  |  Güncelleme: %s", orDash(t.Version), orDash(t.Modified))
		w("       Platformlar   : %s", joinOrDash(t.Platforms))
		w("       Kill Chain    : %s", r.TacticChain)

		if len(t.DataSources) > 0 {
			w("       Veri Kaynakları: %s", strings.Join(t.DataSources, " · "))
		} else {
			w("       Veri Kaynakları: ⚠ YOK — algılama kapasitesi sıfır")
		}

		if len(t.DefensesBypassed) > 0 {
			w("       Savunma Bypass : %s", strings.Join(t.DefensesBypassed, ", "))
		}
		if len(t.Permissions) > 0 {
			w("       Gerekli Yetki  : %s", strings.Join(t.Permissions, ", "))
		}
		if t.NetworkReq {
			w("       Ağ Gereksinimi : Evet")
		}

		// Risk faktörleri — neden bu kadar riskli?
		if len(r.RiskFactors) > 0 {
			w("       Risk Faktörleri:")
			for _, rf := range r.RiskFactors {
				w("         +%.0f  %s", rf.Points, rf.Label)
			}
		}

		// Savunma önerisi
		if t.DetectionHint != "" {
			w("       Algılama İpucu : %s", truncate(t.DetectionHint, 220))
		}

		line("·")
	}

	// ── Kapanış ──
	w("")
	w("  Rapor sonu · CyberLens Scout · %s", time.Now().Format("2006"))
	line("═")

	return path
}

// ─────────────────────────────────────────────
//  Yardımcı Fonksiyonlar
// ─────────────────────────────────────────────

// splitFlag, virgülle ayrılmış flag değerini temizlenmiş dilime çevirir.
func splitFlag(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func orAll(s string) string {
	if strings.TrimSpace(s) == "" {
		return "Tümü (filtre yok)"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func joinOrDash(ss []string) string {
	if len(ss) == 0 {
		return "—"
	}
	return strings.Join(ss, ", ")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// fatal, hataları standart formatta stderr'e yazar ve programı sonlandırır.
// panic yerine os.Exit → stack trace'siz temiz hata mesajı.
func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "\n  [HATA] %s: %v\n\n", msg, err)
	os.Exit(1)
}
