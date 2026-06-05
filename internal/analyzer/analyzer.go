package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cypherlens/scout/internal/parser"
)

// ─────────────────────────────────────────────
//  Konfigürasyon & Çıktı Modelleri
// ─────────────────────────────────────────────

// Config, analistin CLI'dan ilettiği filtre parametrelerini taşır.
// Boş dilim = "hepsini dahil et" anlamına gelir — explicit opt-in filtering.
type Config struct {
	Platforms []string // Normalleştirilmiş küçük harf platform adları
	Tactics   []string // ATT&CK taktik slug'ları
}

// RiskFactor, skoru etkileyen tek bir neden birimidir.
// Raporda "Neden bu kadar riskli?" sorusunu yanıtlar.
type RiskFactor struct {
	Label  string  // Analist için okunabilir açıklama
	Points float64 // Bu faktörün katkısı
}

// Result, tek bir tekniğin tam analiz çıktısıdır.
type Result struct {
	Technique   parser.Technique
	RiskScore   float64      // [0–100]
	RiskLevel   string       // CRITICAL / HIGH / MEDIUM / LOW
	RiskFactors []RiskFactor // Skoru oluşturan faktörler (şeffaflık)
	TacticChain string       // Kill chain akışının okunabilir özeti
}

// Stats, tüm analiz çalışmasının özet sayaçlarıdır.
type Stats struct {
	Matched   int
	Critical  int
	High      int
	Medium    int
	Low       int
	AvgScore  float64
	TopTactic string // En fazla eşleşen taktik
}

// ─────────────────────────────────────────────
//  Sabit Ağırlık Tablosu
// ─────────────────────────────────────────────

// Kritik taktikler: iş etkisi yüksek, doğrudan veri sızıntısı/imha ile sonuçlanır.
var criticalTactics = map[string]float64{
	"exfiltration":         18,
	"impact":               18,
	"credential-access":    16,
	"privilege-escalation": 15,
	"command-and-control":  14,
	"lateral-movement":     12,
	"defense-evasion":      10,
}

// Yüksek riskli yetkiler: yüksek ayrıcalık seviyesi saldırı yüzeyini genişletir.
var elevatedPermissions = map[string]bool{
	"administrator": true,
	"root":          true,
	"system":        true,
	"kernel":        true,
}

// ─────────────────────────────────────────────
//  Ana Giriş Noktası
// ─────────────────────────────────────────────

// Run, tüm teknikleri filtreler, her birine risk skoru atar,
// azalan skor sırasına göre sıralar ve Stats özeti ile birlikte döner.
func Run(techniques []parser.Technique, cfg Config) ([]Result, *Stats) {
	if len(techniques) == 0 {
		return nil, &Stats{}
	}

	// Normalize: filtreleme için tüm girdileri küçük harfe çek
	filterPlatforms := toLower(cfg.Platforms)
	filterTactics := toLower(cfg.Tactics)

	results := make([]Result, 0, len(techniques)/2)
	tacticHits := make(map[string]int) // İstatistik için taktik sayacı

	for _, t := range techniques {
		if !matchesPlatform(t.Platforms, filterPlatforms) {
			continue
		}
		if !matchesTactic(t.Tactics, filterTactics) {
			continue
		}

		score, factors := score(t)
		level := toLevel(score)

		results = append(results, Result{
			Technique:   t,
			RiskScore:   score,
			RiskLevel:   level,
			RiskFactors: factors,
			TacticChain: buildTacticChain(t.Tactics),
		})

		for _, tac := range t.Tactics {
			tacticHits[tac]++
		}
	}

	// Skora göre azalan sıralama: en kritik teknikler üste gelir
	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})

	stats := buildStats(results, tacticHits)
	return results, stats
}

// ─────────────────────────────────────────────
//  Dinamik Risk Skorlama Motoru
// ─────────────────────────────────────────────

// score, çok boyutlu risk modeli uygulayan temel fonksiyondur.
// Her kural bağımsız bir RiskFactor üretir — şeffaf ve genişletilebilir tasarım.
// Skor bileşenleri:
//   A) Platform Yüzeyi    — hibrit tehdit çarpanı
//   B) Taktik Zinciri     — kill chain derinliği
//   C) Alt Teknik         — spesifik, tespit zorluğu yüksek
//   D) Algılama Açığı     — veri kaynağı eksikliği (Altyapı Körlüğü)
//   E) Kritik Taktik      — iş etkisi çarpanı
//   F) Savunma Atlatma    — defense bypass sayısı
//   G) Yetki Seviyesi     — ayrıcalıklı erişim gereksinimi
//   H) Ağ Bağımlılığı     — lateral movement kolaylığı
//   I) Etki Türü          — veri bütünlüğü/kullanılabilirlik hasarı

func score(t parser.Technique) (float64, []RiskFactor) {
	var total float64
	var factors []RiskFactor

	add := func(label string, pts float64) {
		if pts > 0 {
			total += pts
			factors = append(factors, RiskFactor{Label: label, Points: pts})
		}
	}

	// A) Platform Yüzeyi — birden fazla ortamı etkileyen saldırılar çok daha tehlikelidir
	switch {
	case len(t.Platforms) >= 4:
		add("Çok platform hedefleme (4+): ağ genelinde yayılma potansiyeli", 30)
	case len(t.Platforms) == 3:
		add("Üç platform hedefleme: hibrit ortam riski", 22)
	case len(t.Platforms) == 2:
		add("İki platform hedefleme: çapraz ortam riski", 14)
	case len(t.Platforms) == 1:
		add("Tek platform hedefleme", 5)
	}

	// B) Taktik Zinciri — aynı teknik birden fazla kill chain fazında kullanılabiliyorsa
	// bu saldırganın kampanya esnekliğini gösterir
	if len(t.Tactics) >= 3 {
		add("3+ taktik fazı: tam kampanya desteği (persistence → exfil)", 20)
	} else if len(t.Tactics) == 2 {
		add("Çift taktik fazı: lateral movement veya persistence kombinasyonu", 12)
	}

	// C) Alt Teknik — spesifik varyant, genel imzaları atlatır
	if t.IsSubtechnique {
		add("Alt-teknik: genel algılama imzalarını atlatma kapasitesi", 10)
	}

	// D) Algılama Açığı — "Altyapı Körlüğü" sorununu doğrudan skora yansıtır
	switch {
	case len(t.DataSources) == 0:
		add("KRİTİK ALGI AÇIĞI: Bilinen veri kaynağı yok — analist kör", 25)
	case len(t.DataSources) == 1:
		add("Tek veri kaynağı: tek nokta arıza riski", 14)
	case len(t.DataSources) == 2:
		add("Sınırlı veri kaynağı (2): algılama boşluğu mevcut", 7)
	}

	// E) Kritik Taktik — iş etkisi ağırlıklı bonus
	for _, tac := range t.Tactics {
		if pts, ok := criticalTactics[strings.ToLower(tac)]; ok {
			add("Kritik taktik ["+tac+"]: doğrudan iş etkisi", pts)
			break // Tek bonus — yığılmayı önler; en kötü taktik zaten en üstte gelir
		}
	}

	// F) Savunma Atlatma — bypass sayısı algılama karşı-önlemlerini doğrudan etkiler
	if n := len(t.DefensesBypassed); n > 0 {
		pts := float64(n) * 5
		if pts > 20 {
			pts = 20 // Bonus üst tavanı
		}
		add("Savunma atlatma mekanizmaları ("+itoa(n)+"): UAC/AMSI/AV bypass", pts)
	}

	// G) Yetki Seviyesi — ayrıcalıklı erişim saldırganın hareket alanını genişletir
	for _, perm := range t.Permissions {
		if elevatedPermissions[strings.ToLower(perm)] {
			add("Yüksek yetki gereksinimi ["+perm+"]: admin/root erişimi ile tetiklenir", 8)
			break
		}
	}

	// H) Ağ Bağımlılığı — ağ üzerinden çalışan teknikler lateral movement için kullanılabilir
	if t.NetworkReq {
		add("Ağ bağlantısı gerektirir: C2 iletişimi veya lateral movement vektörü", 6)
	}

	// I) Etki Türü — veri imhası veya kullanılabilirlik kaybı en ağır sonuçlardır
	for _, imp := range t.ImpactType {
		low := strings.ToLower(imp)
		if low == "data destruction" || low == "availability" {
			add("Kritik etki türü ["+imp+"]: kalıcı hasar potansiyeli", 10)
			break
		}
	}

	// Normalleştirme: skor [0, 100] bandında kalır
	if total > 100 {
		total = 100
	}

	return total, factors
}

// ─────────────────────────────────────────────
//  Yardımcı Fonksiyonlar
// ─────────────────────────────────────────────

// toLevel, sayısal skoru SOC standartlarına dayalı risk seviyesine çevirir.
func toLevel(score float64) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 45:
		return "HIGH"
	case score >= 20:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// buildTacticChain, taktik listesinden insan okunabilir kill chain özeti üretir.
// Örn: "initial-access → execution → privilege-escalation"
func buildTacticChain(tactics []string) string {
	if len(tactics) == 0 {
		return "—"
	}
	// ATT&CK kill chain sırasını korumak için önceden tanımlı sıra
	order := []string{
		"reconnaissance", "resource-development", "initial-access",
		"execution", "persistence", "privilege-escalation",
		"defense-evasion", "credential-access", "discovery",
		"lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	}

	tacticSet := make(map[string]bool, len(tactics))
	for _, t := range tactics {
		tacticSet[t] = true
	}

	ordered := make([]string, 0, len(tactics))
	for _, o := range order {
		if tacticSet[o] {
			ordered = append(ordered, o)
		}
	}
	// Bilinmeyen taktikleri sona ekle
	for _, t := range tactics {
		if !contains(ordered, t) {
			ordered = append(ordered, t)
		}
	}

	return strings.Join(ordered, " → ")
}

// matchesPlatform, tekniğin filtre platformlarından en az biriyle örtüştüğünü kontrol eder.
// Her iki taraf da normalize (küçük harf) kabul eder.
func matchesPlatform(techPlatforms, filterPlatforms []string) bool {
	if len(filterPlatforms) == 0 {
		return true
	}
	for _, tp := range techPlatforms {
		for _, fp := range filterPlatforms {
			if tp == fp {
				return true
			}
		}
	}
	return false
}

// matchesTactic, tekniğin filtre taktiklerinden en az biriyle örtüştüğünü kontrol eder.
func matchesTactic(techTactics, filterTactics []string) bool {
	if len(filterTactics) == 0 {
		return true
	}
	for _, tt := range techTactics {
		for _, ft := range filterTactics {
			if strings.ToLower(tt) == ft {
				return true
			}
		}
	}
	return false
}

// buildStats, sonuç listesinden özet sayaçları hesaplar.
func buildStats(results []Result, tacticHits map[string]int) *Stats {
	s := &Stats{Matched: len(results)}
	var totalScore float64

	for _, r := range results {
		totalScore += r.RiskScore
		switch r.RiskLevel {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		default:
			s.Low++
		}
	}

	if len(results) > 0 {
		s.AvgScore = totalScore / float64(len(results))
	}

	// En sık eşleşen taktik
	topCount := 0
	for tac, count := range tacticHits {
		if count > topCount {
			topCount = count
			s.TopTactic = tac
		}
	}

	return s
}

// toLower, string diliminin tüm elemanlarını küçük harfe çevirir.
func toLower(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}

// contains, sırasız string diliminde arama yapar.
func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// itoa, int → string dönüşümü (strconv bağımlılığından kaçınmak için minimal impl).
func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
