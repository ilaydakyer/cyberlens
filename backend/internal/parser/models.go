package parser

// ─────────────────────────────────────────────
//  STIX 2.1 Ham Katmanı  (JSON ↔ Go)
// ─────────────────────────────────────────────

// STIXBundle, MITRE ATT&CK JSON dosyasının kök zarfıdır.
type STIXBundle struct {
	Type    string       `json:"type"`
	Objects []STIXObject `json:"objects"`
}

// STIXObject, bundle içindeki her STIX nesnesini temsil eder.
// Gereksiz alanlar kasıtlı olarak dahil edilmemiştir; sadece analiz
// pipeline'ının tükettiği alanlar burada yer alır.
type STIXObject struct {
	Type             string              `json:"type"`                         // "attack-pattern", "malware", "tool" …
	ID               string              `json:"id"`                           // STIX UUID
	Name             string              `json:"name"`                         // İnsan okunabilir teknik adı
	Description      string              `json:"description"`                  // Saldırı açıklaması
	KillChainPhases  []KillChainPhase    `json:"kill_chain_phases"`            // ATT&CK taktik bağlantıları
	ExternalRefs     []ExternalReference `json:"external_references"`          // T-ID, URL
	Platforms        []string            `json:"x_mitre_platforms"`            // Hedef OS/ortamlar
	IsSubtechnique   bool                `json:"x_mitre_is_subtechnique"`      // Alt teknik mi?
	Deprecated       bool                `json:"x_mitre_deprecated"`           // Kullanım dışı
	Revoked          bool                `json:"revoked"`                      // Geri alınmış
	DataSources      []string            `json:"x_mitre_data_sources"`         // Algılama veri kaynakları
	DetectionText    string              `json:"x_mitre_detection"`            // Savunma önerileri
	Version          string              `json:"x_mitre_version"`              // Teknik versiyon numarası
	Modified         string              `json:"modified"`                     // Son güncelleme (ISO 8601)
	Created          string              `json:"created"`                      // Oluşturma tarihi (ISO 8601)
	Permissions      []string            `json:"x_mitre_permissions_required"` // Gerekli yetki seviyesi
	NetworkReq       bool                `json:"x_mitre_network_requirements"` // Ağ bağlantısı gerektirir mi?
	DefensesBypassed []string            `json:"x_mitre_defense_bypassed"`     // Atlatılan savunma mekanizmaları
	ImpactType       []string            `json:"x_mitre_impact_type"`          // Etki türü (availability, integrity…)
}

// KillChainPhase, ATT&CK taktik-teknik ilişkisini tutar.
// Filtrelemede yalnızca "mitre-attack" kill_chain_name'li fazlar kullanılır.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"` // "mitre-attack"
	PhaseName     string `json:"phase_name"`      // "execution", "persistence" …
}

// ExternalReference, ATT&CK teknik ID ve URL'sini içerir.
type ExternalReference struct {
	SourceName string `json:"source_name"` // "mitre-attack" olanı alırız
	ExternalID string `json:"external_id"` // "T1059", "T1059.001"
	URL        string `json:"url"`
}

// ─────────────────────────────────────────────
//  Analiz Katmanı Modeli  (Temiz Alan)
// ─────────────────────────────────────────────

// Technique, ham STIXObject'ten türetilen ve tüm pipeline boyunca
// taşınan tek veri birimidir. Analyzer bu struct'ı okur, RiskScore alanını doldurur.
type Technique struct {
	ID               string // ATT&CK ID: T1059 / T1059.001
	Name             string
	Description      string
	Tactics          []string // kill_chain'den çıkarılan taktik listesi
	Platforms        []string // Windows, Linux, macOS, Azure AD …
	IsSubtechnique   bool
	DataSources      []string // Algılanabilirlik veri kaynakları
	DetectionHint    string   // Analist için savunma metni
	Version          string   // Teknik versiyon
	Modified         string   // Son güncelleme tarihi
	Permissions      []string // Gerekli yetkiler (User, Administrator, root…)
	DefensesBypassed []string // Atlatılan mekanizmalar (UAC, AMSI…)
	ImpactType       []string // Etki türleri (Availability, Data Destruction…)
	NetworkReq       bool     // Ağ bağlantısı gerektiriyor mu?
	RiskScore        float64  // [0–100] Analyzer tarafından hesaplanır
}

// ParseStats, parse aşamasının ürettiği özet sayaçlarıdır.
// Rapordaki "Veri Kalitesi" bölümünü besler.
type ParseStats struct {
	TotalObjects    int
	AttackPatterns  int
	SkippedRevoked  int
	SkippedNoID     int
	FinalTechniques int
}
