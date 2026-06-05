package parser

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Parse, ham STIX JSON baytlarını temiz bir []Technique dilimine dönüştürür.
// Deprecated, revoked ve ID'siz nesneler sessizce elenir; istatistik döner.
func Parse(data []byte) ([]Technique, *ParseStats, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("parser: boş veri")
	}

	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, nil, fmt.Errorf("parser: JSON çözümlenemedi: %w", err)
	}

	if bundle.Type != "bundle" {
		return nil, nil, fmt.Errorf("parser: beklenmeyen STIX tipi: %q", bundle.Type)
	}

	stats := &ParseStats{TotalObjects: len(bundle.Objects)}

	techniques := make([]Technique, 0, stats.TotalObjects/3) // Kapasite tahmini

	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" {
			continue
		}
		stats.AttackPatterns++

		// Artık kullanılmayan ya da geri alınmış teknikleri analize sokma
		if obj.Deprecated || obj.Revoked {
			stats.SkippedRevoked++
			continue
		}

		attackID := extractAttackID(obj.ExternalRefs)
		if attackID == "" {
			stats.SkippedNoID++
			continue
		}

		techniques = append(techniques, Technique{
			ID:               attackID,
			Name:             obj.Name,
			Description:      obj.Description,
			Tactics:          extractTactics(obj.KillChainPhases),
			Platforms:        normalizePlatforms(obj.Platforms),
			IsSubtechnique:   obj.IsSubtechnique,
			DataSources:      obj.DataSources,
			DetectionHint:    obj.DetectionText,
			Version:          obj.Version,
			Modified:         obj.Modified,
			Permissions:      obj.Permissions,
			DefensesBypassed: obj.DefensesBypassed,
			ImpactType:       obj.ImpactType,
			NetworkReq:       obj.NetworkReq,
		})
	}

	stats.FinalTechniques = len(techniques)

	if stats.FinalTechniques == 0 {
		return nil, stats, fmt.Errorf("parser: geçerli teknik bulunamadı (toplam nesne: %d)", stats.TotalObjects)
	}

	return techniques, stats, nil
}

// extractAttackID, ExternalReference listesinden "mitre-attack" kaynaklı teknik ID'yi döner.
// Birden fazla kaynak olabilir; ilk eşleşme alınır.
func extractAttackID(refs []ExternalReference) string {
	for _, r := range refs {
		if r.SourceName == "mitre-attack" && r.ExternalID != "" {
			return r.ExternalID
		}
	}
	return ""
}

// extractTactics, KillChainPhase listesini MITRE ATT&CK taktiklerine filtreler.
// Diğer kill chain framework'leri (örn: LOLBAS, NIST) göz ardı edilir.
func extractTactics(phases []KillChainPhase) []string {
	out := make([]string, 0, len(phases))
	for _, p := range phases {
		if p.KillChainName == "mitre-attack" && p.PhaseName != "" {
			out = append(out, p.PhaseName)
		}
	}
	return out
}

// normalizePlatforms, platform adlarını küçük harfe normalize eder.
// Filtreleme aşamasında EqualFold yerine doğrudan == kullanılabilmesi için.
func normalizePlatforms(platforms []string) []string {
	out := make([]string, 0, len(platforms))
	for _, p := range platforms {
		normalized := strings.ToLower(strings.TrimSpace(p))
		if normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}
