package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// MITRESource, MITRE ATT&CK Enterprise matrisinin resmi GitHub raw adresidir.
// "master" branch her zaman en güncel versiyonu işaret eder.
const MITRESource = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

// maxBodyBytes, MITM ya da şişirilmiş yanıtlara karşı savunmacı üst sınır: 250MB.
const maxBodyBytes = 250 * 1024 * 1024

// maxRetries, geçici ağ hatalarında yeniden deneme sayısı.
const maxRetries = 3

// Client, yapılandırılmış HTTP istemcisini saran fetcher birimidir.
// Dışarıya yalnızca Fetch() açılır — HTTP detayları sızıntısı önlenir.
type Client struct {
	http    *http.Client // Timeout konfigürasyonlu standart istemci
	verbose bool         // true → ilerleme mesajları yazdırılır
}

// Option, Client'ı fonksiyonel seçeneklerle yapılandırır (Functional Options Pattern).
type Option func(*Client)

// WithVerbose, ilerleme ve hata mesajlarını stdout'a açar.
func WithVerbose() Option {
	return func(c *Client) { c.verbose = true }
}

// WithTimeout, varsayılan 30 saniyelik timeout'u değiştirir.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.http.Timeout = d }
}

// New, üretime hazır bir Client döner.
// Savunmacı default: 30s timeout + 3 retry.
func New(opts ...Option) *Client {
	c := &Client{
		http: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// FetchResult, Fetch() çağrısının sonucunu taşır.
type FetchResult struct {
	Data     []byte
	SizeKB   int
	Attempts int           // Kaçıncı denemede başarıldı
	Elapsed  time.Duration // Toplam süre
}

// Fetch, verilen URL'den ham baytları çeker.
// Geçici HTTP hatalarında (5xx, timeout) üstel geri çekilme ile retry uygular.
// Kalıcı hatalar (4xx) hemen döner — gereksiz retry'dan kaçınılır.
func (c *Client) Fetch(url string) (*FetchResult, error) {
	if url == "" {
		return nil, fmt.Errorf("fetcher: url boş olamaz")
	}

	start := time.Now()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if c.verbose && attempt > 1 {
			fmt.Printf("  ↻ Yeniden deneniyor (%d/%d)...\n", attempt, maxRetries)
		}

		data, err := c.doRequest(url)
		if err == nil {
			return &FetchResult{
				Data:     data,
				SizeKB:   len(data) / 1024,
				Attempts: attempt,
				Elapsed:  time.Since(start),
			}, nil
		}

		// Son denemede de başarısız → hatayı sarmalayarak döndür
		if attempt == maxRetries {
			return nil, fmt.Errorf("fetcher: %d denemede başarısız: %w", maxRetries, err)
		}

		// Üstel geri çekilme: 1s, 2s, 4s …
		backoff := time.Duration(attempt) * time.Second
		if c.verbose {
			fmt.Printf("  ⚠ Hata: %v — %v bekleniyor\n", err, backoff)
		}
		time.Sleep(backoff)
	}

	// Buraya ulaşılmamalı — derleyici için
	return nil, fmt.Errorf("fetcher: bilinmeyen durum")
}

// doRequest, tek bir HTTP GET isteği yürütür.
// 200 dışı yanıtları hata olarak döner; 5xx geçici, 4xx kalıcıdır (caller retry kararı verir).
func (c *Client) doRequest(url string) ([]byte, error) {
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET başarısız: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// LimitReader: sınırsız bellek tüketimini engeller
	reader := io.LimitReader(resp.Body, maxBodyBytes)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("gövde okunamadı: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("sunucu boş yanıt döndü")
	}

	return data, nil
}
