package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cyberlens/internal/analyzer"
	"cyberlens/internal/fetcher"
	"cyberlens/internal/parser"
)

type cliConfig struct {
	output string
	top    int
}

func main() {
	var cfg cliConfig
	flag.StringVar(&cfg.output, "output", "reports", "Rapor dizini")
	flag.IntVar(&cfg.top, "top", 10, "Maksimum teknik")
	flag.Parse()

	client := fetcher.New()
	res, err := client.Fetch(fetcher.MITRESource)
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		os.Exit(1)
	}

	techs, _, _ := parser.Parse(res.Data)
	results, _ := analyzer.Run(techs, analyzer.Config{})

	if len(results) > cfg.top {
		results = results[:cfg.top]
	}

	// JSON olarak dump et (Streamlit entegrasyonu için)
	_ = os.MkdirAll(cfg.output, 0750)
	ts := time.Now().Format("20060102-150405")
	path := filepath.Join(cfg.output, fmt.Sprintf("cyberlens-%s.json", ts))

	file, _ := os.Create(path)
	defer file.Close()
	bytes, _ := json.MarshalIndent(results, "", "  ")
	_, _ = file.Write(bytes)

	fmt.Printf("[+] Motor Calisti. Veri Havuzu Guncellendi -> %s\n", path)
}
