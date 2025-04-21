package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const version = "v0.2.0"

var (
	defaultInterval, _ = time.ParseDuration("12h")

	// CLI flags
	flagAddress    = flag.String("address", "0.0.0.0:9099", "HTTP listen address")
	flagDomainFile = flag.String("domain-file", "", "Path to file with domains (separated by newlines)")
	flagInterval   = flag.Duration("interval", defaultInterval, "Interval to check domains at")
	flagQuiet      = flag.Bool("q", false, "Quiet mode: don't print domains being monitored")
	flagVersion    = flag.Bool("version", false, "Print the rdap_exporter version")

	// Prometheus metrics
	domainExpiration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "domain_expiration",
			Help: "Days until the RDAP expiration event states this domain will expire",
		},
		[]string{"domain"},
	)

	defaultDateFormats = []string{
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	}
)

func init() {
	prometheus.MustRegister(domainExpiration)
}

func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Println(version)
		os.Exit(1)
	}

	log.Printf("starting rdap_exporter (%s)", version)

	if *flagDomainFile == "" {
		log.Fatalf("no -domain-file specified")
	}

	domains, err := readDomainFile(*flagDomainFile)
	if err != nil {
		log.Fatalf("error getting domains %q: %v", *flagDomainFile, err)
	}
	if !*flagQuiet {
		for _, d := range domains {
			log.Printf("INFO monitoring %s", d)
		}
	}

	check := &checker{
		domains:    domains,
		handler:    domainExpiration,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		interval:   *flagInterval,
	}

	go check.checkAll()

	http.Handle("/metrics", promhttp.Handler())

	log.Printf("listening on %s", *flagAddress)

	server := &http.Server{
		Addr:              *flagAddress,
		Handler:           nil,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("ERROR binding to %s: %v", *flagAddress, err)
	}
}

type checker struct {
	domains    []string
	handler    *prometheus.GaugeVec
	httpClient *http.Client
	t          *time.Ticker
	interval   time.Duration
}

func (c *checker) checkAll() {
	if c.t == nil {
		c.t = time.NewTicker(c.interval)
		c.checkNow()
	}
	for range c.t.C {
		c.checkNow()
	}
}

func (c *checker) checkNow() {
	for _, domain := range c.domains {
		expiration, err := c.getExpiration(domain)
		if err != nil {
			log.Printf("error getting RDAP expiration for %s: %v", domain, err)
			c.handler.WithLabelValues(domain).Set(0)
			continue
		}
		days := math.Floor(time.Until(*expiration).Hours() / 24)
		c.handler.WithLabelValues(domain).Set(days)
		log.Printf("%s expires in %.2f days", domain, days)
	}
}

func (c *checker) getExpiration(domain string) (*time.Time, error) {
	url := fmt.Sprintf("https://rdap.godaddy.com/v1/domain/%s", domain)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error querying RDAP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	var result struct {
		Events []struct {
			EventAction string `json:"eventAction"`
			EventDate   string `json:"eventDate"`
		} `json:"events"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	for _, event := range result.Events {
		if event.EventAction == "expiration" {
			for _, format := range defaultDateFormats {
				if t, err := time.Parse(format, event.EventDate); err == nil {
					return &t, nil
				}
			}
			return nil, fmt.Errorf("couldn't parse expiration date: %q", event.EventDate)
		}
	}

	return nil, fmt.Errorf("no expiration event found")
}

func readDomainFile(where string) ([]string, error) {
	fullPath, err := filepath.Abs(where)
	if err != nil {
		return nil, fmt.Errorf("when expanding %s: %v", *flagDomainFile, err)
	}

	fd, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("when opening %s: %v", fullPath, err)
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	var domains []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			domains = append(domains, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading domain file: %v", err)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains found in %s", fullPath)
	}
	return domains, nil
}
