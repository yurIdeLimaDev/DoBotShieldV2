package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"dobotshield/blocklist"
	"dobotshield/config"
	"dobotshield/middleware"
	"dobotshield/ratelimit"
	"dobotshield/traininglog"
	"dobotshield/waf"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if cfg.InsecureSkipVerify {
		log.Print("[CONFIG_WARNING] INSECURE_SKIP_VERIFY is enabled; upstream TLS certificates will not be authenticated")
	}

	traininglog.Configure(cfg.TrainingEnabled(), cfg.TrainingLogFile)
	defer traininglog.CloseDefault()
	customRules, err := waf.LoadCustomRules(cfg.CustomRulesFile)
	if err != nil {
		return fmt.Errorf("load CUSTOM_RULES_FILE: %w", err)
	}

	blockList := blocklist.New(cfg.BlockedIPs)
	limiter := ratelimit.NewManager(cfg.MaxTrackedIPs, cfg.RateLimit, cfg.BurstLimit, cfg.MaxConnsPerIP)
	if err := limiter.LoadState(cfg.RateLimitStateFile); err != nil {
		return fmt.Errorf("load rate-limit state: %w", err)
	}

	proxy, err := middleware.BuildProxyWithRules(cfg, customRules)
	if err != nil {
		return fmt.Errorf("build reverse proxy: %w", err)
	}
	webSocketProxy, err := middleware.BuildWebSocketProxy(cfg, customRules)
	if err != nil {
		return fmt.Errorf("build WebSocket proxy: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", middleware.MakeSecureHandlerWithProtection(proxy, webSocketProxy, limiter, blockList, cfg, customRules))

	server := &http.Server{
		Addr:              cfg.ProxyPort,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	printBanner(cfg)

	processContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	maintenanceContext, stopMaintenance := context.WithCancel(context.Background())
	var maintenance sync.WaitGroup
	maintenance.Add(1)
	go func() {
		defer maintenance.Done()
		runMaintenance(maintenanceContext, limiter, cfg.RateLimitStateFile)
	}()

	serverErrors := make(chan error, 1)
	go func() {
		if cfg.HTTPMode {
			serverErrors <- server.ListenAndServe()
			return
		}
		serverErrors <- server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	}()

	select {
	case serveErr := <-serverErrors:
		stopMaintenance()
		maintenance.Wait()
		saveRateLimitState(limiter, cfg.RateLimitStateFile)
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve DoBot Shield: %w", serveErr)
	case <-processContext.Done():
		log.Print("[SHUTDOWN] stopping DoBot Shield")
	}

	stopMaintenance()
	maintenance.Wait()

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShutdown()
	shutdownErr := server.Shutdown(shutdownContext)
	saveRateLimitState(limiter, cfg.RateLimitStateFile)
	if shutdownErr != nil {
		return fmt.Errorf("graceful shutdown: %w", shutdownErr)
	}
	return nil
}

func runMaintenance(ctx context.Context, limiter *ratelimit.Manager, stateFile string) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			limiter.Cleanup()
			saveRateLimitState(limiter, stateFile)
		}
	}
}

func saveRateLimitState(limiter *ratelimit.Manager, stateFile string) {
	if stateFile == "" {
		return
	}
	if err := limiter.SaveState(stateFile); err != nil {
		log.Printf("[STATE_ERROR] could not save rate-limit state: %v", err)
	}
}

func printBanner(cfg config.Config) {
	protocol := "HTTPS"
	scheme := "https"
	if cfg.HTTPMode {
		protocol = "HTTP"
		scheme = "http"
	}
	listenAddress := cfg.ProxyPort
	if len(listenAddress) > 0 && listenAddress[0] == ':' {
		listenAddress = "localhost" + listenAddress
	}

	fmt.Println("--------------------------------------------")
	fmt.Println("  DoBot Shield")
	fmt.Printf("  Protocol:          %s\n", protocol)
	fmt.Printf("  Access URL:        %s://%s\n", scheme, listenAddress)
	fmt.Printf("  Proxy:             %s -> %s\n", cfg.ProxyPort, cfg.TargetURL)
	fmt.Printf("  WAF:               %v (%s)\n", cfg.EnableSanitizer, cfg.WAFMode)
	fmt.Printf("  Response inspect:  %v\n", cfg.EnableResponseInspection)
	fmt.Printf("  WebSocket inspect: %v\n", cfg.EnableWebSocketProtection)
	if cfg.CustomRulesFile != "" {
		fmt.Printf("  Custom rules:      %s\n", cfg.CustomRulesFile)
	}
	fmt.Printf("  Rate limiting:     %v\n", cfg.EnableRateLimit)
	if count := len(cfg.BlockedIPs); count > 0 {
		fmt.Printf("  Blocked IP rules:  %d\n", count)
	}
	if cfg.RateLimitStateFile != "" {
		fmt.Printf("  State file:        %s\n", cfg.RateLimitStateFile)
	}
	upstreamTLS := "verified"
	if cfg.InsecureSkipVerify {
		upstreamTLS = "certificate verification disabled"
	}
	fmt.Printf("  Upstream TLS:      %s\n", upstreamTLS)
	fmt.Println("--------------------------------------------")
}
