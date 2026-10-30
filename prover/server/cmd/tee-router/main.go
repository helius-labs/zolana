package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/helius-labs/zolana/prover/server/router"
)

func run() error {
	bucket := flag.String("registry-bucket", "", "private versioned registry bucket")
	key := flag.String("registry-key", "registry.json", "shared routing registry object")
	region := flag.String("registry-region", "", "AWS region hosting the registry")
	owner := flag.String("registry-owner", "", "AWS account owning the registry and regional origin secrets")
	preferred := flag.String("preferred-region", "", "prefer healthy generations in this region for new attestations")
	var mirrors []router.RegistryMirror
	flag.Func("registry-mirror", "additional region/bucket for the same registry key; repeat for up to two mirrors", func(value string) error {
		region, bucket, ok := strings.Cut(value, "/")
		if !ok || region == "" || bucket == "" {
			return errors.New("registry mirror must be region/bucket")
		}
		mirrors = append(mirrors, router.RegistryMirror{Region: region, Bucket: bucket})
		return nil
	})
	listen := flag.String("listen", "127.0.0.1:3001", "private gateway-facing listener")
	admin := flag.String("admin-listen", "127.0.0.1:9998", "private health/status listener")
	flag.Parse()
	if flag.NArg() != 0 || *region == "" || *bucket == "" || *preferred == "" {
		return errors.New("explicit registry, region and private listener configuration required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	loadCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	cfg, err := config.LoadDefaultConfig(loadCtx, config.WithRegion(*region), config.WithRetryMaxAttempts(2))
	cancel()
	if err != nil {
		return errors.New("AWS credential initialization failed")
	}
	source, err := router.NewAWSSource(cfg, *bucket, *key, *owner, mirrors...)
	if err != nil {
		return err
	}
	proxy, err := router.New(source, os.Getenv("ZOLANA_ROUTER_ORIGIN_KEY"), *preferred)
	if err != nil {
		return errors.New("router configuration rejected; provide a private ingress key")
	}
	publicListener, err := net.Listen("tcp", *listen)
	if err != nil {
		return errors.New("gateway listener failed")
	}
	defer publicListener.Close()
	adminListener, err := net.Listen("tcp", *admin)
	if err != nil {
		return errors.New("admin listener failed")
	}
	defer adminListener.Close()
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/ready", proxy.Ready)
	adminMux.HandleFunc("/status", proxy.Status)
	server := func(handler http.Handler) *http.Server {
		return &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: 11 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	}
	front, health := server(proxy), server(adminMux)
	errorsOut := make(chan error, 2)
	go func() { errorsOut <- front.Serve(publicListener) }()
	go func() { errorsOut <- health.Serve(adminListener) }()
	go proxy.Run(ctx)
	fmt.Printf("TEE router listening on %s; private health on %s\n", publicListener.Addr(), adminListener.Addr())
	var serveError error
	select {
	case <-ctx.Done():
	case err := <-errorsOut:
		if !errors.Is(err, http.ErrServerClosed) {
			serveError = errors.New("router listener stopped unexpectedly")
			stop()
		}
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Minute+5*time.Second)
	defer cancel()
	_ = front.Shutdown(shutdown)
	_ = health.Shutdown(shutdown)
	return serveError
}

func main() {
	if err := run(); err != nil {
		// Errors at this boundary are fixed operator-facing messages, never AWS
		// exceptions, origin URLs, response bodies or credential values.
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
