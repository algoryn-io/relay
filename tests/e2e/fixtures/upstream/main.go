package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
)

func main() {
	var (
		listen   = flag.String("listen", ":8080", "listen address")
		name     = flag.String("name", "upstream", "response name")
		certFile = flag.String("tls-cert", "", "server certificate")
		keyFile  = flag.String("tls-key", "", "server private key")
		clientCA = flag.String("client-ca", "", "CA used to verify client certificates")
	)
	flag.Parse()

	var healthChecks atomic.Uint64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			healthChecks.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/health-count" {
			_, _ = fmt.Fprintf(w, "%d", healthChecks.Load())
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "%s:%s", *name, r.URL.Path)
	})

	server := &http.Server{
		Addr:    *listen,
		Handler: handler,
	}
	if *clientCA != "" {
		pem, err := os.ReadFile(*clientCA)
		if err != nil {
			log.Fatalf("read client CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatal("client CA contains no certificates")
		}
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		}
	}

	var err error
	if *certFile != "" || *keyFile != "" {
		err = server.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
