package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"
)

const (
	addrValid = ":8000"
	addrNoSAN = ":8001"
)

func generateCert(certFile, keyFile io.Writer, dnsNames []string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("Failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Test subject"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),

		DNSNames: dnsNames,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	parent := template
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &parent, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}

	return nil
}

func valid(ctx context.Context, wg *sync.WaitGroup) {
	certFile, err := os.CreateTemp("", "certcheck-cert")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "certcheck-key")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(keyFile.Name())

	if err := generateCert(certFile, keyFile, []string{"example.com"}); err != nil {
		log.Fatal(err)
	}

	if err := certFile.Close(); err != nil {
		log.Fatal(err)
	}
	if err := keyFile.Close(); err != nil {
		log.Fatal(err)
	}

	srv := http.Server{
		Addr:    addrValid,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}

	go func() {
		<-ctx.Done()
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		wg.Done()
	}()

	if err := srv.ListenAndServeTLS(certFile.Name(), keyFile.Name()); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func nosan(ctx context.Context, wg *sync.WaitGroup) {
	certFile, err := os.CreateTemp("", "certcheck-cert")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "certcheck-key")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(keyFile.Name())

	if err := generateCert(certFile, keyFile, nil); err != nil {
		log.Fatal(err)
	}

	if err := certFile.Close(); err != nil {
		log.Fatal(err)
	}
	if err := keyFile.Close(); err != nil {
		log.Fatal(err)
	}

	srv := http.Server{
		Addr:    addrNoSAN,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}

	go func() {
		<-ctx.Done()
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		wg.Done()
	}()

	if err := srv.ListenAndServeTLS(certFile.Name(), keyFile.Name()); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	wg := new(sync.WaitGroup)

	wg.Add(1)
	go nosan(ctx, wg)

	wg.Add(1)
	go valid(ctx, wg)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	fmt.Println("Servers running. Hit ctrl-c to shutdown.")

	<-c
	cancel()

	wg.Wait()
}
