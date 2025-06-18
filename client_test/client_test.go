package client_test

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/seoyhaein/go-grpc-kit/client"
	"github.com/seoyhaein/go-grpc-kit/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDialInsecureSuccess verifies that Dial with insecure credentials can connect to a plain gRPC server.
func TestDialInsecureSuccess(t *testing.T) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	srv := grpc.NewServer()
	defer srv.Stop()
	go srv.Serve(lis)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := client.Dial(ctx, lis.Addr().String(), client.WithInsecure(), client.WithDialOption(grpc.WithBlock()))
	if err != nil {
		t.Fatalf("client.Dial failed: %v", err)
	}
	defer cc.Close()

	if cc.GetState() != connectivity.Ready {
		t.Errorf("expected state READY, got %v", cc.GetState())
	}
}

// TestDialInsecureTimeout verifies that Dial with insecure credentials times out when no server is listening.
func TestDialInsecureTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := client.Dial(ctx, "localhost:9", client.WithInsecure(), client.WithDialOption(grpc.WithBlock()))
	if err == nil {
		t.Fatalf("expected error when dialing closed port, got nil")
	} else {
		t.Logf("expected error received: %v", err)
	}
}

// TestDialTLSSuccess verifies that Dial with TLS credentials can connect to a mTLS-server configured for server-only auth.
func TestDialTLSSuccess(t *testing.T) {
	// 1) Generate self-signed CA and server cert/key
	caCert, caKey, err := utils.GenerateSelfSignedCA(1 * time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA failed: %v", err)
	}
	serverCert, err := utils.GenerateServerCert(caCert, caKey, "localhost", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateServerCert failed: %v", err)
	}

	// 2) Start gRPC server with TLS
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{*serverCert}}
	servCreds := credentials.NewTLS(tlsCfg)
	lis, _ := net.Listen("tcp", "localhost:0")
	srv := grpc.NewServer(grpc.Creds(servCreds))
	defer srv.Stop()
	go srv.Serve(lis)

	// 3) Write CA cert to temp file for client
	tmpDir := t.TempDir()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA pem: %v", err)
	}

	// 4) Dial with TLS
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := client.Dial(ctx, lis.Addr().String(), client.WithTLS(caFile), client.WithDialOption(grpc.WithBlock()))
	if err != nil {
		t.Fatalf("TLS Dial failed: %v", err)
	}
	defer cc.Close()

	if cc.GetState() != connectivity.Ready {
		t.Errorf("expected state READY, got %v", cc.GetState())
	}
}

// TestDialMTLSSuccess verifies that Dial with mutual TLS credentials can connect to a mTLS-enabled server.
func TestDialMTLSSuccess(t *testing.T) {
	// 1) Generate CA, server, and client certs
	caCert, caKey, err := utils.GenerateSelfSignedCA(1 * time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA failed: %v", err)
	}
	serverCert, err := utils.GenerateServerCert(caCert, caKey, "localhost", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateServerCert failed: %v", err)
	}
	clientCert, err := utils.GenerateClientCert(caCert, caKey, "client", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateClientCert failed: %v", err)
	}

	// 2) Start gRPC server with mTLS
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	servCreds := credentials.NewTLS(tlsCfg)
	lis, _ := net.Listen("tcp", "localhost:0")
	srv := grpc.NewServer(grpc.Creds(servCreds))
	defer srv.Stop()
	go srv.Serve(lis)

	// 3) Write certs to temp files for client
	tmpDir := t.TempDir()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA pem: %v", err)
	}

	// write client cert
	certPEMBlock := &pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Certificate[0]}
	certFile := filepath.Join(tmpDir, "client.crt")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(certPEMBlock), 0644); err != nil {
		t.Fatalf("failed to write client cert: %v", err)
	}

	// write client key
	clientKey, ok := clientCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("client private key is not RSA: %T", clientCert.PrivateKey)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(clientKey)
	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	keyFile := filepath.Join(tmpDir, "client.key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		t.Fatalf("failed to write client key: %v", err)
	}

	// 4) Dial with mTLS
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := client.Dial(ctx, lis.Addr().String(), client.WithMTLS(certFile, keyFile, caFile), client.WithDialOption(grpc.WithBlock()))
	if err != nil {
		t.Fatalf("mTLS Dial failed: %v", err)
	}
	defer cc.Close()

	if cc.GetState() != connectivity.Ready {
		t.Errorf("expected state READY, got %v", cc.GetState())
	}
}
