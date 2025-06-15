package server_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/seoyhaein/go-grpc-kit/server"
	"github.com/seoyhaein/go-grpc-kit/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestServerHealth(t *testing.T) {
	// 테스트용 서버 주소
	address := "localhost:50053"

	// 기본 옵션과 HealthCheck, Reflection 서비스 등록
	opts := server.DefaultServerOptions()
	services := []server.RegisterServices{
		server.WithHealthCheck(),
		server.WithReflection(),
	}

	// 서버 실행
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Server(address, opts, services...)
	}()

	// 서버가 시작될 시간을 잠시 대기
	time.Sleep(200 * time.Millisecond)

	// 서버에 연결
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// deprecated 되었지만 테스트 코드에서는 이 메서드가 더 잘 맞음.
	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // deprecated 되었지만 테스트 코드에서는 이 메서드가 더 잘 맞음.
	)
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer func() {
		if cErr := conn.Close(); cErr != nil {
			t.Logf("Failed to close gRPC connection: %v", cErr)
		}
	}()

	// Health check 호출
	healthClient := grpc_health_v1.NewHealthClient(conn)
	healthResp, err := healthClient.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	if healthResp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Errorf("Expected SERVING, got %v", healthResp.Status)
	}

	// graceful shutdown: SIGINT 전송
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("Failed to find process: %v", err)
	}
	if err := proc.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("Failed to send SIGINT: %v", err)
	}

	// 서버 종료 대기 및 에러 검사
	if err := <-serverErrCh; err != nil {
		t.Errorf("Server shutdown returned error: %v", err)
	}
}

func TestServerHealth_MTLS(t *testing.T) {
	address := "localhost:50054"
	errCh, caCert := startMTLSServer(t, address)

	// Build client TLS config
	tlsCfg := &tls.Config{
		RootCAs:      x509.NewCertPool(),
		Certificates: nil, // no client cert in this simple test
		MinVersion:   tls.VersionTLS12,
	}
	tlsCfg.RootCAs.AddCert(caCert)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("Failed to connect with mTLS: %v", err)
	}
	defer conn.Close()

	// Health check gRPC call
	healthClient := grpc_health_v1.NewHealthClient(conn)
	healthResp, err := healthClient.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	if healthResp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Errorf("Expected SERVING, got %v", healthResp.Status)
	}

	// Signal shutdown
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess error: %v", err)
	}
	if err := proc.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("Failed to send SIGINT: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Errorf("Server shutdown returned error: %v", err)
	}
}

// startMTLSServer sets up a gRPC server with self-signed mTLS for testing.
// Returns the server error channel and the CA certificate to configure client.
func startMTLSServer(t *testing.T, address string) (<-chan error, *x509.Certificate) {
	t.Helper()

	// Generate a self-signed CA and server certificate
	caCert, caKey, err := utils.GenerateSelfSignedCA(1 * time.Hour)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}
	serverCert, err := utils.GenerateCert(caCert, caKey, "localhost", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	// Build TLS config requiring client certs
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
		MinVersion:   tls.VersionTLS12,
	}
	tlsCfg.ClientCAs.AddCert(caCert)

	// Prepare server options with mTLS
	opts := server.DefaultServerOptions()
	opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))

	// Register services
	services := []server.RegisterServices{
		server.WithHealthCheck(),
		server.WithReflection(),
	}

	// Start server
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Server(address, opts, services...)
	}()

	// Give server a moment to start
	time.Sleep(200 * time.Millisecond)
	return errCh, caCert
}
