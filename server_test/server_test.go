package server_test

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/seoyhaein/go-grpc-kit/server"
	"github.com/seoyhaein/go-grpc-kit/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"net"
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

// healthServerImpl implements the Health service.
type healthServerImpl struct{}

func (s *healthServerImpl) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (s *healthServerImpl) Watch(req *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	return status.Errorf(codes.Unimplemented, "Watch not implemented")
}

func TestServerHealth_MTLS(t *testing.T) {
	// 1) Start the mTLS gRPC server
	srv, caCert, caKey, address, errCh := startMTLSServer(t)

	// 2) Ensure server started without immediate error
	select {
	case serveErr := <-errCh:
		t.Fatalf("server start failed: %v", serveErr)
	default:
	}

	// 3) Plain TCP check
	if conn, err := net.DialTimeout("tcp", address, 1*time.Second); err != nil {
		t.Fatalf("⚠️ TCP connection failed: %v", err)
	} else {
		t.Log("✅ TCP connection OK")
		conn.Close()
	}

	// 4) Generate a client certificate
	clientCert, err := utils.GenerateClientCert(caCert, caKey, "client", 1*time.Hour)
	if err != nil {
		t.Fatalf("client cert generation failed: %v", err)
	}

	// 5) Build tls.Config for the client
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		RootCAs:      rootCAs,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}

	// 6) Plain TLS handshake + ALPN check
	t.Log("🚧 Attempting plain TLS handshake")
	plain, err := tls.Dial("tcp", address, tlsCfg)
	if err != nil {
		t.Fatalf("⚠️ Plain TLS handshake failed: %v", err)
	}
	state := plain.ConnectionState()
	t.Logf("✅ Plain TLS OK, negotiated proto=%q", state.NegotiatedProtocol)
	plain.Close()

	// 7) gRPC DialContext (WithBlock + context timeout)
	t.Log("🚧 Attempting gRPC DialContext with WithBlock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("⚠️ gRPC DialContext failed: %v", err)
	}
	defer conn.Close()
	t.Log("✅ gRPC connection (mTLS+HTTP/2) established")

	// 8) Health.Check RPC
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hc := grpc_health_v1.NewHealthClient(conn)
	resp, err := hc.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health.Check RPC failed: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Errorf("unexpected status: got %v, want SERVING", resp.Status)
	}
	t.Logf("✅ Health.Check RPC succeeded, status=%v", resp.Status)

	// 9) Shutdown the server gracefully
	srv.GracefulStop()

	// 10) Wait for server to exit
	if serveErr := <-errCh; serveErr != nil && serveErr != grpc.ErrServerStopped {
		t.Errorf("server shutdown error: %v", serveErr)
	} else {
		t.Log("✅ Server shut down gracefully")
	}
}

// startMTLSServer starts a gRPC server with mTLS and returns the server, CA credentials, address, and serve error channel.
func startMTLSServer(t *testing.T) (*grpc.Server, *x509.Certificate, *rsa.PrivateKey, string, <-chan error) {
	t.Helper()

	// Generate CA and server certificates
	caCert, caKey, err := utils.GenerateSelfSignedCA(1 * time.Hour)
	if err != nil {
		t.Fatalf("CA generation failed: %v", err)
	}
	serverCert, err := utils.GenerateServerCert(caCert, caKey, "localhost", 1*time.Hour)
	if err != nil {
		t.Fatalf("Server cert generation failed: %v", err)
	}

	// Create server TLS credentials
	servCreds := credentials.NewServerTLSFromCert(serverCert)

	// Listen on a free loopback port
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	// Create and start gRPC server
	grpcSrv := grpc.NewServer(grpc.Creds(servCreds))
	grpc_health_v1.RegisterHealthServer(grpcSrv, &healthServerImpl{})
	reflection.Register(grpcSrv)

	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcSrv.Serve(lis)
	}()

	return grpcSrv, caCert, caKey, lis.Addr().String(), errCh
}
