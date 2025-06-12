package server_test

import (
	"context"
	"github.com/seoyhaein/go-grpc-kit/server"
	"google.golang.org/grpc"
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
