package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	globallog "github.com/seoyhaein/go-grpc-kit/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

var logger = globallog.Log

func init() {
	// TODO: Prometheus 적용 예정
}

type RegisterServices func(*grpc.Server)

// 기본값 상수들
const (
	defaultMaxRequestBytes          = 4 << 20 // 예: 4MiB
	defaultGrpcOverheadBytes        = 1 << 20 // 예: 1MiB
	defaultMaxSendBytes             = 4 << 20
	defaultMaxStreams        uint32 = 100
)

// options 은 functional 옵션을 누적할 구조체
type options struct {
	unaryInterceptors  []grpc.UnaryServerInterceptor
	streamInterceptors []grpc.StreamServerInterceptor
}

// Option 은 DefaultServerOptions 에 전달할 수 있는 functional 옵션 타입
type Option func(*options)

// WithUnaryInterceptors 는 추가 Unary 인터셉터를 등록
func WithUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) Option {
	return func(o *options) {
		o.unaryInterceptors = append(o.unaryInterceptors, interceptors...)
	}
}

// WithStreamInterceptors 는 추가 Stream 인터셉터를 등록
func WithStreamInterceptors(interceptors ...grpc.StreamServerInterceptor) Option {
	return func(o *options) {
		o.streamInterceptors = append(o.streamInterceptors, interceptors...)
	}
}

// DefaultServerOptions 는 functional 옵션들을 받아 grpc.ServerOption 리스트 반환
func DefaultServerOptions(opts ...Option) []grpc.ServerOption {
	cfg := &options{
		unaryInterceptors:  []grpc.UnaryServerInterceptor{loggingInterceptor},
		streamInterceptors: []grpc.StreamServerInterceptor{streamLoggingInterceptor},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	maxRecv := getEnvInt("GRPC_MAX_RECV_MSG_SIZE", int(defaultMaxRequestBytes))
	maxSend := getEnvInt("GRPC_MAX_SEND_MSG_SIZE", defaultMaxSendBytes)
	maxStreams := getEnvInt("GRPC_MAX_CONCURRENT_STREAMS", int(defaultMaxStreams))

	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(cfg.unaryInterceptors...),
		grpc.ChainStreamInterceptor(cfg.streamInterceptors...),
		grpc.MaxRecvMsgSize(maxRecv),
		grpc.MaxSendMsgSize(maxSend),
		grpc.MaxConcurrentStreams(uint32(maxStreams)),
	}
}

// WithTLS 는 TLS 인증서를 grpc 서버에 적용할 수 있는 ServerOption 반환
func WithTLS(certFile, keyFile string) grpc.ServerOption {
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		logger.Fatalf("failed to load TLS credentials: %v", err)
	}
	return grpc.Creds(creds)
}

// WithMTLS 는 mTLS용 ServerOption을 반환합니다.
// - certFile: 서버 인증서 (PEM)
// - keyFile: 서버 개인키 (PEM)
// - caFile: 신뢰할 CA 인증서 (PEM)
func WithMTLS(certFile, keyFile, caFile string) grpc.ServerOption {
	// 1) 서버 인증서/키 로드
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server key pair: %v", err)
	}

	// 2) CA 인증서 로드
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA cert: %v", err)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caPEM); !ok {
		log.Fatalf("failed to append CA cert to pool")
	}

	// 3) TLS 설정: 클라이언트 인증서 필수 및 검증
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	return grpc.Creds(creds)
}

// WithHealthCheck 는 grpc 서버에 Health Check 서비스를 등록하는 콜백을 반환
func WithHealthCheck() RegisterServices {
	return func(grpcServer *grpc.Server) {
		healthServer := health.NewServer()
		grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	}
}

// WithReflection 는 grpc 서버에 Reflection 서비스를 등록하는 콜백을 반환
func WithReflection() RegisterServices {
	return func(grpcServer *grpc.Server) {
		reflection.Register(grpcServer)
	}
}

// Server 함수는 서비스 등록 함수(들)을 variadic 인자로 받는다
func Server(address string, opts []grpc.ServerOption, registerServices ...RegisterServices) error {
	lis, err := net.Listen("tcp", address)
	if err != nil {

		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	// ServerOption 설정
	grpcServer := grpc.NewServer(opts...)

	// RegisterServices 를 순회하며 각 서비스 등록
	for _, registerServiceServer := range registerServices {
		registerServiceServer(grpcServer)
	}
	// graceful shutdown 처리 추가
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Infof("Received signal: %v. Initiating graceful shutdown...", sig)
		// GracefulStop 은 현재 처리 중인 요청을 모두 완료한 후 서버를 중지함
		grpcServer.GracefulStop()
	}()
	// 서버 시작
	serveErr := grpcServer.Serve(lis)
	if serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
		return serveErr
	}
	return nil
}

// 값이 없거나 잘못된 경우 defaultVal 을 반환
func getEnvInt(key string, defaultVal int) int {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		logger.Warnf("Invalid value for %s: %v. Using default: %d", key, err, defaultVal)
		return defaultVal
	}
	return val
}

// gRPC 요청을 받을 때마다 요청 메서드와 에러 정보를 로깅함
// Unary gRPC 요청 로깅 인터셉터
func loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	logger.Infof("Received request for %s", info.FullMethod)
	resp, err := handler(ctx, req)
	if err != nil {
		logger.Warnf("Method %s error: %v", info.FullMethod, err)
	}
	return resp, err
}

// Stream gRPC 요청 로깅 인터셉터
func streamLoggingInterceptor(
	srv interface{},
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	logger.Infof("[Stream] Start - %s", info.FullMethod)
	err := handler(srv, ss)
	if err != nil {
		logger.Warnf("[Stream] Method %s error: %v", info.FullMethod, err)
	}
	return err
}
