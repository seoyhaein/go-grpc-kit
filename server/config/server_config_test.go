package config

import (
	"testing"
)

func TestLoadServerConfigDefaults(t *testing.T) {

	cfg := LoadServerConfig()
	if cfg.MaxRecvMsgSize != DefaultMaxRequestBytes {
		t.Errorf("MaxRecvMsgSize default = %d; want %d", cfg.MaxRecvMsgSize, DefaultMaxRequestBytes)
	}
	if cfg.MaxSendMsgSize != DefaultMaxSendBytes {
		t.Errorf("MaxSendMsgSize default = %d; want %d", cfg.MaxSendMsgSize, DefaultMaxSendBytes)
	}
	if cfg.MaxConcurrentStreams != DefaultMaxStreams {
		t.Errorf("MaxConcurrentStreams default = %d; want %d", cfg.MaxConcurrentStreams, DefaultMaxStreams)
	}
}

func TestLoadServerConfigEnvOverride(t *testing.T) {
	// Set environment variables to override defaults
	t.Setenv("GRPC_MAX_RECV_MSG_SIZE", "1234")
	t.Setenv("GRPC_MAX_SEND_MSG_SIZE", "2345")
	t.Setenv("GRPC_MAX_CONCURRENT_STREAMS", "42")

	cfg := LoadServerConfig()
	if cfg.MaxRecvMsgSize != 1234 {
		t.Errorf("MaxRecvMsgSize env override = %d; want %d", cfg.MaxRecvMsgSize, 1234)
	}
	if cfg.MaxSendMsgSize != 2345 {
		t.Errorf("MaxSendMsgSize env override = %d; want %d", cfg.MaxSendMsgSize, 2345)
	}
	if cfg.MaxConcurrentStreams != 42 {
		t.Errorf("MaxConcurrentStreams env override = %d; want %d", cfg.MaxConcurrentStreams, 42)
	}
}
