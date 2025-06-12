.PHONY: test lint fmt all

# 모든 Go 파일을 포맷팅
fmt:
	go fmt ./...

# 프로젝트 내 모든 Go 패키지 테스트 실행.
# 데이터 경쟁 조건 검사 및 커버리지 요약을 터미널에 바로 표시.
test:
	go test -v -race -cover ./...

# golangci-lint 실행. 코드 품질 및 스타일 검사.
lint:
	golangci-lint run

# fmt, lint, test 순서로 모두 실행.
# 코드 포맷팅 -> 린트 -> 테스트 순서로 진행되어 편리함.
all: fmt lint test