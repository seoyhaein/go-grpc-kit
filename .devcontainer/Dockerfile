# .devcontainer/Dockerfile
FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

# 1) 공통 의존성 설치 tc(netem)용, ping 테스트용  
RUN apt-get update && apt-get install -y --no-install-recommends \
      wget \
      build-essential \
      unzip \
      iproute2 \
      iputils-ping \
      && rm -rf /var/lib/apt/lists/*

# 2) Go 1.22.4 설치
RUN wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz \
      -O go.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# 3) 작업 디렉터리 & 볼륨
WORKDIR /app