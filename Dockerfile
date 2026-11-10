# ============================================================
#  网络仪表盘 - 多阶段构建
#
#  国内网络问题：默认使用 DaoCloud 镜像源 + goproxy.cn
#  如果你的环境能直连 Docker Hub / proxy.golang.org，可以覆盖：
#     docker compose build \
#       --build-arg GO_IMAGE=golang:1.23-alpine \
#       --build-arg RUNTIME_IMAGE=alpine:3.20
# ============================================================

ARG GO_IMAGE=docker.m.daocloud.io/library/golang:1.23-alpine
ARG RUNTIME_IMAGE=docker.m.daocloud.io/library/alpine:3.20

# ---------- 构建阶段 ----------
FROM ${GO_IMAGE} AS builder

WORKDIR /app

# 国内 Go 模块代理（拉 golang.org/x/crypto）
ENV GOPROXY=https://goproxy.cn,direct
ENV GOSUMDB=off

# git 供 go mod tidy 使用；阿里云 apk 源更稳
RUN sed -i 's|dl-cdn.alpinelinux.org|mirrors.aliyun.com|g' /etc/apk/repositories 2>/dev/null; \
    apk add --no-cache git

COPY go.mod ./
COPY *.go ./
COPY static/ ./static/

RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o dashboard .

# ---------- 运行阶段 ----------
FROM ${RUNTIME_IMAGE}

RUN sed -i 's|dl-cdn.alpinelinux.org|mirrors.aliyun.com|g' /etc/apk/repositories 2>/dev/null; \
    apk add --no-cache ca-certificates tzdata

ENV TZ=Asia/Shanghai

COPY --from=builder /app/dashboard /usr/local/bin/dashboard

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1 || exit 1

CMD ["dashboard"]
