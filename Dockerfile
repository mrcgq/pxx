


# 多阶段构建
FROM golang:1.23-alpine AS builder

WORKDIR /app

# 安装依赖
RUN apk add --no-cache git ca-certificates

# 复制模块文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源码
COPY . .

# 构建
ARG VERSION=dev
ARG BUILD_TIME
ARG GIT_COMMIT

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
        -X 'main.Version=${VERSION}' \
        -X 'main.BuildTime=${BUILD_TIME}' \
        -X 'main.GitCommit=${GIT_COMMIT}'" \
    -o phantom-x-server ./cmd/server

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
        -X 'main.Version=${VERSION}' \
        -X 'main.BuildTime=${BUILD_TIME}' \
        -X 'main.GitCommit=${GIT_COMMIT}'" \
    -o phantom-x-client ./cmd/client

# 服务端镜像
FROM alpine:3.19 AS server

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/phantom-x-server /app/
COPY configs/server.example.yaml /app/config.yaml

EXPOSE 443

ENTRYPOINT ["/app/phantom-x-server"]
CMD ["-c", "/app/config.yaml"]

# 客户端镜像
FROM alpine:3.19 AS client

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/phantom-x-client /app/
COPY configs/client.example.yaml /app/config.yaml

EXPOSE 1080

ENTRYPOINT ["/app/phantom-x-client"]
CMD ["-c", "/app/config.yaml"]

