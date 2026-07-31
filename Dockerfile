FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY blocklist ./blocklist
COPY config ./config
COPY middleware ./middleware
COPY ratelimit ./ratelimit
COPY traininglog ./traininglog
COPY utils ./utils
COPY waf ./waf

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/dobotshield .

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

RUN apk --no-cache add ca-certificates tzdata \
    && addgroup -S dobotshield \
    && adduser -S -D -H -G dobotshield dobotshield \
    && install -d -o dobotshield -g dobotshield /app

WORKDIR /app
COPY --from=builder --chown=dobotshield:dobotshield /out/dobotshield ./dobotshield

USER dobotshield:dobotshield

EXPOSE 8080

ENV HTTP_MODE=true \
    PROXY_PORT=:8080 \
    TRAINING_MODE=false

ENTRYPOINT ["./dobotshield"]
