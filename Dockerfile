# syntax=docker/dockerfile:1

# Stage 1 - build
FROM golang:1.27-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /podwarden ./cmd/podwarden

# Stage 2 - runtime (no shell, no package manager, non-root)
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="PodWarden" \
      org.opencontainers.image.description="Kubernetes runtime incident response controller" \
      org.opencontainers.image.source="https://github.com/0xBrdn/PodWarden" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /podwarden /podwarden
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/podwarden"]
