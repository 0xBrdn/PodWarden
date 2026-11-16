# Stage 1 – build
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" \
    -o /podwarden ./cmd/podwarden

# Stage 2 – runtime
FROM gcr.io/distroless/static-debian12:nonroot
USER nonroot:nonroot
COPY --from=builder /podwarden /podwarden
EXPOSE 8080
ENTRYPOINT ["/podwarden"]
