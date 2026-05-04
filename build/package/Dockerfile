# Build go
FROM --platform=$BUILDPLATFORM golang:1.25.6-alpine AS builder

WORKDIR /app
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

ENV CGO_ENABLED=0
RUN go mod download
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -v -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o anytls-node ./cmd/server

# Release
FROM alpine
# Install dependencies
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

COPY --from=builder /app/anytls-node /usr/local/bin
ENTRYPOINT ["anytls-node"]
