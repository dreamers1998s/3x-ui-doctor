# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.1.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags="-s -w -X github.com/3x-ui-doctor/3x-ui-doctor/internal/version.Version=${VERSION}" \
      -o /out/xui-doctor ./cmd/xui-doctor

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=0.1.0-dev
LABEL org.opencontainers.image.title="3x-ui Doctor" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/3x-ui-doctor/3x-ui-doctor" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/xui-doctor /usr/local/bin/xui-doctor
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/xui-doctor"]
