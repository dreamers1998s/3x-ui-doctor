GO ?= go

.PHONY: test race vet fuzz vuln build cross

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fuzz:
	$(GO) test ./internal/subscription -run '^$$' -fuzz FuzzParseRaw -fuzztime 5s

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

build:
	$(GO) build -trimpath -o bin/xui-doctor ./cmd/xui-doctor

cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o dist/xui-doctor-linux-amd64 ./cmd/xui-doctor
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o dist/xui-doctor-linux-arm64 ./cmd/xui-doctor
