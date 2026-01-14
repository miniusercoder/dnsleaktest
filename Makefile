APP_NAME := dnsleaktest
BUILD_DIR := build
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.1-dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# LDFLAGS definition for version injection
LDFLAGS := -s -w -X "main.version=$(VERSION)" -X "main.commit=$(COMMIT)" -X "main.date=$(DATE)"

.PHONY: all clean build build-linux build-windows build-darwin test lint help

all: build

help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)

lint: ## Run linter
	golangci-lint run ./...

build: build-linux build-windows build-darwin ## Build for all platforms

build-linux: ## Build for Linux (amd64, arm64)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 .

build-windows: ## Build for Windows (amd64)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP_NAME).exe .

build-darwin: ## Build for macOS (amd64, arm64)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 .

