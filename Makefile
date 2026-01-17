.PHONY: all build build-cli build-gui clean test test-all test-gui test-encryptor help bench

# Build directory
BUILD_DIR := build
CLI_NAME := data-leak-locator
GUI_NAME := data-leak-locator-gui
APP_NAME := DataLeakLocator

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    OS := linux
    EXTENSION :=
endif
ifeq ($(UNAME_S),Darwin)
    OS := darwin
    EXTENSION :=
endif
ifeq ($(OS),Windows_NT)
    OS := windows
    EXTENSION := .exe
endif

# Default target
all: build

help:
	@echo "Data Leak Locator - Build Commands"
	@echo ""
	@echo "  make build           - Build both CLI and GUI binaries"
	@echo "  make build-cli       - Build CLI only"
	@echo "  make build-gui       - Build GUI binary only"
	@echo "  make test            - Run all tests"
	@echo "  make test-all        - Run all tests with coverage"
	@echo "  make test-gui        - Run GUI tests only"
	@echo "  make test-encryptor  - Run encryptor tests only"
	@echo "  make bench           - Run searcher benchmarks"
	@echo "  make bench-encryptor - Run encryption benchmarks"
	@echo "  make clean           - Remove build directory"
	@echo ""

build:
	@mkdir -p $(BUILD_DIR)
	@echo "🔨 Building CLI..."
	@go build -o $(BUILD_DIR)/$(CLI_NAME)$(EXTENSION) -ldflags="-s -w" .
	@echo "✅ CLI built: $(BUILD_DIR)/$(CLI_NAME)$(EXTENSION)"
	@echo "🔨 Building GUI..."
	@go build -o $(BUILD_DIR)/$(GUI_NAME)$(EXTENSION) -ldflags="-s -w" ./cmd/gui
	@echo "✅ GUI built: $(BUILD_DIR)/$(GUI_NAME)$(EXTENSION)"
	@echo "✅ Build complete!"

build-cli:
	@mkdir -p $(BUILD_DIR)
	@echo "🔨 Building CLI..."
	@go build -o $(BUILD_DIR)/$(CLI_NAME)$(EXTENSION) -ldflags="-s -w" .
	@echo "✅ CLI built: $(BUILD_DIR)/$(CLI_NAME)$(EXTENSION)"

build-gui:
	@mkdir -p $(BUILD_DIR)
	@echo "🔨 Building GUI..."
	@go build -o $(BUILD_DIR)/$(GUI_NAME)$(EXTENSION) -ldflags="-s -w" ./cmd/gui
	@echo "✅ GUI built: $(BUILD_DIR)/$(GUI_NAME)$(EXTENSION)"

test:
	@echo "🧪 Running tests..."
	@go test ./... -v -count=1

test-all:
	@mkdir -p $(BUILD_DIR)
	@echo "🧪 Running all tests with coverage..."
	@go test ./... -v -cover -coverprofile=$(BUILD_DIR)/coverage.out
	@go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "✅ Coverage report: $(BUILD_DIR)/coverage.html"

bench:
	@echo "📊 Running benchmarks..."
	@go test ./searcher -bench=. -benchmem

test-gui:
	@echo "🧪 Running GUI tests..."
	@go test ./gui/... -v -count=1

test-encryptor:
	@echo "🧪 Running encryptor tests..."
	@go test ./encryptor/... -v -count=1

bench-encryptor:
	@echo "📊 Running encryption benchmarks..."
	@go test ./encryptor -bench=. -benchmem

clean:
	@echo "🧹 Cleaning..."
	@rm -rf $(BUILD_DIR)/
	@rm -rf cmd/gui/$(APP_NAME).app cmd/gui/Contents
	@rm -f $(CLI_NAME) $(GUI_NAME)
	@echo "✅ Clean complete!"
