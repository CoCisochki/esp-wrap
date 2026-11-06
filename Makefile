.PHONY: all build server client test clean

GO ?= go
BIN_DIR := bin
CGO_ENABLED := 0
LDFLAGS := -s -w

all: build

build: server client

server:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/esp-server ./cmd/esp-server

client:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/esp-client ./cmd/esp-client

test:
	$(GO) test -v ./pkg/esp/...

clean:
	rm -rf $(BIN_DIR) dist generated_clients *.log *.pid *.tar.gz
