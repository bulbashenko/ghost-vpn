BIN_DIR  := bin
GO       := go
GOFLAGS  := -trimpath
LDFLAGS  := -s -w
BINARIES := ghost-server ghost-client ghost-tools nm-ghost-service

.PHONY: all build build-linux build-nm-plugin-linux build-nm-plugin-gtk \
        install install-nm-plugin keygen \
        test vet tidy clean \
        deploy deploy-server deploy-client \
        autotest autotest-quick autotest-no-deploy \
        route-on route-off route-ping \
        analyze test-moscow

# ── Build ─────────────────────────────────────────────────────────────────────

all: build

build: $(BINARIES)

$(BINARIES):
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$@ ./cmd/$@

build-linux:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
	    -o $(BIN_DIR)/ghost-server-linux  ./cmd/ghost-server
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
	    -o $(BIN_DIR)/ghost-client-linux  ./cmd/ghost-client
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
	    -o $(BIN_DIR)/ghost-tools-linux   ./cmd/ghost-tools
	@echo "Built: bin/ghost-{server,client,tools}-linux"

build-nm-plugin-linux:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
	    -o $(BIN_DIR)/ghost-client-linux     ./cmd/ghost-client
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
	    -o $(BIN_DIR)/nm-ghost-service-linux ./cmd/nm-ghost-service
	@echo "Built: bin/ghost-client-linux  bin/nm-ghost-service-linux"

build-nm-plugin-gtk:
	$(MAKE) -C nm-plugin-gtk

# ── Install ───────────────────────────────────────────────────────────────────

install: build-linux
	install -Dm755 $(BIN_DIR)/ghost-server-linux /usr/local/bin/ghost-server
	install -Dm755 $(BIN_DIR)/ghost-client-linux /usr/local/bin/ghost-client
	install -Dm755 $(BIN_DIR)/ghost-tools-linux  /usr/local/bin/ghost-tools

install-nm-plugin: build-nm-plugin-linux build-nm-plugin-gtk
	sudo bash scripts/install-nm-plugin.sh $(BIN_DIR)/nm-ghost-service-linux

# ── Development ───────────────────────────────────────────────────────────────

keygen: build
	$(BIN_DIR)/ghost-tools keygen

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR)

# ── Deploy ────────────────────────────────────────────────────────────────────

deploy: build-linux
	bash scripts/deploy.sh

deploy-server: build-linux
	bash scripts/deploy.sh --server-only

deploy-client: build-linux
	bash scripts/deploy.sh --client-only

# ── Remote operations ─────────────────────────────────────────────────────────

route-on:
	bash scripts/safe-route.sh on

route-off:
	bash scripts/safe-route.sh off

route-ping:
	bash scripts/safe-route.sh ping

test-moscow:
	bash scripts/test-moscow.sh

analyze:
	bash scripts/analyze.sh

# ── Automated test suite ──────────────────────────────────────────────────────
# autotest        Full run: build+deploy → start tunnel → security+perf+pcap tests
# autotest-quick  Fast run: skip PCAP and ML (~5 min)
# autotest-no-deploy  Run tests without rebuilding/redeploying

autotest: build-linux
	bash scripts/autotest.sh

autotest-quick: build-linux
	bash scripts/autotest.sh --quick

autotest-no-deploy:
	bash scripts/autotest.sh --no-deploy
