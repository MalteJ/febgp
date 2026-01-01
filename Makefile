GOBGP_VERSION := 4.1.0
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	GOBGP_ARCH := amd64
else ifeq ($(ARCH),aarch64)
	GOBGP_ARCH := arm64
else
	$(error Unsupported architecture: $(ARCH))
endif

GOBGP_URL := https://github.com/osrg/gobgp/releases/download/v$(GOBGP_VERSION)/gobgp_$(GOBGP_VERSION)_linux_$(GOBGP_ARCH).tar.gz
TOOLS_DIR := tools

.PHONY: test test-integration clean build tools clippy deb

build:
	cargo build --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

deb:
	cargo build --release
	cargo deb

# Download gobgp binaries
tools: $(TOOLS_DIR)/gobgpd

$(TOOLS_DIR)/gobgpd:
	mkdir -p $(TOOLS_DIR)
	curl -sL $(GOBGP_URL) | tar xz -C $(TOOLS_DIR)
	@echo "Downloaded gobgp $(GOBGP_VERSION) for $(GOBGP_ARCH)"

test: tools build
	cargo test --lib --bins
	@sudo -E env "PATH=$$PATH" cargo test -p tests-integration -- --nocapture --test-threads=1; \
	status=$$?; \
	sudo ip netns list 2>/dev/null | grep '^febgp_test' | awk '{print $$1}' | xargs -r -n1 sudo ip netns del 2>/dev/null || true; \
	exit $$status

# Clean up any leftover network namespaces from failed tests
clean:
	-sudo ip netns list 2>/dev/null | grep '^febgp_test' | awk '{print $$1}' | xargs -r -n1 sudo ip netns del 2>/dev/null
	cargo clean

clean-tools:
	rm -rf $(TOOLS_DIR)

clean-all: clean clean-tools
