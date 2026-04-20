.PHONY: build release test lint fmt clean help

CARGO ?= cargo
TARGETS := aarch64-unknown-linux-musl x86_64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu

help:
	@echo "PacketFrame build targets"
	@echo "  make build        debug build, host target"
	@echo "  make release      release build, host target"
	@echo "  make release-all  release build, all published targets"
	@echo "  make test         cargo test across the workspace"
	@echo "  make lint         cargo fmt --check + cargo clippy"
	@echo "  make fmt          cargo fmt"
	@echo "  make clean        cargo clean"

build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --release --workspace

release-all:
	@for t in $(TARGETS); do \
		echo "==> Building $$t"; \
		$(CARGO) build --release --workspace --target $$t || exit 1; \
	done

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt --all

clean:
	$(CARGO) clean

# bpf-test target is defined by v0.1 when BPF sources exist
bpf-test:
	@echo "bpf-test: no BPF sources in v0.0.1; see plan forward view" && exit 0
