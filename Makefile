.PHONY: build test lint fmt bench

build:
	cargo build --workspace

test:
	cargo test --workspace

lint:
	cargo clippy --all-targets --workspace -- -D warnings

fmt:
	cargo fmt --check

bench:
	cargo bench --workspace