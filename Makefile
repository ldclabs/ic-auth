.PHONY: lint fix test

lint:
	@cargo fmt --all -- --check
	@cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

fix:
	@cargo clippy --fix --locked --workspace --all-targets --all-features
	@cargo fmt --all

test:
	@cargo test --locked --workspace --all-features -- --nocapture
