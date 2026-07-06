ROOT := $(CURDIR)
SECRETS_FILE := $(ROOT)/.secrets
WRANGLER_CONFIG := $(ROOT)/wrangler.toml
WRANGLER ?= npx wrangler
DEPLOY_ENV ?= CI=1

.PHONY: build test deploy deploy-secrets

build:
	cargo build

test:
	cargo test

deploy-secrets:
	@test -f "$(SECRETS_FILE)" || { echo "missing $(SECRETS_FILE)"; exit 1; }
	@set -a; . "$(SECRETS_FILE)"; set +a; \
	test -n "$${CLOUDFLARE_API_TOKEN:-}" || { echo "missing CLOUDFLARE_API_TOKEN"; exit 1; }; \
	test -n "$${R2_PRESIGN_ACCOUNT_ID:-}" || { echo "missing R2_PRESIGN_ACCOUNT_ID"; exit 1; }; \
	test -n "$${R2_PRESIGN_BUCKET_NAME:-}" || { echo "missing R2_PRESIGN_BUCKET_NAME"; exit 1; }; \
	test -n "$${R2_PRESIGN_EXPIRES_SECONDS:-}" || { echo "missing R2_PRESIGN_EXPIRES_SECONDS"; exit 1; }; \
	test -n "$${R2_PRESIGN_ACCESS_KEY_ID:-}" || { echo "missing R2_PRESIGN_ACCESS_KEY_ID"; exit 1; }; \
	test -n "$${R2_PRESIGN_SECRET_ACCESS_KEY:-}" || { echo "missing R2_PRESIGN_SECRET_ACCESS_KEY"; exit 1; }; \
	printf "%s" "$${R2_PRESIGN_ACCOUNT_ID}" | CLOUDFLARE_API_TOKEN="$${CLOUDFLARE_API_TOKEN}" $(WRANGLER) secret put R2_PRESIGN_ACCOUNT_ID --config "$(WRANGLER_CONFIG)"; \
	printf "%s" "$${R2_PRESIGN_BUCKET_NAME}" | CLOUDFLARE_API_TOKEN="$${CLOUDFLARE_API_TOKEN}" $(WRANGLER) secret put R2_PRESIGN_BUCKET_NAME --config "$(WRANGLER_CONFIG)"; \
	printf "%s" "$${R2_PRESIGN_EXPIRES_SECONDS}" | CLOUDFLARE_API_TOKEN="$${CLOUDFLARE_API_TOKEN}" $(WRANGLER) secret put R2_PRESIGN_EXPIRES_SECONDS --config "$(WRANGLER_CONFIG)"; \
	printf "%s" "$${R2_PRESIGN_ACCESS_KEY_ID}" | CLOUDFLARE_API_TOKEN="$${CLOUDFLARE_API_TOKEN}" $(WRANGLER) secret put R2_PRESIGN_ACCESS_KEY_ID --config "$(WRANGLER_CONFIG)"; \
	printf "%s" "$${R2_PRESIGN_SECRET_ACCESS_KEY}" | CLOUDFLARE_API_TOKEN="$${CLOUDFLARE_API_TOKEN}" $(WRANGLER) secret put R2_PRESIGN_SECRET_ACCESS_KEY --config "$(WRANGLER_CONFIG)"

deploy: test deploy-secrets
	@set -a; . "$(SECRETS_FILE)"; set +a; \
	test -n "$${CLOUDFLARE_API_TOKEN:-}" || { echo "missing CLOUDFLARE_API_TOKEN"; exit 1; }; \
	CLOUDFLARE_API_TOKEN="$${CLOUDFLARE_API_TOKEN}" $(DEPLOY_ENV) $(WRANGLER) deploy --config "$(WRANGLER_CONFIG)"
