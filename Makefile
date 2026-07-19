ROOT := $(CURDIR)
SECRETS_FILE := $(ROOT)/.secrets
WRANGLER_CONFIG := $(ROOT)/wrangler.toml
WRANGLER ?= /Users/jamie/.npm/_npx/61e1327a8aba9411/node_modules/.bin/wrangler
DEPLOY_ENV ?= CI=1

.PHONY: build dev test deploy deploy-secrets

build:
	cargo build

dev:
	npx wrangler dev --config "$(WRANGLER_CONFIG)"

test:
	cargo test

deploy-secrets:
	@test -f "$(SECRETS_FILE)" || { echo "missing $(SECRETS_FILE)"; exit 1; }
	@set -a; . "$(SECRETS_FILE)"; set +a; \
	test -n "$${CLOUDFLARE_EMAIL:-}" || { echo "missing CLOUDFLARE_EMAIL"; exit 1; }; \
	test -n "$${CLOUDFLARE_API_KEY:-}" || { echo "missing CLOUDFLARE_API_KEY"; exit 1; }; \
	test -n "$${R2_PRESIGN_ACCOUNT_ID:-}" || { echo "missing R2_PRESIGN_ACCOUNT_ID"; exit 1; }; \
	test -n "$${R2_PRESIGN_BUCKET_NAME:-}" || { echo "missing R2_PRESIGN_BUCKET_NAME"; exit 1; }; \
	test -n "$${R2_PRESIGN_EXPIRES_SECONDS:-}" || { echo "missing R2_PRESIGN_EXPIRES_SECONDS"; exit 1; }; \
	test -n "$${R2_PRESIGN_ACCESS_KEY_ID:-}" || { echo "missing R2_PRESIGN_ACCESS_KEY_ID"; exit 1; }; \
	test -n "$${R2_PRESIGN_SECRET_ACCESS_KEY:-}" || { echo "missing R2_PRESIGN_SECRET_ACCESS_KEY"; exit 1; }; \
	printf "%s" "$${R2_PRESIGN_ACCOUNT_ID}" | CLOUDFLARE_EMAIL="$${CLOUDFLARE_EMAIL}" CLOUDFLARE_API_KEY="$${CLOUDFLARE_API_KEY}" $(WRANGLER) secret put R2_PRESIGN_ACCOUNT_ID --config "$(WRANGLER_CONFIG)"; \
	printf "%s" "$${R2_PRESIGN_BUCKET_NAME}" | CLOUDFLARE_EMAIL="$${CLOUDFLARE_EMAIL}" CLOUDFLARE_API_KEY="$${CLOUDFLARE_API_KEY}" $(WRANGLER) secret put R2_PRESIGN_BUCKET_NAME --config "$(WRANGLER_CONFIG)"; \
	printf "%s" "$${R2_PRESIGN_EXPIRES_SECONDS}" | CLOUDFLARE_EMAIL="$${CLOUDFLARE_EMAIL}" CLOUDFLARE_API_KEY="$${CLOUDFLARE_API_KEY}" $(WRANGLER) secret put R2_PRESIGN_EXPIRES_SECONDS --config "$(WRANGLER_CONFIG)"; \
	printf "%s" "$${R2_PRESIGN_ACCESS_KEY_ID}" | CLOUDFLARE_EMAIL="$${CLOUDFLARE_EMAIL}" CLOUDFLARE_API_KEY="$${CLOUDFLARE_API_KEY}" $(WRANGLER) secret put R2_PRESIGN_ACCESS_KEY_ID --config "$(WRANGLER_CONFIG)"; \
	printf "%s" "$${R2_PRESIGN_SECRET_ACCESS_KEY}" | CLOUDFLARE_EMAIL="$${CLOUDFLARE_EMAIL}" CLOUDFLARE_API_KEY="$${CLOUDFLARE_API_KEY}" $(WRANGLER) secret put R2_PRESIGN_SECRET_ACCESS_KEY --config "$(WRANGLER_CONFIG)"

deploy: test deploy-secrets
	@set -a; . "$(SECRETS_FILE)"; set +a; \
	test -n "$${CLOUDFLARE_EMAIL:-}" || { echo "missing CLOUDFLARE_EMAIL"; exit 1; }; \
	test -n "$${CLOUDFLARE_API_KEY:-}" || { echo "missing CLOUDFLARE_API_KEY"; exit 1; }; \
	CLOUDFLARE_EMAIL="$${CLOUDFLARE_EMAIL}" CLOUDFLARE_API_KEY="$${CLOUDFLARE_API_KEY}" $(DEPLOY_ENV) $(WRANGLER) deploy --config "$(WRANGLER_CONFIG)"
