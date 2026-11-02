# devsecops-quality-gates — GNU Make 3.81+ (macOS default) compatible.
SHELL := /bin/sh
COMPOSE := docker compose -f stand/compose.yaml -p qa-crapi
GATE := uv run python -m tools.gate

.PHONY: help install lint format typecheck unit check stand-up stand-down stand-reset stand-status seed \
	scan-secrets scan-sast scan-sca scan-dast scan-static gate gate-target security-tests report clean

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install locked Python dependencies with uv
	uv sync --frozen --all-groups

lint: ## ruff lint + format check
	uv run ruff check .
	uv run ruff format --check .

format: ## Apply ruff formatting
	uv run ruff format .

typecheck: ## mypy --strict
	uv run mypy

unit: ## Unit tests of the gate and report tools (coverage >= 90 %)
	uv run pytest --cov --cov-report=term-missing

check: lint typecheck unit ## Everything that needs no stand

# --- crAPI stand (127.0.0.1 only) ---------------------------------------------------------------
stand-up: ## Start crAPI (Compose project qa-crapi) and wait until healthy
	$(COMPOSE) up -d --wait --wait-timeout 600

stand-down: ## Stop crAPI, keep data
	$(COMPOSE) down

stand-reset: ## Stop crAPI and delete its volumes (fresh database)
	$(COMPOSE) down -v

stand-status: ## Container status
	$(COMPOSE) ps

seed: ## Idempotent test data: users A and B, vehicles, posts, orders
	uv run python -m security_tests.seed

# --- scanners -----------------------------------------------------------------------------------
scan-secrets: ## Gitleaks over the full history of this and sibling portfolio repositories
	sh scripts/scan-secrets.sh

scan-sast: ## Semgrep: own code (gate) and crAPI source (report)
	sh scripts/scan-sast.sh

scan-sca: ## Trivy (repo + crAPI images), Syft SBOM, Grype
	sh scripts/scan-sca.sh
	uv run python -m tools.sca_summary reports

scan-dast: ## ZAP Automation Framework + Nuclei against the local stand
	sh scripts/scan-dast.sh

scan-static: scan-secrets scan-sast scan-sca ## All static scanners

gate: ## Blocking gate: new High/Critical in own code, secrets or repo config fail the build
	$(GATE) -b security-baseline.yml \
		$(foreach f,$(wildcard reports/gitleaks-*.json),-i gitleaks-json:$(f)) \
		-i semgrep-json:reports/semgrep.json -i trivy-json:reports/trivy-repo.json \
		--json-out reports/gate.json --md-out reports/gate.md

gate-target: ## Target gate: DAST results against the triaged baseline (blocking); image SCA report-only
	$(GATE) -b stand/target-baseline.yml --allow-missing \
		-i zap-json:reports/zap/zap-report.json -i nuclei-jsonl:reports/nuclei.jsonl \
		--json-out reports/gate-target.json --md-out reports/gate-target.md
	$(GATE) --report-only $(foreach f,$(wildcard reports/trivy-image-*.json),-i trivy-json:$(f)) \
		--json-out reports/gate-images.json --md-out reports/gate-images.md > /dev/null

security-tests: ## API security regression tests (strict xfail per finding + positive controls)
	uv run pytest security_tests --junitxml=reports/security-tests.xml

report: ## Build the PDF security assessment report
	uv run python -m tools.report

clean: ## Remove generated reports and caches (not Docker volumes)
	rm -rf reports .cache .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
