.PHONY: help security security-report security-strict security-l1 security-l2 security-l3 security-l4 security-l5 security-l6 security-l7 release

help:
	@echo "7-Layer Security Pipeline - Local Execution"
	@echo "==========================================="
	@echo ""
	@echo "Run all layers:"
	@echo "  make security          - Run layers 1, 2, 3, and 6 locally (report mode)"
	@echo "  make security-strict   - Run blocking ShipGuard checks (fail on findings)"
	@echo ""
	@echo "Run individual layers:"
	@echo "  make security-l1       - Layer 1: Check dependency vulnerabilities"
	@echo "  make security-l2       - Layer 2: Detect hardcoded secrets"
	@echo "  make security-l3       - Layer 3: Full SAST scan"
	@echo "  make security-l4       - Layer 4: Manual AI review reminder"
	@echo "  make security-l5       - Layer 5: DAST reminder (requires running app)"
	@echo "  make security-l6       - Layer 6: Supply chain integrity checks"
	@echo "  make security-l7       - Layer 7: Observability setup reminder"
	@echo ""
	@echo "Other targets:"
	@echo "  make install           - Install development dependencies"
	@echo "  make release BUMP=patch|minor|major - Bump version, tag, and push to trigger PyPI publish"
	@echo "  make help              - Show this help message"

# Layer 1: Dependencies - Check for vulnerable packages
security-l1:
	@echo "🔍 Layer 1: Checking Dependencies for Vulnerabilities..."
	@echo ""
	@if command -v pip-audit >/dev/null 2>&1; then \
		echo "Running pip-audit for Python dependencies..."; \
		pip-audit --skip-editable || true; \
	else \
		echo "⚠️  pip-audit not found. Install with: pip install pip-audit"; \
	fi
	@echo ""
	@if command -v npm >/dev/null 2>&1 && [ -f "package-lock.json" ] || [ -f "pnpm-lock.yaml" ]; then \
		if [ -f "package-lock.json" ]; then \
			echo "Running npm audit..."; \
			npm audit --audit-level=moderate || true; \
		elif [ -f "pnpm-lock.yaml" ]; then \
			echo "Running pnpm audit..."; \
			pnpm audit || true; \
		fi; \
	else \
		echo "No Node.js dependencies found"; \
	fi
	@echo ""
	@echo "✅ Layer 1 complete"

# Layer 2: Secrets - Detect hardcoded credentials
security-l2:
	@echo "🔐 Layer 2: Detecting Hardcoded Secrets..."
	@echo ""
	@if command -v gitleaks >/dev/null 2>&1; then \
		echo "Running gitleaks..."; \
		gitleaks detect --source=local --verbose || true; \
	else \
		echo "⚠️  gitleaks not found. Install with: brew install gitleaks"; \
	fi
	@echo ""
	@echo "Running ShipGuard for secrets rules (SEC-001 through SEC-015)..."
	@shipguard scan . --severity critical --include-rules SEC-001,SEC-002,SEC-003,SEC-004,SEC-005,SEC-006,SEC-007,SEC-008,SEC-009,SEC-010,SEC-011,SEC-012,SEC-013,SEC-014,SEC-015 --format terminal || true
	@echo ""
	@echo "✅ Layer 2 complete"

# Layer 3: SAST - Full static analysis scan
security-l3:
	@echo "📊 Layer 3: Running Full SAST Scan..."
	@echo ""
	@shipguard scan .
	@echo ""
	@echo "✅ Layer 3 complete"

# Layer 4: AI Reasoning - Manual review reminder
security-l4:
	@echo "🤖 Layer 4: AI Reasoning & Manual Review"
	@echo ""
	@echo "Recommended: Use an LLM (Claude, GPT-4, etc.) or human architect to review:"
	@echo "  - Authentication and authorization logic"
	@echo "  - Business logic vulnerabilities"
	@echo "  - Architectural patterns and design decisions"
	@echo "  - Data handling and privacy considerations"
	@echo "  - High-risk code paths"
	@echo ""
	@echo "Example prompt for Claude:"
	@echo "  'Review this code for security vulnerabilities, focusing on:'"
	@echo "  '  - Authentication/authorization bypasses'"
	@echo "  '  - SQL injection opportunities'"
	@echo "  '  - XSS vulnerabilities'"
	@echo "  '  - Race conditions'"
	@echo "  '  - Data leaks'"
	@echo ""
	@echo "✅ Layer 4 reminder complete"

# Layer 5: DAST - Dynamic application testing
security-l5:
	@echo "🔧 Layer 5: DAST (Dynamic Application Security Testing)"
	@echo ""
	@echo "This layer requires a running application."
	@echo ""
	@echo "To run OWASP ZAP baseline scan:"
	@echo "  docker run -t owasp/zap2docker-stable:latest \\"
	@echo "    zap-baseline.py -t http://localhost:3000 -r report.html"
	@echo ""
	@echo "Or use Burp Suite Community for interactive testing."
	@echo ""
	@echo "✅ Layer 5 reminder complete"

# Layer 6: Supply Chain - Check container images and dependency pinning
security-l6:
	@echo "🔒 Layer 6: Supply Chain Integrity Checks..."
	@echo ""
	@echo "Checking for unpinned Docker images (SC-001)..."
	@shipguard scan . --include-rules SC-001 --format terminal || true
	@echo ""
	@echo "Checking for unpinned Python dependencies (SC-002)..."
	@shipguard scan . --include-rules SC-002 --format terminal || true
	@echo ""
	@echo "Checking for npm/pnpm without lockfile (SC-003)..."
	@shipguard scan . --include-rules SC-003 --format terminal || true
	@echo ""
	@echo "Checking .gitignore for missing secret entries (SC-004)..."
	@shipguard scan . --include-rules SC-004 --format terminal || true
	@echo ""
	@echo "Verifying lockfiles..."
	@if [ -f "requirements.txt" ]; then echo "  ✓ requirements.txt found"; fi
	@if [ -f "requirements-dev.txt" ]; then echo "  ✓ requirements-dev.txt found"; fi
	@if [ -f "package-lock.json" ]; then echo "  ✓ package-lock.json found"; fi
	@if [ -f "pnpm-lock.yaml" ]; then echo "  ✓ pnpm-lock.yaml found"; fi
	@if [ -f "yarn.lock" ]; then echo "  ✓ yarn.lock found"; fi
	@echo ""
	@echo "✅ Layer 6 complete"

# Layer 7: Observability - Monitoring and incident response
security-l7:
	@echo "📈 Layer 7: Observability & Incident Response"
	@echo ""
	@echo "Ensure your production deployment includes:"
	@echo "  - Security event logging (auth, API calls, permission changes)"
	@echo "  - Real-time alerting for suspicious activities"
	@echo "  - SIEM integration (Splunk, ELK, Datadog)"
	@echo "  - Incident response runbooks"
	@echo "  - Post-incident analysis and learning"
	@echo ""
	@echo "Recommended tools:"
	@echo "  - Logging: ELK Stack, Splunk, Datadog"
	@echo "  - Alerting: PagerDuty, Opsgenie"
	@echo "  - Monitoring: Grafana, New Relic"
	@echo "  - SIEM: Splunk, IBM QRadar"
	@echo ""
	@echo "✅ Layer 7 reminder complete"

# Combined: Run layers 1, 2, 3, and 6 locally (report mode; non-blocking external tools)
security: security-l1 security-l2 security-l3 security-l6
	@echo ""
	@echo "================================"
	@echo "7-Layer Security Pipeline Summary"
	@echo "================================"
	@echo "✅ Layer 1: Dependencies - Complete"
	@echo "✅ Layer 2: Secrets - Complete"
	@echo "✅ Layer 3: SAST - Complete"
	@echo "⏭️  Layer 4: AI Reasoning - Manual review needed"
	@echo "⏭️  Layer 5: DAST - Requires running application"
	@echo "✅ Layer 6: Supply Chain - Complete"
	@echo "⏭️  Layer 7: Observability - Production monitoring needed"
	@echo "================================"

# Explicit alias for report mode
security-report: security

# Strict mode: blocking checks suitable for CI/release gates
security-strict:
	@echo "🔒 ShipGuard Strict Gate (blocking)"
	@echo ""
	@shipguard scan . --severity high
	@echo ""
	@echo "✅ Strict gate complete"

# Release: bump version, commit, tag, push → triggers publish.yml → PyPI
# Usage: make release BUMP=patch   (or minor / major)
BUMP ?= patch
release:
	@command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 required"; exit 1; }
	@git diff --quiet && git diff --cached --quiet || { echo "ERROR: working tree is dirty — commit or stash first"; exit 1; }
	@CURRENT=$$(python3 -c "import tomllib; f=open('pyproject.toml','rb'); d=tomllib.load(f); print(d['project']['version'])"); \
	IFS='.' read -r MAJ MIN PAT <<< "$$CURRENT"; \
	case "$(BUMP)" in \
	  major) NEW="$$((MAJ+1)).0.0" ;; \
	  minor) NEW="$${MAJ}.$$((MIN+1)).0" ;; \
	  patch) NEW="$${MAJ}.$${MIN}.$$((PAT+1))" ;; \
	  *) echo "ERROR: BUMP must be patch, minor, or major"; exit 1 ;; \
	esac; \
	echo "Bumping $$CURRENT → $$NEW"; \
	PYBIN=$$([ -f .venv/bin/python ] && echo .venv/bin/python || echo python3); PYTHONPATH=src $$PYBIN -m pytest tests/ -q || { echo "Tests failed — aborting release"; exit 1; }; \
	sed -i.bak "s/^version = \".*\"/version = \"$$NEW\"/" pyproject.toml && rm pyproject.toml.bak; \
	git add pyproject.toml; \
	git commit -m "chore(release): bump version $$CURRENT → $$NEW"; \
	git tag "v$$NEW"; \
	git push origin HEAD; \
	git push origin "v$$NEW"; \
	echo "✅ Released v$$NEW — publish.yml will build and upload to PyPI"

# Install development dependencies
install:
	@echo "Installing development dependencies..."
	@pip install -e ".[dev]"
	@echo ""
	@echo "Recommended additional tools:"
	@echo "  pip install pip-audit"
	@echo "  brew install gitleaks"
	@echo "  brew install shellcheck"
	@echo "  npm install -g eslint"
	@echo ""
	@echo "✅ Installation complete"
