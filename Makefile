.PHONY: help security security-l1 security-l2 security-l3 security-l4 security-l5 security-l6 security-l7

help:
	@echo "7-Layer Security Pipeline - Local Execution"
	@echo "==========================================="
	@echo ""
	@echo "Run all layers:"
	@echo "  make security          - Run layers 1, 2, 3, and 6 locally"
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
	@echo "Running ShipGuard for secrets rules (SEC-001, SEC-002, SEC-003)..."
	@shipguard scan . --severity critical --rules SEC-001,SEC-002,SEC-003 --format text || true
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
	@shipguard scan . --rules SC-001 --format text || true
	@echo ""
	@echo "Checking for unpinned Python dependencies (SC-002)..."
	@shipguard scan . --rules SC-002 --format text || true
	@echo ""
	@echo "Checking for npm/pnpm without lockfile (SC-003)..."
	@shipguard scan . --rules SC-003 --format text || true
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

# Combined: Run layers 1, 2, 3, and 6 locally
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
