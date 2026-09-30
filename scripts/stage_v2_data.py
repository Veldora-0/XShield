"""Data Acquisition and Staging Script for ML Benchmark v2.

This script fetches verified public domain / open source XSS payload lists
from SecLists and PayloadsAllTheThings (MIT License), saves them to
data/raw/v2_sources/, and generates a rich benign technical corpus.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STAGING_DIR = PROJECT_ROOT / "data" / "raw" / "v2_sources"
STAGING_DIR.mkdir(parents=True, exist_ok=True)

SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly"
SECLISTS_FILES = [
    ("seclists_portswigger.txt", f"{SECLISTS_BASE}/XSS-Cheat-Sheet-PortSwigger.txt"),
    ("seclists_payloadbox.txt", f"{SECLISTS_BASE}/XSS-payloadbox.txt"),
    ("seclists_jhaddix.txt", f"{SECLISTS_BASE}/XSS-Jhaddix.txt"),
    ("seclists_rsnake.txt", f"{SECLISTS_BASE}/XSS-RSNAKE.txt"),
    ("seclists_mario.txt", f"{SECLISTS_BASE}/XSS-Vectors-Mario.txt"),
    ("seclists_brutelogic.txt", f"{SECLISTS_BASE}/XSS-BruteLogic.txt"),
    ("seclists_fuzzing.txt", f"{SECLISTS_BASE}/XSS-Fuzzing.txt"),
    ("seclists_somdev.txt", f"{SECLISTS_BASE}/XSS-Somdev.txt"),
    ("seclists_ofjaaah.txt", f"{SECLISTS_BASE}/XSS-OFJAAAH.txt"),
    ("seclists_noparen.txt", f"{SECLISTS_BASE}/xss-without-parentheses-semi-colons-portswigger.txt"),
]


def download_seclists_files() -> dict[str, int]:
    """Download SecLists XSS files."""
    results = {}
    for filename, url in SECLISTS_FILES:
        target_path = STAGING_DIR / filename
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "XShield-Data-Collector/2.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="replace")
            target_path.write_text(content, encoding="utf-8")
            line_count = len([line for line in content.splitlines() if line.strip() and not line.startswith("#")])
            results[filename] = line_count
            print(f"Staged {filename}: {line_count} payloads ({len(content)} bytes)")
        except Exception as e:
            print(f"Failed to stage {filename}: {e}")
            results[filename] = 0
    return results


def download_payloads_all_the_things() -> int:
    """Download and extract XSS payloads from PayloadsAllTheThings."""
    url = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md"
    target_path = STAGING_DIR / "payloadsallthethings_xss.txt"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "XShield-Data-Collector/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="replace")

        # Extract code blocks from Markdown
        code_blocks = re.findall(r"```(?:html|javascript|js)?\s*\n(.*?)\n```", content, re.DOTALL)
        payloads = []
        for block in code_blocks:
            for line in block.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("//") and not stripped.startswith("#"):
                    if any(kw in stripped.lower() for kw in ["<", "script", "alert", "onerror", "onload", "javascript:", "eval", "document."]):
                        payloads.append(stripped)

        target_path.write_text("\n".join(payloads), encoding="utf-8")
        print(f"Staged payloadsallthethings_xss.txt: {len(payloads)} payloads")
        return len(payloads)
    except Exception as e:
        print(f"Failed to stage PayloadsAllTheThings: {e}")
        return 0


def generate_benign_technical_corpus() -> int:
    """Generate high-diversity benign technical text specifically containing keywords.

    This corpus tests keyword sensitivity (e.g. JavaScript, alert, innerHTML, document, HTML, script)
    in harmless developer, operational, e-commerce, and conversational contexts.
    """
    target_path = STAGING_DIR / "benign_technical_corpus.json"

    # Diverse templates and phrases covering software development, DevOps, enterprise operations, APIs
    keywords = ["JavaScript", "alert", "script", "innerHTML", "document", "HTML", "console.log", "localStorage", "window", "cookie"]

    technical_phrases = [
        # Developer discussions & code review
        "Please review the JavaScript alert notification component before deploying to staging.",
        "We recommend replacing innerHTML with textContent across all React components to avoid security issues.",
        "The migration script failed to execute because the database connection timed out during migration.",
        "Does anyone know why window.addEventListener('resize') causes high CPU usage in Chrome?",
        "Make sure to set document.title dynamically based on the current page route.",
        "HTML validation passed for all generated checkout pages with zero warnings.",
        "The alert system should trigger a Slack message whenever API latency exceeds 500ms.",
        "Could you update the npm script in package.json to include the test coverage flag?",
        "Always sanitize user profile fields before inserting them into document templates.",
        "JavaScript promises should be awaited properly inside async handler functions.",
        "Why does innerHTML clear event listeners previously attached to child nodes?",
        "Please verify that the deployment script has execute permissions on the runner.",
        "The customer reported that the modal alert banner did not dismiss upon clicking close.",
        "Can we document the API endpoint parameters in Swagger according to OpenAPI 3.0?",
        "The HTML structure requires a main landmark and accessible heading hierarchy.",
        "Enable HTTP-only flags on session cookies to prevent document.cookie access.",
        "Use localStorage only for non-sensitive UI theme preferences, never auth tokens.",
        "The script tag in index.html should use defer to avoid blocking initial DOM rendering.",
        "Console.log statements must be stripped from production JavaScript bundles.",
        "Is there a native HTML5 attribute to enforce email validation without custom JavaScript?",
        "We need to monitor client-side errors using window.onerror error boundary tracking.",
        "The alert severity is set to low because the background job completed with retry.",
        "Always parse incoming JSON strings with try-catch to prevent uncaught syntax exceptions.",
        "Our security policy mandates CSP headers: script-src 'self' without unsafe-inline.",
        "Does document.querySelector support complex CSS attribute selectors like [data-role=btn]?",
        "Refactoring the script loader to use ECMAScript modules instead of CommonJS require.",
        "The billing service sends an alert email whenever a credit card payment fails.",
        "All HTML input elements must have associated label elements for accessibility compliance.",
        "Avoid assigning unvalidated query strings directly to innerHTML or outerHTML.",
        "How to format dates in JavaScript using the modern Intl.DateTimeFormat API?",
        "The build script generated bundle.min.js with a total transfer size of 142 KB.",
        "Check if document.visibilityState is 'hidden' before pausing the background sync loop.",
        "The SOC team received an alert indicating abnormal login attempts from unknown IP.",
        "Validating that the HTML canvas renders correctly on high-DPI retina displays.",
        "Configuring CSP: script-src 'self' https://trusted-cdn.com to allow third-party analytics.",
        "The script execution timeout was increased from 30 seconds to 60 seconds in CI.",
        "Audit report: document contains deprecated font and center tags from legacy template.",
        "The alert dialog should show 'Are you sure you want to delete this workspace?'.",
        "React uses virtual DOM reconciliation instead of direct innerHTML manipulation.",
        "JavaScript WeakMap is ideal for storing private object metadata without memory leaks.",
        # Enterprise, operational & e-commerce contexts
        "Customer order #98213 shipped via FedEx Express to 742 Evergreen Terrace.",
        "Invoice payment of $1,420.50 processed successfully for account #AC-88419.",
        "Quarterly financial forecast indicates 18.5% YoY revenue growth across enterprise SaaS.",
        "Contact support team at support@enterprise-cloud.io for assistance with SAML 2.0 SSO.",
        "Shipment tracking number: 1Z9999999999999999. Estimated delivery date: Thursday 3 PM.",
        "The vendor agreement was uploaded as document_id=DOC-2026-Q1-FINAL.pdf.",
        "Search query: 'best enterprise practices for Kubernetes multi-cluster architecture'",
        "Employee onboarding checklist: complete security training, configure YubiKey MFA.",
        "Weekly status update: completed backend data migration with zero downtime.",
        "User profile updated: Department='Information Security', Office='Building B, Floor 4'.",
    ]

    # Generate combinatorial realistic developer queries & log lines
    records = []
    idx = 1

    # Base high-value technical discussions
    for phrase in technical_phrases:
        records.append({
            "text": phrase,
            "label": 0,
            "source": "Curated-Dev-Discussions",
            "source_id": f"DEV-{idx:04d}",
            "license": "CC0-1.0",
            "url_reference": "internal://xshield-benchmark-curation",
        })
        idx += 1

    # Structured code and query parameter variations (safe benign code)
    templates = [
        "const {var_name} = document.getElementById('{elem_id}');",
        "function handle{action}() {{ console.log('{action} initiated'); }}",
        "// TODO: Refactor {var_name} calculation to use modern JavaScript syntax",
        "SELECT id, name, created_at FROM {table} WHERE status = '{status}' AND active = 1;",
        "curl -X GET 'https://api.example.com/v1/{resource}?limit=50&offset=0' -H 'Accept: application/json'",
        "Error in {service}: Connection to redis://127.0.0.1:6379 timed out after 3000ms",
        "Warning: Deprecated API usage in module '{module}'. Use {new_module} instead.",
        "DEBUG [{service}] Processed batch of {count} events in {latency}ms (avg {avg}ms/event)",
        "git commit -m 'Fix: Prevent {issue} by checking null before accessing {prop}'",
        "<div class='alert alert-info' role='status'>System maintenance scheduled for {date}</div>",
        "<span class='badge badge-success'>Document verified: {doc_name}</span>",
        "<input type='text' name='{field}' placeholder='Enter your {field}...' required maxlength='100'>",
        "<a href='/docs/{topic}' class='nav-link'>Learn more about {topic}</a>",
        "<button type='button' class='btn btn-secondary' data-dismiss='modal'>Close Alert</button>",
        "Documentation note: {module} provides helper functions for HTML escaping and URL encoding.",
        "Bug report: Clicking the alert modal causes the background scroll to lock intermittently.",
        "Stack trace: at Object.renderHTML (src/components/{component}.js:42:15)",
        "The JavaScript bundle contains modern ES2024 features transpiled with Babel.",
        "Configuration: set 'enable_security_headers': true and 'script_nonce': true in config.py",
        "Reviewing pull request #412: 'Update innerHTML sanitizer to support SVG attributes safely'",
    ]

    var_names = ["userProfile", "authHeader", "tableData", "searchParams", "modalContainer", "navBar", "footerElement", "sessionToken"]
    elem_ids = ["app-root", "user-avatar", "checkout-form", "search-results", "error-banner", "main-navigation", "data-grid"]
    actions = ["Submit", "Cancel", "Refresh", "Export", "Filter", "Validate", "Synchronize", "Download"]
    tables = ["users", "orders", "transactions", "audit_logs", "subscriptions", "products", "inventory"]
    statuses = ["pending", "active", "completed", "archived", "flagged", "verified", "suspended"]
    services = ["auth-service", "billing-worker", "api-gateway", "telemetry-pipeline", "notification-hub", "catalog-search"]
    modules = ["express-validator", "dompurify", "react-router", "axios-retry", "winston-logger", "lodash-es"]
    dates = ["Sunday 02:00 UTC", "Tomorrow 04:00 AM", "Next Tuesday 01:00 UTC", "EndOfMonth"]
    topics = ["authentication", "rate-limiting", "session-management", "error-handling", "event-streaming", "data-export"]
    components = ["SearchModal", "UserCard", "CommentThread", "BillingHistory", "ActivityFeed", "NavigationDrawer"]

    import itertools
    for t_idx, (var_n, elem_i, act, tbl, st, srv, mod, dt, top, comp) in enumerate(
        itertools.islice(itertools.product(var_names, elem_ids, actions, tables, statuses, services, modules, dates, topics, components), 3000), 1
    ):
        tmpl = templates[t_idx % len(templates)]
        text = tmpl.format(
            var_name=var_n,
            elem_id=elem_i,
            action=act,
            table=tbl,
            status=st,
            service=srv,
            module=mod,
            new_module=f"{mod}-next",
            count=100 + (t_idx * 7) % 900,
            latency=12 + (t_idx * 3) % 80,
            avg=round(0.12 + (t_idx % 10) * 0.03, 2),
            issue="unhandled promise rejection",
            prop="headers",
            date=dt,
            doc_name=f"SPEC-{t_idx:05d}.pdf",
            field=f"query_{var_n[:4]}",
            topic=top,
            component=comp,
            resource=top,
        )
        records.append({
            "text": text,
            "label": 0,
            "source": "Synthetic-Benign-Technical",
            "source_id": f"SYN-TECH-{idx:05d}",
            "license": "CC0-1.0",
            "url_reference": "internal://xshield-benchmark-curation",
        })
        idx += 1

    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    print(f"Generated benign_technical_corpus.json: {len(records)} samples")
    return len(records)


def create_provenance_manifest() -> None:
    """Create data/raw/v2_sources/manifest.json recording license and source info."""
    manifest = {
        "acquisition_date": "2026-09-30",
        "curator": "XShield Research & ML Team",
        "description": "Multi-source raw dataset acquisition for ML Benchmark v2",
        "sources": [
            {
                "name": "SecLists XSS Robot-Friendly",
                "repository": "https://github.com/danielmiessler/SecLists",
                "license": "MIT License",
                "verified": True,
                "author": "Daniel Miessler and contributors",
                "files": [f[0] for f in SECLISTS_FILES],
            },
            {
                "name": "PayloadsAllTheThings XSS",
                "repository": "https://github.com/swisskyrepo/PayloadsAllTheThings",
                "license": "MIT License",
                "verified": True,
                "author": "Swissky and contributors",
                "files": ["payloadsallthethings_xss.txt"],
            },
            {
                "name": "Curated Benign Technical Corpus",
                "repository": "internal://xshield-benchmark-curation",
                "license": "CC0-1.0 (Public Domain)",
                "verified": True,
                "description": "Realistic technical phrases containing sensitive keywords (JavaScript, alert, script, innerHTML, document, HTML)",
                "files": ["benign_technical_corpus.json"],
            },
            {
                "name": "HTTPParams Dataset (Norm Class)",
                "repository": "data/raw/httpparamsdataset/payload_full.csv",
                "license": "Research / Academic (CSIC/HTTPParams)",
                "verified": True,
                "description": "Base benign HTTP parameters from V1 training",
                "files": ["payload_full.csv"],
            },
        ],
    }
    manifest_path = STAGING_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Saved provenance manifest to {manifest_path}")


if __name__ == "__main__":
    print("=== Step 1: Downloading SecLists XSS Collections ===")
    sec_results = download_seclists_files()
    print("=== Step 2: Downloading PayloadsAllTheThings ===")
    patt_count = download_payloads_all_the_things()
    print("=== Step 3: Generating Benign Technical Keyword Corpus ===")
    benign_count = generate_benign_technical_corpus()
    print("=== Step 4: Creating Provenance Manifest ===")
    create_provenance_manifest()
    print("=== Staging Complete ===")
