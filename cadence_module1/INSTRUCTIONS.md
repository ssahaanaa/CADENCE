# CADENCE Module 1 — Quick Start

## 1. Install dependencies

```bash
pip install -r requirements.txt --break-system-packages
```
(Drop `--break-system-packages` if you're using a virtualenv, which is recommended.)

## 2. Try it on the included demo first

This proves everything works before you point it at anything real.

```bash
python cli.py sample_target --project-name demo
```

You should see something like:
```
[*] Scanning source tree: sample_target
[+] 17 findings (13 high-confidence, 4 needs_review)
[+] Wrote ./cbom.json
[+] Wrote ./vulnerabilities.json
```

`sample_target/` has deliberately vulnerable Python, Java, JS, and config
files so you can see every detection layer fire at once — and two "should
NOT be flagged" functions (SHA-256 in both the Java and JS samples) to
prove the AST layers aren't just keyword-matching.

## 3. Run it for real

```bash
# Just a local folder:
python cli.py /path/to/your/codebase --project-name my-project

# A whole GitHub org, auto-discovering every repo:
python cli.py --github-org your-org-name --github-token ghp_xxxxx

# Live network/TLS scan of specific known hosts:
python cli.py /path/to/code --hosts example.com internal-api.corp:8443

# Auto-discover every live subdomain of a domain, then TLS-scan them:
python cli.py /path/to/code --domain your-company.com
```

⚠️ **Only use `--domain` or `--hosts` on infrastructure you own or are
explicitly authorized to test.** Unauthorized scanning is illegal
regardless of intent.

⚠️ **GitHub API is rate-limited to 60 requests/hour without a token.**
Get a free personal access token at github.com/settings/tokens
(no special scopes needed for public repos) and pass it via
`--github-token` for any real use.

## 4. What you get out

- **`cbom.json`** — the primary output, in CycloneDX 1.6 format (the
  industry-standard Cryptography Bill of Materials schema)
- **`vulnerabilities.json`** — same findings, in CADENCE's original
  schema, kept so your teammates' Modules 2–4 can keep consuming it
  unchanged

## 5. File map

| File | What it does |
|---|---|
| `cli.py` | Entry point — run this |
| `scanner.py` | Python AST detection (original design) + dispatch to other languages |
| `ast_multilang.py` | Java + JavaScript/TS AST detection (tree-sitter) |
| `network_scanner.py` | Live TLS/cipher/certificate inspection of a host |
| `github_discovery.py` | Auto-enumerate + scan every repo in a GitHub org |
| `network_discovery.py` | Auto-discover live subdomains of a domain |
| `cbom.py` | Shared CycloneDX 1.6 output builder |
| `sample_target/` | Demo files with intentional vulnerabilities |
| `README.md` | Full design notes, what's new vs. the original scanner, and what's deliberately out of scope |

Full details, design rationale, and honest scope limitations are in
`README.md`.
