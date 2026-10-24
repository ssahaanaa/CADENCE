# CADENCE Module 1 — The Scanner (v2)

Upgraded from a source-code-only scanner into a two-layer crypto discovery
tool, with output aligned to the CycloneDX 1.6 CBOM standard (the format
named in US Executive Order 14412, June 2026) instead of a bespoke schema.

## What's new vs. `scanner_final.py`

| | Before | Now |
|---|---|---|
| Scope | Python source only | Python, Java, JavaScript/TS AST + config-file keyword fallback + live network/TLS/certificates |
| Output | Custom `vulnerabilities.json` | CycloneDX 1.6 **CBOM** (`cbom.json`) — industry standard, plus legacy `vulnerabilities.json` kept for backward compatibility with Modules 2-4 |
| Detection | AST (primary) + keyword (fallback) | Same, **plus** tree-sitter AST for Java/JS, live network probing (protocol/cipher/cert inspection), GitHub-org and subdomain auto-discovery |

## Layers

1. **`scanner.py`** — your original design: `WeakCryptoVisitor` AST walker
   for Python (high confidence) with regex keyword fallback (`needs_review`)
   for anything it can't parse.
2. **`ast_multilang.py`** — new. Same AST philosophy, extended to Java
   (`MessageDigest.getInstance("MD5")`, `Cipher.getInstance("DES")`,
   `SSLContext.getInstance("TLSv1")`) and JavaScript/TS
   (`crypto.createHash('md5')`, `crypto.createCipheriv('des-...', ...)`)
   via tree-sitter. Falls back to keyword matching only on a genuine
   parse failure, not just "found nothing" — so a clean Java file with a
   comment mentioning "MD5" correctly produces zero findings instead of
   a keyword false positive.
3. **`network_scanner.py`** — connects to real hosts, inspects the
   TLS version/cipher actually negotiated and the certificate's key size
   and signature algorithm.
4. **`github_discovery.py`** — enumerates every repo in a GitHub org/user
   via the API, clones and scans each one automatically.
5. **`network_discovery.py`** — given one root domain, finds live
   subdomains and feeds them into the network scanner.
6. **`cbom.py`** — the shared output layer everything feeds into, emitting
   CycloneDX 1.6.

## Usage

Source traversal prunes version-control history and generated/cache folders
(`.git`, `.venv`, `__pycache__`, `build`, `dist`, and related caches) before
walking them. Dependency/vendor source directories such as `node_modules` and
`vendor` remain in scope so their cryptographic usage is still inspected.

```bash
pip install cryptography pycryptodome tree-sitter tree-sitter-java tree-sitter-javascript --break-system-packages

# Source only (now scans .py, .java, .js/.ts with full AST, others via keyword):
python cli.py ./path/to/repo

# Source + manual host list:
python cli.py ./path/to/repo --hosts example.com internal-api.corp:8443

# Auto-discover and scan every repo in a GitHub org (code layer):
python cli.py --github-org my-company --github-token ghp_xxx

# Auto-discover and scan every live subdomain of a root domain (network layer):
python cli.py --domain my-company.com

# All of it together:
python cli.py ./path/to/repo --github-org my-company --domain my-company.com
```

### Discovery layers (v3)

These are what turn this from "scan one folder / one host" into
"scan an enterprise" — same shape as AC-Scanner's `subfinder → dnsx →
httpx` pipeline, built dependency-free:

- **`github_discovery.py`** — lists every repo in a GitHub org/user via
  the API, shallow-clones each, scans it, tags findings with which repo
  they came from. **Unauthenticated GitHub API calls are capped at 60/hr**
  and will 403 past that — pass `--github-token` for real use (also
  required to reach private repos).
- **`network_discovery.py`** — given one root domain, tries a wordlist of
  common subdomains (`api.`, `vpn.`, `staging.`, etc.), keeps the ones
  that resolve, keeps the ones actually live on :443, and feeds that
  list into the existing TLS/cert scanner. Real recon tools also mine
  certificate-transparency logs (crt.sh) for far more coverage — left out
  here since CT-log queries were blocked in the sandbox this was tested
  in, but it's a straightforward addition with open network access.

**⚠️ Only ever point `--domain` at infrastructure you own or are
explicitly authorized to test.** Scanning without authorization is
illegal in most jurisdictions regardless of intent.

Produces `cbom.json` (primary) and `vulnerabilities.json` (legacy schema,
same data, kept so Modules 2-4 don't need to change yet).

## Demo

`sample_target/` has deliberately vulnerable code (MD5, SHA1, DES, RC4,
1024-bit RSA, TLSv1) plus a non-Python config file to exercise the
keyword fallback. Run:

```bash
python cli.py sample_target --project-name cadence-demo
```

## Design notes / what was deliberately NOT built

- **No vendored external tool.** Rather than shipping IBM's CBOMkit or
  the AC-Scanner project wholesale (separate licenses, separate repos,
  harder to explain as "your" work in a portfolio context), the network
  layer is a small native implementation inspired by the same idea:
  connect, observe what's actually negotiated, flag it.
- **Container/runtime layers (CBOMkit-theia style, eBPF-based runtime
  tracing) are not implemented.** They're real, valuable layers but
  meaningfully bigger scope (container introspection, kernel tracing
  permissions). Documented here as explicit future work rather than
  half-built.
- **cryptography / pycryptodome are optional-ish**: certificate
  inspection degrades gracefully (skips cert-level findings, keeps
  protocol/cipher findings) if `cryptography` isn't installed, so the
  tool doesn't hard-fail on a minimal environment.
