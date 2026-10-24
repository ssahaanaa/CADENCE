"""
ast_multilang.py — AST-based detection for Java and JavaScript, using
tree-sitter. Same philosophy as scanner.py's WeakCryptoVisitor: parse
real syntax, don't guess from text, so `MessageDigest.getInstance("MD5")`
is caught with high confidence and a comment mentioning "MD5" is not.

This is what closes the biggest gap from before: previously, anything
that wasn't Python fell straight to keyword matching. Java and JS are
now first-class, AST-verified languages — covering the two stacks most
likely to actually make up a polyglot enterprise codebase alongside
Python.

Adding another language later is the same three-step recipe:
  1. pip install tree-sitter-<lang>
  2. write a Query string for that language's call-expression syntax
  3. map matched (object, method, arg) triples to weak algorithms below
"""

from __future__ import annotations

import re
from pathlib import Path
from tree_sitter import Language, Parser, Query, QueryCursor

from cbom import CryptoAsset, Occurrence

# ---------------------------------------------------------------- Java ----

import tree_sitter_java as tsjava

JAVA_LANGUAGE = Language(tsjava.language())

JAVA_QUERY = Query(JAVA_LANGUAGE, """
(method_invocation
  object: (identifier) @obj
  name: (identifier) @method
  arguments: (argument_list (string_literal) @arg)
) @call
""")

JAVA_WEAK_ALGOS = {
    "MessageDigest": {"MD5": ("hash", "medium"), "SHA-1": ("hash", "medium"), "SHA1": ("hash", "medium")},
    "Cipher": {  # Cipher.getInstance("DES"), ("DES/ECB/PKCS5Padding"), ("RC4"), ...
        # matched via substring below, not exact keys
    },
    "SSLContext": {"TLS": None, "TLSv1": ("protocol", "high"), "SSLv3": ("protocol", "high"), "SSL": ("protocol", "high")},
    "KeyPairGenerator": {"RSA": ("signature", None)},  # key size checked separately
}
JAVA_WEAK_CIPHER_SUBSTRINGS = ("DES", "RC4", "ARCFOUR", "BLOWFISH")
JAVA_WEAK_TLS_PROTOCOLS = {"SSL", "SSLV2", "SSLV3", "SSLV23", "TLSV1", "TLSV1.0", "TLSV1.1", "TLS1.0", "TLS1.1"}


def scan_java_file(path: Path) -> list[CryptoAsset] | None:
    """Returns None only on a genuine parse failure (caller should then
    fall back to keyword scanning); returns [] for a clean, successfully
    parsed file with no weak crypto found."""
    findings = []
    try:
        source = path.read_bytes()
        tree = Parser(JAVA_LANGUAGE).parse(source)
    except Exception:
        return None
    if tree.root_node.has_error:
        return None

    for _, captures in QueryCursor(JAVA_QUERY).matches(tree.root_node):
        obj = captures["obj"][0].text.decode()
        method = captures["method"][0].text.decode()
        arg_node = captures["arg"][0]
        arg = arg_node.text.decode().strip('"')
        line = arg_node.start_point[0] + 1

        if method != "getInstance":
            continue

        if obj == "MessageDigest" and arg.upper().replace("-", "") in {"MD5", "SHA1"}:
            findings.append(CryptoAsset(
                name=arg.upper(), asset_type="algorithm", primitive="hash",
                confidence="high", detection_method="ast", severity="medium",
                occurrences=[Occurrence(location=str(path), line=line)],
                notes="Broken hash algorithm requested via MessageDigest.getInstance().",
            ))
        elif obj == "Cipher" and any(w in arg.upper() for w in JAVA_WEAK_CIPHER_SUBSTRINGS):
            findings.append(CryptoAsset(
                name=arg, asset_type="algorithm", primitive="cipher",
                confidence="high", detection_method="ast", severity="high",
                occurrences=[Occurrence(location=str(path), line=line)],
                notes="Deprecated cipher requested via Cipher.getInstance().",
            ))
        elif obj == "SSLContext" and arg.strip().upper() in JAVA_WEAK_TLS_PROTOCOLS:
            findings.append(CryptoAsset(
                name=arg, asset_type="protocol",
                confidence="high", detection_method="ast", severity="high",
                occurrences=[Occurrence(location=str(path), line=line)],
                notes="Deprecated TLS/SSL protocol via SSLContext.getInstance().",
            ))

    return findings


# --------------------------------------------------------------- JS/TS ----

import tree_sitter_javascript as tsjs

JS_LANGUAGE = Language(tsjs.language())

JS_QUERY = Query(JS_LANGUAGE, """
(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method)
  arguments: (arguments (string (string_fragment) @arg))
) @call
""")
JS_DIRECT_QUERY = Query(JS_LANGUAGE, """
(call_expression
  function: (identifier) @method
  arguments: (arguments (string (string_fragment) @arg))
) @call
""")

JS_WEAK_HASH = {"md5", "sha1"}
JS_WEAK_CIPHER_SUBSTRINGS = ("des", "rc4", "arcfour")


def scan_js_file(path: Path) -> list[CryptoAsset] | None:
    """Same None-vs-[] contract as scan_java_file above."""
    findings = []
    try:
        source = path.read_bytes()
        tree = Parser(JS_LANGUAGE).parse(source)
    except Exception:
        return None
    if tree.root_node.has_error:
        return None

    source_text = source.decode("utf-8", errors="ignore")
    crypto_aliases = {"crypto"}
    crypto_aliases.update(re.findall(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"](?:node:)?crypto['\"]\s*\)",
        source_text,
    ))
    crypto_aliases.update(re.findall(
        r"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['\"](?:node:)?crypto['\"]",
        source_text,
    ))
    crypto_aliases.update(re.findall(
        r"import\s+([A-Za-z_$][\w$]*)\s+from\s+['\"](?:node:)?crypto['\"]",
        source_text,
    ))
    named_methods: dict[str, str] = {}
    named_imports = re.finditer(
        r"import\s*\{([^}]+)\}\s*from\s*['\"](?:node:)?crypto['\"]|"
        r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['\"](?:node:)?crypto['\"]\s*\)",
        source_text,
    )
    for match in named_imports:
        for entry in (match.group(1) or match.group(2)).split(","):
            tokens = re.split(r"\s+as\s+|\s*:\s*", entry.strip())
            if tokens and tokens[0].strip():
                original = tokens[0].strip()
                local = tokens[-1].strip()
                named_methods[local] = original
    for _, captures in QueryCursor(JS_QUERY).matches(tree.root_node):
        obj = captures["obj"][0].text.decode()
        method = captures["method"][0].text.decode()
        arg_node = captures["arg"][0]
        arg = arg_node.text.decode()
        line = arg_node.start_point[0] + 1

        if obj not in crypto_aliases:
            continue

        if method == "createHash" and arg.lower() in JS_WEAK_HASH:
            findings.append(CryptoAsset(
                name=arg.upper(), asset_type="algorithm", primitive="hash",
                confidence="high", detection_method="ast", severity="medium",
                occurrences=[Occurrence(location=str(path), line=line)],
                notes="Broken hash algorithm requested via crypto.createHash().",
            ))
        elif method in {"createCipheriv", "createCipher", "createDecipheriv"} and \
                any(w in arg.lower() for w in JS_WEAK_CIPHER_SUBSTRINGS):
            findings.append(CryptoAsset(
                name=arg, asset_type="algorithm", primitive="cipher",
                confidence="high", detection_method="ast", severity="high",
                occurrences=[Occurrence(location=str(path), line=line)],
                notes=f"Deprecated cipher requested via crypto.{method}().",
            ))

    for _, captures in QueryCursor(JS_DIRECT_QUERY).matches(tree.root_node):
        local_method = captures["method"][0].text.decode()
        method = named_methods.get(local_method, "")
        arg_node = captures["arg"][0]
        arg = arg_node.text.decode()
        line = arg_node.start_point[0] + 1
        if method == "createHash" and arg.lower() in JS_WEAK_HASH:
            findings.append(CryptoAsset(
                name=arg.upper(), asset_type="algorithm", primitive="hash",
                confidence="high", detection_method="ast", severity="medium",
                occurrences=[Occurrence(location=str(path), line=line)],
                notes="Broken hash algorithm requested via an imported crypto.createHash().",
            ))
        elif method in {"createCipheriv", "createCipher", "createDecipheriv"} and \
                any(w in arg.lower() for w in JS_WEAK_CIPHER_SUBSTRINGS):
            findings.append(CryptoAsset(
                name=arg, asset_type="algorithm", primitive="cipher",
                confidence="high", detection_method="ast", severity="high",
                occurrences=[Occurrence(location=str(path), line=line)],
                notes=f"Deprecated cipher requested via an imported crypto.{method}().",
            ))

    return findings
