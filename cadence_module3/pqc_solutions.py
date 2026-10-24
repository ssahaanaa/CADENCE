#!/usr/bin/env python3
"""
CADENCE — Module 3 add-on: PQC Solutions Engine

Module 3's decision engine answers "in what order do we migrate systems".
This module answers the next question: "for each system, what exactly do we
change, how, and how do we know it worked?"

It takes the output of a finished run (migration_ranking.json + the Module 1
findings) and produces, per system:

  * what to change      - every weak algorithm mapped to a concrete replacement,
                          with a plain-English explanation and the real threat
                          (broken today / broken by a quantum computer / both)
  * an ordered plan     - phased, checkable steps (prepare -> fix now ->
                          deploy PQC -> validate & retire)
  * code changes        - before/after snippets (Python, Java, JavaScript,
                          TLS/proxy config)
  * how to verify       - commands and expected results
  * deployment impact   - real key / signature / handshake size changes

Honesty rule baked into the data: most of what Module 1 flags (MD5, SHA-1,
DES, RC4, SSLv3, TLS 1.0/1.1) is already broken by classical attacks and is
NOT fixed by a post-quantum algorithm — it is fixed by a modern symmetric
cipher / hash / TLS 1.3. Those items are labelled "fix first" and are shown
as the on-ramp to PQC. Only public-key uses (RSA, ECDSA, ECDH, DH, Ed25519)
get a direct ML-KEM / ML-DSA / SLH-DSA swap.

Sizes below are the byte sizes NIST published in FIPS 203 / 204 / 205.
Classical baselines are rough DER-encoded figures for a "how much bigger"
comparison only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# 1. Parameter sets and profiles
# --------------------------------------------------------------------------

KEM_PROFILES: dict[str, dict[str, Any]] = {          # FIPS 203
    "ML-KEM-512":  {"public_key": 800,  "ciphertext": 768,  "shared_secret": 32, "nist_level": 1},
    "ML-KEM-768":  {"public_key": 1184, "ciphertext": 1088, "shared_secret": 32, "nist_level": 3},
    "ML-KEM-1024": {"public_key": 1568, "ciphertext": 1568, "shared_secret": 32, "nist_level": 5},
}
DSA_PROFILES: dict[str, dict[str, Any]] = {          # FIPS 204
    "ML-DSA-44": {"public_key": 1312, "signature": 2420, "nist_level": 2},
    "ML-DSA-65": {"public_key": 1952, "signature": 3309, "nist_level": 3},
    "ML-DSA-87": {"public_key": 2592, "signature": 4627, "nist_level": 5},
}
SLH_PROFILES: dict[str, dict[str, Any]] = {          # FIPS 205
    "SLH-DSA-SHA2-128s": {"public_key": 32, "signature": 7856,  "nist_level": 1, "signing": "slow"},
    "SLH-DSA-SHA2-128f": {"public_key": 32, "signature": 17088, "nist_level": 1, "signing": "fast"},
    "SLH-DSA-SHA2-192s": {"public_key": 48, "signature": 16224, "nist_level": 3, "signing": "slow"},
    "SLH-DSA-SHA2-256s": {"public_key": 64, "signature": 29792, "nist_level": 5, "signing": "slow"},
}
SIG_PROFILES = {**DSA_PROFILES, **SLH_PROFILES}

CLASSICAL_BASELINES: dict[str, dict[str, int]] = {
    "rsa-1024":   {"public_key": 162, "signature": 128},
    "rsa-2048":   {"public_key": 270, "signature": 256},
    "rsa-3072":   {"public_key": 398, "signature": 384},
    "rsa-4096":   {"public_key": 550, "signature": 512},
    "ecdsa-p256": {"public_key": 64,  "signature": 72},
    "ed25519":    {"public_key": 32,  "signature": 64},
}

PROFILES: dict[str, dict[str, Any]] = {
    "standard": {
        "id": "standard",
        "label": "Standard",
        "blurb": "NIST level 3. The sensible default for most enterprise systems.",
        "kem": "ML-KEM-768", "sig": "ML-DSA-65", "firmware_sig": "SLH-DSA-SHA2-128s",
        "tls_group": "X25519MLKEM768", "ec_share": 32,
        "sym": "AES-256-GCM", "hash": "SHA-256",
    },
    "high": {
        "id": "high",
        "label": "High assurance",
        "blurb": "NIST level 5, aligned with the NSA CNSA 2.0 suite. Bigger keys, more handshake overhead.",
        "kem": "ML-KEM-1024", "sig": "ML-DSA-87", "firmware_sig": "SLH-DSA-SHA2-256s",
        "tls_group": "SecP384r1MLKEM1024", "ec_share": 97,
        "sym": "AES-256-GCM", "hash": "SHA-384",
    },
}

PHASES = {
    0: "Prepare",
    1: "Fix now",
    2: "Deploy PQC",
    3: "Validate & retire",
}

CATEGORY_LABELS = {
    "hash": "Hash function",
    "symmetric": "Symmetric cipher",
    "protocol": "Transport protocol",
    "cipher_suite": "TLS cipher suite",
    "public_key": "Public-key cryptography",
    "certificate": "Certificate",
    "hygiene": "Operational",
    "other": "Unclassified",
}

RELEVANCE_LABELS = {
    "direct": "Direct PQC swap",
    "prerequisite": "Fix first, then PQC",
    "fix-first": "Fix first, no PQC needed",
    "upsize": "Increase key size",
    "none": "Operational fix",
}

# --------------------------------------------------------------------------
# 2. Code snippets. <<TOKENS>> are filled from the active profile.
# --------------------------------------------------------------------------

SNIPPETS: dict[str, dict[str, Any]] = {
    "hash": {
        "title": "Replace MD5 / SHA-1",
        "python": {
            "before": "import hashlib\ndigest = hashlib.md5(data).hexdigest()",
            "after": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()\n\n# Passwords are different: use a slow, salted hash, not a fast one.\n# pip install argon2-cffi\nfrom argon2 import PasswordHasher\nstored = PasswordHasher().hash(password)",
            "note": "Digest length changes (16/20 → 32 bytes). Check DB columns and any fixed-size fields.",
        },
        "java": {
            "before": 'MessageDigest md = MessageDigest.getInstance("MD5");',
            "after": 'MessageDigest md = MessageDigest.getInstance("SHA-256");\n// Keyed integrity checks: use HMAC, not a bare hash\nMac mac = Mac.getInstance("HmacSHA256");',
            "note": "SHA-1 → SHA-256 is the same API call with a different name.",
        },
        "javascript": {
            "before": "const h = crypto.createHash('md5').update(data).digest('hex');",
            "after": "const h = crypto.createHash('sha256').update(data).digest('hex');\n\n// Passwords: use scrypt (built in) or argon2\nconst key = crypto.scryptSync(password, salt, 64);",
            "note": "Never store passwords with a plain hash, even SHA-256.",
        },
    },
    "symmetric": {
        "title": "Replace DES / RC4 / Blowfish with AES-256-GCM",
        "python": {
            "before": "from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)\nct = cipher.encrypt(pad(data, 8))",
            "after": "import os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\nkey = AESGCM.generate_key(bit_length=256)   # keep in a KMS, not in code\naead = AESGCM(key)\nnonce = os.urandom(12)                       # unique per message, never reused\nct = nonce + aead.encrypt(nonce, data, associated_data)",
            "note": "GCM authenticates as well as encrypts. Store the nonce next to the ciphertext.",
        },
        "java": {
            "before": 'Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");\nc.init(Cipher.ENCRYPT_MODE, key);',
            "after": 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\nbyte[] iv = new byte[12];\nnew SecureRandom().nextBytes(iv);\nc.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));\nc.updateAAD(aad);\nbyte[] ct = c.doFinal(plaintext);',
            "note": "aesKey must be a 256-bit AES key. Prepend the IV to the output.",
        },
        "javascript": {
            "before": "const c = crypto.createCipheriv('des-ecb', key, null);",
            "after": "const iv = crypto.randomBytes(12);\nconst c = crypto.createCipheriv('aes-256-gcm', key32, iv);\nc.setAAD(aad);\nconst ct = Buffer.concat([c.update(data), c.final()]);\nconst tag = c.getAuthTag();          // store iv + tag + ct",
            "note": "key32 must be exactly 32 bytes.",
        },
    },
    "tls": {
        "title": "Require TLS 1.3 and offer hybrid post-quantum key exchange",
        "config": {
            "before": "# nginx\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;\nssl_ciphers  ALL:!aNULL;",
            "after": "# nginx built against OpenSSL 3.5+\nssl_protocols TLSv1.2 TLSv1.3;     # drop TLSv1.2 too once all clients support 1.3\nssl_ecdh_curve <<TLS_GROUP>>:X25519:prime256v1;\nssl_prefer_server_ciphers off;",
            "note": "Clients that don't know the hybrid group quietly fall back to X25519, so this is safe to roll out first.",
        },
        "python": {
            "before": "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)",
            "after": "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nctx.minimum_version = ssl.TLSVersion.TLSv1_3\nctx.check_hostname = True\n# Python on OpenSSL 3.5+ offers <<TLS_GROUP>> by default. No extra code.",
            "note": "To see which OpenSSL Python is linked against, run: python -c \"import ssl; print(ssl.OPENSSL_VERSION)\"",
        },
        "java": {
            "before": 'SSLContext ctx = SSLContext.getInstance("TLSv1");',
            "after": 'SSLContext ctx = SSLContext.getInstance("TLSv1.3");\n// Hybrid groups depend on your JDK release. Check its release notes.\n// Until then, terminate TLS at a PQ-capable proxy or load balancer.',
            "note": "Move to TLS 1.3 now even if your JDK can't do hybrid groups yet.",
        },
    },
    "kem": {
        "title": "Key exchange / key transport → hybrid <<KEM>>",
        "python": {
            "before": "# wrap a session key with RSA\nwrapped = rsa_public_key.encrypt(session_key, padding.OAEP(\n    mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))",
            "after": "# pip install liboqs-python   (needs the liboqs C library)\nimport oqs\nfrom cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey\nfrom cryptography.hazmat.primitives.kdf.hkdf import HKDF\n\ndef combine(*secrets: bytes) -> bytes:\n    # Hybrid: the key stays safe if EITHER ML-KEM or X25519 holds up\n    return HKDF(hashes.SHA256(), 32, None, b\"myapp-v1 hybrid\").derive(b\"\".join(secrets))\n\n# receiver: publish kem_pub and x_priv.public_key()\nx_priv = X25519PrivateKey.generate()\nkem = oqs.KeyEncapsulation(\"<<KEM>>\")\nkem_pub = kem.generate_keypair()\n\n# sender: send kem_ct and x_eph.public_key() back\nwith oqs.KeyEncapsulation(\"<<KEM>>\") as sender:\n    kem_ct, kem_ss = sender.encap_secret(kem_pub)\nx_eph = X25519PrivateKey.generate()\nsession_key = combine(kem_ss, x_eph.exchange(x_priv.public_key()))\n\n# receiver: derive the same key\nsession_key = combine(kem.decap_secret(kem_ct), x_priv.exchange(x_eph.public_key()))",
            "note": "The ciphertext (<<KEM_CT>> bytes) replaces the RSA-wrapped key. Make sure message formats can carry it.",
        },
        "java": {
            "before": 'Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\nbyte[] wrapped = c.doFinal(sessionKey);',
            "after": '// JDK 24+ (JEP 496)\nKeyPairGenerator g = KeyPairGenerator.getInstance("<<KEM>>");\nKeyPair kp = g.generateKeyPair();             // receiver\n\nKEM kem = KEM.getInstance("ML-KEM");\nKEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic()).encapsulate();\nSecretKey k1 = enc.key();                     // sender\'s secret\nbyte[] ct = enc.encapsulation();              // send this\n\nSecretKey k2 = kem.newDecapsulator(kp.getPrivate()).decapsulate(ct);\n// Combine with an X25519 secret via HKDF for a hybrid key',
            "note": "On JDK older than 24, use Bouncy Castle's PQC provider.",
        },
        "javascript": {
            "before": "const wrapped = crypto.publicEncrypt(rsaPublicKey, sessionKey);",
            "after": "// npm i @noble/post-quantum   (audited, pure JS)\nimport { ml_kem768 } from '@noble/post-quantum/ml-kem';\n\nconst { publicKey, secretKey } = ml_kem768.keygen();               // receiver\nconst { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey); // sender\nconst same = ml_kem768.decapsulate(cipherText, secretKey);         // receiver\n// Combine with an X25519 secret via HKDF for a hybrid key",
            "note": "Pin the version and check the import path against its README.",
        },
    },
    "signature": {
        "title": "Signatures → <<SIG>> (dual-sign during transition)",
        "python": {
            "before": "from cryptography.hazmat.primitives.asymmetric import rsa, padding\nsig = rsa_private_key.sign(msg, padding.PKCS1v15(), hashes.SHA1())",
            "after": "# pip install liboqs-python\nimport oqs\n\nwith oqs.Signature(\"<<SIG>>\") as signer:\n    public_key = signer.generate_keypair()\n    pq_sig = signer.sign(msg)\n\n# transition: ship BOTH signatures, accept either until all verifiers upgrade\nrecord = {\"sig_rsa\": classical_sig, \"sig_pq\": pq_sig, \"alg_pq\": \"<<SIG>>\"}\n\nwith oqs.Signature(\"<<SIG>>\") as verifier:\n    ok = verifier.verify(msg, pq_sig, public_key)",
            "note": "A <<SIG>> signature is <<SIG_BYTES>> bytes. Check JWT/cookie/header limits and DB column sizes first.",
        },
        "java": {
            "before": 'Signature s = Signature.getInstance("SHA1withRSA");',
            "after": '// JDK 24+ (JEP 497)\nKeyPairGenerator g = KeyPairGenerator.getInstance("<<SIG>>");\nKeyPair kp = g.generateKeyPair();\n\nSignature s = Signature.getInstance("ML-DSA");\ns.initSign(kp.getPrivate());\ns.update(message);\nbyte[] sig = s.sign();\n\ns.initVerify(kp.getPublic());\ns.update(message);\nboolean ok = s.verify(sig);',
            "note": "On JDK older than 24, use Bouncy Castle's PQC provider.",
        },
        "javascript": {
            "before": "const sig = crypto.sign('sha1', data, rsaPrivateKey);",
            "after": "// npm i @noble/post-quantum\nimport { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\n\nconst { publicKey, secretKey } = ml_dsa65.keygen();\nconst sig = ml_dsa65.sign(data, secretKey);\nconst ok = ml_dsa65.verify(sig, data, publicKey);\n// Argument order has changed between releases. Check your pinned version.",
            "note": "Use ml_dsa87 for the High assurance profile.",
        },
    },
}

# --------------------------------------------------------------------------
# 3. Verification recipes
# --------------------------------------------------------------------------

VERIFY: dict[str, list[dict[str, str]]] = {
    "hash": [
        {"label": "Find leftover uses",
         "command": "grep -rniE '\\b(md5|sha-?1)\\b' --include='*.py' --include='*.java' --include='*.js' .",
         "expect": "No matches outside tests and explicit legacy-compat shims."},
    ],
    "symmetric": [
        {"label": "Round-trip a sample of real records",
         "command": "",
         "expect": "Old ciphertext decrypts with the old key, re-encrypts with AES-256-GCM, and decrypts back to the same plaintext."},
    ],
    "tls": [
        {"label": "Confirm the hybrid group negotiates",
         "command": "openssl s_client -connect HOST:443 -tls1_3 -groups <<TLS_GROUP>> </dev/null 2>&1 | grep -i 'group\\|protocol'",
         "expect": "Negotiated TLS1.3 group: <<TLS_GROUP>> (needs an OpenSSL 3.5+ client)."},
        {"label": "Confirm legacy protocols are refused",
         "command": "openssl s_client -connect HOST:443 -tls1 </dev/null",
         "expect": "Handshake failure."},
        {"label": "Enumerate what the server still offers",
         "command": "nmap --script ssl-enum-ciphers -p 443 HOST",
         "expect": "Only TLSv1.2 / TLSv1.3 with AEAD suites."},
    ],
    "kem": [
        {"label": "Round-trip the key exchange in a unit test",
         "command": "",
         "expect": "Sender and receiver derive the same 32-byte key, and decryption works with it."},
    ],
    "signature": [
        {"label": "Generate a key and check signature size",
         "command": "openssl genpkey -algorithm <<SIG>> -out key.pem && openssl pkeyutl -sign -inkey key.pem -rawin -in msg.bin -out sig.bin && wc -c sig.bin",
         "expect": "sig.bin is <<SIG_BYTES>> bytes (needs OpenSSL 3.5+)."},
        {"label": "Verify the signature",
         "command": "openssl pkeyutl -verify -inkey key.pem -rawin -in msg.bin -sigfile sig.bin",
         "expect": "Signature Verified Successfully."},
    ],
    "rescan": [
        {"label": "Re-run the CADENCE scan",
         "command": "",
         "expect": "The findings you just fixed no longer appear for this system."},
    ],
}

# --------------------------------------------------------------------------
# 4. Algorithm catalog
# --------------------------------------------------------------------------


def _entry(id, title, pattern, category, threat, relevance, urgency, swap, replace,
           plain, threat_text, gotchas, difficulty="medium", snippets=(), verify=(),
           roles=None):
    return dict(id=id, title=title, pattern=re.compile(pattern, re.I), category=category,
                threat=threat, relevance=relevance, urgency=urgency, swap=swap,
                replace=replace, plain=plain, threat_text=threat_text, gotchas=gotchas,
                difficulty=difficulty, snippets=list(snippets), verify=list(verify),
                roles=roles)


_PK_ROLES = [
    {"role": "Digital signatures (signing, certificates, tokens, code signing)",
     "replace": "<<SIG>> (FIPS 204). Use <<FW_SIG>> (FIPS 205) for firmware and long-lived root keys.",
     "snippet": "signature"},
    {"role": "Key exchange / key transport (session keys, TLS handshakes)",
     "replace": "Hybrid <<KEM>> (FIPS 203) + X25519, so security holds if either one does.",
     "snippet": "kem"},
]

CATALOG: list[dict[str, Any]] = [
    # ---- operational findings (must match before algorithm names) ----
    _entry("expired-cert", "Expired certificate", r"expired", "hygiene", "none", "none", "high",
           "Renew + automate rotation",
           ["Renew the certificate now.", "Automate issuance and renewal (ACME or your PKI's equivalent)."],
           "The certificate's validity period has ended, so clients will refuse the connection or, worse, users learn to click through warnings. Automated renewal is also what makes the later switch to post-quantum certificates painless.",
           "Not a cryptographic weakness, but an outage and trust risk.",
           ["Check every host that shares this certificate.", "Add expiry monitoring with at least 30 days' warning."],
           "low", [], ["rescan"]),
    _entry("unreachable", "Host unreachable", r"^unreachable$", "hygiene", "none", "none", "low",
           "Fix access, then re-scan",
           ["Confirm the host and port, and that the scanner can reach it.", "Re-run the scan."],
           "The scanner could not complete a handshake, so this endpoint was not assessed. It is not a finding about the host's cryptography.",
           "Unknown. The host was not assessed.",
           ["A firewall or allow-list is the usual cause."], "low", [], ["rescan"]),
    _entry("hash-signed-cert", "Certificate signed with a broken hash", r"(md5|sha-?1)-signed certificate", "certificate",
           "classical", "prerequisite", "critical", "Reissue with SHA-256, then plan ML-DSA",
           ["Reissue the certificate signed with <<HASH>>.", "Then add <<SIG>> certificates through your private PKI."],
           "The certificate's seal was made with a hash that can be forged, so someone could in principle produce a fake certificate that looks identical. Reissue it now. This needs no post-quantum algorithm.",
           "MD5 and SHA-1 collisions are practical today.",
           ["Reissue the whole chain if intermediates use the same hash.", "Public CAs may not issue post-quantum certificates yet. Keep classical certificates on public endpoints and trial ML-DSA internally first."],
           "medium", ["signature"], ["signature", "rescan"]),
    _entry("rsa-cert", "RSA certificate key", r"rsa-\d+.*certificate", "certificate",
           "both", "direct", "critical", "Reissue (RSA-3072 / ECDSA now), then ML-DSA",
           ["Interim: reissue with RSA-3072+ or ECDSA P-256 to remove the classical weakness today.", "Target: <<SIG>> certificates, dual-signed during transition."],
           "A certificate's key proves a server is who it claims to be. This one is too short to trust even against today's computers, and every RSA key can be broken once a large quantum computer exists. Fix the length now, and plan the post-quantum switch.",
           "Weak against classical attack today; all RSA is breakable by Shor's algorithm.",
           ["Certificate chains grow a lot with ML-DSA (about 5 KB per certificate: key + signature).", "Check load balancers, HSMs and clients for certificate size limits before issuing."],
           "high", ["signature"], ["signature", "rescan"]),
    # ---- weak cipher suites (names like RC4-SHA, DES-CBC3-SHA) ----
    _entry("weak-suite", "Weak TLS cipher suite", r"^(?!(?:3?des|arc4|rc4|md5)$)(?=.*[-_]).*(rc4|des|null|export|md5)", "cipher_suite",
           "classical", "prerequisite", "critical", "TLS 1.3 AEAD suites",
           ["Allow only TLS 1.3 suites (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256).", "If TLS 1.2 must stay, restrict to ECDHE with AES-GCM."],
           "A cipher suite is the bundle of algorithms two machines agree on for a connection. This one includes an algorithm that is already breakable. Removing it from the allowed list is a configuration change.",
           "Broken by classical attacks today.",
           ["Very old clients may stop connecting. Check access logs for the TLS versions in use first."],
           "low", ["tls"], ["tls", "rescan"]),
    # ---- public key ----
    _entry("rsa", "RSA", r"^rsa(-\d+)?$", "public_key", "both", "direct", "high",
           "<<SIG>> and/or <<KEM>>",
           ["Signatures → <<SIG>>", "Key exchange → hybrid <<KEM>> + X25519"],
           "RSA is the lock-and-key math behind most signatures and key exchanges. A large quantum computer breaks it completely (Shor's algorithm), and short RSA keys are weak even now. The replacement depends on what the RSA key is used for: signing or protecting a secret.",
           "Quantum: broken. Short keys (under 2048-bit): weak today as well. Data protected by RSA key exchange can be recorded now and decrypted later.",
           ["Find out what each RSA key is used for before choosing. The scanner only reports the key size.", "Interim: if you cannot ship PQC yet, move to RSA-3072 or ECDSA P-256 so you are not weak classically while you wait."],
           "high", ["signature", "kem"], ["signature", "kem", "rescan"], roles=_PK_ROLES),
    _entry("ecdsa", "ECDSA / Ed25519", r"^(ecdsa|ed25519|ed448)", "public_key", "quantum", "direct", "medium",
           "<<SIG>>", ["<<SIG>> (FIPS 204), dual-signed during transition."],
           "Elliptic-curve signatures are small and fast, but a large quantum computer breaks them. They are fine today and need a planned move, not an emergency one.",
           "Quantum: broken by Shor's algorithm. Classical: strong.",
           ["Signatures grow from about 64 bytes to <<SIG_BYTES>> bytes."], "medium", ["signature"], ["signature", "rescan"]),
    _entry("ecdh", "ECDH / X25519 / DH", r"^(x25519|x448|ecdh|dh|diffie)", "public_key", "quantum", "direct", "high",
           "Hybrid <<KEM>> + X25519", ["Hybrid <<KEM>> + X25519 (TLS group <<TLS_GROUP>>)."],
           "Diffie-Hellman style key exchange is how most connections agree on a secret key. A large quantum computer breaks it, and traffic recorded today could be decrypted later. This is the most time-sensitive PQC change.",
           "Quantum: broken. Recorded traffic is exposed to harvest-now-decrypt-later.",
           ["Hybrid keeps X25519's proven security as a safety net."], "medium", ["kem", "tls"], ["tls", "kem", "rescan"]),
    # ---- protocols ----
    _entry("tls-legacy", "Legacy SSL/TLS", r"^ssl(v?\d+(\.\d)?)?$|^tls-?v?1(\.[01])?(/1\.1)?$", "protocol",
           "classical", "prerequisite", "critical", "TLS 1.3 + <<TLS_GROUP>>",
           ["Disable SSLv2/v3 and TLS 1.0/1.1.", "Require TLS 1.3 and offer hybrid group <<TLS_GROUP>>."],
           "These old versions of the secure-connection protocol have known attacks (such as POODLE), and the newest version is the only one that can carry post-quantum key exchange. Upgrading fixes today's problem and gets you ready for the quantum one.",
           "Broken or deprecated today (RFC 8996). TLS 1.3 is also required for ML-KEM hybrids.",
           ["Check access logs for client TLS versions before switching off 1.2.", "Some middleboxes choke on a larger ClientHello. Test through your real network path."],
           "medium", ["tls"], ["tls", "rescan"]),
    # ---- hashes ----
    _entry("md5", "MD5", r"^md5$", "hash", "classical", "fix-first", "critical", "<<HASH>>",
           ["<<HASH>> (or SHA3-256).", "HMAC-SHA-256 for keyed integrity; Argon2id for passwords."],
           "A hash is a fingerprint of data. MD5 fingerprints can be forged, so anything that trusts them (integrity checks, signatures, password storage) can be tricked. This is a small code change. Quantum computers barely affect SHA-256, so it is a one-time fix.",
           "Collisions are practical today. Not a quantum problem.",
           ["Stored digests change length (16 → 32 bytes). Check DB columns and protocol fields.", "Passwords: rehash on next login with Argon2id, don't just swap to SHA-256.", "If the hash is part of a signature or certificate, reissue it."],
           "low", ["hash"], ["hash", "rescan"]),
    _entry("sha1", "SHA-1", r"^sha-?1$", "hash", "classical", "fix-first", "high", "<<HASH>>",
           ["<<HASH>> (or SHA3-256).", "HMAC-SHA-256 for keyed integrity."],
           "SHA-1 is the successor to MD5 and has since been broken the same way. Replace it with the SHA-2 family. This is a small code change, and SHA-256 stays safe against quantum computers.",
           "Collisions demonstrated publicly in 2017. Not a quantum problem.",
           ["Git object IDs and some legacy protocols use SHA-1 internally. Those are separate migrations.", "Digest length changes (20 → 32 bytes)."],
           "low", ["hash"], ["hash", "rescan"]),
    # ---- symmetric ----
    _entry("des", "DES / 3DES", r"^3?des$|^triple-?des$", "symmetric", "classical", "fix-first", "critical",
           "<<SYM>>", ["<<SYM>> (or ChaCha20-Poly1305).", "Re-encrypt existing data."],
           "DES locks data with a key so short that it can be guessed by brute force in hours. 3DES is stronger but deprecated by NIST. AES-256 is safe against both today's and quantum computers, so the swap is permanent.",
           "56-bit DES is brute-forceable today. 3DES is deprecated (Sweet32).",
           ["Existing ciphertext must be re-encrypted. Plan a migration job.", "Never reuse a GCM nonce with the same key.", "Do not carry ECB mode over to AES."],
           "medium", ["symmetric"], ["symmetric", "rescan"]),
    _entry("rc4", "RC4 / ARC4", r"^(arc4|rc4|arcfour)$", "symmetric", "classical", "fix-first", "critical",
           "<<SYM>>", ["<<SYM>> (or ChaCha20-Poly1305).", "Re-encrypt existing data."],
           "RC4's output has statistical biases that let attackers recover plaintext, and it is banned from TLS (RFC 7465). Swap it for AES-GCM or ChaCha20-Poly1305.",
           "Practical plaintext-recovery attacks exist today.",
           ["RC4 has no authentication. Moving to an AEAD mode also adds tamper detection.", "Re-encrypt stored data."],
           "medium", ["symmetric"], ["symmetric", "rescan"]),
    _entry("blowfish", "Blowfish", r"^blowfish$", "symmetric", "classical", "fix-first", "high",
           "<<SYM>>", ["<<SYM>> (or ChaCha20-Poly1305)."],
           "Blowfish works on small 64-bit blocks, which makes it leak data when a lot is encrypted under one key (Sweet32). AES uses 128-bit blocks and doesn't have the problem.",
           "64-bit block size: practical attacks on large volumes of data.",
           ["Re-encrypt stored data."], "medium", ["symmetric"], ["symmetric", "rescan"]),
    _entry("aes128", "AES-128", r"^aes-?128", "symmetric", "quantum", "upsize", "low", "AES-256-GCM",
           ["AES-256-GCM."],
           "AES-128 is secure today. Quantum computers cut an AES key's strength roughly in half (Grover's algorithm), so 256-bit keys keep a comfortable margin. NSA's CNSA 2.0 requires AES-256.",
           "Quantum: security margin roughly halved.",
           ["Only the key length changes. The API stays the same."], "low", ["symmetric"], ["symmetric", "rescan"]),
]

FALLBACK = _entry("unclassified", "Unclassified", r".*", "other", "none", "none", "low",
                  "Review manually",
                  ["Review this finding manually. It did not match a known algorithm pattern."],
                  "CADENCE doesn't have a specific recipe for this finding yet. Check the file and line in the Findings tab and decide whether it's a real use of weak cryptography.",
                  "Unknown.", ["Consider reporting the pattern so a recipe can be added."], "low", [], ["rescan"])

URGENCY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def classify(name: str) -> dict[str, Any]:
    n = (name or "").strip()
    for e in CATALOG:
        if e["pattern"].search(n):
            return e
    return FALLBACK


# --------------------------------------------------------------------------
# 5. Filling in profile values
# --------------------------------------------------------------------------

def _tokens(p: dict) -> dict[str, str]:
    kem, sig = KEM_PROFILES[p["kem"]], SIG_PROFILES[p["sig"]]
    return {
        "<<KEM>>": p["kem"], "<<SIG>>": p["sig"], "<<FW_SIG>>": p["firmware_sig"],
        "<<TLS_GROUP>>": p["tls_group"], "<<HASH>>": p["hash"], "<<SYM>>": p["sym"],
        "<<KEM_CT>>": f"{kem['ciphertext']:,}", "<<SIG_BYTES>>": f"{sig['signature']:,}",
    }


def _fill(obj, tok):
    if isinstance(obj, str):
        for k, v in tok.items():
            obj = obj.replace(k, v)
        return obj
    if isinstance(obj, list):
        return [_fill(x, tok) for x in obj]
    if isinstance(obj, dict):
        return {k: _fill(v, tok) for k, v in obj.items()}
    return obj


def _resolve_entry(e: dict, tok: dict, display_name: str | None = None) -> dict[str, Any]:
    out = {
        "id": e["id"],
        "name": display_name or e["title"],
        "title": e["title"],
        "category": e["category"],
        "category_label": CATEGORY_LABELS[e["category"]],
        "threat": e["threat"],
        "threat_text": e["threat_text"],
        "relevance": e["relevance"],
        "relevance_label": RELEVANCE_LABELS[e["relevance"]],
        "urgency": e["urgency"],
        "swap": e["swap"],
        "replace": e["replace"],
        "plain": e["plain"],
        "gotchas": e["gotchas"],
        "difficulty": e["difficulty"],
        "roles": e["roles"],
    }
    return _fill(out, tok)


# --------------------------------------------------------------------------
# 6. Impact (real sizes)
# --------------------------------------------------------------------------

def _rsa_baseline(name: str) -> str:
    m = re.search(r"rsa-(\d+)", name.lower())
    key = f"rsa-{m.group(1)}" if m else "rsa-2048"
    return key if key in CLASSICAL_BASELINES else "rsa-2048"


def _impact_for(entries: list[tuple[str, dict]], p: dict) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    kem, sig = KEM_PROFILES[p["kem"]], SIG_PROFILES[p["sig"]]
    cats = {e["id"] for _, e in entries}
    need_sig = bool(cats & {"rsa", "rsa-cert", "ecdsa", "hash-signed-cert"})
    need_kem = bool(cats & {"rsa", "ecdh"})
    need_tls = bool(cats & {"tls-legacy", "ecdh", "weak-suite"})

    for name, e in entries:
        if e["id"] in ("rsa", "rsa-cert") or e["id"] == "ecdsa":
            base_key = _rsa_baseline(name) if e["id"] != "ecdsa" else (
                "ed25519" if "25519" in name.lower() else "ecdsa-p256")
            b = CLASSICAL_BASELINES[base_key]
            out.append({"label": f"Signature size ({base_key.upper()} → {p['sig']})",
                        "before": f"{b['signature']:,} B", "after": f"{sig['signature']:,} B",
                        "multiplier": round(sig["signature"] / b["signature"], 1)})
            out.append({"label": f"Public key size ({base_key.upper()} → {p['sig']})",
                        "before": f"{b['public_key']:,} B", "after": f"{sig['public_key']:,} B",
                        "multiplier": round(sig["public_key"] / b["public_key"], 1)})
    if need_sig and not any("Signature" in o["label"] for o in out):
        b = CLASSICAL_BASELINES["rsa-2048"]
        out.append({"label": f"Signature size (RSA-2048 → {p['sig']})",
                    "before": f"{b['signature']:,} B", "after": f"{sig['signature']:,} B",
                    "multiplier": round(sig["signature"] / b["signature"], 1)})
    if need_kem or need_tls:
        share_c = kem["public_key"] + p["ec_share"]
        share_s = kem["ciphertext"] + p["ec_share"]
        out.append({"label": f"TLS ClientHello key share (X25519 → {p['tls_group']})",
                    "before": "32 B", "after": f"{share_c:,} B",
                    "multiplier": round(share_c / 32, 1),
                    "note": "Pushes many ClientHellos past one 1,500-byte packet. Test through middleboxes."})
        out.append({"label": "TLS ServerHello key share",
                    "before": "32 B", "after": f"{share_s:,} B",
                    "multiplier": round(share_s / 32, 1)})
    # de-dup by label
    seen, uniq = set(), []
    for o in out:
        if o["label"] not in seen:
            seen.add(o["label"]); uniq.append(o)
    return uniq


# --------------------------------------------------------------------------
# 7. Step generation
# --------------------------------------------------------------------------

def _step(sid, phase, title, detail):
    return {"id": sid, "phase": phase, "phase_label": PHASES[phase], "title": title, "detail": detail}


def _build_steps(asset: dict, entries: list[tuple[str, dict]], p: dict) -> list[dict]:
    system = asset["asset_id"]
    ids = {e["id"] for _, e in entries}
    cats = {e["category"] for _, e in entries}
    names = ", ".join(n for n, _ in entries)
    steps: list[dict] = []

    if not entries:
        steps.append(_step("verify-config", 0, f"Check {system} by hand",
            "The scan found no weak cryptography in code for this system, which doesn't prove there is none. "
            "Confirm its TLS termination, at-rest encryption (AES-256) and the crypto libraries it ships with."))
        dep = asset.get("total_dependents") or 0
        steps.append(_step("pq-ready", 2, "Make sure it can speak hybrid post-quantum TLS",
            f"{dep} other system(s) depend on this one. Put it behind OpenSSL 3.5+ (or a proxy that has it) so "
            f"it can negotiate {p['tls_group']} once its upstream systems are fixed."))
        steps.append(_step("rescan", 3, "Re-run the CADENCE scan",
            "Confirm nothing new has appeared for this system."))
        return steps

    n_find = asset.get("finding_count") or len(entries)
    steps.append(_step("inventory", 0, f"Confirm and assign the {n_find} finding{'' if n_find == 1 else 's'} in {system}",
        f"Weak items: {names}. Open the Findings tab, check each is real (not test code), and give each an owner."))
    if cats & {"public_key", "certificate", "protocol", "cipher_suite"}:
        steps.append(_step("agility", 0, "Put crypto behind one interface",
            "Route hashing, encryption and signing through one small internal module so the algorithm is a config "
            "value, not a constant scattered through the code. This migration, and the next one, become config changes."))

    if "hash" in cats:
        steps.append(_step("fix-hash", 1, f"Replace MD5/SHA-1 with {p['hash']}",
            "Swap the hash calls, widen any stored-digest columns, and rehash passwords with Argon2id on next login."))
    if "symmetric" in cats:
        steps.append(_step("fix-symmetric", 1, f"Replace DES/RC4 with {p['sym']} and re-encrypt data",
            "Ship the new cipher for new writes, run a background job that re-encrypts old records, then remove the old key from the app."))
    if ids & {"hash-signed-cert", "expired-cert"}:
        steps.append(_step("reissue-cert", 1, "Reissue the affected certificate",
            "Issue a replacement signed with SHA-256, install it everywhere the old one is deployed, and automate renewal."))
    if ids & {"rsa", "rsa-cert"}:
        steps.append(_step("interim-rsa", 1, "Interim: lift RSA to 3072-bit (or ECDSA P-256)",
            "This removes today's weakness while the post-quantum rollout is prepared. It does nothing against a quantum computer, so don't stop here."))
    if cats & {"protocol", "cipher_suite"}:
        steps.append(_step("disable-legacy", 1, "Disable SSLv3 / TLS 1.0 / 1.1 and weak suites",
            "Turn them off in the server or proxy config. Check access logs first for any client still using them."))

    if cats & {"protocol", "cipher_suite"} or ids & {"ecdh", "rsa"}:
        steps.append(_step("tls-hybrid", 2, f"Offer hybrid key exchange ({p['tls_group']})",
            "Require TLS 1.3 and enable the hybrid group on every endpoint of this system. Clients that don't support it fall back to X25519, so it is safe to roll out first."))
    if ids & {"rsa"}:
        steps.append(_step("kem-app", 2, f"Move application-level key wrapping to hybrid {p['kem']}",
            "Where code wraps keys with RSA directly, switch to ML-KEM combined with X25519 through HKDF."))
    if ids & {"rsa", "rsa-cert", "ecdsa", "hash-signed-cert"}:
        steps.append(_step("sig-dual", 2, f"Introduce {p['sig']} signatures alongside the classical ones",
            f"Generate {p['sig']} keys in your KMS/HSM (confirm vendor support first), dual-sign during transition, and "
            f"use {p['firmware_sig']} for firmware and long-lived roots."))

    if cats & {"public_key", "certificate", "protocol", "cipher_suite"}:
        steps.append(_step("compat-test", 3, "Test size and compatibility",
            "Run the real client mix against a staging copy. Check handshake size through load balancers and firewalls, "
            "token/header/DB limits for larger signatures, and HSM or library support."))
    steps.append(_step("canary", 3, "Roll out gradually",
        "Start at 5% of traffic, watch error rates and latency, then 50%, then 100%. Keep a one-flag rollback."))
    steps.append(_step("retire", 3, "Remove the old algorithm and its fallbacks",
        "Once traffic is fully moved, delete the legacy code paths and config so they can't be re-enabled by accident."))
    steps.append(_step("rescan", 3, "Re-run the CADENCE scan",
        "Confirm the findings for this system are gone and nothing new appeared."))
    return steps


# --------------------------------------------------------------------------
# 8. Mapping findings to systems (for file locations and language hints)
# --------------------------------------------------------------------------

LANG_BY_EXT = {
    ".py": "python", ".java": "java", ".js": "javascript", ".mjs": "javascript",
    ".ts": "javascript", ".conf": "config", ".cfg": "config", ".ini": "config",
    ".yml": "config", ".yaml": "config",
}

AUTO_FIX_EXTENSIONS = {
    ".py": {"MD5", "SHA1", "RSA-1024"},
    ".java": {"MD5", "SHA1", "RSA-1024"},
    ".js": {"MD5", "SHA1"}, ".mjs": {"MD5", "SHA1"},
    ".cjs": {"MD5", "SHA1"}, ".ts": {"MD5", "SHA1"},
    ".jsx": {"MD5", "SHA1"}, ".tsx": {"MD5", "SHA1"},
}


def _normalized_algorithm(name: str) -> str:
    return "".join(char for char in str(name).lower() if char.isalnum())


def _auto_fix_supported(algorithm: str, path: str, confidence: str) -> bool:
    canonical = _normalized_algorithm(algorithm)
    suffix = Path(path).suffix.lower()
    allowed = {_normalized_algorithm(value) for value in AUTO_FIX_EXTENSIONS.get(suffix, set())}
    return confidence.lower() == "high" and canonical in allowed


def extract_findings(run_row: dict) -> list[dict]:
    """Normalise Module 1's findings out of a stored run (vulnerabilities.json preferred, CBOM fallback)."""
    out: list[dict] = []
    raw = run_row.get("vulnerabilities_json")
    if raw:
        try:
            for f in json.loads(raw):
                out.append({"algorithm": f.get("algorithm", ""), "file": f.get("file", ""),
                            "line": f.get("line"), "confidence": f.get("confidence", "")})
            return out
        except (json.JSONDecodeError, TypeError):
            pass
    raw = run_row.get("cbom_json")
    if raw:
        try:
            for c in json.loads(raw).get("components", []):
                if c.get("type") != "cryptographic-asset":
                    continue
                occ = ((c.get("evidence") or {}).get("occurrences") or [{}])[0]
                properties = {item.get("name"): item.get("value") for item in c.get("properties", [])
                              if isinstance(item, dict)}
                out.append({"algorithm": c.get("name", ""), "file": occ.get("location", ""),
                            "line": occ.get("line"), "confidence": properties.get("cadence:confidence", "")})
        except (json.JSONDecodeError, TypeError):
            pass
    return out


def _load_file_map(run_row: dict | None = None) -> dict[str, str]:
    # A stored run is always isolated to its own persisted map. In particular,
    # a missing/null map must not fall through to a shared fixture from another
    # scan or sample project.
    if run_row is not None:
        if not run_row.get("system_file_map_json"):
            return {}
        try:
            raw = json.loads(run_row["system_file_map_json"])
            if isinstance(raw, dict):
                return {k: v for k, v in raw.items()
                        if isinstance(k, str) and isinstance(v, str) and not k.startswith("_")}
        except (TypeError, json.JSONDecodeError):
            return {}
    try:
        raw = json.loads((HERE / "system_file_map.json").read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def _system_for_file(path: str, system_names: list[str], file_map: dict[str, str]) -> str | None:
    normalized = (path or "").replace("\\", "/").casefold().removeprefix("./")
    if normalized:
        for key, system in file_map.items():
            mapped_path = key.replace("\\", "/").casefold().removeprefix("./")
            if mapped_path == normalized:
                return system
    # Do not infer ownership from a filename fragment or service-name text:
    # those guesses can attach another scan's findings to this run's plan.
    return None


# --------------------------------------------------------------------------
# 9. Public API
# --------------------------------------------------------------------------

def get_profile(profile_id: str) -> dict:
    if profile_id not in PROFILES:
        raise ValueError(f"Unknown profile '{profile_id}'. Options: {list(PROFILES)}")
    return PROFILES[profile_id]


def build_catalog(profile_id: str = "standard") -> dict[str, Any]:
    """Everything that does not depend on a scan: the algorithm guide and reference sizes."""
    p = get_profile(profile_id)
    tok = _tokens(p)
    algos = [_resolve_entry(e, tok) for e in CATALOG]
    for a, e in zip(algos, CATALOG):
        a["snippet_ids"] = e["snippets"]
    return {
        "profile": p,
        "profiles": list(PROFILES.values()),
        "algorithms": algos,
        "reference": {"kem": KEM_PROFILES, "signature": SIG_PROFILES, "classical": CLASSICAL_BASELINES},
        "snippets": _fill(SNIPPETS, tok),
    }


def swap_for(name: str, profile_id: str = "standard") -> dict[str, str]:
    """Short 'replace with' label for one algorithm name (used by the Findings table)."""
    p = get_profile(profile_id)
    e = classify(name)
    r = _resolve_entry(e, _tokens(p), name)
    return {"swap": r["swap"], "relevance": r["relevance"], "relevance_label": r["relevance_label"], "urgency": r["urgency"]}


def build_plan(run_row: dict, profile_id: str = "standard",
               progress: dict[tuple[str, str], bool] | None = None) -> dict[str, Any]:
    """Per-system PQC remediation plan for one stored run."""
    p = get_profile(profile_id)
    tok = _tokens(p)
    progress = progress or {}

    raw = run_row.get("migration_ranking_json")
    if not raw:
        raise ValueError("This run has no migration plan to build solutions from.")
    order = sorted(json.loads(raw).get("migration_order", []), key=lambda a: a.get("priority_rank", 10**6))

    findings = extract_findings(run_row)
    file_map = _load_file_map(run_row)
    names = [a["asset_id"] for a in order]
    by_system: dict[str, list[dict]] = {}
    for f in findings:
        s = _system_for_file(f.get("file", ""), names, file_map)
        if s:
            by_system.setdefault(s, []).append(f)

    systems: list[dict[str, Any]] = []
    for asset in order:
        sid = asset["asset_id"]
        algos = list(asset.get("algorithms") or [])
        entries = [(a, classify(a)) for a in algos]
        entries.sort(key=lambda t: URGENCY_ORDER[t[1]["urgency"]])

        mapped = by_system.get(sid, [])
        changes = []
        for name, e in entries:
            c = _resolve_entry(e, tok, name)
            locs = [f"{Path(f['file']).name}:{f['line']}" if f.get("line") else Path(f["file"]).name
                    for f in mapped if (f.get("algorithm") or "").lower() == name.lower()]
            c["locations"] = locs[:6]
            c["occurrences"] = len(locs)
            targets = []
            seen_paths = set()
            for finding in mapped:
                if _normalized_algorithm(finding.get("algorithm", "")) != _normalized_algorithm(name):
                    continue
                file_path = str(finding.get("file") or "")
                if not file_path or file_path in seen_paths:
                    continue
                seen_paths.add(file_path)
                line = finding.get("line")
                display = Path(file_path).name + (f":{line}" if line else "")
                confidence = str(finding.get("confidence") or "")
                targets.append({"path": file_path, "display": display,
                                "can_fix": _auto_fix_supported(name, file_path, confidence)})
            c["file_targets"] = targets
            changes.append(c)

        steps = _build_steps(asset, entries, p)
        for s in steps:
            s["done"] = bool(progress.get((sid, s["id"])))

        snippet_ids: list[str] = []
        verify_ids: list[str] = []
        for _, e in entries:
            for x in e["snippets"]:
                if x not in snippet_ids:
                    snippet_ids.append(x)
            for x in e["verify"]:
                if x not in verify_ids and x != "rescan":
                    verify_ids.append(x)
        verify_ids.append("rescan")
        if not entries:
            verify_ids = ["rescan"]

        langs = []
        for f in mapped:
            lang = LANG_BY_EXT.get(Path(f.get("file", "")).suffix.lower())
            if lang and lang not in langs:
                langs.append(lang)

        done = sum(1 for s in steps if s["done"])
        urgencies = [c["urgency"] for c in changes]
        top_urgency = min(urgencies, key=lambda u: URGENCY_ORDER[u]) if urgencies else None

        systems.append({
            "asset_id": sid,
            "priority_rank": asset.get("priority_rank"),
            "scheduled_week": asset.get("scheduled_week"),
            "worst_severity": asset.get("worst_severity"),
            "compliance_deadline": asset.get("compliance_deadline"),
            "days_remaining": asset.get("days_remaining"),
            "total_dependents": asset.get("total_dependents"),
            "effort_weeks": asset.get("effort_weeks"),
            "estimated_cost": asset.get("estimated_cost"),
            "module2_criticality": asset.get("module2_criticality"),
            "status": "action" if entries else "verify",
            "top_urgency": top_urgency,
            "changes": changes,
            "steps": steps,
            "snippet_ids": snippet_ids,
            "preferred_languages": langs,
            "verify": [_fill(v, tok) for k in verify_ids for v in VERIFY[k]],
            "impact": _impact_for(entries, p),
            "progress": {"done": done, "total": len(steps)},
        })

    total_steps = sum(s["progress"]["total"] for s in systems)
    done_steps = sum(s["progress"]["done"] for s in systems)
    all_changes = [c for s in systems for c in s["changes"]]
    summary = {
        "systems": len(systems),
        "systems_needing_action": sum(1 for s in systems if s["status"] == "action"),
        "distinct_algorithms": len({c["name"] for c in all_changes}),
        "urgent": sum(1 for c in all_changes if c["urgency"] in ("critical", "high")),
        "direct_pqc": sum(1 for c in all_changes if c["relevance"] == "direct"),
        "fix_first": sum(1 for c in all_changes if c["relevance"] in ("fix-first", "prerequisite")),
        "steps_total": total_steps,
        "steps_done": done_steps,
    }
    swap_names = {f.get("algorithm") for f in findings if f.get("algorithm")}
    for a in order:
        swap_names.update(a.get("algorithms") or [])
    swaps = {n: swap_for(n, profile_id) for n in sorted(swap_names)}
    return {
        "profile": p,
        "profiles": list(PROFILES.values()),
        "summary": summary,
        "systems": systems,
        "snippets": _fill(SNIPPETS, tok),
        "swaps": swaps,
    }
