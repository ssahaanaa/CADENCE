"""
network_scanner.py — Network layer of CADENCE Module 1.

This is the piece Module 1 was missing: it doesn't just read source code,
it connects to real hosts and inspects what's actually negotiated on the
wire — same problem space as the open-source AC-Scanner project, built
natively here so CADENCE owns the full pipeline without vendoring
external code or its license.

Findings are lower "AST-equivalent" confidence semantics don't apply here;
network probes get detection_method="network-probe" / "cert-inspect" and
are always high confidence (it's not a keyword guess — it's what the
server actually presented).
"""

from __future__ import annotations

import ssl
import socket
import datetime
from concurrent.futures import ThreadPoolExecutor

from cbom import CryptoAsset, Occurrence

WEAK_PROTOCOL_NAMES = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_SUBSTRINGS = ("RC4", "DES", "NULL", "EXPORT", "3DES", "MD5")
MIN_RSA_CERT_KEY_SIZE = 2048


def probe_host(host: str, port: int = 443, timeout: float = 5.0) -> list[CryptoAsset]:
    """
    Connect to host:port, negotiate TLS, and inspect protocol version,
    cipher suite, and certificate key size. Returns CBOM-ready findings.
    Best-effort: connection failures are reported as a single low-confidence
    note rather than raising, since a subset of hosts being unreachable
    shouldn't crash a full-network scan.
    """
    target = f"{host}:{port}"
    findings: list[CryptoAsset] = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Deliberately permissive so we can *see* what the server will
    # negotiate, including weak protocols, rather than being blocked
    # by our own client's modern defaults.
    try:
        ctx.minimum_version = ssl.TLSVersion.SSLv3
    except (ValueError, AttributeError):
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                proto = tls.version()  # e.g. "TLSv1.2"
                cipher_name, _, _ = tls.cipher()
                cert_bin = tls.getpeercert(binary_form=True)

        if proto and proto.replace("v", "").replace(".", "") in {
            p.replace("v", "").replace(".", "") for p in WEAK_PROTOCOL_NAMES
        }:
            findings.append(CryptoAsset(
                name=proto, asset_type="protocol",
                confidence="high", detection_method="network-probe", severity="high",
                occurrences=[Occurrence(location=target)],
                notes=f"Server negotiated deprecated TLS version {proto}.",
            ))

        if cipher_name and any(w in cipher_name.upper() for w in WEAK_CIPHER_SUBSTRINGS):
            findings.append(CryptoAsset(
                name=cipher_name, asset_type="algorithm", primitive="cipher-suite",
                confidence="high", detection_method="network-probe", severity="high",
                occurrences=[Occurrence(location=target)],
                notes="Weak cipher suite offered/negotiated.",
            ))

        if cert_bin:
            findings.extend(_inspect_certificate(cert_bin, target))

    except (socket.timeout, socket.gaierror, ConnectionRefusedError, ssl.SSLError, OSError) as e:
        findings.append(CryptoAsset(
            name="unreachable", asset_type="protocol",
            confidence="needs_review", detection_method="network-probe", severity="low",
            occurrences=[Occurrence(location=target)],
            notes=f"Host unreachable or handshake failed: {e.__class__.__name__}.",
        ))

    return findings


def _inspect_certificate(cert_der: bytes, target: str) -> list[CryptoAsset]:
    """Pull key size / signature algorithm out of the presented certificate."""
    findings = []
    try:
        # Uses only the stdlib; avoids adding a pyOpenSSL/cryptography
        # dependency just for this lightweight inspection.
        import binascii  # noqa: F401
        from ssl import _ssl  # type: ignore
        # Fallback: python's ssl module doesn't expose key size directly
        # without `cryptography`. If it's available, use it for real
        # parsing; otherwise skip this enrichment gracefully.
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa

        cert = x509.load_der_x509_certificate(cert_der)
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size < MIN_RSA_CERT_KEY_SIZE:
            findings.append(CryptoAsset(
                name=f"RSA-{pubkey.key_size} (certificate)", asset_type="certificate",
                primitive="signature",
                confidence="high", detection_method="cert-inspect", severity="high",
                occurrences=[Occurrence(location=target)],
                notes=f"Leaf certificate RSA key size {pubkey.key_size} below "
                      f"{MIN_RSA_CERT_KEY_SIZE}-bit minimum.",
            ))

        sig_algo = cert.signature_hash_algorithm
        if sig_algo and sig_algo.name.lower() in {"md5", "sha1"}:
            findings.append(CryptoAsset(
                name=f"{sig_algo.name.upper()}-signed certificate", asset_type="certificate",
                primitive="signature",
                confidence="high", detection_method="cert-inspect", severity="high",
                occurrences=[Occurrence(location=target)],
                notes="Certificate signed with a broken hash algorithm.",
            ))

        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        if not_after < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=not_after.tzinfo) if not_after.tzinfo else datetime.datetime.now():
            findings.append(CryptoAsset(
                name="expired-certificate", asset_type="certificate",
                confidence="high", detection_method="cert-inspect", severity="medium",
                occurrences=[Occurrence(location=target)],
                notes=f"Certificate expired {not_after.isoformat()}.",
            ))
    except ImportError:
        # `cryptography` not installed: skip cert-level enrichment,
        # protocol/cipher findings above still stand.
        pass
    except Exception:
        pass
    return findings


def scan_hosts(hosts: list[str], max_workers: int = 12) -> list[CryptoAsset]:
    """hosts: list of 'hostname' or 'hostname:port' strings.

    Probes run concurrently — each probe_host() call already carries a real
    socket-level timeout, so running them in parallel is safe and turns an
    N-host scan from N x timeout worst case into roughly one timeout total."""
    findings: list[CryptoAsset] = []
    if not hosts:
        return findings

    def _parse(entry: str) -> tuple[str, int]:
        if ":" in entry:
            host, port_s = entry.rsplit(":", 1)
            return host, int(port_s)
        return entry, 443

    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as pool:
        futures = [pool.submit(probe_host, *_parse(entry)) for entry in hosts]
        for future in futures:
            findings.extend(future.result())
    return findings
