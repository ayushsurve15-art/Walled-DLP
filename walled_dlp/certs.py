"""The local certificate authority that lets the proxy read HTTPS traffic to the monitored sites.

On first run a CA key and certificate are generated in the data directory (the key never leaves
this machine). For each monitored host the proxy presents a short certificate for that host signed
by this CA. The browser accepts it only after the user trusts the CA (`walled-dlp setup`). Hosts
that aren't monitored are tunnelled untouched and never see this CA.

The CA carries X.509 name constraints that limit it to the monitored domains. Even if its key were
stolen, browsers would reject any certificate it signed for another site (a bank, an email
provider). If the monitored domains change, the CA is regenerated and must be trusted again.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import os
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_NAME = "Walled DLP Local CA"


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _permitted(cert: x509.Certificate) -> list[str] | None:
    try:
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return None
    return sorted(n.value for n in (nc.permitted_subtrees or []) if isinstance(n, x509.DNSName))


class CertificateAuthority:
    def __init__(self, directory: Path, domains: list[str] | None = None) -> None:
        from .sites import all_hosts

        self.dir = Path(directory)
        self.domains = sorted(set(domains or all_hosts()))
        self.cert_path = self.dir / "walled-dlp-ca.pem"
        self.key_path = self.dir / "walled-dlp-ca.key"
        if not (self.cert_path.exists() and self.key_path.exists()):
            self._generate()
        self.cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        if _permitted(self.cert) != self.domains:  # monitored domains changed: issue a new CA
            self._generate()
            self.cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        self.key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        # One key for every per-host certificate: generating keys is the slow part.
        self._leaf_key = ec.generate_private_key(ec.SECP256R1())
        self._leaf_key_pem = self._leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()
        self._scratch = tempfile.TemporaryDirectory(prefix="walled-dlp-certs-")

    def _generate(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Walled DLP (this computer only)"),
        ])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.NameConstraints(permitted_subtrees=[x509.DNSName(d) for d in self.domains], excluded_subtrees=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        _write_private(
            self.key_path,
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        )
        self.cert_path.parent.mkdir(parents=True, exist_ok=True)
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint, as browsers and `certutil` print it."""
        digest = self.cert.fingerprint(hashes.SHA256()).hex().upper()
        return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))

    @property
    def spki_hash(self) -> str:
        """Base64 SHA-256 of the CA public key, for Chrome's --ignore-certificate-errors-spki-list."""
        der = self.cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(hashlib.sha256(der).digest()).decode()

    def leaf_pem(self, host: str) -> bytes:
        now = dt.datetime.now(dt.timezone.utc)
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self.cert.subject)
            .public_key(self._leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.cert.public_key()), critical=False
            )
            .sign(self.key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM) + self.pem

    def server_context(self, host: str) -> ssl.SSLContext:
        """TLS context that presents a certificate for `host`. Cached per host."""
        host = host.lower()
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is None:
                chain = Path(self._scratch.name) / f"{hashlib.sha1(host.encode()).hexdigest()}.pem"
                _write_private(chain, self.leaf_pem(host) + self._leaf_key_pem)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.set_alpn_protocols(["http/1.1"])
                ctx.load_cert_chain(chain)
                chain.unlink()
                self._contexts[host] = ctx
            return ctx
