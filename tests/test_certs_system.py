"""The local CA, PAC routing rules, site definitions and the setup commands (with a fake shell)."""

import json
import ssl
import subprocess

import pytest
from cryptography import x509

from walled_dlp import system
from walled_dlp.certs import CA_NAME, CertificateAuthority
from walled_dlp.sites import CHATGPT, PERPLEXITY, site_for


def test_ca_is_created_once_and_key_is_private(tmp_path):
    ca = CertificateAuthority(tmp_path)
    assert (tmp_path / "walled-dlp-ca.key").stat().st_mode & 0o077 == 0
    again = CertificateAuthority(tmp_path)
    assert again.fingerprint == ca.fingerprint
    cert = x509.load_pem_x509_certificate(ca.pem)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca


def test_ca_is_limited_to_the_monitored_domains(tmp_path):
    ca = CertificateAuthority(tmp_path)
    nc = ca.cert.extensions.get_extension_for_class(x509.NameConstraints)
    assert nc.critical
    names = {n.value for n in nc.value.permitted_subtrees}
    assert {"chatgpt.com", "perplexity.ai", "oaiusercontent.com"} <= names
    assert not any("google" in n or "bank" in n for n in names)


def test_ca_regenerated_when_domains_change(tmp_path):
    old = CertificateAuthority(tmp_path, domains=["chatgpt.com"]).fingerprint
    assert CertificateAuthority(tmp_path, domains=["chatgpt.com"]).fingerprint == old
    assert CertificateAuthority(tmp_path, domains=["chatgpt.com", "perplexity.ai"]).fingerprint != old


def test_openssl_rejects_a_certificate_for_another_site(tmp_path):
    """Even with the CA key, a certificate for a non-monitored host fails verification."""
    import socket
    import threading

    ca = CertificateAuthority(tmp_path)
    srv_ctx = ca.server_context("www.example-bank.com")  # forged on purpose
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        try:
            srv_ctx.wrap_socket(conn, server_side=True).recv(1)
        except (ssl.SSLError, OSError):
            pass

    threading.Thread(target=serve, daemon=True).start()
    client = ssl.create_default_context(cafile=str(ca.cert_path))
    with pytest.raises(ssl.SSLCertVerificationError):
        client.wrap_socket(socket.create_connection(listener.getsockname()), server_hostname="www.example-bank.com")


def test_leaf_chains_to_ca_and_names_the_host(tmp_path):
    ca = CertificateAuthority(tmp_path)
    leaf = x509.load_pem_x509_certificate(ca.leaf_pem("chatgpt.com"))
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["chatgpt.com"]
    leaf.verify_directly_issued_by(ca.cert)
    assert isinstance(ca.server_context("chatgpt.com"), ssl.SSLContext)
    assert ca.server_context("chatgpt.com") is ca.server_context("CHATGPT.com")


def test_site_routing():
    assert site_for("chatgpt.com") is CHATGPT and site_for("files07.oaiusercontent.com") is CHATGPT
    assert site_for("www.perplexity.ai") is PERPLEXITY and site_for("suggest.perplexity.ai") is PERPLEXITY
    assert site_for("example.com") is None and site_for("notchatgpt.com") is None
    assert CHATGPT.is_side_channel("chatgpt.com", "/ces/v1/t")
    assert not CHATGPT.is_side_channel("chatgpt.com", "/backend-api/f/conversation")
    assert PERPLEXITY.is_side_channel("suggest.perplexity.ai", "/suggest/ws")
    assert not PERPLEXITY.is_side_channel("www.perplexity.ai", "/rest/sse/perplexity_ask")


class FakeShell:
    def __init__(self, outputs=None):
        self.calls = []
        self.outputs = outputs or {}

    def __call__(self, cmd, check=False):
        self.calls.append(cmd)
        for key, out in self.outputs.items():
            if key in " ".join(cmd):
                return subprocess.CompletedProcess(cmd, 0, out, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


@pytest.fixture
def linux(tmp_path, monkeypatch):
    monkeypatch.setattr(system.sys, "platform", "linux")
    monkeypatch.setattr(system, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(system.Path, "home", lambda: tmp_path / "home")
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "ubuntu:GNOME")
    return tmp_path


def test_gnome_proxy_set_and_restored(linux, monkeypatch):
    shell = FakeShell({"get org.gnome.system.proxy mode": "'manual'", "get org.gnome.system.proxy autoconfig-url": "''"})
    monkeypatch.setattr(system, "_run", shell)
    monkeypatch.setattr(system.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "gsettings" else None)
    step = system.set_system_proxy("http://127.0.0.1:8899/proxy.pac")
    assert step.ok
    assert ["gsettings", "set", "org.gnome.system.proxy", "mode", "auto"] in shell.calls
    assert ["gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", "http://127.0.0.1:8899/proxy.pac"] in shell.calls
    shell.calls.clear()
    system.restore_system_proxy()
    assert ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"] in shell.calls
    assert json.loads((linux / "data" / "system-state.json").read_text()) == {}


def test_trust_without_certutil_explains_what_to_do(linux, tmp_path, monkeypatch):
    monkeypatch.setattr(system.shutil, "which", lambda name: None)
    step = system.trust_ca(CertificateAuthority(tmp_path / "ca"))
    assert not step.ok and "libnss3-tools" in step.detail and "Manage certificates" in step.detail


def test_trust_with_certutil_adds_to_nss(linux, tmp_path, monkeypatch):
    shell = FakeShell()
    monkeypatch.setattr(system, "_run", shell)
    monkeypatch.setattr(system.shutil, "which", lambda name: "/usr/bin/certutil" if name == "certutil" else None)
    ca = CertificateAuthority(tmp_path / "ca")
    step = system.trust_ca(ca)
    assert step.ok
    add = [c for c in shell.calls if "-A" in c][0]
    assert add[add.index("-n") + 1] == CA_NAME and add[add.index("-t") + 1] == "C,," and str(ca.cert_path) in add


def test_macos_and_windows_commands(tmp_path, monkeypatch):
    shell = FakeShell()
    monkeypatch.setattr(system, "_run", shell)
    ca = CertificateAuthority(tmp_path / "ca")
    monkeypatch.setattr(system.sys, "platform", "darwin")
    system.trust_ca(ca)
    assert shell.calls[-1][:4] == ["security", "add-trusted-cert", "-r", "trustRoot"]
    monkeypatch.setattr(system.sys, "platform", "win32")
    system.trust_ca(ca)
    assert shell.calls[-1][:5] == ["certutil", "-user", "-f", "-addstore", "Root"]


def test_launcher_entry(linux, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    monkeypatch.setattr(system, "_run", FakeShell())
    step = system.install_launcher()
    text = (tmp_path / "share" / "applications" / "walled-dlp.desktop").read_text()
    assert step.ok and "Name=Walled DLP" in text and "Exec=" in text and " app" in text and "icon.png" in text
    system.remove_launcher()
    assert not (tmp_path / "share" / "applications" / "walled-dlp.desktop").exists()
