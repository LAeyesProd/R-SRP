#!/usr/bin/env python3
"""Real-process release contract tests; Python stdlib + OpenSSL CLI only.

Run from the repository root:
  python3 services/api-service/tests/release_integration.py --binary "$PWD/target/release/api-service"
  python3 services/api-service/tests/release_integration.py --image rsrp-api:test

The image must already exist in the local Docker daemon. Both modes run exactly
the same unittest cases over TLS 1.3, without mocks or an external running API.
--startup-timeout (default 30 seconds) bounds startup; each socket/command and
shutdown also has a timeout. SIGINT/SIGTERM trigger cleanup. Scratch directories
are created under the working directory, never the system temporary directory.

No caller-provided service environment is needed or inherited. The fixture sets
ENV/APP_ENV/RUST_ENV/RSRP_DEPLOYMENT_PROFILE=test, API_BIND_ADDR (random loopback
port for a binary; 0.0.0.0:8080 in Docker), TLS_ENABLED=true, TLS_CERT_PATH,
TLS_KEY_PATH, TLS_CLIENT_CA_PATH, JWT_ALGORITHM=EdDSA, JWT_ISSUER, JWT_AUDIENCE,
JWT_DEFAULT_KID, JWT_PUBLIC_KEY_PATH, MISSION_SCHEDULE_PATH, IMMUTABLE_LOG_WAL_PATH,
AUDIT_PUBLICATIONS_DIR, AUDIT_PUBLICATION_SIGNING_PROVIDER=software-ed25519,
AUDIT_PUBLICATION_SIGNING_SECRET (random), AUDIT_PUBLICATION_SIGNING_KEY_ID,
RATE_LIMIT_BACKEND=in-memory, RATE_LIMIT_PER_WINDOW, RATE_LIMIT_WINDOW_SECONDS,
ENTROPY_HEALTHCHECK_ENABLED=false, ENTROPY_FAIL_CLOSED=false,
CORS_ALLOWED_ORIGINS=https://localhost and RUST_LOG=warn.
Docker additionally clears optional image-provided config that could interfere.

This is a release-artifact test in a deterministic *test deployment profile*,
not a production/HSM certification. /health is public at the HTTP layer (still
requires mTLS); JWT assertions target /api/v1 endpoints. The API exposes legacy
CRUE decisions, not proof envelopes. Its legacy export rule currently fails
closed (ENGINE_ERROR) for an ordinary request; no Allow-path claim is made.
Signed publication tampering and WAL replay tampering are tested, but
proof-envelope/PQ verification, TSA, external rate
limiters, production entropy/HSM and crash/power-loss durability are not.
"""

import argparse
import base64
import copy
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
import uuid


OPTIONS = None
REQUEST_TIMEOUT = 5
COMMAND_TIMEOUT = 30
ACTIVE_SERVICES = set()


def run(*args, **kwargs):
    return subprocess.run(
        [str(arg) for arg in args], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=COMMAND_TIMEOUT, **kwargs
    ).stdout


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class Credentials:
    def __init__(self, root):
        self.root = root
        self.private = root / "private"
        self.certs = root / "certs"
        self.config = root / "config"
        for directory in (self.private, self.certs, self.config):
            directory.mkdir()
        for name in ("jwt", "forged"):
            run("openssl", "genpkey", "-algorithm", "ED25519",
                "-out", self.private / (name + ".key"))
        run("openssl", "pkey", "-in", self.private / "jwt.key", "-pubout",
            "-out", self.config / "jwt.pub")
        for name in ("ca", "rogue-ca"):
            run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
                "-subj", "/CN=" + name, "-keyout", self.private / (name + ".key"),
                "-out", self.certs / (name + ".pem"),
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for name, ca, usage in (
            ("server", "ca", "serverAuth"),
            ("client", "ca", "clientAuth"),
            ("rogue-client", "rogue-ca", "clientAuth"),
        ):
            key = (self.certs if name == "server" else self.private) / (name + ".key")
            csr = self.private / (name + ".csr")
            extensions = self.private / (name + ".ext")
            extensions.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=" + usage + "\n"
                "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
                encoding="ascii",
            )
            run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=" + name,
                "-keyout", key, "-out", csr)
            run("openssl", "x509", "-req", "-in", csr, "-days", "2",
                "-CA", self.certs / (ca + ".pem"),
                "-CAkey", self.private / (ca + ".key"),
                "-set_serial", str(secrets.randbits(120) + 1),
                "-extfile", extensions, "-out", self.certs / (name + ".pem"))
        (self.config / "missions.json").write_text(json.dumps({"missions": [{
            "mission_id": "integration-mission", "allowed_weekdays": list(range(1, 8)),
            "start_hour": 0, "end_hour": 24,
        }]}), encoding="utf-8")
        # The host scratch root is 0700; only these two directories are mounted
        # read-only into the non-root container. CA/JWT private keys stay outside.
        for directory in (self.certs, self.config):
            directory.chmod(0o755)
            for path in directory.iterdir():
                path.chmod(0o444)

    def context(self, client="client"):
        context = ssl.create_default_context(cafile=str(self.certs / "ca.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        if client:
            context.load_cert_chain(
                str(self.certs / (client + ".pem")),
                str(self.private / (client + ".key")),
            )
        return context

    def token(self, role="ADMIN", forged=False, **claims):
        payload = {
            "sub": "integration-agent", "role": role, "exp": int(time.time()) + 600,
            "iss": "integration-issuer", "aud": "integration-audience",
        }
        payload.update(claims)
        header = {"alg": "EdDSA", "typ": "JWT", "kid": "integration"}
        message = ".".join(b64url(json.dumps(value).encode()) for value in (header, payload))
        message_path = self.private / "signing-input"
        signature_path = self.private / "signature"
        message_path.write_bytes(message.encode("ascii"))
        run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
            self.private / ("forged.key" if forged else "jwt.key"),
            "-in", message_path, "-out", signature_path)
        return message + "." + b64url(signature_path.read_bytes())


class Service:
    def __init__(self, root, credentials, limit=1000, window=60):
        self.root = root
        self.credentials = credentials
        self.data = root / "data"
        self.data.mkdir()
        (self.data / "publications").mkdir()
        # Only isolated fixture data is writable to UID 65532 inside Docker.
        self.data.chmod(0o777)
        (self.data / "publications").chmod(0o777)
        self.process = None
        self.container = None
        self.log = None
        self.limit = limit
        self.window = window
        self.port = None

    def environment(self):
        certs = Path("/fixture/certs") if OPTIONS.image else self.credentials.certs
        config = Path("/fixture/config") if OPTIONS.image else self.credentials.config
        data = Path("/fixture/data") if OPTIONS.image else self.data
        env = dict.fromkeys(("ENV", "APP_ENV", "RUST_ENV", "RSRP_DEPLOYMENT_PROFILE"), "test")
        env.update({
            "API_BIND_ADDR": "0.0.0.0:8080" if OPTIONS.image else f"127.0.0.1:{self.port}",
            "TLS_ENABLED": "true", "TLS_CERT_PATH": str(certs / "server.pem"),
            "TLS_KEY_PATH": str(certs / "server.key"),
            "TLS_CLIENT_CA_PATH": str(certs / "ca.pem"),
            "JWT_ALGORITHM": "EdDSA", "JWT_PUBLIC_KEY_PATH": str(config / "jwt.pub"),
            "JWT_ISSUER": "integration-issuer", "JWT_AUDIENCE": "integration-audience",
            "JWT_DEFAULT_KID": "integration",
            "MISSION_SCHEDULE_PATH": str(config / "missions.json"),
            "IMMUTABLE_LOG_WAL_PATH": str(data / "ledger.wal"),
            "AUDIT_PUBLICATIONS_DIR": str(data / "publications"),
            "AUDIT_PUBLICATION_SIGNING_PROVIDER": "software-ed25519",
            "AUDIT_PUBLICATION_SIGNING_SECRET": self.signing_secret,
            "AUDIT_PUBLICATION_SIGNING_KEY_ID": "integration-publication",
            "RATE_LIMIT_BACKEND": "in-memory", "RATE_LIMIT_PER_WINDOW": str(self.limit),
            "RATE_LIMIT_WINDOW_SECONDS": str(self.window),
            "ENTROPY_HEALTHCHECK_ENABLED": "false", "ENTROPY_FAIL_CLOSED": "false",
            "RUST_LOG": "warn",
            "CORS_ALLOWED_ORIGINS": "https://localhost",
        })
        for name in ("JWT_PUBLIC_KEY_PEM", "AUDIT_TSA_URL", "AUDIT_TSA_TRUST_STORE_PEM",
                     "TRUSTED_PROXY_CIDRS"):
            env[name] = ""
        return env

    def start(self, expect_failure=False):
        ACTIVE_SERVICES.add(self)
        if not hasattr(self, "signing_secret"):
            self.signing_secret = secrets.token_hex(32)
        if not OPTIONS.image:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self.port = reservation.getsockname()[1]
        env = self.environment()
        if OPTIONS.image:
            self.container = "rsrp-integration-" + uuid.uuid4().hex
            env_file = self.root / "service.env"
            env_file.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
            env_file.chmod(0o600)
            command = [
                "docker", "run", "--detach", "--name", self.container, "--pull=never",
                "--user", "65532:65532", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--publish", "127.0.0.1::8080",
                "--env-file", str(env_file),
            ]
            for source, target, readonly in (
                (self.credentials.certs, "certs", True),
                (self.credentials.config, "config", True),
                (self.data, "data", False),
            ):
                command += ["--mount", f"type=bind,src={source},dst=/fixture/{target}"
                            + (",readonly" if readonly else "")]
            run(*command, OPTIONS.image)
            mapping = json.loads(run("docker", "inspect", self.container))[0]
            if not expect_failure:
                self.port = int(mapping["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"])
        else:
            inherited = {key: os.environ[key] for key in
                         ("PATH", "LD_LIBRARY_PATH", "SYSTEMROOT") if key in os.environ}
            self.log = (self.root / "service.log").open("wb")
            self.process = subprocess.Popen(
                [str(OPTIONS.binary)], cwd=self.root, env={**inherited, **env},
                stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
            )
        deadline = time.monotonic() + OPTIONS.startup_timeout
        last_error = None
        while time.monotonic() < deadline:
            if not self.running():
                if expect_failure:
                    return
                raise AssertionError("Service exited before readiness:\n" + self.logs())
            if not expect_failure:
                try:
                    status, _, body = self.request("/health")
                    if status == 200 and json.loads(body)["status"] == "healthy":
                        return
                except (OSError, http.client.HTTPException, ValueError) as error:
                    last_error = error
            time.sleep(0.05)
        raise AssertionError(
            f"Service did not {'reject startup' if expect_failure else 'become ready'} "
            f"within {OPTIONS.startup_timeout}s ({last_error}):\n{self.logs()}"
        )

    def running(self):
        if self.container:
            return run("docker", "inspect", "--format", "{{.State.Running}}",
                       self.container).strip() == b"true"
        return self.process is not None and self.process.poll() is None

    def logs(self):
        if self.container:
            result = subprocess.run(
                ["docker", "logs", self.container], check=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=COMMAND_TIMEOUT,
            )
            return result.stdout.decode(errors="replace")[-12000:]
        path = self.root / "service.log"
        return path.read_text(errors="replace")[-12000:] if path.exists() else ""

    def request(self, path, method="GET", token=None, body=None, client="client",
                headers=None, chunked=False):
        headers = dict(headers or {})
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.port, timeout=REQUEST_TIMEOUT,
            context=self.credentials.context(client),
        )
        try:
            connection.request(method, path, body=[body] if chunked else body,
                               headers=headers, encode_chunked=chunked)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def stop(self):
        if self.container:
            run("docker", "rm", "--force", self.container)
            self.container = None
        if self.process:
            process, self.process = self.process, None
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if self.log:
            self.log.close()
            self.log = None
        ACTIVE_SERVICES.discard(self)


class ReleaseIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix=".api-integration-", dir=Path.cwd())
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.root = Path(cls.scratch.name).resolve()
        cls.credentials = Credentials(cls.root)

    def setUp(self):
        self.case_root = self.root / self.id().rsplit(".", 1)[-1]
        self.case_root.mkdir()
        self.service = Service(self.case_root, self.credentials)
        self.addCleanup(self.service.stop)
        self.admin = self.credentials.token()
        self.agent = self.credentials.token(role="AGENT")
        self.auditor = self.credentials.token(role="AUDITOR")

    def request_json(self, path, expected=200, **kwargs):
        status, headers, body = self.service.request(path, **kwargs)
        self.assertEqual(status, expected, body.decode(errors="replace"))
        self.assertIn("application/json", headers.get("content-type", ""))
        return json.loads(body)

    def chain(self):
        return self.request_json("/api/v1/audit/chain/verify", token=self.auditor)

    def validation(self, **changes):
        return {
            "agent_id": "integration-agent", "agent_org": "PUBLIC",
            "mission_id": "integration-mission", "legal_basis": "PUBLIC_TASK",
            "justification": "Integration test authorized purpose", **changes,
        }

    def evaluate(self, **changes):
        return self.request_json("/api/v1/validate", method="POST", token=self.agent,
                                 body=self.validation(**changes))

    def test_health_and_real_mtls(self):
        self.service.start()
        health = self.request_json("/health")
        self.assertEqual(health["status"], "healthy")
        self.assertTrue(health["timestamp"])
        self.assertTrue(self.request_json("/ready")["ready"])
        for client in (None, "rogue-client"):
            with self.subTest(client=client):
                # TLS 1.3 can report a client-certificate alert on the first read,
                # not only in connect(). An HTTP 401 is NOT a TLS refusal.
                with self.assertRaises(ssl.SSLError):
                    self.service.request("/health", client=client)
        self.assertEqual(self.request_json("/health")["status"], "healthy")

    def test_jwt_authentication_and_roles(self):
        self.service.start()
        self.request_json("/api/v1/metrics", token=self.auditor)
        tokens = {
            "missing": None, "malformed": "not-a-jwt",
            "expired": self.credentials.token(exp=int(time.time()) - 3600),
            "forged-signature": self.credentials.token(forged=True),
            "wrong-issuer": self.credentials.token(iss="other"),
            "wrong-audience": self.credentials.token(aud="other"),
        }
        for name, token in tokens.items():
            with self.subTest(token=name):
                error = self.request_json("/api/v1/metrics", expected=401, token=token)
                self.assertIn("error", error)
        self.request_json("/api/v1/metrics", expected=403, token=self.agent)
        self.request_json("/api/v1/audit/daily/publish", method="POST",
                          expected=403, token=self.auditor)
        self.request_json("/api/v1/validate", method="POST", expected=403,
                          token=self.credentials.token(role="UNKNOWN"), body=self.validation())
        self.assertEqual(self.chain()["entry_count"], 0)

    def test_crue_decisions_ledger_and_restart(self):
        self.service.start()
        before = self.chain()
        self.assertTrue(before["valid"])
        self.assertEqual(before["entry_count"], 0)
        normal = self.evaluate()
        # The legacy export rule requires a numeric field but the API exposes
        # an optional string. Preserve its existing fail-closed contract here.
        self.assertEqual(normal["decision"], "Block")
        self.assertEqual(normal["rule_id"], "CRUE_003")
        self.assertEqual(normal["error_code"], "ENGINE_ERROR")
        blocked = self.evaluate(requests_last_hour=50)
        self.assertEqual(blocked["decision"], "Block")
        self.assertEqual(blocked["rule_id"], "CRUE_001")
        self.assertEqual(blocked["error_code"], "VOLUME_EXCEEDED")
        self.assertNotEqual(normal["request_id"], blocked["request_id"])
        after = self.chain()
        self.assertTrue(after["valid"])
        self.assertEqual(after["entry_count"], 2)
        self.assertNotEqual(before["current_hash"], after["current_hash"])
        metrics = self.request_json("/api/v1/metrics", token=self.auditor)
        self.assertEqual(metrics["total_requests"], 2)
        self.assertEqual(metrics["blocked_requests"], 2)
        self.assertEqual(metrics["warnings"], 0)
        self.service.stop()
        self.service.start()
        replay = self.chain()
        self.assertTrue(replay["valid"])
        self.assertEqual(replay["entry_count"], after["entry_count"])
        self.assertEqual(replay["current_hash"], after["current_hash"])

    def test_validation_errors_and_payload_limit(self):
        self.service.start()
        for payload in ({}, self.validation(agent_id=""),
                        self.validation(legal_basis="INVALID"),
                        self.validation(justification="x" * 4097)):
            with self.subTest(payload_fields=list(payload)):
                status, _, _ = self.service.request(
                    "/api/v1/validate", method="POST", token=self.agent, body=payload)
                self.assertEqual(status, 422)
        status, _, _ = self.service.request(
            "/api/v1/validate", method="POST", token=self.agent, body=b"{",
            headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        # Known oversized lengths must be rejected before reading the body.
        # Do not race an early 413/connection close by continuing to upload.
        status, _, _ = self.service.request(
            "/api/v1/validate", method="POST", token=self.agent,
            headers={"Content-Type": "application/json", "Content-Length": str(65 * 1024)})
        self.assertEqual(status, 413)
        status, _, _ = self.service.request(
            "/api/v1/validate", method="POST", token=self.agent, body=b"x" * (65 * 1024),
            headers={"Content-Type": "application/json"}, chunked=True)
        self.assertEqual(status, 413)
        self.assertEqual(self.chain()["entry_count"], 0)
        self.request_json("/api/v1/audit/daily/not-a-date/root", token=self.auditor,
                          expected=400)
        self.request_json("/api/v1/audit/daily/2000-01-01/root", token=self.auditor,
                          expected=404)
        self.request_json("/api/v1/audit/daily/publish", token=self.admin,
                          method="POST", expected=409)

    def test_ip_rate_limit_and_recovery(self):
        self.service.limit = 3
        self.service.window = 3
        self.service.start()
        for _ in range(3):
            self.request_json("/api/v1/metrics", token=self.auditor)
        status, headers, body = self.service.request(
            "/api/v1/metrics", token=self.admin,
            headers={"X-Forwarded-For": "198.51.100.77"})
        self.assertEqual(status, 429)
        retry = int(headers["retry-after"])
        self.assertGreaterEqual(retry, 1)
        self.assertEqual(json.loads(body)["retry_after_seconds"], retry)
        self.request_json("/health")
        time.sleep(self.service.window + 0.1)
        self.request_json("/api/v1/metrics", token=self.auditor)

    def test_signed_publication_and_tampering(self):
        self.service.start()
        self.evaluate()
        publication = self.request_json(
            "/api/v1/audit/daily/publish", method="POST", token=self.admin)
        self.assertEqual(publication["entry_count"], 1)
        self.assertEqual(publication["signature_algorithm"], "ED25519")
        self.assertIs(publication["signature_verified"], True)
        date = publication["date"]
        root = self.request_json(f"/api/v1/audit/daily/{date}/root", token=self.auditor)
        self.assertEqual(root["root_hash"], publication["root_hash"])
        path = f"/api/v1/audit/daily/{date}/verify"
        verified = self.request_json(path, token=self.auditor)
        self.assertIs(verified["root_hash_verified"], True)
        self.assertIs(verified["signature_verified"], True)
        self.assertIs(verified["tsa_present"], False)
        self.request_json("/api/v1/audit/daily/publish", method="POST",
                          token=self.admin, expected=409)
        files = list((self.service.data / "publications").glob("*.json"))
        self.assertEqual(len(files), 1)
        stored = files[0]
        original = stored.read_bytes()
        document = json.loads(original)
        try:
            for field in ("root_hash", "signature"):
                with self.subTest(tampering=field):
                    tampered = copy.deepcopy(document)
                    if field == "root_hash":
                        tampered["root_hash"] = "0" * 64
                    else:
                        signature = bytearray(base64.b64decode(tampered["signature"]["value"]))
                        signature[0] ^= 1
                        tampered["signature"]["value"] = base64.b64encode(signature).decode()
                    # Replace via the host-owned directory, including Docker UID files.
                    stored.unlink()
                    stored.write_text(json.dumps(tampered), encoding="utf-8")
                    stored.chmod(0o644)
                    result = self.request_json(path, token=self.auditor)
                    self.assertIs(result["signature_verified"], False)
                    self.assertEqual(result["root_hash_verified"], field == "signature")
        finally:
            stored.unlink()
            stored.write_bytes(original)
            stored.chmod(0o644)
        self.assertIs(self.request_json(path, token=self.auditor)["signature_verified"], True)

    def test_tampered_wal_rejected_on_restart(self):
        self.service.start()
        self.evaluate()
        self.assertEqual(self.chain()["entry_count"], 1)
        self.service.stop()
        wal = self.service.data / "ledger.wal"
        entries = [json.loads(line) for line in wal.read_text().splitlines()]
        self.assertEqual(len(entries), 1)
        entries[0]["integrity"]["content_hash"] = "0" * 64
        wal.unlink()
        wal.write_text("\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8")
        wal.chmod(0o666)
        self.service.start(expect_failure=True)
        self.assertIn("Failed to initialize WAL log", self.service.logs())


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--binary", type=Path, help="absolute path to the built API executable")
    target.add_argument("--image", help="local Docker image containing the API executable")
    parser.add_argument("--startup-timeout", type=float, default=30)
    OPTIONS = parser.parse_args()
    if OPTIONS.startup_timeout <= 0:
        parser.error("--startup-timeout must be positive")
    if not shutil.which("openssl"):
        parser.error("OpenSSL CLI is required for ephemeral certificates and EdDSA JWTs")
    if OPTIONS.binary:
        if not OPTIONS.binary.is_absolute() or not OPTIONS.binary.is_file():
            parser.error("--binary must name an existing absolute executable path")
        if not os.access(OPTIONS.binary, os.X_OK):
            parser.error("--binary is not executable")
    else:
        if not shutil.which("docker"):
            parser.error("Docker CLI is required for --image")
        run("docker", "image", "inspect", OPTIONS.image)
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        unittest.main(argv=[__file__], verbosity=2)
    finally:
        try:
            for service in list(ACTIVE_SERVICES):
                service.stop()
        finally:
            ReleaseIntegration.doClassCleanups()


if __name__ == "__main__":
    main()
