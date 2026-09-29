#!/usr/bin/env python3
"""Materialize and validate the offline GB100-M2-05 PKI fixture matrix."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "config/m2-05-pki-fixture-matrix.json"
DEFAULT_OUTPUT = ROOT / "artifacts/m2-05-pki-fixtures"


class FixtureError(RuntimeError):
    pass


def command(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["openssl", *args], cwd=cwd, text=True, capture_output=True, check=False
    )


def checked(*args: str, cwd: Path) -> None:
    result = command(*args, cwd=cwd)
    if result.returncode:
        raise FixtureError(
            f"openssl {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}"
        )


def write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def create_key_and_csr(name: str, subject: str, output: Path) -> None:
    checked(
        "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/{subject}",
        "-keyout", f"private/{name}.key", "-out", f"private/{name}.csr", cwd=output
    )


def create_root(name: str, subject: str, path_length: int, output: Path) -> Path:
    create_key_and_csr(name, subject, output)
    extensions = output / f"private/{name}.cnf"
    write(
        extensions,
        "[v3_ca]\n"
        f"basicConstraints=critical,CA:TRUE,pathlen:{path_length}\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n",
    )
    cert = output / f"pki/{name}.pem"
    checked(
        "x509", "-req", "-in", f"private/{name}.csr", "-signkey", f"private/{name}.key",
        "-days", "3650", "-sha256", "-extfile", str(extensions), "-extensions", "v3_ca",
        "-out", str(cert), cwd=output
    )
    return cert


def create_signed(
    name: str,
    subject: str,
    issuer: str,
    extensions: str,
    output: Path,
) -> Path:
    create_key_and_csr(name, subject, output)
    extension_path = output / f"private/{name}.cnf"
    write(extension_path, extensions)
    cert = output / f"pki/{name}.pem"
    checked(
        "x509", "-req", "-in", f"private/{name}.csr", "-CA", f"pki/{issuer}.pem",
        "-CAkey", f"private/{issuer}.key", "-CAcreateserial", "-days", "3650", "-sha256",
        "-extfile", str(extension_path), "-extensions", "v3", "-out", str(cert), cwd=output
    )
    return cert


def intermediate_extensions(path_length: int, *, ca: bool = True) -> str:
    constraints = f"CA:TRUE,pathlen:{path_length}" if ca else "CA:FALSE"
    usage = "keyCertSign,cRLSign" if ca else "digitalSignature,keyEncipherment"
    return (
        "[v3]\n"
        f"basicConstraints=critical,{constraints}\n"
        f"keyUsage=critical,{usage}\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )


def leaf_extensions(hostname: str, *, eku: str = "serverAuth") -> str:
    return (
        "[v3]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage={eku}\n"
        f"subjectAltName=DNS:{hostname}\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )


def copy_fixture(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def mutate_signature(source: Path, destination: Path) -> None:
    der = source.with_suffix(".der")
    checked("x509", "-in", str(source), "-outform", "DER", "-out", str(der), cwd=source.parents[1])
    contents = bytearray(der.read_bytes())
    contents[-1] ^= 0x01
    encoded = base64.encodebytes(contents).decode("ascii")
    write(destination, "-----BEGIN CERTIFICATE-----\n" + encoded + "-----END CERTIFICATE-----\n")


def pem_bundle(output: Path, relative: str, names: list[str]) -> Path:
    path = output / relative
    write(path, "".join((output / f"pki/{name}.pem").read_text(encoding="utf-8") for name in names))
    return path


def materialize(output: Path) -> dict[str, Path]:
    if shutil.which("openssl") is None:
        raise FixtureError("OpenSSL is required to build the local PKI fixtures")
    if output.exists():
        shutil.rmtree(output)
    (output / "pki").mkdir(parents=True)
    (output / "negative").mkdir()
    (output / "private").mkdir()

    print("[M2-05 1/4] Generating local Standard and Russian test roots", flush=True)
    standard_root = create_root("standard-root", "CN=Good Bear Test Standard Root", 2, output)
    russian_root = create_root("russian-root", "CN=Good Bear Test Russian Root/O=Good Bear Test PKI", 2, output)
    fake_root = create_root("same-name-fake-root", "CN=Good Bear Test Russian Root/O=Good Bear Test PKI", 2, output)

    print("[M2-05 2/4] Generating valid local chains and negative X.509 variants", flush=True)
    standard_int = create_signed("standard-intermediate", "CN=Good Bear Test Standard Intermediate", "standard-root", intermediate_extensions(1), output)
    standard_leaf = create_signed("standard-leaf", "CN=test-standard.example", "standard-intermediate", leaf_extensions("test-standard.example"), output)
    russian_int = create_signed("russian-intermediate", "CN=Good Bear Test Russian Intermediate", "russian-root", intermediate_extensions(1), output)
    russian_leaf = create_signed("russian-leaf", "CN=test-russian.example", "russian-intermediate", leaf_extensions("test-russian.example"), output)
    fake_leaf = create_signed("same-name-fake-leaf", "CN=test-russian.example", "same-name-fake-root", leaf_extensions("test-russian.example"), output)
    wrong_host = create_signed("wrong-hostname-leaf", "CN=wrong-host.example", "russian-intermediate", leaf_extensions("wrong-host.example"), output)
    expired = create_signed("expired-leaf", "CN=expired-russian.example", "russian-intermediate", leaf_extensions("expired-russian.example"), output)
    bad_signature_source = create_signed("bad-signature-source", "CN=bad-signature-russian.example", "russian-intermediate", leaf_extensions("bad-signature-russian.example"), output)
    wrong_eku = create_signed("wrong-eku-leaf", "CN=wrong-eku-russian.example", "russian-intermediate", leaf_extensions("wrong-eku-russian.example", eku="clientAuth"), output)
    not_ca_int = create_signed("not-ca-intermediate", "CN=Good Bear Test Not A CA", "russian-root", intermediate_extensions(0, ca=False), output)
    not_ca_leaf = create_signed("not-ca-leaf", "CN=not-ca-russian.example", "not-ca-intermediate", leaf_extensions("not-ca-russian.example"), output)
    pathlen_int = create_signed("pathlen-intermediate", "CN=Good Bear Test Pathlen Zero", "russian-intermediate", intermediate_extensions(0), output)
    pathlen_subint = create_signed("pathlen-subintermediate", "CN=Good Bear Test Pathlen Overflow", "pathlen-intermediate", intermediate_extensions(0), output)
    pathlen_leaf = create_signed("pathlen-leaf", "CN=pathlen-russian.example", "pathlen-subintermediate", leaf_extensions("pathlen-russian.example"), output)

    copy_fixture(fake_root, output / "negative/same-name-fake-root.pem")
    copy_fixture(fake_leaf, output / "negative/same-name-fake-leaf.pem")
    copy_fixture(wrong_host, output / "negative/wrong-hostname-leaf.pem")
    copy_fixture(expired, output / "negative/expired-leaf.pem")
    mutate_signature(bad_signature_source, output / "negative/bad-signature-leaf.pem")
    copy_fixture(wrong_eku, output / "negative/wrong-eku-leaf.pem")
    copy_fixture(not_ca_int, output / "negative/not-ca-intermediate.pem")
    copy_fixture(not_ca_leaf, output / "negative/not-ca-leaf.pem")
    copy_fixture(pathlen_int, output / "negative/pathlen-intermediate.pem")
    copy_fixture(pathlen_subint, output / "negative/pathlen-subintermediate.pem")
    copy_fixture(pathlen_leaf, output / "negative/pathlen-leaf.pem")
    copy_fixture(russian_leaf, output / "negative/missing-intermediate-chain.pem")
    pem_bundle(output, "pki/standard-chain.pem", ["standard-intermediate"])
    pem_bundle(output, "pki/russian-chain.pem", ["russian-intermediate"])
    pem_bundle(output, "negative/not-ca-chain.pem", ["not-ca-intermediate"])
    pem_bundle(output, "negative/pathlen-chain.pem", ["russian-intermediate", "pathlen-intermediate", "pathlen-subintermediate"])

    return {
        "standard_root": standard_root, "standard_leaf": standard_leaf,
        "russian_root": russian_root, "russian_leaf": russian_leaf,
        "fake_root": output / "negative/same-name-fake-root.pem",
        "fake_leaf": output / "negative/same-name-fake-leaf.pem",
        "wrong_host": output / "negative/wrong-hostname-leaf.pem",
        "expired": output / "negative/expired-leaf.pem",
        "bad_signature": output / "negative/bad-signature-leaf.pem",
        "wrong_eku": output / "negative/wrong-eku-leaf.pem",
        "not_ca": output / "negative/not-ca-leaf.pem",
        "pathlen": output / "negative/pathlen-leaf.pem",
        "missing_intermediate": output / "negative/missing-intermediate-chain.pem",
    }


def assert_verify(output: Path, expected: bool, *args: str) -> None:
    result = command("verify", *args, cwd=output)
    if (result.returncode == 0) != expected:
        raise FixtureError(
            f"verification expectation {expected} failed for {' '.join(args)}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def fingerprint(path: Path, output: Path) -> str:
    der = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-outform", "DER"],
        cwd=output, capture_output=True, check=False,
    )
    if der.returncode:
        raise FixtureError(f"cannot parse fixture {path}: {der.stderr.decode().strip()}")
    return hashlib.sha256(der.stdout).hexdigest()


def validate(output: Path, paths: dict[str, Path]) -> None:
    print("[M2-05 3/4] Validating exact-anchor and negative-chain behavior offline", flush=True)
    assert_verify(output, True, "-CAfile", str(paths["standard_root"]), "-untrusted", "pki/standard-chain.pem", str(paths["standard_leaf"]))
    assert_verify(output, True, "-CAfile", str(paths["russian_root"]), "-untrusted", "pki/russian-chain.pem", str(paths["russian_leaf"]))
    assert_verify(output, False, "-CAfile", str(paths["standard_root"]), "-untrusted", "pki/russian-chain.pem", str(paths["russian_leaf"]))
    assert_verify(output, False, "-CAfile", str(paths["russian_root"]), str(paths["fake_leaf"]))
    assert_verify(output, False, "-CAfile", str(paths["russian_root"]), "-untrusted", "pki/russian-chain.pem", "-verify_hostname", "test-russian.example", str(paths["wrong_host"]))
    assert_verify(output, False, "-attime", "2524608000", "-CAfile", str(paths["russian_root"]), "-untrusted", "pki/russian-chain.pem", str(paths["expired"]))
    assert_verify(output, False, "-CAfile", str(paths["russian_root"]), "-untrusted", "pki/russian-chain.pem", str(paths["bad_signature"]))
    assert_verify(output, False, "-purpose", "sslserver", "-CAfile", str(paths["russian_root"]), "-untrusted", "pki/russian-chain.pem", str(paths["wrong_eku"]))
    assert_verify(output, False, "-CAfile", str(paths["russian_root"]), "-untrusted", "negative/not-ca-chain.pem", str(paths["not_ca"]))
    assert_verify(output, False, "-CAfile", str(paths["russian_root"]), "-untrusted", "negative/pathlen-chain.pem", str(paths["pathlen"]))
    assert_verify(output, False, "-CAfile", str(paths["russian_root"]), str(paths["missing_intermediate"]))
    if fingerprint(paths["russian_root"], output) == fingerprint(paths["fake_root"], output):
        raise FixtureError("same-name fake root has the genuine root fingerprint")


def write_index(output: Path, paths: dict[str, Path]) -> None:
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    index = {
        "task": matrix["task"], "offline_only": matrix["offline_only"],
        "exact_anchor_sha256": fingerprint(paths["russian_root"], output),
        "same_name_fake_root_sha256": fingerprint(paths["fake_root"], output),
        "fixture_files": sorted(str(path.relative_to(output)) for path in output.rglob("*.pem")),
    }
    write(output / "fixture-index.json", json.dumps(index, indent=2) + "\n")


def run(output: Path) -> None:
    paths = materialize(output)
    validate(output, paths)
    write_index(output, paths)
    print("[M2-05 4/4] Offline PKI fixture matrix passed", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        run(args.output.resolve())
    except FixtureError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
