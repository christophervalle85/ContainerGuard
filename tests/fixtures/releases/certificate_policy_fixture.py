"""Generate disposable CA and certificate-signed bundles for opt-in tests only."""

import base64
import datetime
import json
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier


def generate(directory):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    def b64(data):
        return base64.b64encode(data).decode()

    root = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "certificateAuthorities": [
            {
                "subject": {"commonName": "Fixture CA"},
                "uri": "https://fixture.invalid",
                "certChain": {
                    "certificates": [
                        {"rawBytes": b64(ca.public_bytes(serialization.Encoding.DER))}
                    ]
                },
                "validFor": {
                    "start": (now - datetime.timedelta(days=1))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "end": (now + datetime.timedelta(days=3))
                    .isoformat()
                    .replace("+00:00", "Z"),
                },
            }
        ],
    }
    (directory / "root.json").write_text(json.dumps(root))
    expected = {
        "workflow": "https://github.com/christophervalle85/ContainerGuard/.github/workflows/release.yml@refs/tags/v1.0.0",
        "issuer": "https://token.actions.githubusercontent.com",
        "event": "push",
        "sha": "a" * 40,
        "repository": "christophervalle85/ContainerGuard",
        "ref": "refs/tags/v1.0.0",
    }
    variants = [("valid", None, False)] + [
        (prefix + "-" + field, field, missing)
        for field in expected
        for prefix, missing in (("wrong", False), ("missing", True))
    ]
    payload_type = "application/vnd.in-toto+json"
    payload = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "fixture", "digest": {"sha256": "b" * 64}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"fixture": True},
        },
        separators=(",", ":"),
    ).encode()
    pae = (
        b"DSSEv1 "
        + str(len(payload_type)).encode()
        + b" "
        + payload_type.encode()
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )
    for serial, (label, field, missing) in enumerate(variants, 2):
        values = dict(expected)
        if field:
            if missing:
                del values[field]
            else:
                values[field] += "-wrong"
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
            )
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, False, False, False, False
                ),
                True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False
            )
        )
        if "workflow" in values:
            cert = cert.add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(values["workflow"])]
                ),
                False,
            )
        for name, oid in (
            ("issuer", 1),
            ("event", 2),
            ("sha", 3),
            ("repository", 5),
            ("ref", 6),
        ):
            if name in values:
                cert = cert.add_extension(
                    x509.UnrecognizedExtension(
                        ObjectIdentifier(f"1.3.6.1.4.1.57264.1.{oid}"),
                        values[name].encode(),
                    ),
                    False,
                )
        leaf = cert.sign(ca_key, hashes.SHA256())
        ca.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            ec.ECDSA(leaf.signature_hash_algorithm),
        )
        signature = key.sign(pae, ec.ECDSA(hashes.SHA256()))
        leaf.public_key().verify(signature, pae, ec.ECDSA(hashes.SHA256()))
        bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {
                    "rawBytes": b64(leaf.public_bytes(serialization.Encoding.DER))
                }
            },
            "dsseEnvelope": {
                "payload": b64(payload),
                "payloadType": payload_type,
                "signatures": [{"sig": b64(signature)}],
            },
        }
        (directory / (label + ".json")).write_text(json.dumps(bundle))


if __name__ == "__main__":
    generate(pathlib.Path(sys.argv[1]))
