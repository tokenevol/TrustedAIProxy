#!/usr/bin/env python3
"""Fetch and verify a Confidential Space-bound TrustedAIProxy Ed25519 key.

By default, only the verified base64url public key is written to stdout.
Diagnostics go to stderr, so the script is safe to use in command substitution:

    export ATTESTATION_PUBLIC_KEY="$(python3 get_attested_public_key.py \
      --attestation-url https://SERVICE_HOST/.well-known/confidential-attestation \
      --proof-ref "$PROOF_REF" \
      --without-postgres)"

The omitted deployment-policy flags must also be supplied with independently
approved values. Use --output-json when a client needs to cache the verified
key together with its proof reference, key ID, expiry, and replica instance
name.

Dependencies:
    python3 -m pip install requests 'PyJWT[crypto]'
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import sys
from typing import Any
from urllib.parse import urlparse


ISSUER = "https://confidentialcomputing.googleapis.com"
DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration"
GOOGLE_JWKS_URL = (
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/"
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
)
ALLOWED_JWT_ALGORITHM = "RS256"
MAX_RESPONSE_BYTES = 1 << 20

# These are deliberately non-production placeholders. Before relying on this
# verifier, replace them or pass the corresponding CLI flags with values that
# the customer has independently reviewed and approved.
DEFAULT_ATTESTATION_URL = (
    "https://api.example.com/.well-known/confidential-attestation"
)
DEFAULT_AUDIENCE = "tap/customer/v1"
DEFAULT_PROJECT_ID = "example-project"
DEFAULT_PROJECT_NUMBER = "123456789012"
DEFAULT_ZONE = "us-central1-a"
DEFAULT_INSTANCE_NAME = "trusted-ai-proxy-01"
DEFAULT_SERVICE_ACCOUNT = (
    "trusted-ai-proxy@example-project.iam.gserviceaccount.com"
)
DEFAULT_IMAGE_DIGEST = "sha256:" + "0" * 64
DEFAULT_IMAGE_REFERENCE = (
    "ghcr.io/tokenevol/trustedaiproxy@"
    + DEFAULT_IMAGE_DIGEST
)
POSTGRES_SECRET_ENV = "TAP_PG_DSN_SECRET_VERSION"


def expected_container_args(audience: str) -> list[str]:
    return [
        "/tap",
        "-listen",
        ":8080",
        "-ca-cert",
        "/data/mitm-ca.pem",
        "-ca-key",
        "/data/mitm-ca-key.pem",
        "-attestation-audience",
        audience,
    ]


DEFAULT_ARGS = expected_container_args(DEFAULT_AUDIENCE)


class AttestationError(Exception):
    """The proof is missing, malformed, cryptographically invalid, or off-policy."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def strict_json_loads(raw: bytes, description: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError(f"{description} is not valid UTF-8 JSON") from exc


def b64url_decode(value: str, description: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise AttestationError(f"{description} is not unpadded base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as exc:
        raise AttestationError(f"cannot decode {description}") from exc


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def expect_equal(actual: Any, expected: Any, claim: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise AttestationError(
            f"claim {claim} mismatch: got {actual!r}, expected {expected!r}"
        )


def require_object(value: Any, claim: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttestationError(f"claim {claim} must be a JSON object")
    return value


def get_json(session: Any, url: str, *, timeout: float, description: str, params=None) -> Any:
    try:
        response = session.get(
            url,
            params=params,
            timeout=timeout,
            allow_redirects=False,
            headers={"Accept": "application/json"},
        )
    except Exception as exc:
        raise AttestationError(f"request {description} failed: {exc}") from exc
    if response.status_code != 200:
        body = response.content[:200].decode("utf-8", "replace").strip()
        raise AttestationError(
            f"{description} returned HTTP {response.status_code}: {body}"
        )
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise AttestationError(f"{description} exceeds {MAX_RESPONSE_BYTES} bytes")
    return strict_json_loads(response.content, description)


def inspect_jwt_json(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AttestationError("attestation_token is not a compact JWT")
    header = strict_json_loads(b64url_decode(parts[0], "JWT header"), "JWT header")
    claims = strict_json_loads(b64url_decode(parts[1], "JWT payload"), "JWT payload")
    return require_object(header, "JWT header"), require_object(claims, "JWT payload")


def verify_google_jwt(
    session: Any,
    token: str,
    *,
    audience: str,
    timeout: float,
) -> dict[str, Any]:
    try:
        import jwt
    except ImportError as exc:
        raise RuntimeError(
            "missing dependency; run: python3 -m pip install requests 'PyJWT[crypto]'"
        ) from exc

    untrusted_header, _ = inspect_jwt_json(token)
    expect_equal(untrusted_header.get("alg"), ALLOWED_JWT_ALGORITHM, "JWT header.alg")
    kid = untrusted_header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AttestationError("JWT header.kid is missing")

    discovery = require_object(
        get_json(
            session,
            DISCOVERY_URL,
            timeout=timeout,
            description="Google OIDC discovery",
        ),
        "OIDC discovery",
    )
    expect_equal(discovery.get("issuer"), ISSUER, "OIDC discovery.issuer")
    algorithms = discovery.get("id_token_signing_alg_values_supported")
    if not isinstance(algorithms, list) or ALLOWED_JWT_ALGORITHM not in algorithms:
        raise AttestationError("Google discovery does not advertise RS256")
    expect_equal(discovery.get("jwks_uri"), GOOGLE_JWKS_URL, "OIDC discovery.jwks_uri")

    jwks = require_object(
        get_json(
            session,
            GOOGLE_JWKS_URL,
            timeout=timeout,
            description="Google Confidential Space JWKS",
        ),
        "JWKS",
    )
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise AttestationError("Google JWKS.keys must be an array")
    matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
    if len(matches) != 1:
        raise AttestationError(f"Google JWKS has {len(matches)} keys for kid {kid!r}")
    jwk = matches[0]
    expect_equal(jwk.get("kty"), "RSA", "JWKS key.kty")
    if jwk.get("alg") not in (None, ALLOWED_JWT_ALGORITHM):
        raise AttestationError(f"JWKS key has unsupported alg {jwk.get('alg')!r}")

    try:
        signing_key = jwt.PyJWK.from_dict(jwk, algorithm=ALLOWED_JWT_ALGORITHM).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=[ALLOWED_JWT_ALGORITHM],
            audience=audience,
            issuer=ISSUER,
            leeway=30,
            options={
                "require": ["iss", "aud", "exp", "iat", "nbf", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.PyJWTError as exc:
        raise AttestationError(f"Google JWT validation failed: {exc}") from exc
    return require_object(claims, "verified JWT claims")


def validate_bundle_and_policy(
    bundle: dict[str, Any],
    claims: dict[str, Any],
    *,
    challenge: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    expect_equal(bundle.get("token_type"), "OIDC", "bundle.token_type")
    expect_equal(bundle.get("audience"), args.audience, "bundle.audience")
    expect_equal(bundle.get("challenge_nonce"), challenge, "bundle.challenge_nonce")
    expect_equal(bundle.get("expires_at"), claims.get("exp"), "bundle.expires_at")

    key = require_object(bundle.get("attestation_key"), "bundle.attestation_key")
    expect_equal(key.get("algorithm"), "ed25519", "attestation_key.algorithm")
    public_key_text = key.get("public_key")
    public_key = b64url_decode(public_key_text, "attestation_key.public_key")
    if len(public_key) != 32:
        raise AttestationError("attestation Ed25519 public key must be exactly 32 bytes")

    binding = b64url_encode(
        hashlib.sha256(
            b"attestation-ed25519-public-key-v1\x00" + public_key
        ).digest()
    )
    expect_equal(key.get("binding_nonce"), binding, "attestation_key.binding_nonce")

    digest_suffix = b64url_encode(hashlib.sha256(public_key).digest()[:18])
    expect_equal(bundle.get("key_id"), f"ed25519-{digest_suffix}", "bundle.key_id")
    expect_equal(bundle.get("proof_ref"), f"proof-{digest_suffix}", "bundle.proof_ref")
    if args.proof_ref:
        expect_equal(bundle.get("proof_ref"), args.proof_ref, "requested proof_ref")

    nonces = claims.get("eat_nonce")
    if isinstance(nonces, str):
        nonces = [nonces]
    if not isinstance(nonces, list) or any(not isinstance(item, str) for item in nonces):
        raise AttestationError("claim eat_nonce must be a string or string array")
    if len(nonces) != 2 or set(nonces) != {challenge, binding}:
        raise AttestationError("claim eat_nonce is not exactly the challenge and key binding")

    expect_equal(claims.get("swname"), "CONFIDENTIAL_SPACE", "swname")
    expect_equal(claims.get("dbgstat"), "disabled-since-boot", "dbgstat")
    expect_equal(claims.get("secboot"), True, "secboot")
    expect_equal(claims.get("oemid"), 11129, "oemid")
    expect_equal(claims.get("hwmodel"), args.hwmodel, "hwmodel")

    service_accounts = claims.get("google_service_accounts")
    expect_equal(
        service_accounts,
        [args.service_account],
        "google_service_accounts",
    )

    submods = require_object(claims.get("submods"), "submods")
    gce = require_object(submods.get("gce"), "submods.gce")
    expect_equal(gce.get("project_id"), args.project_id, "submods.gce.project_id")
    expect_equal(
        gce.get("project_number"), args.project_number, "submods.gce.project_number"
    )
    expect_equal(gce.get("zone"), args.zone, "submods.gce.zone")
    instance_name = gce.get("instance_name")
    if not isinstance(instance_name, str) or instance_name not in args.allowed_instance_names:
        raise AttestationError(
            "claim submods.gce.instance_name is not an allowed replica: "
            f"got {instance_name!r}, allowed {list(args.allowed_instance_names)!r}"
        )

    confidential_space = require_object(
        submods.get("confidential_space"), "submods.confidential_space"
    )
    support = confidential_space.get("support_attributes")
    if not isinstance(support, list) or args.support_attribute not in support:
        raise AttestationError(
            f"support_attributes does not contain {args.support_attribute!r}"
        )
    expect_equal(
        confidential_space.get("monitoring_enabled"),
        {"memory": False},
        "submods.confidential_space.monitoring_enabled",
    )

    container = require_object(submods.get("container"), "submods.container")
    expect_equal(
        container.get("image_digest"), args.image_digest, "submods.container.image_digest"
    )
    expect_equal(
        container.get("image_reference"),
        args.image_reference,
        "submods.container.image_reference",
    )
    expect_equal(
        container.get("args"),
        expected_container_args(args.audience),
        "submods.container.args",
    )
    # Google omits override claims when no override was supplied. Normalize
    # absence to the corresponding empty JSON value before enforcing policy.
    expect_equal(container.get("cmd_override", []), [], "submods.container.cmd_override")
    expected_env = {
        "HOSTNAME": instance_name,
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    }
    expected_env_override = {}
    if args.secret_version:
        expected_env[POSTGRES_SECRET_ENV] = args.secret_version
        expected_env_override[POSTGRES_SECRET_ENV] = args.secret_version
    expect_equal(container.get("env"), expected_env, "submods.container.env")
    expect_equal(
        container.get("env_override", {}),
        expected_env_override,
        "submods.container.env_override",
    )
    expect_equal(
        container.get("restart_policy"), "OnFailure", "submods.container.restart_policy"
    )

    subject = claims.get("sub")
    if not isinstance(subject, str):
        raise AttestationError("claim sub must be a string")
    expected_subject = (
        "https://www.googleapis.com/compute/v1/projects/"
        f"{args.project_id}/zones/{args.zone}/instances/{instance_name}"
    )
    expect_equal(subject, expected_subject, "sub")

    return {
        "public_key": public_key_text,
        "key_id": bundle["key_id"],
        "proof_ref": bundle["proof_ref"],
        "expires_at": bundle["expires_at"],
        "instance_name": instance_name,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch a TrustedAIProxy key only after full Confidential Space "
            "verification. Replace all example policy defaults before production use."
        )
    )
    parser.add_argument("--attestation-url", default=DEFAULT_ATTESTATION_URL)
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE)
    parser.add_argument("--project-id", default=DEFAULT_PROJECT_ID)
    parser.add_argument("--project-number", default=DEFAULT_PROJECT_NUMBER)
    parser.add_argument("--zone", default=DEFAULT_ZONE)
    parser.add_argument(
        "--instance-name",
        default=DEFAULT_INSTANCE_NAME,
        help="single allowed replica name (used when --allowed-instance-name is absent)",
    )
    parser.add_argument(
        "--allowed-instance-name",
        action="append",
        default=[],
        help="allowed replica instance name; repeat for multi-replica deployments",
    )
    parser.add_argument(
        "--proof-ref",
        help="proof reference from X-Attestation-Proof-Ref",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="write verified key metadata as JSON instead of only the public key",
    )
    parser.add_argument("--service-account", default=DEFAULT_SERVICE_ACCOUNT)
    parser.add_argument("--image-digest", default=DEFAULT_IMAGE_DIGEST)
    parser.add_argument("--image-reference", default=DEFAULT_IMAGE_REFERENCE)
    postgres = parser.add_mutually_exclusive_group(required=True)
    postgres.add_argument(
        "--secret-version",
        help=(
            "fixed Secret Manager version containing the PostgreSQL DSN; "
            "cannot be latest"
        ),
    )
    postgres.add_argument(
        "--without-postgres",
        action="store_true",
        help="expect a single-replica launch without a PostgreSQL secret override",
    )
    parser.add_argument("--hwmodel", default="GCP_AMD_SEV")
    parser.add_argument("--support-attribute", default="STABLE")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    url = urlparse(args.attestation_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        parser.error("--attestation-url must be an HTTPS URL without user info")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_digest):
        parser.error("--image-digest must be sha256 followed by 64 lowercase hex digits")
    if args.proof_ref and not re.fullmatch(r"proof-[A-Za-z0-9_-]{24}", args.proof_ref):
        parser.error("--proof-ref is malformed")
    if args.secret_version and not re.fullmatch(
        r"projects/[^/]+/secrets/[^/]+/versions/[1-9][0-9]*",
        args.secret_version,
    ):
        parser.error("--secret-version must reference a fixed numbered version")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.allowed_instance_name:
        args.allowed_instance_names = tuple(dict.fromkeys(args.allowed_instance_name))
    else:
        args.allowed_instance_names = (args.instance_name,)
    return args


def main() -> int:
    args = parse_args()
    try:
        import requests
    except ImportError:
        print(
            "ERROR: missing dependency; run: "
            "python3 -m pip install requests 'PyJWT[crypto]'",
            file=sys.stderr,
        )
        return 2

    challenge = secrets.token_urlsafe(24)
    session = requests.Session()
    session.trust_env = True
    try:
        params = {"nonce": challenge}
        if args.proof_ref:
            params["proof_ref"] = args.proof_ref
        bundle = require_object(
            get_json(
                session,
                args.attestation_url,
                params=params,
                timeout=args.timeout,
                description="TrustedAIProxy confidential attestation",
            ),
            "attestation bundle",
        )
        token = bundle.get("attestation_token")
        if not isinstance(token, str) or len(token) > MAX_RESPONSE_BYTES:
            raise AttestationError("bundle.attestation_token is missing or too large")
        claims = verify_google_jwt(
            session,
            token,
            audience=args.audience,
            timeout=args.timeout,
        )
        verified = validate_bundle_and_policy(
            bundle,
            claims,
            challenge=challenge,
            args=args,
        )
    except AttestationError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("✅ VALID: Google Confidential Space proof and local policy verified", file=sys.stderr)
    if args.output_json:
        print(json.dumps(verified, sort_keys=True, separators=(",", ":")))
    else:
        print(verified["public_key"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
