#!/usr/bin/env python3
"""Call an OpenAI-compatible API and verify TAP response headers.

The Ed25519 public key passed to this script must already be trusted (normally
after validating the corresponding Google Confidential Space attestation).

Dependencies:
    python3 -m pip install openai cryptography rfc8785

Example:
    export TOKENEVOL_API_KEY='...'
    export ATTESTATION_PUBLIC_KEY='BASE64URL_RAW_ED25519_PUBLIC_KEY'
    python3 verify_response.py \
      --expected-domain api.deepseek.com \
      --expected-path /v1/chat/completions
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Mapping


HEADER_ALGORITHM = "x-attestation-algorithm"
HEADER_PROFILE = "x-attestation-profile"
HEADER_KEY_ID = "x-attestation-key-id"
HEADER_DOMAIN = "x-attestation-domain"
HEADER_PATH = "x-attestation-path"
HEADER_MODEL = "x-attestation-model"
HEADER_CERTIFICATE_SHA256 = "x-attestation-certificate-sha256"
HEADER_TIMESTAMP = "x-attestation-timestamp"
HEADER_NONCE = "x-attestation-nonce"
HEADER_SIGNED_FIELDS = "x-attestation-signed-fields"
HEADER_SIGNATURE = "x-attestation-signature"
HEADER_PROOF_REF = "x-attestation-proof-ref"
HEADER_CHALLENGE = "x-attestation-challenge"
HEADER_RESPONSE_STATUS = "x-attestation-response-status"
HEADER_RESPONSE_CONTENT_TYPE = "x-attestation-response-content-type"

REQUIRED_HEADERS = (
    HEADER_ALGORITHM,
    HEADER_PROFILE,
    HEADER_KEY_ID,
    HEADER_DOMAIN,
    HEADER_PATH,
    HEADER_MODEL,
    HEADER_CERTIFICATE_SHA256,
    HEADER_TIMESTAMP,
    HEADER_NONCE,
    HEADER_SIGNED_FIELDS,
    HEADER_SIGNATURE,
    HEADER_PROOF_REF,
)

EXPECTED_SIGNED_FIELDS = (
    "tls_certificate_sha256,domain,request.path,"
    "request.body.model,request.body.messages,response.body.messages"
)

REQUEST_UPSTREAM_REQUIRED_HEADERS = REQUIRED_HEADERS + (
    HEADER_CHALLENGE,
    HEADER_RESPONSE_STATUS,
    HEADER_RESPONSE_CONTENT_TYPE,
)

REQUEST_UPSTREAM_EXPECTED_SIGNED_FIELDS = (
    "tls_certificate_sha256,domain,request.path,"
    "request.body.model,request.body.messages,request.body.stream,"
    "response.status,response.content_type,challenge"
)


class VerificationError(Exception):
    """The response is present but its attestation is invalid."""


def base64url_decode(value: str, description: str) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise VerificationError(f"{description} is not unpadded base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as exc:
        raise VerificationError(f"cannot decode {description}") from exc


def public_key_identifiers(public_key: bytes) -> tuple[str, str]:
    digest = hashlib.sha256(public_key).digest()
    suffix = base64.urlsafe_b64encode(digest[:18]).rstrip(b"=").decode("ascii")
    return f"ed25519-{suffix}", f"proof-{suffix}"


def response_messages(response_body: Any) -> list[dict[str, str]]:
    """Normalize one OpenAI Chat choice to llm-conversation-text-v1."""
    try:
        choices = response_body["choices"]
        if not isinstance(choices, list) or len(choices) != 1:
            raise VerificationError("response must contain exactly one choice")
        message = choices[0]["message"]
        if not isinstance(message, Mapping):
            raise VerificationError("response message must be an object")
        if message.get("role") != "assistant":
            raise VerificationError("response message role must be assistant")
        content = message.get("content")
        texts: list[str] = []
        found_text = False
        if isinstance(content, str):
            texts.append(content)
            found_text = True
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, Mapping):
                    raise VerificationError("response content block must be an object")
                block_type = block.get("type", "")
                if block_type in ("text", "input_text", "output_text", "refusal") or (
                    block_type == "" and isinstance(block.get("text"), str)
                ):
                    value = block.get("text")
                    if block_type == "refusal" and value is None:
                        value = block.get("refusal")
                    if not isinstance(value, str):
                        raise VerificationError("text response block has no text value")
                    texts.append(value)
                    found_text = True
        elif content is not None:
            raise VerificationError("response content must be a string or array")

        refusal = message.get("refusal")
        if refusal is not None:
            if not isinstance(refusal, str):
                raise VerificationError("response refusal must be a string")
            if found_text:
                raise VerificationError(
                    "response message contains both content text and refusal text"
                )
            texts.append(refusal)
            found_text = True
        if not found_text:
            raise VerificationError("response contains no final text")
        return [{"role": "assistant", "text": "".join(texts)}]
    except (KeyError, TypeError) as exc:
        raise VerificationError("response is not OpenAI-compatible JSON") from exc


def require_headers(
    headers: Mapping[str, str], required: tuple[str, ...] = REQUIRED_HEADERS
) -> dict[str, str]:
    normalized = {str(name).lower(): str(value) for name, value in headers.items()}
    missing = [name for name in required if not normalized.get(name)]
    if missing:
        raise VerificationError("missing required headers: " + ", ".join(missing))
    return normalized


def validate_business_challenge(challenge: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{10,74}", challenge):
        raise VerificationError(
            "business request challenge must be 10-74 URL-safe ASCII characters"
        )


def validate_route_and_model_policy(
    headers: Mapping[str, str], *, expected_path: str, expected_model: str
) -> None:
    if headers[HEADER_PATH] != expected_path:
        raise VerificationError(
            f"path mismatch: got {headers[HEADER_PATH]!r}, expected {expected_path!r}"
        )
    if headers[HEADER_MODEL] != expected_model:
        raise VerificationError(
            f"model mismatch: got {headers[HEADER_MODEL]!r}, "
            f"expected {expected_model!r}"
        )


def consume_nonce(
    cache_path: str,
    *,
    key_id: str,
    nonce: str,
    timestamp: int,
) -> None:
    """Atomically persist a verified nonce and reject a replay."""
    path = Path(cache_path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.touch(mode=0o600, exist_ok=True)
        path.chmod(0o600)
        connection = sqlite3.connect(path, timeout=5)
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_nonces (
                    key_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    PRIMARY KEY (key_id, nonce)
                )
                """
            )
            try:
                connection.execute(
                    "INSERT INTO consumed_nonces "
                    "(key_id, nonce, timestamp) VALUES (?, ?, ?)",
                    (key_id, nonce, timestamp),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                raise VerificationError(
                    "attestation nonce has already been consumed"
                ) from exc
        finally:
            connection.close()
    except VerificationError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise VerificationError(f"cannot update nonce replay cache: {exc}") from exc


def verify_response(
    *,
    headers: Mapping[str, str],
    response_body: Any,
    public_key_text: str,
    expected_domain: str,
    expected_path: str,
    expected_model: str,
    prompt: str,
    max_age_seconds: int,
    nonce_cache_path: str,
) -> Any:
    try:
        import rfc8785
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError(
            "missing dependency; run: python3 -m pip install openai cryptography rfc8785"
        ) from exc

    h = require_headers(headers)
    public_key = base64url_decode(public_key_text, "attestation public key")
    if len(public_key) != 32:
        raise VerificationError("attestation public key must decode to 32 bytes")

    if h[HEADER_ALGORITHM] != "ed25519":
        raise VerificationError(f"unsupported algorithm: {h[HEADER_ALGORITHM]!r}")
    if h[HEADER_PROFILE] != "llm-conversation-text-v1":
        raise VerificationError(f"unsupported profile: {h[HEADER_PROFILE]!r}")
    if h[HEADER_DOMAIN].lower() != expected_domain.lower():
        raise VerificationError(
            f"domain mismatch: got {h[HEADER_DOMAIN]!r}, expected {expected_domain!r}"
        )
    validate_route_and_model_policy(
        h, expected_path=expected_path, expected_model=expected_model
    )
    if h[HEADER_SIGNED_FIELDS] != EXPECTED_SIGNED_FIELDS:
        raise VerificationError(
            "signed fields do not match local policy: "
            f"got {h[HEADER_SIGNED_FIELDS]!r}"
        )

    certificate_sha256 = h[HEADER_CERTIFICATE_SHA256]
    if not re.fullmatch(r"[0-9a-f]{64}", certificate_sha256):
        raise VerificationError(
            "certificate SHA-256 must be 64 lowercase hex characters"
        )

    try:
        timestamp = int(h[HEADER_TIMESTAMP], 10)
    except ValueError as exc:
        raise VerificationError("attestation timestamp is not an integer") from exc
    age = time.time() - timestamp
    if age < -30 or age > max_age_seconds:
        raise VerificationError(
            f"attestation timestamp is outside the allowed window (age={age:.1f}s)"
        )

    nonce = base64url_decode(h[HEADER_NONCE], "attestation nonce")
    if len(nonce) != 16:
        raise VerificationError("attestation nonce must decode to 16 bytes")

    expected_key_id, expected_proof_ref = public_key_identifiers(public_key)
    if h[HEADER_KEY_ID] != expected_key_id:
        raise VerificationError(
            f"key ID does not match trusted public key: expected {expected_key_id!r}"
        )
    if h[HEADER_PROOF_REF] != expected_proof_ref:
        raise VerificationError(
            f"proof reference does not match trusted public key: expected {expected_proof_ref!r}"
        )

    messages = response_messages(response_body)
    signed_path = h[HEADER_PATH]
    signed_model = h[HEADER_MODEL]
    claims = {
        "version": "trusted-ai-proxy-v1",
        "profile": "llm-conversation-text-v1",
        "key_id": h[HEADER_KEY_ID],
        "tls_certificate_sha256": certificate_sha256,
        "domain": expected_domain.lower(),
        "request_path": signed_path,
        "request_fields": [
            {"name": "model", "value": signed_model},
            {
                "name": "messages",
                "value": [{"role": "user", "text": prompt}],
            },
        ],
        "response_fields": [
            {"name": "messages", "value": messages},
        ],
        "timestamp": timestamp,
        "nonce": h[HEADER_NONCE],
    }
    try:
        payload = rfc8785.dumps(claims)
    except (ValueError, TypeError) as exc:
        raise VerificationError(f"cannot canonicalize signed payload: {exc}") from exc

    signature = base64url_decode(h[HEADER_SIGNATURE], "attestation signature")
    if len(signature) != 64:
        raise VerificationError("attestation signature must decode to 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except InvalidSignature as exc:
        raise VerificationError("Ed25519 signature verification failed") from exc

    consume_nonce(
        nonce_cache_path,
        key_id=h[HEADER_KEY_ID],
        nonce=h[HEADER_NONCE],
        timestamp=timestamp,
    )

    return "".join(message["text"] for message in messages)


def verify_request_upstream(
    *,
    headers: Mapping[str, str],
    public_key_text: str,
    expected_domain: str,
    expected_path: str,
    expected_model: str,
    request_messages: list[dict[str, str]],
    challenge: str,
    response_status: int,
    response_content_type: str,
    max_age_seconds: int,
    nonce_cache_path: str,
) -> None:
    """Verify llm-request-upstream-v1 without trusting the stream body."""
    try:
        import rfc8785
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError(
            "missing dependency; run: python3 -m pip install cryptography rfc8785"
        ) from exc

    validate_business_challenge(challenge)
    h = require_headers(headers, REQUEST_UPSTREAM_REQUIRED_HEADERS)
    public_key = base64url_decode(public_key_text, "attestation public key")
    if len(public_key) != 32:
        raise VerificationError("attestation public key must decode to 32 bytes")
    if h[HEADER_ALGORITHM] != "ed25519":
        raise VerificationError(f"unsupported algorithm: {h[HEADER_ALGORITHM]!r}")
    if h[HEADER_PROFILE] != "llm-request-upstream-v1":
        raise VerificationError(f"unsupported profile: {h[HEADER_PROFILE]!r}")
    if h[HEADER_DOMAIN].lower() != expected_domain.lower():
        raise VerificationError(
            f"domain mismatch: got {h[HEADER_DOMAIN]!r}, expected {expected_domain!r}"
        )
    validate_route_and_model_policy(
        h, expected_path=expected_path, expected_model=expected_model
    )
    if h[HEADER_SIGNED_FIELDS] != REQUEST_UPSTREAM_EXPECTED_SIGNED_FIELDS:
        raise VerificationError(
            "signed fields do not match request-upstream policy: "
            f"got {h[HEADER_SIGNED_FIELDS]!r}"
        )
    if h[HEADER_CHALLENGE] != challenge:
        raise VerificationError("business request challenge does not match")
    try:
        signed_status = int(h[HEADER_RESPONSE_STATUS], 10)
    except ValueError as exc:
        raise VerificationError("signed response status is not an integer") from exc
    if signed_status != response_status:
        raise VerificationError(
            f"response status mismatch: got {signed_status}, expected {response_status}"
        )
    if h[HEADER_RESPONSE_CONTENT_TYPE] != response_content_type:
        raise VerificationError(
            "response content type mismatch: "
            f"got {h[HEADER_RESPONSE_CONTENT_TYPE]!r}, "
            f"expected {response_content_type!r}"
        )

    certificate_sha256 = h[HEADER_CERTIFICATE_SHA256]
    if not re.fullmatch(r"[0-9a-f]{64}", certificate_sha256):
        raise VerificationError(
            "certificate SHA-256 must be 64 lowercase hex characters"
        )
    try:
        timestamp = int(h[HEADER_TIMESTAMP], 10)
    except ValueError as exc:
        raise VerificationError("attestation timestamp is not an integer") from exc
    age = time.time() - timestamp
    if age < -30 or age > max_age_seconds:
        raise VerificationError(
            f"attestation timestamp is outside the allowed window (age={age:.1f}s)"
        )
    nonce = base64url_decode(h[HEADER_NONCE], "attestation nonce")
    if len(nonce) != 16:
        raise VerificationError("attestation nonce must decode to 16 bytes")

    expected_key_id, expected_proof_ref = public_key_identifiers(public_key)
    if h[HEADER_KEY_ID] != expected_key_id:
        raise VerificationError(
            f"key ID does not match trusted public key: expected {expected_key_id!r}"
        )
    if h[HEADER_PROOF_REF] != expected_proof_ref:
        raise VerificationError(
            f"proof reference does not match trusted public key: expected {expected_proof_ref!r}"
        )

    claims = {
        "version": "trusted-ai-proxy-v1",
        "profile": "llm-request-upstream-v1",
        "key_id": h[HEADER_KEY_ID],
        "tls_certificate_sha256": certificate_sha256,
        "domain": expected_domain.lower(),
        "request_path": h[HEADER_PATH],
        "request_fields": [
            {"name": "model", "value": h[HEADER_MODEL]},
            {"name": "messages", "value": request_messages},
            {"name": "stream", "value": True},
        ],
        "response_fields": [],
        "timestamp": timestamp,
        "nonce": h[HEADER_NONCE],
        "challenge": challenge,
        "response_status": signed_status,
        "response_content_type": response_content_type,
    }
    try:
        payload = rfc8785.dumps(claims)
    except (ValueError, TypeError) as exc:
        raise VerificationError(f"cannot canonicalize signed payload: {exc}") from exc
    signature = base64url_decode(h[HEADER_SIGNATURE], "attestation signature")
    if len(signature) != 64:
        raise VerificationError("attestation signature must decode to 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except InvalidSignature as exc:
        raise VerificationError("Ed25519 signature verification failed") from exc

    consume_nonce(
        nonce_cache_path,
        key_id=h[HEADER_KEY_ID],
        nonce=h[HEADER_NONCE],
        timestamp=timestamp,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Call an OpenAI-compatible API and verify TAP headers."
    )
    parser.add_argument(
        "--base-url",
        default="https://api.example.com/v1",
        help="OpenAI-compatible API base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("TOKENEVOL_API_KEY") or os.getenv("OPENAI_API_KEY"),
        help="API key; prefer TOKENEVOL_API_KEY or OPENAI_API_KEY",
    )
    parser.add_argument(
        "--public-key",
        default=os.getenv("ATTESTATION_PUBLIC_KEY"),
        help="trusted base64url raw Ed25519 key (or ATTESTATION_PUBLIC_KEY)",
    )
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--prompt", default="你好")
    parser.add_argument(
        "--expected-domain",
        default="api.deepseek.com",
        help="trusted upstream domain policy (default: %(default)s)",
    )
    parser.add_argument(
        "--expected-path",
        default="/v1/chat/completions",
        help="trusted upstream request path policy (default: %(default)s)",
    )
    parser.add_argument(
        "--max-age",
        type=int,
        default=300,
        help="maximum header age in seconds",
    )
    parser.add_argument(
        "--nonce-cache",
        default=os.getenv("TAP_NONCE_CACHE")
        or "~/.cache/trusted-ai-proxy/consumed-nonces.sqlite3",
        help="persistent SQLite replay cache (default: %(default)s)",
    )
    args = parser.parse_args()
    if not args.api_key:
        parser.error("API key is required; set TOKENEVOL_API_KEY or pass --api-key")
    if not args.public_key:
        parser.error(
            "trusted public key is required; set ATTESTATION_PUBLIC_KEY or pass --public-key"
        )
    if args.max_age <= 0:
        parser.error("--max-age must be greater than zero")
    if (
        not args.expected_path.startswith("/")
        or "?" in args.expected_path
        or "#" in args.expected_path
    ):
        parser.error(
            "--expected-path must be an absolute URL path without query or fragment"
        )
    return args


def main() -> int:
    args = parse_args()
    try:
        from openai import OpenAI
    except ImportError:
        print(
            "ERROR: missing dependency; run: "
            "python3 -m pip install openai cryptography rfc8785",
            file=sys.stderr,
        )
        return 2

    client = OpenAI(base_url=args.base_url, api_key=args.api_key)
    try:
        raw_response = client.chat.completions.with_raw_response.create(
            model=args.model,
            messages=[{"role": "user", "content": args.prompt}],
        )
        response_body = raw_response.http_response.json()
        print(raw_response.headers)
        content = verify_response(
            headers=raw_response.headers,
            response_body=response_body,
            public_key_text=args.public_key,
            expected_domain=args.expected_domain,
            expected_path=args.expected_path,
            expected_model=args.model,
            prompt=args.prompt,
            max_age_seconds=args.max_age,
            nonce_cache_path=args.nonce_cache,
        )
    except VerificationError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: request or response parsing failed: {exc}", file=sys.stderr)
        return 2

    print("✅ VALID: TAP Ed25519 response signature verified")
    print(json.dumps({"content": content}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
