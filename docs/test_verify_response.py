import io
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import verify_response as verifier


class NonceReplayCacheTest(unittest.TestCase):
    def test_rejects_consumed_nonce_for_same_key(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = str(Path(directory) / "nonces.sqlite3")
            arguments = {
                "cache_path": cache,
                "key_id": "ed25519-example",
                "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                "timestamp": int(time.time()),
            }
            verifier.consume_nonce(**arguments)
            with self.assertRaises(verifier.VerificationError):
                verifier.consume_nonce(**arguments)

    def test_allows_same_nonce_for_different_key(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = str(Path(directory) / "nonces.sqlite3")
            arguments = {
                "cache_path": cache,
                "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                "timestamp": int(time.time()),
            }
            verifier.consume_nonce(key_id="ed25519-one", **arguments)
            verifier.consume_nonce(key_id="ed25519-two", **arguments)


class RouteAndModelPolicyTest(unittest.TestCase):
    def setUp(self):
        self.headers = {
            verifier.HEADER_PATH: "/v1/chat/completions",
            verifier.HEADER_MODEL: "approved-model",
        }

    def test_accepts_expected_route_and_model(self):
        verifier.validate_route_and_model_policy(
            self.headers,
            expected_path="/v1/chat/completions",
            expected_model="approved-model",
        )

    def test_rejects_unexpected_route(self):
        with self.assertRaises(verifier.VerificationError):
            verifier.validate_route_and_model_policy(
                self.headers,
                expected_path="/v1/responses",
                expected_model="approved-model",
            )

    def test_rejects_unexpected_model(self):
        with self.assertRaises(verifier.VerificationError):
            verifier.validate_route_and_model_policy(
                self.headers,
                expected_path="/v1/chat/completions",
                expected_model="other-model",
            )


class BusinessChallengeTest(unittest.TestCase):
    def test_accepts_url_safe_challenge(self):
        verifier.validate_business_challenge("customer_challenge_123")

    def test_rejects_invalid_challenges(self):
        for challenge in ("short", "contains spaces", "a" * 75):
            with self.subTest(challenge=challenge):
                with self.assertRaises(verifier.VerificationError):
                    verifier.validate_business_challenge(challenge)


class ContentTypeTest(unittest.TestCase):
    def test_normalizes_media_type_and_removes_parameters(self):
        self.assertEqual(
            verifier.normalized_content_type("Text/Event-Stream; charset=utf-8"),
            "text/event-stream",
        )

    def test_rejects_invalid_media_type(self):
        with self.assertRaises(verifier.VerificationError):
            verifier.normalized_content_type("not a media type")


class StreamingClientTest(unittest.TestCase):
    def test_verifies_headers_before_reading_body(self):
        events = []

        class FakeResponse:
            status_code = 200
            headers = {
                "content-type": "text/event-stream; charset=utf-8",
                verifier.HEADER_DOMAIN: "api.example.com",
                verifier.HEADER_CERTIFICATE_SHA256: "a" * 64,
            }

            def iter_lines(self):
                events.append("body")
                return iter(("data: example", "", "data: [DONE]"))

        class FakeContext:
            def __enter__(self):
                events.append("headers")
                return FakeResponse()

            def __exit__(self, exc_type, exc_value, traceback):
                events.append("close")

        def create(**kwargs):
            events.append("request")
            self.assertTrue(kwargs["stream"])
            self.assertEqual(
                kwargs["extra_headers"]["X-Attestation-Challenge"],
                "customer_challenge_123",
            )
            return FakeContext()

        client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(
                    with_streaming_response=SimpleNamespace(create=create)
                )
            )
        )
        args = SimpleNamespace(
            challenge="customer_challenge_123",
            prompt="hello",
            model="approved-model",
            public_key="unused-by-mock",
            expected_domain="api.example.com",
            expected_path="/v1/chat/completions",
            max_age=300,
            nonce_cache="unused-by-mock",
        )

        def record_verification(**kwargs):
            events.append("verify")
            self.assertEqual(kwargs["response_content_type"], "text/event-stream")
            self.assertEqual(
                kwargs["request_messages"], [{"role": "user", "text": "hello"}]
            )

        with mock.patch.object(
            verifier, "verify_request_upstream", side_effect=record_verification
        ):
            with redirect_stdout(io.StringIO()):
                verifier.run_streaming(client, args)

        self.assertEqual(events, ["request", "headers", "verify", "body", "close"])

    def test_rejects_non_sse_response_without_reading_body(self):
        body_read = False

        class FakeResponse:
            status_code = 200
            headers = {"content-type": "application/json"}

            def iter_lines(self):
                nonlocal body_read
                body_read = True
                return iter(())

        class FakeContext:
            def __enter__(self):
                return FakeResponse()

            def __exit__(self, exc_type, exc_value, traceback):
                return None

        client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(
                    with_streaming_response=SimpleNamespace(
                        create=lambda **kwargs: FakeContext()
                    )
                )
            )
        )
        args = SimpleNamespace(
            challenge="customer_challenge_123",
            prompt="hello",
            model="approved-model",
            public_key="unused",
            expected_domain="api.example.com",
            expected_path="/v1/chat/completions",
            max_age=300,
            nonce_cache="unused",
        )

        with self.assertRaises(verifier.VerificationError):
            verifier.run_streaming(client, args)

        self.assertFalse(body_read)


if __name__ == "__main__":
    unittest.main()
