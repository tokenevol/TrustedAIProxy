import tempfile
import time
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
