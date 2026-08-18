import base64
import hashlib
import types
import unittest

import get_attested_public_key as verifier


class ValidateBundlePolicyTest(unittest.TestCase):
    def fixture(self, *, instance_name="trusted-ai-proxy-02"):
        raw_key = bytes(range(32))
        public_key = base64.urlsafe_b64encode(raw_key).rstrip(b"=").decode("ascii")
        digest = hashlib.sha256(raw_key).digest()
        suffix = base64.urlsafe_b64encode(digest[:18]).rstrip(b"=").decode("ascii")
        binding = verifier.b64url_encode(
            hashlib.sha256(
                b"attestation-ed25519-public-key-v1\x00" + raw_key
            ).digest()
        )
        challenge = "customer_challenge_123"
        args = types.SimpleNamespace(
            audience="tap/customer/v1",
            proof_ref=f"proof-{suffix}",
            hwmodel="GCP_AMD_SEV",
            service_account="tap@example.iam.gserviceaccount.com",
            project_id="example-project",
            project_number="123456789",
            zone="us-central1-a",
            allowed_instance_names=(
                "trusted-ai-proxy-01",
                "trusted-ai-proxy-02",
            ),
            support_attribute="STABLE",
            image_digest="sha256:" + "a" * 64,
            image_reference="example.invalid/image@sha256:" + "a" * 64,
            secret_version="projects/example-project/secrets/postgres/versions/1",
            secret_env_name="TAP_PG_DSN_SECRET_VERSION",
        )
        expires_at = 2_000_000_000
        bundle = {
            "token_type": "OIDC",
            "attestation_token": "header.payload.signature",
            "audience": args.audience,
            "key_id": f"ed25519-{suffix}",
            "challenge_nonce": challenge,
            "proof_ref": args.proof_ref,
            "expires_at": expires_at,
            "attestation_key": {
                "algorithm": "ed25519",
                "public_key": public_key,
                "binding_nonce": binding,
            },
        }
        claims = {
            "exp": expires_at,
            "eat_nonce": [challenge, binding],
            "swname": "CONFIDENTIAL_SPACE",
            "dbgstat": "disabled-since-boot",
            "secboot": True,
            "oemid": 11129,
            "hwmodel": args.hwmodel,
            "google_service_accounts": [args.service_account],
            "sub": (
                "https://www.googleapis.com/compute/v1/projects/"
                f"{args.project_id}/zones/{args.zone}/instances/{instance_name}"
            ),
            "submods": {
                "gce": {
                    "project_id": args.project_id,
                    "project_number": args.project_number,
                    "zone": args.zone,
                    "instance_name": instance_name,
                },
                "confidential_space": {
                    "support_attributes": [args.support_attribute],
                    "monitoring_enabled": {"memory": False},
                },
                "container": {
                    "image_digest": args.image_digest,
                    "image_reference": args.image_reference,
                    "args": verifier.expected_container_args(args.audience),
                    "env": {
                        "HOSTNAME": instance_name,
                        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
                        "TAP_PG_DSN_SECRET_VERSION": args.secret_version,
                    },
                    "env_override": {
                        "TAP_PG_DSN_SECRET_VERSION": args.secret_version
                    },
                    "restart_policy": "OnFailure",
                },
            },
        }
        return bundle, claims, challenge, args

    def test_accepts_requested_proof_from_allowed_replica(self):
        bundle, claims, challenge, args = self.fixture()
        result = verifier.validate_bundle_and_policy(
            bundle, claims, challenge=challenge, args=args
        )
        self.assertEqual(result["proof_ref"], args.proof_ref)
        self.assertEqual(result["instance_name"], "trusted-ai-proxy-02")
        self.assertEqual(result["public_key"], bundle["attestation_key"]["public_key"])

    def test_rejects_proof_reference_other_than_requested(self):
        bundle, claims, challenge, args = self.fixture()
        args.proof_ref = "proof-AAAAAAAAAAAAAAAAAAAAAAAA"
        with self.assertRaises(verifier.AttestationError):
            verifier.validate_bundle_and_policy(
                bundle, claims, challenge=challenge, args=args
            )

    def test_rejects_replica_outside_allowlist(self):
        bundle, claims, challenge, args = self.fixture(
            instance_name="trusted-ai-proxy-03"
        )
        with self.assertRaises(verifier.AttestationError):
            verifier.validate_bundle_and_policy(
                bundle, claims, challenge=challenge, args=args
            )

    def test_accepts_launch_without_postgres(self):
        bundle, claims, challenge, args = self.fixture()
        args.secret_version = None
        container = claims["submods"]["container"]
        container["env"].pop("TAP_PG_DSN_SECRET_VERSION")
        container["env_override"] = {}
        result = verifier.validate_bundle_and_policy(
            bundle, claims, challenge=challenge, args=args
        )
        self.assertEqual(result["proof_ref"], args.proof_ref)

    def test_accepts_deprecated_secret_environment_when_explicit(self):
        bundle, claims, challenge, args = self.fixture()
        args.secret_env_name = "TRUSTED_PROXY_PG_DSN_SECRET_VERSION"
        container = claims["submods"]["container"]
        secret_version = container["env"].pop("TAP_PG_DSN_SECRET_VERSION")
        container["env"][args.secret_env_name] = secret_version
        container["env_override"] = {args.secret_env_name: secret_version}
        result = verifier.validate_bundle_and_policy(
            bundle, claims, challenge=challenge, args=args
        )
        self.assertEqual(result["proof_ref"], args.proof_ref)


if __name__ == "__main__":
    unittest.main()
