#!/usr/bin/env bash
set -euo pipefail

# Fill these values before running. Use an immutable image digest, not :latest.
#
# IMPORTANT: the production binary fails closed unless a stable internal MITM
# CA certificate and key are available at the configured file paths. This VM
# template does not put CA private key material in metadata. Integrate an
# attestation-gated Secret Manager/KMS bootstrap before using it in production.
PROJECT_ID="your-project"
ZONE="us-central1-a"
INSTANCE_NAME="tap"
MACHINE_TYPE="n2d-standard-2"
WORKLOAD_SERVICE_ACCOUNT="tap-workload@${PROJECT_ID}.iam.gserviceaccount.com"
IMAGE="ghcr.io/OWNER/REPOSITORY@sha256:REPLACE_ME"
INTERNAL_CALLER_CIDR="10.0.0.0/24"

gcloud compute firewall-rules create tap-from-internal \
  --project="${PROJECT_ID}" \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:8080 \
  --source-ranges="${INTERNAL_CALLER_CIDR}" \
  --target-tags=tap

gcloud compute instances create "${INSTANCE_NAME}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --machine-type="${MACHINE_TYPE}" \
  --confidential-compute-type=SEV \
  --maintenance-policy=MIGRATE \
  --shielded-secure-boot \
  --image-project=confidential-space-images \
  --image-family=confidential-space \
  --service-account="${WORKLOAD_SERVICE_ACCOUNT}" \
  --scopes=cloud-platform \
  --tags=tap \
  --metadata="^~^tee-image-reference=${IMAGE}~tee-restart-policy=OnFailure"
