# TrustedAIProxy

**English** | [简体中文](README.zh-CN.md)

🌐 **Website: [tokenevol.github.io/TrustedAIProxy](https://tokenevol.github.io/TrustedAIProxy/)**

> A trusted proxy signing service for AI gateways such as New API and One API—verifiable cryptographic evidence of what your gateway sends and receives.

When users call a model through a gateway, HTTPS proves only that they connected to the gateway. It cannot prove whether the gateway substituted a model, changed a prompt, or rewrote a response.

TrustedAIProxy sits between the gateway and the model provider. It records the upstream domain, model, request text, and response text it actually observes, then signs them with a key running inside Google Confidential Space. By verifying the signature and workload attestation, users can check whether their messages match what the trusted proxy observed.

Think of it as a tamper-evident seal at the gateway's egress: changes to the signed request or response text can be detected during verification.

For the complete end-user verification process, see the [customer verification guide (Chinese)](docs/customer-verification-guide.md). An English walkthrough is available in the [website user guide](https://tokenevol.github.io/TrustedAIProxy/user-guide.html).

## What problem does it solve?

Suppose a user sends a gateway this request:

```text
Model: gpt-example
Question: What is the weather in Beijing today?
```

A conventional gateway asks users to trust that it has not changed the request or response. With TrustedAIProxy, users can independently verify:

- Which upstream domain received the request;
- Which model and API path were used;
- Whether the gateway added, removed, reordered, or modified text messages;
- Whether the returned text matches what the trusted proxy received from upstream;
- Whether the signing key belongs to an approved Confidential Space image, rather than an arbitrary program created by the gateway.

**The gateway forwards traffic; TrustedAIProxy leaves a verifiable record of the original exchange.**

## How it works

```text
User
  │ Sends requests; receives responses and attestation headers
  ▼
AI gateway (New API / One API, etc.)
  │ HTTP_PROXY / HTTPS_PROXY
  ▼
TrustedAIProxy (Confidential Space)
  │ Observes and signs requests and responses
  ▼
Upstream provider (OpenAI / Anthropic / Azure OpenAI / AWS Bedrock, etc.)
```

Each request follows four steps:

1. The gateway sends its upstream request through TrustedAIProxy.
2. TrustedAIProxy verifies the upstream HTTPS certificate normally and forwards the request.
3. After the upstream response arrives, TrustedAIProxy generates an Ed25519 signature over the covered content and returns the attestation in response headers.
4. The gateway returns the original API content and attestation headers to the user, who verifies them independently.

Customers do not need to connect to the proxy, install its MITM CA, or blindly trust a gateway-supplied public key. Each TAP process generates a fresh Ed25519 key in memory and obtains a Google Confidential Space attestation bound to that public key before opening its listening port. Startup terminates if attestation fails. Customers trust the ephemeral signing public key only after verifying its Google attestation and approved image binding.

## What can it prove—and what is outside its scope?

The non-streaming `llm-conversation-text-v1` signature covers:

- The upstream HTTPS leaf certificate's SHA-256 fingerprint;
- The upstream domain and request URL path;
- The actual model;
- Plain-text request and response messages, including roles, order, message boundaries, and text;
- A timestamp and replay-protection nonce.

It does not currently cover:

- Images, files, audio, tool definitions, tool calls, reasoning, citations, or usage;
- The HTTP method, query string, status code, or other fields outside this signature profile;
- Streaming response bodies, including SSE and AWS EventStream;
- How a model provider generates answers internally, or gateway business behavior such as billing and availability.

For SSE requests with a valid `X-Attestation-Challenge` and `stream: true` in the request JSON, TAP can generate a `llm-request-upstream-v1` attestation before the first response body byte. It covers the upstream domain, certificate, request path, normalized `model`/`messages`, `stream: true`, response status, normalized Content-Type, and customer challenge. It **does not cover any streaming response events or text**. A gateway could modify or replace the entire stream without invalidating this profile's signature; customers must not interpret it as proof of response content.

Precisely stated, the guarantee is: **users can verify that the signed request and response content was not silently altered before or after TrustedAIProxy observed it.** Fields outside the signature scope are not attested.

## Supported APIs

| API | Extractor |
| --- | --- |
| OpenAI Chat Completions | `openai-chat-conversation-v1` |
| OpenAI Responses | `openai-responses-conversation-v1` |
| Anthropic Messages | `anthropic-messages-conversation-v1` |
| AWS Bedrock Invoke | `bedrock-invoke-conversation-v1` |
| AWS Bedrock Converse | `bedrock-converse-conversation-v1` |

Compatible APIs that put the model or deployment in the URL path, such as Azure OpenAI, can also be configured. Different protocols are normalized into the shared `llm-conversation-text-v1` format so users can reconstruct the same signed payload. OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages JSON requests with `stream: true` can also receive `llm-request-upstream-v1` attestations. Bedrock streaming paths currently pass through without signatures.

These API rules ship with the project and are updated by its maintainers. At runtime, TAP first reads `signing-rules.json` relative to the current working directory. If the file does not exist, it uses `/etc/tap/signing-rules.json` inside the image. There is no CLI path override. Running from the repository root uses the repository file directly. If the relative file exists but is invalid, TAP fails rather than silently falling back. Rule changes must be included in a new image with a new immutable digest.

## Build and run

### 1. Run local checks

Run the full test suite locally:

```sh
go test ./...
python3 -B -m unittest discover -s docs -p 'test_*.py'
go vet ./...
```

The `tap` runtime must connect to the Confidential Space launcher. It generates a fresh Ed25519 key in memory and requests startup attestation before listening. A normal local environment has no launcher, so startup fails by design. Tests cover this flow with a fake token provider; there is no runtime flag to skip attestation.

### 2. Start inside Confidential Space

Use the repository's deployment template and always specify an immutable image digest:

```sh
cp deploy/confidential-space.example.sh deploy/confidential-space.sh
# Set IMAGE, project, region, instance, and service account.
bash deploy/confidential-space.sh
```

Each process start generates a new `key_id` and `proof_ref`. Private keys are never read from or written to PEM files. Startup attestation uses an internally generated random nonce as a fail-closed startup gate; it does not replace the customer's own proof challenge.

### 3. Route gateway upstream traffic through the proxy

Set these variables in the runtime environment of New API, One API, or your gateway:

```sh
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export NO_PROXY=127.0.0.1,localhost
```

Also add TrustedAIProxy's internal CA certificate to the gateway's system or application trust store. Do not disable TLS verification. Some gateways use custom HTTP clients; after deployment, confirm that real upstream requests actually pass through the proxy.

Run TrustedAIProxy as a sidecar or a separate internal service within the required Confidential Space environment, and restrict its proxy port to gateway callers.

### 4. Inspect the attestation

When text requests and responses are parsed successfully, responses include:

```text
X-Attestation-Algorithm: ed25519
X-Attestation-Profile: llm-conversation-text-v1
X-Attestation-Key-Id: ed25519-...
X-Attestation-Domain: api.example.com
X-Attestation-Path: /v1/chat/completions
X-Attestation-Model: model-name
X-Attestation-Certificate-SHA256: ...
X-Attestation-Timestamp: ...
X-Attestation-Nonce: ...
X-Attestation-Signed-Fields: ...
X-Attestation-Signature: ...
X-Attestation-Proof-Ref: proof-...
```

The gateway must return these headers unchanged. TrustedAIProxy does not modify the response body or copy input/output messages into headers.

For streaming requests, the customer must generate a unique 10–74 character URL-safe ASCII challenge, which the gateway passes on the upstream request:

```text
X-Attestation-Challenge: CUSTOMER_UNIQUE_CHALLENGE
```

TAP removes this internal header before forwarding to the model provider. If the upstream returns SSE, response headers use `llm-request-upstream-v1` and additionally include:

```text
X-Attestation-Challenge: CUSTOMER_UNIQUE_CHALLENGE
X-Attestation-Response-Status: 200
X-Attestation-Response-Content-Type: text/event-stream
```

With a missing, duplicated, or invalid challenge, the stream passes through normally without attestation headers.

For internal diagnostics, retrieve the current process's public key:

```sh
curl http://127.0.0.1:8080/.well-known/http-attestation-key
```

The repository provides a Python reference client for end-to-end signature verification. It sends OpenAI Chat Completions requests through the normal customer-facing service URL and stores the nonce in a local SQLite replay cache after successful verification. Supply a public key whose workload attestation you have already verified:

```sh
OPENAI_API_KEY='API_KEY' \
ATTESTATION_PUBLIC_KEY='BASE64URL_PUBLIC_KEY' \
python3 docs/verify_response.py \
  --base-url 'https://SERVICE_HOST/v1' \
  --model APPROVED_MODEL \
  --expected-domain api.example.com \
  --expected-path /v1/chat/completions \
  --prompt hello
```

For the streaming request-upstream profile:

```sh
OPENAI_API_KEY='API_KEY' \
ATTESTATION_PUBLIC_KEY='BASE64URL_PUBLIC_KEY' \
python3 docs/verify_response.py \
  --stream \
  --challenge "$(openssl rand -hex 16)" \
  --base-url 'https://SERVICE_HOST/v1' \
  --model APPROVED_MODEL \
  --expected-domain api.example.com \
  --expected-path /v1/chat/completions \
  --prompt hello
```

This command verifies the request-upstream signature before reading the SSE body and explicitly reports `response_body=unverified`.

## How do users verify it?

The signing public key needs provenance too: otherwise, the gateway could simply generate its own key. TrustedAIProxy uses Google Confidential Space attestation to establish that provenance.

Users generate a one-time challenge and retrieve a proof bundle through the gateway's customer-facing endpoint:

```sh
NONCE=$(openssl rand -hex 16)
curl "https://SERVICE_HOST/.well-known/confidential-attestation?nonce=${NONCE}"
```

Users must verify:

1. The Google attestation token's signature, issuer, audience, and validity period;
2. That the token binds this challenge to the Ed25519 public key;
3. That the workload runs in the approved Confidential Space environment and image digest;
4. Each API response's content signature, timestamp, and nonce.

Google attestation is not required for every request. Users can verify the workload proof for a workload lifecycle or session, subject to proof expiry and local policy, then associate individual API responses using `X-Attestation-Proof-Ref`.

For the reference implementation and detailed verification policy, see the [customer verification guide (Chinese)](docs/customer-verification-guide.md) and [`docs/get_attested_public_key.py`](docs/get_attested_public_key.py).

## Multiple replicas and proof persistence

By default, the service does not connect to a database or retain historical proofs. PostgreSQL is recommended for production with multiple replicas: each running process registers its `proof_ref`, allowing any replica to route new proof requests to the owner that still holds the corresponding in-memory private key. The load balancer does not need session affinity.

When a process exits, its ephemeral private key cannot be recovered. PostgreSQL can retain historical proofs already issued for a particular customer challenge, but cannot sign a new challenge for a terminated process. Customers should retrieve and save the proof bundle promptly after receiving an API response with an unknown `proof_ref`.

For local configuration, set the DSN directly:

```sh
export TAP_PG_DSN='postgres://tap:PASSWORD@postgres.internal:5432/tap?sslmode=verify-full'
```

In production Confidential Space deployments, store the full DSN in Secret Manager and pass only a fixed-version resource name:

```sh
export TAP_PG_DSN_SECRET_VERSION='projects/PROJECT_ID/secrets/tap-pg-dsn/versions/1'
```

Do not use `latest` or put database passwords in images, Git, instance metadata, or command lines. The service automatically creates or migrates the `attestation_proofs`, `attestation_replicas`, and `attestation_requests` tables.

## Container image build and release

The GitHub Actions workflow is [`.github/workflows/ci.yml`](.github/workflows/ci.yml). When manually triggered on a branch, it runs tests and `go vet`, then publishes the image using `GITHUB_TOKEN` to:

```text
ghcr.io/tokenevol/trustedaiproxy
```

No GCP Artifact Registry credentials are required. Each release uses a `<branch>-<short-commit-hash>` tag and reports an immutable `image@sha256:...` reference in the workflow summary.

After the first release, set the GHCR package visibility to **Public** so Confidential Space can pull it anonymously. Public images must never contain production secrets.

To build and push locally:

```sh
docker build -t ghcr.io/OWNER/REPOSITORY:VERSION .
docker push ghcr.io/OWNER/REPOSITORY:VERSION
```

Deploy with an immutable digest, never `latest`:

```sh
cp deploy/confidential-space.example.sh deploy/confidential-space.sh
# Set IMAGE to ghcr.io/OWNER/REPOSITORY@sha256:...
bash deploy/confidential-space.sh
```

## Website and GitHub Pages

The product website in [`website/`](website/) is a static site with no build step. English is the default; the home, deployment, and user-guide pages each have a Chinese counterpart under [`website/zh/`](website/zh/). Use the header language switch to open the same page in the other language. Navigation stays within the selected language, and JavaScript preserves the current section when switching.

[`.github/workflows/pages.yml`](.github/workflows/pages.yml) automatically publishes changes to website files or the Pages workflow on `main`. You can also trigger it manually in GitHub Actions.

Before the first deployment, select **GitHub Actions** under **Settings → Pages → Build and deployment → Source**. The website directory is excluded by `.dockerignore`, so website files and content changes neither enter nor invalidate the Go image's Docker build layers.

## Production security requirements

- TrustedAIProxy decrypts HTTPS traffic sent by the gateway to upstream providers. Restrict the proxy port to the internal network; do not expose it to end users or the internet.
- End users must not install or trust the internal MITM CA. It serves only the internal gateway-to-proxy link.
- Use an offline Root CA to issue a dedicated Intermediate CA in production. The Root private key must never enter the runtime environment.
- Never include MITM CA private keys or other secrets in public images. The example CA in this repository is for development demonstrations only.
- Each process generates an ephemeral Ed25519 private key in memory. It is never loaded from files or Secret Manager, or written to disk; the key identity ends when the process exits. Disable core dumps, heap dumps, and uncontrolled debug endpoints in production.
- Before opening its listening port, TAP must obtain a startup workload attestation bound to its ephemeral public key. This is only a startup gate: customers still need their own challenge to obtain and verify a Google proof.
- Upstream TLS always uses normal system-root and hostname verification. Never enable `InsecureSkipVerify`.
- Well-formed non-streaming JSON requests matching a configured path and allowing complete text extraction can receive conversation text attestations. SSE requests with `stream: true` receive request-upstream attestations only when they carry exactly one valid challenge and all required request fields, response TLS, and response metadata are valid. Other unsupported requests pass through without local attestation headers.
- Timestamps only limit the replay window. Strict replay protection also requires verifiers to cache consumed nonces.

## License and support

Copyright 2026 TokenEvol Inc.

This project is released under the [MIT License](LICENSE). You may use, copy, modify, merge, publish, distribute, sublicense, and sell copies of the software under its terms, provided you retain the required copyright and permission notices.

For deployment guidance, integration, custom development, or other technical support, contact [business@tokenevol.com](mailto:business@tokenevol.com). The [LICENSE](LICENSE) contains the complete, binding terms.
