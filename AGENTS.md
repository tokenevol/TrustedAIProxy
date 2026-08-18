# TrustedAIProxy repository guide

TrustedAIProxy is an internal HTTP/HTTPS MITM proxy for AI gateway services. It currently observes supported non-streaming JSON requests and responses, normalizes their text conversations, and adds Ed25519 attestation headers bound to the verified upstream TLS certificate and a Google Confidential Space workload proof. Streaming support is planned; until a stream is covered by an end-to-end verifiable profile, it is forwarded without an attestation.

## Read before changing behavior

- **Proxy, signing, protocol, deployment, or public behavior:** read `README.md`.
- **Customer verification or proof-bundle behavior:** also read `docs/customer-verification-guide.md` and the reference helpers under `docs/`.
- **Domain terminology or architectural decisions:** follow `docs/agents/domain.md`.

## Code map

- `cmd/tap/` wires configuration, CA and signing keys, Confidential Space attestation, optional PostgreSQL persistence, metadata endpoints, graceful shutdown, and the proxy server.
- `cmd/tap-verify/` is the local OpenAI-compatible end-to-end verification client; it is a demo, not the complete customer verifier.
- `internal/mitmproxy/` performs TLS interception, path-rule matching, bounded body inspection, protocol extraction, upstream TLS fingerprinting, and response signing.
- `internal/attestation/` owns the public signed-claims contract: semantic fields, RFC 8785/JCS canonicalization, Ed25519 headers, signing, and verification.
- `internal/gcpattestation/` requests challenge-bound tokens from the Confidential Space launcher socket. `internal/gcpsecret/` reads explicitly numbered Secret Manager versions.
- `internal/proofcache/` creates proof bundles and optionally persists and routes them across replicas through PostgreSQL.
- `signing-rules.json` maps supported URL paths to versioned extractors. Treat a new protocol or route as one change across the extractor registry, rules, normalization tests, README, and verification documentation.

## Security invariants

- Preserve normal hostname and certificate verification for outbound TLS. The proxy's own transport must bypass `HTTP_PROXY`/`HTTPS_PROXY` to avoid loops.
- Fail closed for attestation: sign only when the configured path, content type, bounded request and response bodies, extractor results, and verified upstream TLS chain are all valid. Forward other traffic unchanged and without locally generated attestation headers.
- Evolve streaming as an explicit, versioned protocol surface. Before signing SSE, AWS EventStream, or another streaming format, define its event model, ordering, terminal and error semantics, cancellation and partial-delivery behavior, resource bounds, signature transport, deterministic customer reconstruction, and verifier behavior. Streaming remains unsigned until all of these are implemented and tested end to end.
- Clear upstream-supplied `X-Attestation-*` headers before deciding whether to add this proxy's headers. Never allow stale or forged proof headers to pass through as local output.
- Treat `trusted-ai-proxy-v1`, `llm-conversation-text-v1`, field names and ordering, normalization rules, and header semantics as a public cryptographic protocol. A change is complete only when signer, verifier, cross-protocol tests, README, and customer verification guidance agree.
- Preserve message roles, ordering, message boundaries, and text exactly according to the selected extractor. Reject ambiguous or partially supported content instead of signing an incomplete representation.
- Keep request and response bodies, query strings, URL userinfo, credentials, DSNs, private keys, and attestation tokens out of logs. Validate all values copied into response headers.
- Treat repository CA files as development fixtures only. Production uses a stable provisioned MITM CA, workload-bound signing keys, fixed Secret Manager version names, and immutable image digests; production secrets never enter Git, images, command lines, or instance metadata.
- Preserve per-replica `proof_ref` ownership. PostgreSQL-backed routing must send a challenge to the replica that holds the corresponding private key and must respect stale and draining owners.

## Change and verification workflow

1. Locate the owning package above and read its adjacent tests before editing. For signing-profile changes, trace the complete path from extractor to canonical claims, headers, verifier, proof reference, and customer reconstruction.
2. Add or update focused tests for success and rejection paths. Security-sensitive parsing should demonstrate that malformed, duplicate, oversized, non-text, or ambiguous input remains unsigned as applicable. Streaming work must additionally cover chunk resegmentation, ordering changes, missing terminal events, upstream errors, cancellation, partial delivery, and signature verification.
3. Format changed Go files with `gofmt`.
4. Run `go test ./...`, `python3 -m unittest discover -s docs -p 'test_*.py'`, and `go vet ./...`. PostgreSQL integration coverage additionally requires `TAP_TEST_POSTGRES_DSN`; an unset variable intentionally skips that test.
5. For Docker, CI, or deployment changes, also build the image and verify that runtime files, nonroot/root requirements, launch-policy labels, secrets, and immutable deployment references remain consistent. The change is complete when every relevant check passes and public behavior is documented.

## Agent skills

### Issue tracker

Issues and specs are tracked in GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default mattpocock/skills triage label vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. See `docs/agents/domain.md`.
