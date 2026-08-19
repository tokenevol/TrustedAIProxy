# TrustedAIProxy

TrustedAIProxy produces workload-bound cryptographic evidence about AI gateway traffic observed across a verified upstream TLS connection.

## Language

**Conversation text attestation**:
An attestation that covers normalized request and response text messages for a completed non-streaming interaction.
_Avoid_: Full-body signature, response certificate

**Request-upstream attestation**:
An attestation emitted before a streaming body that covers normalized request fields and verified upstream response metadata, but not the response body.
_Avoid_: Streaming response attestation, stream signature

**Business request challenge**:
A unique customer-generated value bound to one request-upstream attestation so the customer can associate the evidence with its own invocation.
_Avoid_: Server nonce, proof challenge
