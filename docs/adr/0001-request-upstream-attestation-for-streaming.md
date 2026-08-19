---
status: accepted
---

# Use a request-upstream attestation for streaming responses

Streaming responses use the public `llm-request-upstream-v1` profile: TAP signs normalized request fields, the customer challenge, and verified upstream response metadata before forwarding the body, while leaving the streamed response body explicitly unverified. We chose this over buffering the response, trailers, or per-event signatures so the first version preserves streaming latency and works through intermediaries that forward ordinary response headers; a future response-integrity profile must use a different profile name and cannot silently strengthen or reinterpret this one.
