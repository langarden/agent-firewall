# Security

## Reporting

Please do **not** open a public issue for security problems. Report privately by
opening a private advisory or contacting the maintainers directly.

## Design posture

- Fail-closed: any unexpected fault resolves to `deny`, never `allow`.
- No raw tool arguments are persisted. Only sha256 payload hashes enter the trail.
- Rules are declarative data (JSON), making policy reviewable and diffable.
- Verify your trail: `fw.verify_trail()` detects tampering of the hash chain.

## Known boundaries

- This library is a research prototype. It inspects MCP `tools/call` messages
  and returns verdicts; it is not a full network proxy (roadmap).
- Argument red lines use regex on stringified values; they are a defense layer,
  not a replacement for server-side validation.
- The allowlist default-deny posture is the safe default. Do not start with
  `allowed_tools=["*"]` unless you fully understand the blast radius.