# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Email: andrewj.hannaford@gmail.com  
Subject: `[mcpshark security]`

I'll acknowledge within 48 hours and aim to ship a patch within 7 days for
critical findings. I'll credit you in the release notes unless you prefer otherwise.

## Scope

mcpshark is a local visibility tool. The primary threat surface is:

- The JSON-L output sink (could leak sensitive params if misconfigured)
- The secrets detection pipeline (trufflehog integration)
- The local SQLite state store

mcpshark does **not** make network connections, does not phone home, and does
not store params by default (reference_only redaction mode).
