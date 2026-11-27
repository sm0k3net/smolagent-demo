# Security notes

## Trust model

OWASP Helper is a single-operator experimental assessment application. It has no user accounts, per-user permissions, or uniform target-scope policy. The API includes sensitive settings and scanner operations, so the default deployment must remain local or on a tightly controlled network. Agent-generated suggestions are untrusted input; review targets, commands, and outputs.

## Network access

The standalone server defaults to loopback. In Docker, the app listens on container interfaces while Compose publishes host ports on loopback by default. `LocalOrBasicAuthMiddleware` permits loopback clients if remote credentials are absent and requires HTTP Basic credentials for non-loopback requests when both `APP_USERNAME` and `APP_PASSWORD` are set. Health endpoints are public. Configure credentials before any remote access and terminate HTTPS at a trusted proxy. Basic authentication is not a substitute for TLS, multi-user authorization, rate limiting, or an audited identity provider. Do not trust arbitrary proxy client-IP headers.

Docker Compose host ports are loopback-published by default. Do not change this without a security review, firewall restrictions, HTTPS, strong credentials, and network isolation. A container is not a sandbox against a malicious target if it has broad network access.

## Sensitive data

API keys, task prompts, chat/task state, notes, screenshots, reports, tool output, and integration settings may be persisted locally or returned by app APIs. Protect the host and backups, avoid unnecessary data collection, use short retention, and rotate credentials that may have been disclosed. Do not commit `.env` or real tokens.

## Scanning and egress

The app wraps local scanner binaries and can make HTTP/browser requests. An operator must have explicit authorization for every target. Use network egress controls to prevent access to cloud metadata, internal management planes, and unrelated hosts. Enforce scope at the network boundary when possible. Observe rate limits and stop conditions.

## Deployment checklist

- Bind to loopback unless remote access is intentionally approved.
- Set strong `APP_USERNAME` and `APP_PASSWORD` for any non-loopback access and use HTTPS.
- Restrict inbound access, outbound egress, host permissions, and container resources.
- Keep TLS verification enabled; use trusted certificates for integrations.
- Do not mount the Docker socket or sensitive host directories.
- Use minimum-privilege API keys, rotate on suspected exposure, and never include credentials in logs or prompts.
- Restrict and encrypt backups when required; define a data retention and deletion process.
- Run tests and a security review before upgrades; review dependency, base image, scanner, and template changes.
- Confirm written authorization and scope before every assessment; manually verify generated findings.

## Vulnerability reporting

Do not publish exploit details, credentials, private target data, or customer reports in public issues. Contact the repository maintainer privately with a concise reproduction and affected commit. Rotate any credential included in the report immediately.
