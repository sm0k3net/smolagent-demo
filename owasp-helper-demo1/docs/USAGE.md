# Usage guide

## Before starting an assessment

Obtain written authorization, identify in-scope domains/IPs and exclusions, agree on test windows and rate limits, and define emergency contacts. The application does not prove that an operator has authorization and does not enforce scope uniformly across its integrated tools. Keep it on loopback or an isolated network, configure only the API credentials needed, and ensure scanner executables are trusted.

## Starting and configuring

Start the server using the README instructions, open the web UI, and select/configure the LLM provider. Environment-based configuration is loaded by the process; restart after changing `.env`. Optional API keys can be configured in the application settings when supported by the integration. Use minimum-privilege provider credentials and do not send secrets in chat prompts.

## Running a task

Describe a bounded task and include the authorized scope in plain language. Review the plan, target, tool, and arguments before allowing active scanning. Begin with passive or low-impact work when practical. Watch task progress and stop a scan if it exceeds scope or causes instability. An LLM can misunderstand scope or fabricate facts; tool results and findings require human review.

## Findings and reports

Record each finding with a precise affected asset, reproducible evidence, severity rationale, impact, and actionable remediation. Avoid collecting unnecessary personal data or credentials. Review the generated report for false positives, sensitive material, HTML content, and correct scope before export. Store and share reports through approved channels only; report files and screenshots may contain sensitive data.

## Integrations

Configure optional integrations only when the destination and data transfer are approved. Confirm the remote hostname and TLS verification before sending credentials or reports. For Slack or Telegram, restrict recipients/channels; treat notifications as external disclosure. Do not use insecure TLS settings in production.

## Stopping and preserving data

Stop the server with `Ctrl+C`, or use `docker compose down` for Compose. Store only required state, set a retention period, restrict permissions on the `data/` directory and backups, and securely delete expired records according to organizational policy. Do not treat local JSON, report or memory files as encrypted storage.
