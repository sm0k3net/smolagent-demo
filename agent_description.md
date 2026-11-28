# OWASP Helper — Product Overview

OWASP Helper is an experimental, self-hosted AI-assisted security-assessment workspace. The application lives in `owasp-helper-demo1/` and uses FastAPI and `smolagents`. It is not an official OWASP project, a certified security product, or an authorization system.

## Implemented capabilities

- Browser-based chat, task tracking, notes, settings, and tools panels.
- OWASP Top 10 (2021) lookup, vulnerability classification, and test-scenario generation.
- Optional browser automation and a mix of passive and active security-tool wrappers.
- An offline HTTP security-header analyzer that evaluates a supplied captured-header JSON object and does not make network requests.
- Finding collection and validation workflows, scan-output storage, and HTML, Markdown, and PDF report generation.
- Optional integrations that depend on local software, credentials, network access, and external service availability.

The app includes a multi-agent workflow for reconnaissance, scanning, manual testing, quality review, reporting, and project/task coordination. Actual capabilities depend on the configured environment. A tool being present in the code or UI does not mean its executable or API credential is installed, configured, or available.

## Typical operator workflow

1. Establish written authorization, exact in-scope assets, exclusions, permitted techniques, test window, and data-handling requirements.
2. Configure the model provider and start the app in a dedicated, isolated environment.
3. Use the assistant and tools for proportionate assessment tasks; inspect the actual target and commands before running active scans.
4. Review scanner output as leads, verify findings with safe evidence, and redact sensitive data.
5. Review findings, limitations, remediation, and report content before sharing it.

A generated plan, agent statement, or phase flag is not evidence that a tool ran. Confirm execution and results from the available logs and output. A report may disclose unconfirmed findings or testing limitations; successful exploitation and screenshots are not universal prerequisites.

## Tooling and environment

The codebase includes wrappers for web/network reconnaissance, HTTP requests, browser automation, TLS checks, directory and parameter discovery, template-driven scanning, CVE reference lookups, selected application-testing utilities, reporting, and integrations such as VirusTotal, Shodan, SecurityTrails, Telegram, Slack, DefectDojo, and others. These integrations are optional; some tools execute external programs and require independent installation. Availability, output quality, and behavior vary by operating system, configuration, and provider.

See the [root README](README.md), [installation guide](owasp-helper-demo1/docs/INSTALL.md), [usage guide](owasp-helper-demo1/docs/USAGE.md), and [security and deployment guide](owasp-helper-demo1/docs/SECURITY.md) for maintained setup and operating instructions.

## Safety and limitations

Use only with explicit authorization. The application does not enforce target scope for every tool and can invoke tools that make network requests, potentially including sensitive or internal systems. It can also produce inaccurate or incomplete model output. Keep the app isolated, restrict network egress, verify target scope and commands, use test accounts and synthetic data, minimize collected data, and independently review all findings. Do not expose the service publicly without a separate security review and suitable authentication, HTTPS, access restrictions, and operational controls.

The automated test suite covers selected regressions and workflow behavior; it does not certify security, scanner availability, or integration correctness. See `owasp-helper-demo1/LICENSE` for license terms.
