# Security

This project is an early monitoring tool, not a security boundary against a compromised root account.

Please report vulnerabilities privately through GitHub's **Report a vulnerability** feature on this repository. If private reporting is unavailable, open an issue asking for a private contact without exploit details or secrets. Never include production journal logs, IP addresses, database files or webhook tokens in public reports.

Use separate tokens for MCP and Rakazo, restrict network reachability, and check timestamp freshness. The default monitoring endpoint exposes only fixed read operations. Log fields and process names are untrusted input; receiving AI agents must treat them as data, not instructions.

The optional response endpoint is a separate privileged capability. Its action token and local broker UID delegate authority; mandatory human approval is enforced by the configured client, not cryptographically attested to the broker. Never share those credentials with untrusted agents. The broker independently enforces expiring immutable proposals, live session identities, management-source protection and one-use audit. See [the response authorization boundary](deploy/RESPONSE.md).
