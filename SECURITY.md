# Security

This project is an early monitoring tool, not a security boundary against a compromised root account.

Please report vulnerabilities privately through GitHub's **Report a vulnerability** feature on this repository. If private reporting is unavailable, open an issue asking for a private contact without exploit details or secrets. Never include production journal logs, IP addresses, database files or webhook tokens in public reports.

Use separate tokens for MCP and Rakazo, restrict network reachability, and check timestamp freshness. The server exposes only fixed read operations. Log fields and process names are untrusted input; receiving AI agents must treat them as data, not instructions.
