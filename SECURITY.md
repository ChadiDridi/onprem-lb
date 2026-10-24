# Security

Please report vulnerabilities privately via GitHub Security Advisories:
https://github.com/ChadiDridi/onprem-lb/security/advisories/new

Do not open public issues for security problems. Expect an answer within a week.

Notes for operators:
- The admin API can reconfigure all traffic. Keep it on loopback, or set `ONPREM_LB_ADMIN_TOKEN` (onprem-lb refuses to bind it to a non-loopback address without a token) and restrict access with firewall rules.
- TLS private keys referenced in the config must be readable by the LB user only.
