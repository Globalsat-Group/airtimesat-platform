# Security policy

This is a private repository. It will hold the code that can write to Globalsat's Iridium service provider account, so we treat security reports as urgent.

## Report a vulnerability

- **Do not** open a public issue, a PR or a chat thread about it.
- Report it privately to: [FILL: name, email and phone of the security contact; today the CTO].
- If GitHub private vulnerability reporting is enabled, you can use **Security → Report a vulnerability** in this repository instead.
- Never paste a secret, credential, token or real personal data (IMEI, ICCID, MSISDN, names) into the report. Say where it is and what kind it is.

Include: what you found, where (file, commit, workflow run), how to reproduce it, and what you think the impact is.

## What happens next

- We acknowledge the report within [FILL: for example 2 business days].
- Support is best effort in business hours (re-plan §8.1). There is no 24x7 on-call.
- These are Sev1 and handled first: a suspected leak or compromise of the IWS or SFTP credential, wrong or unintended IWS writes, and any personal data exposure. The first action is to switch writes off or stop the gateway; then rotate the credential and reconcile. Ops keeps working through SPNet Pro.

## If you find a secret in this repository

1. Do not copy, test or use it.
2. Tell the security contact above at once.
3. The CTO rotates it. Removing it from git history does not make it safe; rotation does.

## Scope

In scope: this repository's code, Terraform, CI workflows and dependencies.

Out of scope: Iridium's systems (IWS, SITEST, SPNet Pro). Report issues there through Globalsat's CTO, who coordinates with Iridium.
