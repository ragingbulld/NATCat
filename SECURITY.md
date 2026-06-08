# Security Policy

NATCat is a network utility and may expose operational details such as public endpoints, internal ports, and hook script output.

## Reporting

If you find a security issue, avoid posting secrets or exploit details in a public issue. Use a private security advisory if the repository supports it, or contact the maintainer out of band.

## Handling Secrets

- Do not commit `data.json`.
- Do not commit hook scripts containing cloud credentials.
- Rotate any credential that was accidentally pasted into a public issue, commit, screenshot, or log.
- Prefer environment variables or host-local secret files for notification scripts.

## Deployment

- Use a strong admin password.
- Put NATCat behind a trusted network boundary if possible.
- If listening on `0.0.0.0`, restrict access with firewall rules when the WebUI should not be LAN-visible.
- Review notification scripts carefully; they execute with the privileges of the NATCat process.
