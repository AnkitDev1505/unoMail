# Security policy

## Supported versions

Security fixes are released for the latest minor version only. Upgrade to it to receive them
(see [Deployment and upgrades](docs/deployment.md#upgrading)).

| Version | Supported |
| --- | --- |
| 1.1.x | ✅ |
| < 1.1 | ❌ |

## Reporting a vulnerability

Please do **not** report security vulnerabilities through public issues, discussions or pull
requests.

Report them privately instead:

- through GitHub's [private vulnerability reporting](https://github.com/RikoDEV/unoMail/security/advisories/new)
  (preferred), or
- by e-mail to kontakt@riko.dev.

Please include as much of the following as you can:

- the affected component (SMTP, IMAP, web client, admin panel, API, …) and version;
- how the server is deployed (Docker image or binary, behind a proxy or not) and any
  relevant configuration;
- step-by-step instructions to reproduce the issue, ideally with a proof of concept against
  a local or test instance;
- the impact you expect: what an attacker could read, change or disrupt.

Only test against servers you own or are allowed to test. Do not access, modify or delete
other people's mail, and do not run denial-of-service tests against public servers.

## What to expect

- You will get an acknowledgement of your report, and follow-up questions if something is
  unclear.
- Once the issue is confirmed, a fix is prepared privately and released as a patch version.
  The advisory is published with the release, crediting you unless you prefer otherwise.
- If the report is declined, you will be told why.

## Hardening a server

The [threat model](docs/threat-model.md) describes what unoMail protects, its trust
boundaries, the risks it accepts, a production checklist and incident response steps. The
controls themselves are described in the [security model](docs/security-model.md).
