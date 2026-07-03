# Security Policy

Wisp is an authentication project, so security reports matter more
than feature requests.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Instead send a
private message to **`u/legitslei`** on Reddit with:

- A description of the issue and where it lives in the code
- Steps to reproduce (a proof-of-concept is ideal)
- Impact as you understand it

You'll get an acknowledgment within a few days — best effort; this is a
solo-maintained project. Fixes will be published as soon as practical, with
credit to the reporter unless you prefer otherwise.

## Scope notes (read before reporting)

Some things look like vulnerabilities but are documented, deliberate limits:

- **Duplicate accounts are possible.** Incognito, a VPN, or a second device
  defeats duplicate-signup friction. This is by design — we never claim
  "one human, one account."
- **Lost passkey = lost account.** There is intentionally no recovery channel.
- **Proof-of-work slows bots; it does not stop a funded attacker.** Also
  documented.

Bypasses of things we *do* claim (session forgery, WebAuthn verification
flaws, PoW replay, challenge reuse) are absolutely in scope. Please report those.
