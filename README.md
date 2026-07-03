# Wisp

**Anonymous, email-free accounts a real person can return to.**

A free, self-hostable, drop-in tool for any website where an account is a
*convenience*, not an *obligation*: forums, comments, reviews, polls,
"save my preferences," indie-game profiles.

No email. No password. Nothing to leak. The user gets a passkey; your site
gets an account it can trust probably came from a human and can recognize
when that person comes back.

## What it honestly does / doesn't do

| Claim | Honest status |
|-------|---------------|
| Anonymous account, no email/password | ✅ True — nothing to leak |
| You can return to it later | ✅ True for passkey and code accounts — ❌ not for guests |
| Filters out bots | ✅ True-ish — proof-of-work gate |
| Adds friction to casual duplicate signups | 🟡 A nudge, not a wall — the friction is the puzzle plus the passkey ceremony itself; nothing prevents a second signup |
| Guarantees one account per human | ❌ We never claim this |

Confidence labels returned to your backend:

- **bot-filtered** — passed proof-of-work. "Probably human."
- **same-passkey return** — presented a known passkey. "Same passkey — and
  wherever it syncs — as before." Usually the same person.
- **same-code return** — presented a valid account code. "Whoever holds the code."
  Weaker than a passkey: codes can be copied, shared, or phished.

## Three ways in

Every mode starts with the same proof-of-work bot filter. Operators pick
which modes to expose via `WISP_MODES` (all three by default):

| Mode | How the user returns | Trade-off |
|------|----------------------|-----------|
| **Passkey** | Passkey prompt (biometric/PIN) | Strongest: phishing-resistant; the private key never leaves your passkey manager. Needs a passkey-capable device. |
| **Code** | Pastes a server-generated code (`wisp-xxxx-…`) they saved anywhere — notes, paper | Works everywhere, nothing to install. Anyone holding the code holds the account. |
| **Guest** | They don't — the account lives only as long as the session cookie | Zero ceremony beyond the bot check. Ephemeral by design. |

The code is generated server-side (~120 bits of entropy — not guessable),
shown exactly once, and only its hash is stored. Code sign-in is also
PoW-gated, so brute-force guessing costs a puzzle per attempt.

## The recovery caveat (tell your users)

No email means nothing to send a reset link to. If a user loses their device
and their passkey wasn't synced (iCloud / Google Password Manager), the
account is gone. Code accounts survive device loss — as long as the code was
saved somewhere. Guest accounts are gone the moment the cookie is. Say it
plainly at sign-up:

> *This account lives on your device (passkey) or wherever you saved your
> code. Keep it backed up, or you'll start fresh.*

## Passkey app compatibility (the QR / phone flow)

When a user signs up on a desktop and scans the QR code with their phone,
**the phone — not the website — decides which app stores the passkey.**
WebAuthn gives the site no way to pick or even suggest a passkey app, so
this cannot be fixed or worked around in code.

Two things worth telling your users:

- **Microsoft Authenticator will refuse the passkey** with a message like
  *"doesn't support this kind of key."* By design it only stores passkeys
  for Microsoft Entra ID (work/school) accounts, never third-party sites.
- The fix is in the phone's settings: enable a general-purpose passkey
  manager — Apple Passwords / iCloud Keychain, Google Password Manager,
  1Password, Bitwarden, and similar all work.
  - iPhone / iPad: **Settings → General → AutoFill & Passwords**
  - Android: **Settings → Passwords & accounts** (name varies by vendor)

The server offers ES256 and RS256, the two algorithms every mainstream
passkey provider supports — a refusal like the above is an app policy,
not a compatibility gap on this side.

## Quick start

Requires [Node.js](https://nodejs.org) 20+.

```bash
npm install
npm run dev
```

Open http://localhost:8787 — the demo page lets you create an anonymous
account, sign out, and return to it.

## Drop-in buttons (optional)

The widget script registers ready-made custom elements, so a site can skip
the wiring entirely — busy states, inline error display, and the shown-once
code panel are handled for you:

```html
<script src="/wisp.js"></script>

<wisp-status></wisp-status>                    <!-- live session chip -->
<wisp-button action="signup"></wisp-button>    <!-- passkey account -->
<wisp-button action="signin"></wisp-button>    <!-- return with passkey -->
<wisp-button action="guest"></wisp-button>     <!-- guest session -->
<wisp-button action="signout"></wisp-button>
<wisp-code-signup></wisp-code-signup>          <!-- code account + reveal panel -->
<wisp-code-signin></wisp-code-signin>          <!-- paste-a-code form -->

<script>
  addEventListener("wisp-success", (e) => {
    // e.detail = { userId, confidence, code? } — code only on code sign-up
  });
  addEventListener("wisp-signout", () => { /* … */ });
  addEventListener("wisp-error", (e) => { /* e.detail.message */ });
</script>
```

Restyle them with CSS custom properties (`--wisp-accent`,
`--wisp-accent-text`, `--wisp-border`, `--wisp-error`, `--wisp-radius`) or
target any internal piece via `::part(button | input | panel | code | chip)`.
Override a button's text with the `label` attribute. Using the elements is
optional — the headless API below does the same things from your own UI.

A zero-dependency component gallery (every element in every state — busy,
error, the reveal panel, theming recipes) ships with the demo server at
http://localhost:8787/components.html.

## How it works

1. **Bot filter** — the server hands the browser a sealed, single-use
   challenge (HMAC-signed, expires in 5 minutes, can't be forged or replayed).
   The browser hashes it with a counter until it finds a hash with 15 leading
   zero bits — ~33,000 attempts, about a second of invisible work — and the
   server verifies the winning answer with two cheap operations. Cheap for a
   person, an added cost at bot scale.
2. **Anonymous account** — the user picks a mode: a passkey (WebAuthn
   discoverable credential), a copyable account code, or a guest session.
   The server stores a random user ID, a creation timestamp, and which mode
   created the account. For passkeys it also stores the passkey's credential
   ID, public key, and signature counter — that's how WebAuthn works; the
   credential ID is generated by the authenticator, not derived from the
   person. For codes it stores a hash of the code. For guests, just the ID
   row — which persists until deleted; "ephemeral" means nothing links back
   to the browser once the cookie is gone.
3. **Return flow** — next visit, the browser solves the same proof-of-work
   puzzle, then the passkey signs a challenge or the user pastes their code.
   Same key or code, same account. No identifier ever collected. (Guests
   don't return — that's the deal.)

**Honest limits of the bot filter:** a determined spammer with optimized
native code or a GPU solves the puzzle in milliseconds, not the ~1 second a
browser takes. The filter stops casual, off-the-shelf spam tools (which
won't implement a custom solver at all) and makes bulk abuse cost real
electricity — it is not a wall against a funded attacker, and nothing
identifier-free can be. Raising the difficulty wouldn't change that math:
each extra bit doubles the wait for real people in a browser while an
optimized solver barely notices. That's why the difficulty stays modest and
volume policing belongs to the rate-limiting proxy in front (see
"Deploying publicly").

## Repo layout

```
packages/server/   Hono server: PoW, WebAuthn ceremonies, sessions, storage
packages/widget/   Drop-in browser widget (bundles to apps/demo/public/wisp.js)
apps/demo/         Demo page served by the server
```

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `PORT` | `8787` | Server port |
| `WISP_RP_ID` | `localhost` | WebAuthn relying-party ID (your domain in prod) |
| `WISP_ORIGIN` | `http://localhost:8787` | Expected browser origin |
| `WISP_SECRET` | random per boot | HMAC secret for sessions + PoW challenges. **Set this in prod** or sessions die on restart |
| `WISP_DB` | `./wisp-data.json` | Where accounts are stored (JSON file for v0; SQLite adapter planned) |
| `WISP_MODES` | `code,guest,passkey` | Comma-separated sign-up modes to expose. Endpoints for a disabled mode return 404 |

## Deploying publicly

Wisp deliberately never sees IP addresses — which also means it cannot
rate-limit by itself. A public deployment **must** sit behind a
rate-limiting reverse proxy (Caddy, nginx, Cloudflare, or similar). Two
more things to know:

- The bundled JSON `FileStore` is demo-scale: it rewrites the whole file on
  every write. Fine for trying things out; a SQLite adapter is planned for
  real deployments.
- Your front proxy keeps its own access logs (IPs included). Those logs are
  outside Wisp's privacy promise — retention there is yours to manage.

## What's deliberately NOT here

- Device fingerprinting (privacy-hostile, consent-gated, decaying)
- Any "guaranteed unique human" claim (impossible without an identity anchor)
- Cross-site tracking or shared abuse intelligence (contradicts the promise)

Each of these was considered and deliberately rejected — the confidence
labels above are exactly what Wisp can honestly stand behind, and nothing more.

## License & name

The **code** is [MIT](./LICENSE) — use it, change it, fork it, ship it, even
commercially. The **name** "Wisp" is protected so it always points to
the version that keeps the promises above: forks that change the honesty
contract must rename. See [`TRADEMARK.md`](./TRADEMARK.md).
