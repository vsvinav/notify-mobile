# Single-process Render Free hosting

`render.yaml` describes **one Free web service**, not a launched deployment.
There is no paid disk, database, custom domain, background worker, or Rust build.
Generated browser WASM is committed; the build is `npm ci --ignore-scripts`.
Automatic deploys are disabled. Blueprint creation itself is a separate manual
deployment action; this change does not authorize or perform it.

**Do not deploy `npm start`.** It remains the native-stdin LAN companion.
The hosted entrypoint is `node src/hosted-main.mjs` (`npm run start:hosted`).
Read [the managed-ingress trust boundary](render-ingress.md) before using it.
Free-plan isolation, TLS termination, and HTTP redirects must still be verified
on the actual Render service; environment variables are not platform attestation.
Do not set fake Render variables to expose this listener on a public machine.

## Configuration and state

- Render supplies `PORT`, `RENDER=true`, and `RENDER_EXTERNAL_HOSTNAME`.
  The process listens once on `0.0.0.0:$PORT`.
- `NOTIFY_ORIGIN` is optional. When absent, the entrypoint derives
  `https://$RENDER_EXTERNAL_HOSTNAME`. If supplied, it must be that **exact**
  HTTPS origin: no path, trailing slash, credentials, query, custom domain,
  or nondefault port. The `onrender.com` hostname need not be bought.
- `NODE_TLS_REJECT_UNAUTHORIZED=1` is configured for build and runtime.
  The CLI also forces TLS verification on; no insecure TLS fallback exists.
- Account public credentials are stored privately in repository-local
  `.hosted-data/state.json` (directory `0700`, file `0600`). Do not commit or
  publish that runtime directory. The process is its sole writer.
- **Render Free disk is ephemeral. Restart, redeploy, or idle spin-down can
  lose every account record.** Even if the file happens to survive, account
  sessions, Mac bindings, pending pairing, routing grants, and relay rooms
  are invalidated on every process restart. Re-enroll explicitly; a local
  remembered device is not cloud authorization. This is not durable hosting.
- Free services sleep and can take time to wake. Workspace hour/bandwidth/build
  limits and possible overage charges still apply; confirm billing controls
  before any deployment. A Free instance is not a guarantee of zero charges.

## Exposed surface

The outer HTTP listener checks the actual Host and managed-ingress policy.
The account and relay services have dedicated **unstarted** inner servers;
the outer listener forwards the original HTTP request and WebSocket socket,
not synthetic headers. It owns connection, header, timeout, body, rate and
concurrency limits. Rate limits use the actual socket peer; proxy peers can
share limits. Forwarded client IPs never grant a separate allowance.
Authorization renewal has its own bounded 120-request/minute allowance per
socket peer, separate from the ordinary 120-request/minute allowance; the
stricter bootstrap and concurrency limits still apply.

`GET /healthz` returns only `{"status":"ok"}` with no authority or secrets.
`GET`/`HEAD /` serves `public/remote.html`. Static routing is an exact allowlist:
`remote-app.mjs`, `remote-transport.mjs`, `remote-identity.mjs`, `workspace.mjs`,
`styles.css`, `remote-crypto/channel.js`, and `remote-crypto/channel_bg.wasm`.
`workspace.mjs` is the shared read-only renderer, not the LAN app or its APIs.
Unknown paths, query variants, the LAN application, and service workers are
not exposed. Factories return 404 for missing assets; CLI startup requires all
listed assets to exist.

All control requests use `POST` with exact `Content-Type: application/json`,
at most 16 KiB, no content encoding, and no unexpected fields.

| Path | Fields / authorization |
| --- | --- |
| `/v1/account/register/options`, `/v1/account/register/verify` | Existing account contract, exact browser Origin |
| `/v1/account/login/options`, `/v1/account/login/verify` | Existing account contract, exact browser Origin |
| `/v1/account/session`, `/v1/account/logout` | `{}`, account cookie and exact browser Origin |
| `/v1/remote/mac/begin` | `macID`, `publicKey`; native, no Origin |
| `/v1/remote/mac/register` | `id`, `signature`; native, no Origin |
| `/v1/remote/pair` | `setupID`, `deviceID`, `publicKey`, `name`; fresh passkey session |
| `/v1/remote/mac/status` | `{}`; native Bearer credential |
| `/v1/remote/mac/decision` | `id`, `allow`; native Bearer credential |
| `/v1/remote/mac/revoke` | `deviceID`; native Bearer credential |
| `/v1/remote/grant/begin` | `role`, `deviceID`, optional `macID`; Mac credential only from Bearer, phone from account cookie |
| `/v1/remote/grant/finish` | `id`, `signature`; phone must still authorize as the account that began the grant |
| `/v1/remote/grant/renew` | `id`, `signature`; connected, unexpired grant, current same-account phone cookie or original native Mac Bearer credential |

Clients sign authority-issued challenges using the documented P-256 domain
separator and UTF-8 JSON challenge, with canonical base64url DER signatures. Phone grant completion
returns no credential in JSON: it sets `__Host-notify-relay`, Secure, HttpOnly,
SameSite=Strict, Path=/, lifetime at most 30 seconds. The native Mac receives its
short-lived credential in JSON. No credential belongs in a URL.
`/v1/relay` upgrades use the existing `notify-relay-v1` protocol: native Bearer
without Origin, or phone relay cookie with exact browser Origin. Browser fetch
metadata, when present, must agree with same-origin API/WebSocket access.

Grant completion also returns `renewal: { id, challenge }`. While connected,
each endpoint signs that challenge and renews every 10 seconds in one HTTPS
roundtrip. Success rotates the one-use challenge and extends authorization by
at most 30 seconds without replacing the socket, MLS group, epoch or pending
actions. It returns no new bearer credential or relay cookie. Initial relay
credentials remain single-use; pending enrollment retains its original deadline.
Expired, closed or revoked connections cannot renew. Failed or uncertain renewal
does not replay a challenge or user action; logout and revocation still close the
connection. This protocol does not depend on a particular hosting plan.

The phone waits up to 25 seconds for mutation acknowledgments, allowing the
native runtime's 20-second action window to finish; reads retain a 12-second
timeout. A missing acknowledgment means delivery may be uncertain, not that the
action was rejected or is safe to resend. Browser suspension, network loss and
free-host restarts can still interrupt a connection.

After a restart, distinguish account login from Mac/device enrollment. A rejected
Mac registration stops polling and hides its stale QR code; choose **Pair an
internet device** on the Mac to register again with the same signing identity.
If the phone still has a relationship that the service no longer recognizes,
explicitly forget that phone pairing, then scan a fresh Mac code and pair again.
Reload the phone page when reopening a setup link in an existing tab. Local
full-key approval is still required. Signing in again alone does not restore
lost enrollment. A different account remains blocked by the saved Mac owner;
never silently reset or transfer that trust.

Responses are no-store, deny framing, suppress referrers, and use a self-only
CSP with `wasm-unsafe-eval` solely for WebAssembly compilation and an explicit
same-host WSS connection source for browser compatibility. No third-party
scripts or service-worker session cache are used. The relay only forwards opaque
encrypted frames; account identity and routing metadata are not plaintext Notify
session contents. Local Mac approval and endpoint cryptographic verification
remain mandatory. Health success is not proof of pairing or session access.

## Verification and shutdown

`NODE_TLS_REJECT_UNAUTHORIZED=1 node --test test/hosted-main.test.mjs` uses
loopback HTTP with controlled Render environment values and repository-local
fixtures. It exercises the actual account service and authority, synthetic
passkey registration, cookie-bound phone grants, native grant headers, relay
upgrades, rejection boundaries, limits, and shutdown. It does not contact Render,
use a person's passkey, or deploy anything.

Exported interfaces:

```js
const app = await createHostedService({
  origin, managedIngress: 'render-free', store,
  publicDirectory, // optional; defaults to this repository's public directory
  reportError     // optional; receives only a sanitized generic Error
});
// app.server is unstarted; tests listen on loopback.
await app.close(); // idempotent; closes accounts, authority, relay and listener

const running = await main(); // validates process.env, storage/assets, listens
await running.close();
```

CLI `SIGINT`/`SIGTERM` closes all services. Before describing internet access as
ready, separately verify the actual edge HTTPS redirects, exact health Host,
WSS upgrades, sleep/restart invalidation, phone passkeys and in-person Mac
approval end to end. Loopback tests cannot prove those platform behaviors.
