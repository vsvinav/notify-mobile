# Single-process Render Free hosting

`render.yaml` describes **one Free web service**, not a launched deployment.
There is no paid disk, custom domain, background worker, or Rust build.
Optional durable storage uses a separate Notify-only Firebase **Spark** project
and its default Firestore database; no billing account or FCM setup is required.
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
- For durable hosting, set **both** `NOTIFY_FIREBASE_PROJECT_ID` (public project
  ID) and `NOTIFY_FIREBASE_CREDENTIALS_FILE` (absolute path to an explicitly
  provisioned Notify-only service-account JSON). Render must have its own
  explicitly uploaded secret file, for example `/etc/secrets/notify-firebase.json`.
  Never put JSON credentials in Git, the blueprint, browser code, or logs.
  Use only the new project's service account with Firestore data access, not
  an existing personal account. Keep browser/mobile Firestore rules deny-all:
  only this backend accesses the database using its project-scoped IAM identity.
- Credentials must be a regular, non-symlink file, at most 32 KiB, contain a
  matching project and service-account email, and an RSA private key of at
  least 2048 bits. Only Google's standard token endpoint/universe is accepted;
  the Firestore endpoint is pinned. No application-default credentials,
  `gcloud` login, or ambient Google credential file is used.
  Emulator redirection and ambient Google client-certificate/mTLS opt-ins are
  rejected. Partial/invalid configuration,
  permission errors, quota exhaustion or unavailable storage fail closed;
  configured Firebase never falls back to a local file.
- With neither Firebase variable set, development retains private account
  storage in `.hosted-data/state.json` (`0700` directory, `0600` file) and
  memory-only Mac/device registration. **That mode is not durable on Render
  Free:** disk loss can erase accounts and every process restart erases pairing.
  Do not publish or commit the runtime directory.
- Free services sleep and can take time to wake. Workspace hour/bandwidth/build
  limits and possible overage charges still apply; confirm billing controls
  before any deployment. A Free instance is not a guarantee of zero charges.

### What survives a durable restart

Firestore stores only account public passkeys and counters, the exact approved
owner, Mac and approved phone public keys, names/IDs, and a SHA-256 hash of the
existing Mac bearer credential. Revocation removes the approved phone record
durably before success is returned. It never stores conversations, commands,
client private keys, sessions/cookies, grants, challenges, setup links, sockets,
or MLS channel state. The backend's service-account key stays in its secret file,
not Firestore.

After a restart, sign in with the **same passkey/account** and reconnect. Existing
Mac credentials and pinned keys still work; no re-pairing or trust reset occurs.
The Mac waits for a freshly authenticated phone before creating new routing
grants. Old cookies, grants and pending setup flows are invalid. To add another
phone, explicitly choose **Pair an internet device** in the updated Mac helper:
it requests a fresh three-minute invitation using the retained Mac credential,
without rotating that credential or changing the owner. Old helper builds can
reconnect approved phones but cannot refresh a stale setup QR; update the helper
before inviting a new phone.

This is not recovery for records **already lost** by the old memory-only
service. There is no automatic migration, import from caller-supplied owner/key,
or silent re-enrollment. Establishing the initial durable pairing still requires
real passkey verification and explicit local full-key approval.

### Overlapping deploys, limits and free quotas

There is one logical active writer, not a horizontally scaled service. Three
fixed documents under `notifyState` hold the startup fence, accounts and trust.
A Firestore transaction takes a new fence at startup; record writes verify that
fence **and** their previously read revision in the committing transaction.
Every grant, renewal, relay admission and trust mutation checks the fence before
returning, unless a fenced write already did so. Account requests check freshness
too. Only non-authorizing Mac status polls reuse a successful fence check, for
at most 30 monotonic seconds (including the checking request's elapsed time).
Status still returns current local pending/device information, not a cached
response; that information never bypasses fresh authorization. A known storage
fault invalidates the sample immediately. A stale process cannot overwrite
newer trust or keep renewing a revoked phone; its next successful-operation
check fails closed. Already-issued leases on that old process can remain usable
for **at most their existing 30 seconds**, never an extended revocation window.

Keep `numInstances: 1`. During overlapping Render deploys, requests routed to the
old instance may fail until it drains; cookies are process-local and fresh
sign-in on the new instance is required. Do not run competing auto-restarting
instances against the same project: every startup takes over. Health reflects
known readiness without making additional database reads. Only these fenced service
writers may modify the documents; direct console edits, deletion/restoration of
the database, or old unfenced binaries are not a supported concurrent writer.
Never roll back to an unfenced backend against durable state.

Limits remain 256 accounts, 64 Macs and 8 approved phones per Mac. Each serialized
record is additionally capped at **900,000 UTF-8 bytes**, below Firestore's 1 MiB
document limit; unusually large passkeys may hit that byte cap before the count
limit. Oversize/corrupt/missing records and uncertain writes reject the operation
rather than resetting data. Corruption, credential/permission errors and
ownership/revision conflicts stay fail-closed for intervention; never delete
state to clear an error.

For one continuously connected Mac/phone, 10-second renewals cost approximately
**17,280 document reads/day and zero writes**. Status polling reuses these fresh
checks and adds no reads in the steady-state synthetic cadence test. Two active
phones (for example browser plus Android) cost **34,560 reads/day**. Conservatively,
allow another **2,880 status reads/day per service** when not covered by other
checks: totals **20,160 / 37,440**, before sign-ins, reconnects, retries and
deployments. Idle status-only service use is at most 2,880 reads/day, even if
heartbeats trigger extra polls. This is not an unrestricted multi-user quota
budget against Spark's usual 50,000 reads/day allowance. A trust mutation or
passkey counter update costs one document write and two transactional reads;
sign-in also has freshness reads. Startup reads three documents and writes one
fence (three writes on first initialization), plus two reads per service load.
There are no writes on polls or lease renewals, no collection scans/listeners,
and no payload history. Confirm current Firebase quotas in the private console;
quota exhaustion intentionally interrupts access rather than enabling billing.

### Transient storage recovery

Exhausted, recognized transport/deadline/quota errors suspend both account and
remote authorization and close active relay connections. A single service
coordinator retries after 1, 2, 4… seconds, capped at 60 seconds; quota errors wait
at least 60 seconds. Client Retry requests do not create additional recovery
work. `/healthz` returns 503 during suspension and returns 200 only after both
services have reloaded and validated their durable records.

Recovery drains in-flight storage operations, verifies the **same owned startup
generation**, and transactionally changes its recovery incarnation. That real
fence change prevents a delayed, unknown-outcome commit from writing past the
reload boundary. It does not acquire a successor's ownership. Old storage
handles are invalidated; fresh account/authority instances reload the committed
records, with no cookies, grants, challenges or sockets carried over. Sign in
again and reconnect; an uncertain mutation is never automatically replayed.
Even a lost recovery-transaction reply can resume only that process's own
pending incarnation.

A successful recovery costs seven document reads and one fence write, before
client sign-in/reconnection; retries may cost additional reads/writes if a commit
reply is lost. Unrecognized
errors, corruption and conflicting owners/revisions are not automatically
recovered. Live Firestore acceptance must still verify this behavior; the local
transaction fixture is not an emulator or proof of live-service semantics.

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

`GET /healthz` returns `{"status":"ok"}` only while ready, otherwise 503; it
contains no authority or secrets and performs no database reads.
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
| `/v1/remote/mac/invite` | `{}`; native Bearer credential; explicit fresh setup link, no trust change |
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

Mac sleep closes local channel authority and cancels the current status poll.
Wake heartbeats retry transient network/service failures without replacing
the saved identity or trusted account. The phone retries with a short backoff,
then every 30 seconds; returning to a visible page or coming online checks for
an expired channel immediately. **Reconnect** starts a fresh attempt.
Recovery creates new grants, an encrypted channel and action epoch, never
revives an expired lease or replays an uncertain action. Authorization rejection
stops automatic recovery: an expired account requires explicit sign-in, and a
lost Mac registration still requires explicit local re-enrollment. Durable
Firestore prevents normal process restarts from losing that registration;
reconnect logic alone cannot repair an already-lost account or registration.

The phone waits up to 25 seconds for mutation acknowledgments, allowing the
native runtime's 20-second action window to finish; reads retain a 12-second
timeout. A missing acknowledgment means delivery may be uncertain, not that the
action was rejected or is safe to resend. Browser suspension, network loss and
free-host restarts can still interrupt a connection.

Without durable storage, distinguish account login from Mac/device enrollment. A rejected
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
  origin, managedIngress: 'render-free', persistence,
  publicDirectory, // optional; defaults to this repository's public directory
  reportError     // optional; receives only a sanitized generic Error
});
// app.server is unstarted; tests listen on loopback.
await app.close(); // idempotent; closes accounts, authority, relay and listener

const running = await main(); // validates process.env, storage/assets, listens
await running.close();
```

`persistence = await createFirebaseStores({origin})` supplies both stores and
the recovery lifecycle from the explicit environment configuration. Its
`close()` releases the Firestore client; `main` owns that cleanup. For development
or isolated tests, `store` and `trustStore` may still be supplied separately,
without automatic recovery. Supplying storage to `createRemoteAuthority` makes its factory
and operations asynchronous (except `close`); its in-memory API stays compatible.

`NODE_TLS_REJECT_UNAUTHORIZED=1 node --test test/firestore-store.test.mjs test/account-service.test.mjs test/remote-authority.test.mjs test/hosted-main.test.mjs test/remote-companion.test.mjs`
uses synthetic credentials, real passkey/signature paths and an in-memory
transaction seam. It covers restart, revocation, stale writers, failures and
the public hosted routes, **not live Firestore acceptance**. No emulator or
Google authentication is involved.

CLI `SIGINT`/`SIGTERM` closes all services. Before describing internet access as
ready, separately verify the actual edge HTTPS redirects, exact health Host,
WSS upgrades, durable restart/revocation with freshly authenticated phone passkeys,
overlapping-deploy fencing, and in-person Mac
approval end to end. Loopback tests cannot prove those platform behaviors.
