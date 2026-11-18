# Render Free ingress foundation — not a deployment

The account and opaque relay modules support an explicitly selected HTTP backend
behind Render's HTTPS/WSS edge. Their default remains a dedicated HTTPS server.
These modules do **not** themselves deploy Notify or expose a Mac.
The separate [hosted entrypoint and Free Blueprint](render-hosting.md) compose
the account service, account-bound authority, and opaque relay in one process.

**Never deploy `npm start` / `src/main.mjs`.** That is the local native-stdin LAN
companion, not an internet service. `render.yaml` targets only the separate
`src/hosted-main.mjs` entrypoint; adding a Blueprint does not launch it.

## Explicit module contract

`createAccountService` and `createRemoteRelay` accept the optional argument:

```js
managedIngress: 'render-free'
```

Only this exact opt-in permits a `node:http` server. Initialization requires:

- `RENDER` equals the string `true`.
- `RENDER_EXTERNAL_HOSTNAME` is one exact lowercase `*.onrender.com` hostname.
- The module's configured public origin (`origin` for accounts, `publicOrigin`
  for relay) equals that hostname's HTTPS origin, without a nondefault port.
- An unstarted dedicated server, with the existing listener constraints.

No environment variable alone turns the mode on. Unknown modes, direct HTTP
without the opt-in, mismatched hostnames, and TLS servers with the HTTP mode fail
initialization. Existing passkey UV, HTTPS issuer, Secure/HttpOnly/SameSite cookies,
account-only scope, grant checks and role-specific Origin checks are unchanged.

Accounts may be initialized first, then the relay attached to the same server
using the same mode and public origin. The relay does not replace an existing
request handler. If used alone with no request handler, it adds only the health
route and an empty 404 fallback. A caller that supplies its own request handler
must own and protect that handler; the relay only authorizes upgrades.

## Trust boundary and required operator checks

This mode relies on these **documented Render Free platform guarantees**, checked
against official documentation on 2026-11-17:

1. The HTTP backend port is not directly reachable from the public internet.
2. Render terminates HTTPS at its load balancer and forwards HTTP to the backend;
   external HTTP is redirected to HTTPS first.
3. **Free** web services cannot receive private-network traffic.

Sources: [web services](https://render.com/docs/web-services),
[Free limitations](https://render.com/docs/free#other-limitations),
[private networking](https://render.com/docs/private-network),
[default environment variables](https://render.com/docs/environment-variables).

Environment values are configuration guardrails, **not platform attestation or
proof of a Free plan**. Before any eventual deployment, verify it is still a Free
web service with those ingress guarantees. Do not enable this mode on a public
HTTP server, a paid Render service receiving private traffic, another platform,
or behind another proxy. No application header check can authenticate an
arbitrary direct connection to this backend. If these isolation guarantees change,
stop using the mode rather than widening the trust boundary.

The raw `Host` must appear once and exactly match the configured public hostname.
`X-Forwarded-Host` cannot repair a wrong Host. If present, `X-Forwarded-Proto`
must be exactly `https`, `X-Forwarded-Host` must match Host, and
`X-Forwarded-Port` must be `443`; lists and conflicting values fail closed.
RFC `Forwarded` is rejected. None of these headers proves TLS or selects an
issuer, host, browser origin, credential scope or client identity.

Forwarding headers may be absent, including on health probes. Absence is safe
only because the explicitly selected deployment supplies the isolation and TLS
guarantees above. This avoids inventing an undocumented header-sanitization
contract. Forwarded client IPs are not trusted: account rate limits still use the
immediate socket peer, so shared proxy peers can share limits. A rate-limit
rejection is not a reason to trust spoofable IP headers.

Clients must use HTTPS/WSS directly; do not transmit credentials over HTTP and
rely on a redirect. See [Render WebSockets](https://render.com/docs/websocket).

## Health and restart behavior

In managed mode, `GET /healthz` returns only `{"status":"ok"}`, `Cache-Control:
no-store`, and no cookies, identities, room counts, device information or secrets.
Host/forwarding checks still apply; Origin may be absent, otherwise it must match
the public origin. Wrong methods fail. This is process liveness, **not** proof that
a Mac is connected or authorized. Render uses the `onrender.com` hostname for
health probes when no custom domains are configured
([health checks](https://render.com/docs/health-checks)).

Account cookie sessions and in-flight ceremonies are memory-only and invalidated
on service restart even if public credential records survive. Relay rooms and
connections are not restored. Render Free disk is ephemeral and can disappear
on restart, redeploy or idle spin-down; it is not an account database or durable
authorization store. Losing enrollment must require fresh explicit enrollment,
never silently restore trust. This foundation adds no persistent disk, database
subscription, credential backup or automatic trust restoration.

## Remaining prerequisites — do not launch yet

- Verify the composed hosted entrypoint, verified account/session authority,
  one-time enrollment, endpoint identity, authenticated E2EE, and real Mac
  adapter together. Prove no session data reaches the opaque relay in plaintext.
- Review the separate Free Blueprint and hosted tests. It binds only Render's
  `PORT` / `0.0.0.0`, closes all services on shutdown, never starts the LAN
  companion, and configures verified TLS without paid resources or auto-deploys.
- Obtain and pin the actual service hostname; exercise real edge HTTP redirects,
  WSS upgrades, header behavior, restart invalidation and in-person enrollment
  before representing internet access as ready.
- Verify billing controls without purchasing anything. Free services share 750
  monthly instance hours; idle services spin down, startup may take a minute,
  and bandwidth/build overages can incur charges if a payment method exists.
  Without a payment method Render instead suspends relevant usage. A Free
  instance label alone is **not** a guarantee of zero workspace charges.

No deployment, account access, real user session, purchase or native change was
performed to add or test this foundation.
