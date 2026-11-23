# Connect your own dashboard

The Dashboard feature shows a small feed from a service running on your Mac.
The native Mac client reads it locally; the native Android client
uses your existing approved phone and encrypted Notify connection, including
over mobile data. Neither path exposes your service to the internet or provides
a general HTTP proxy.

Notify remains a general-purpose terminal companion. You do not need a dashboard,
ticket tracker, pipeline, or work-specific automation to use it. A custom provider
is yours to build and run; personal dashboards, organization-specific hooks,
internal URLs and credentials are not bundled with Notify.

**Availability:** use [Mac beta 8 / build 18](https://github.com/vsvinav/notify/releases/tag/v0.2.0-beta.8)
and [Android 0.3.6 / build 9](https://github.com/vsvinav/notify-android/releases/tag/v0.3.6-beta.1).
The Mac download bundles `src/panel-main.mjs` and the matching companion.
Older Mac beta 7 and Android 0.3.3 downloads do not include Dashboard.
Updating source alone does not install an app.
The LAN browser app does not have a Dashboard screen.

**Explicit opt-in:** **Settings > Custom dashboard** defaults Off, including
upgrades without a saved choice. On and Off persist independently of pairing,
Internet access and alerts. Turning it Off hides the Dashboard entry and stops
future dashboard requests; it cannot undo an already-sent action. Its pending
or uncertain result remains visible in Settings. Latest-build physical-phone,
real-provider action and Mac keyboard/window acceptance remain pending.

## What you build

The public integration is a small display-and-action interface, not a copy of
someone else's work setup:

1. Build a local service that reads only data you choose to expose. Return the
   bounded JSON feed below; do not serve raw files, credentials or arbitrary HTML.
2. Start read-only: return an empty `actions` array for each item. A read-only
   provider needs no agent hooks or command bridge.
3. If you want controls, add an adapter to a destination you explicitly authorize.
   Implement preview and one-use confirmation before enabling any action.
4. Configure data-source access on the Mac, outside source control. The phone
   needs neither your tracker credentials nor your local provider bearer.
5. Test with fictional items and a non-executing destination before connecting
   real work. Keep your provider/configuration private if its contents are private.

Notify's agent connection is separate from dashboard discovery. For supported
Copilot controls, install and explicitly enable the Notify extension using the
[Mac connection guide](https://github.com/vsvinav/notify/blob/main/docs/guide.md#existing-copilot-terminals);
an update may require an explicit reload in the original terminal. A provider
still needs its own supported dispatch adapter; installing Notify does not
automatically create one for an arbitrary dashboard.

Claude hooks expose supported permission/question events, not a general command
API for an already-running Claude terminal. Do not advertise a dashboard action
unless its destination actually supports it. Never scrape terminal screens,
send synthetic keystrokes or install broad approval hooks as a substitute.

The examples below are fictional. The optional form, stage and recent-activity
extensions are included in the matching client releases above.
Older 0.3.4 clients show ordinary cards and do not render these extensions.

## Use it on the Mac

1. Use Mac beta 8 or a matching source build with this companion bundled and Node.js
   22.18 or newer available.
2. Start a trusted local provider implementing the interface below.
3. Enable **Settings > Custom dashboard**, then choose **Dashboard** beside
   Sessions. No phone, pairing, Notify cloud account or Internet transport is
   required. Your provider may still need network access for its own data sources.
4. Select a provider action or form, review its exact preview, then explicitly
   choose **Send**. Cancel sends nothing and preserves the draft.

The Mac uses a bounded, short-lived local helper only when requesting data or
an action. A visible Dashboard refreshes every 15 seconds, or every 60 seconds
when a provider is missing. Hidden, covered or disabled dashboards do not poll.
Reopening requires a fresh read before actions can run. Drafts survive navigation
and offline states in memory, not app restarts.

Form shortcuts use the provider's title, such as **Add a todo**, and respect its
UTF-16 length limits below. There is no hardcoded ticket tracker, pipeline,
provider command or agent destination.

## Use it on Android

1. Keep your Mac awake, online and running Notify with Internet access enabled.
2. Start a trusted local provider implementing the interface below.
3. Open Notify on your paired Android phone and enable **Settings > Custom
   dashboard**. **Dashboard** appears in the drawer once the provider is
   discovered; discovery can take up to 60 seconds while the app is visible.
4. Choose a tab and an action. Read the exact preview, then choose **Send** or
   **Cancel**. Previewing alone never runs the action.

A visible dashboard refreshes every 15 seconds. Hidden available dashboards do
not poll. Missing providers are checked every 60 seconds only while the app is
visible and Custom dashboard is On. Background connection does not add dashboard
polling. Disconnecting disables
actions; last-reported content is not proof that the provider is still current.

Expired or changed previews need a fresh preview and explicit Send. Nothing is
automatically resent after a timeout. Check the destination before trying again:
it might already have accepted the instruction.

## Protect your data

Only expose data you are permitted to view on the phone. The provider must remove
credentials and sensitive content **before** returning its feed or preview.
Notify limits fields and sizes; that is not semantic secret redaction. An
allowed title, subtitle, link or prompt can still contain confidential information.

Payloads are encrypted between your Mac and approved phone across the relay.
They are readable at those endpoints and on the authenticated local loopback
connection. This does not protect a compromised Mac, phone, provider or installed
client. Links open in the phone's browser, outside the encrypted Notify channel;
do not include credentials in URLs. Generic approval alerts do not add dashboard
text to notifications.

## Provider discovery

Bind the provider to `127.0.0.1`, never all interfaces. Write a regular,
user-owned file at `~/.copilot/pipeline-ui/panel.json`, mode `0600`, under 4 KiB:

```json
{
  "version": 1,
  "port": 4317,
  "token": "<random per-start bearer>",
  "pid": 12345,
  "name": "My dashboard"
}
```

The bearer must contain 32-128 URL-safe letters, digits, underscores or hyphens.
Rotate it on each start and remove only your own discovery file on exit. Never
commit the file or print its contents. Symlinks and group/other access are refused.
`NOTIFY_PANEL_FILE` overrides the discovery path in the companion process for
testing; this is not a phone setting or a requirement to change terminal sessions.
The current default path is a legacy discovery location, not a requirement to
use a particular pipeline or put work configuration into Notify's repositories.

Require `Authorization: Bearer <token>` on both endpoints. Refuse non-loopback
clients and invalid authorization; do not rely on the file's secrecy alone.

## Feed: `GET /api/panel`

Return JSON with `version: 1` and this shape:

```json
{
  "version": 1,
  "title": "My dashboard",
  "updatedAt": "2026-01-01T12:00:00Z",
  "copilot": { "connected": true, "busy": false },
  "tabs": [{
    "id": "work",
    "label": "Work",
    "badge": 1,
    "sections": [{
      "title": "Needs attention",
      "items": [{
        "id": "example",
        "title": "Example task",
        "subtitle": "Ready for review",
        "tone": "info",
        "actions": [{ "id": "status:example", "label": "Status" }]
      }]
    }]
  }]
}
```

The legacy `copilot` field controls the connection/busy chip. A provider decides
which fixed actions it supports; Notify has no project-specific action logic.
An optional item `url` must be HTTPS and at most 300 characters.

| Field | Limit |
|---|---|
| Feed | 256 KiB; 6 tabs; 12 sections per tab; 60 items per section; 4 actions per item |
| Title / section title | 60 characters |
| Tab ID | `^[a-z][a-z0-9-]{0,31}$` |
| Tab / action label | 24 characters |
| Item ID / title / subtitle | 64 / 140 / 280 characters |
| Badge | Integer, 0-999 |
| Tone | `ok`, `warn`, `red`, `info`, `idle` |
| Action ID | `^[A-Za-z0-9:._-]{1,128}$` |
| Action style | `primary`, `danger`, `default` |

Unknown fields and invalid entries are discarded. Use unique IDs within each
collection. The companion uses a four-second timeout and refuses redirects.

### Optional form, stages and recent activity

These are additive version-1 fields. Older clients can ignore them and retain
ordinary cards. They contain presentation data, not scripts or action authority.
String limits below count UTF-16 code units.

A tab may supply one text form:

```json
{
  "form": {
    "version": 1,
    "actionId": "create-note",
    "title": "Add a todo",
    "submitLabel": "Research and draft",
    "placeholder": "Describe a feature",
    "minLength": 5,
    "maxLength": 300
  }
}
```

Use the existing action-ID syntax. Title and submit label limits are 60 and 24;
the optional placeholder limit is 140. Integer lengths must satisfy
`1 <= minLength <= maxLength <= 300`. An invalid form is omitted as a whole,
not converted into a blank-text action. The provider must enforce its own input
rules and confirmation binding.

A tab may also supply an ordered track:

```json
{
  "track": {
    "version": 1,
    "title": "Stages",
    "stages": [{
      "id": "plan",
      "label": "Plan",
      "hint": "Choose a route",
      "kind": "decision"
    }],
    "placements": [{ "itemId": "example", "stageId": "plan" }]
  }
}
```

Provide 1-24 stages with unique IDs using the tab-ID syntax, labels up to 40,
optional hints up to 80, and kind `normal`, `gate` or `decision`. Track title
is limited to 60. At most 60 placements may each reference one unique, surviving
item in the same tab and a known stage. Duplicate or dangling references discard
the whole track; ordinary sections remain available. Stage order never implies
that earlier stages completed. Items without placements remain ordinary cards.

Sections may set `"emphasis":"attention"` without relying on a particular
English title. Items may supply recent activity:

```json
{
  "log": {
    "entries": [{ "at": "12:14", "text": "Work was reported." }],
    "truncated": false
  }
}
```

Keep the provider's intended order, with at most eight entries. Each entry has
nonempty plain text up to 1,000 and an optional time label up to 40; C0 and DEL
control characters are not accepted. The companion drops invalid entries and sets
`truncated:true` when entries are invalid or exceed the limit. Set it yourself
when the provider has already shortened its data. This is recent activity, not
a full transcript, and contributes to the same 256 KiB feed limit.

## Actions: `POST /api/panel/action`

Accept JSON only and implement **both** steps:

1. Preview request: `{"actionId":"status:example","preview":true}`.
   Return `{"ok":true,"label":"Status","confirm":"Exact instruction text","confirmationToken":"<43-character base64url token>"}`.
2. Send request: `{"actionId":"status:example","preview":false,"confirmationToken":"<same token>"}`.
   Return `{"ok":true,"sent":true,"wasBusy":false}` only after the destination
   accepts the instruction.

For a text form, include the same exact `"text"` string in both requests.
It must be nonblank and at most 300 UTF-16 code units. C0 controls other than
tab/CR/LF, and DEL/C1 controls, are rejected before contacting the provider.
The provider decides which actions accept text; it must reject unexpected text
on other actions. Never trim or normalize the text between preview and Send.

Keep confirmation text and labels within 1,000 characters, response bodies below
64 KiB, and form requests within 2 KiB. Only `actionId`, `preview`,
`confirmationToken` and optional `text` are forwarded. The
companion timeout is ten seconds; Android waits up to 25 seconds for mutations.
Preview and send both use the authenticated mutation replay ledger.

**The provider owns confirmation enforcement.** Issue unpredictable, short-lived,
one-use tokens. Bind each to the exact action, full item revision, exact prompt,
raw form text (when present) and destination identity. Text edits require a fresh
preview even if they normalize to an identical instruction. Bound outstanding confirmations (the reference provider
uses 64 and a 120-second monotonic lifetime). Consume before dispatch. Reject
expired, reused or changed confirmations, including destination/provider restarts.
Send only to the captured destination, never fall back to another session.
Do not treat the phone's preview text or action ID as executable shell input.

Use explicit non-success responses for invalid/stale actions, unavailable
destinations and uncertain delivery. Do not retry mutations automatically.
In demo mode return `{"ok":true,"sent":false,"demo":true}` and do not supply a live
confirmation. Older providers without confirmation tokens cannot send actions.

**Acceptance is not completion.** A bridge's `queued:true` acknowledgment means
it accepted an instruction, not that the model consumed it or completed a task.
The phone's current "Sent to Copilot" message represents that acceptance.
The destination's own queue/steering behavior still applies.

## Before using real data

- Confirm that only loopback can reach the provider and both endpoints reject
  missing or incorrect authentication.
- Check the feed and preview for secrets yourself; field filtering does not
  recognize all confidential text.
- Verify that preview performs no action, Cancel sends nothing, and a confirmed
  action goes only to the exact captured destination.
- Reject expired, replayed and changed confirmations. Simulate a lost response
  and show an uncertain outcome rather than automatically retrying.
- Stop the provider or disconnect the phone and verify that stale content cannot
  authorize an action.
- Share only fictional example providers and sanitized screenshots. Do not
  publish discovery files, bearer tokens, private hooks or real work payloads.
