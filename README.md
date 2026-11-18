# Notify Mobile

**Your coding agent needs you. Answer from your phone.**

Approve a command, pick an option, or write your own answer without returning to your terminal. Notify Mobile connects to your Copilot and Claude Code sessions through [Notify on your Mac](https://github.com/vsvinav/notify).

**A focused phone workspace:** review one request at a time, switch straight into chat, and keep setup out of your way.

[Quickstart](#quickstart) · [Install on iPhone](#install-on-iphone) · [Install on Android](#install-on-android) · [Using the app](#using-notify)

**Choose your connection:** the quickstart below is the same-Wi-Fi web app. Optional internet access uses a separate HTTPS service, passkey sign-in and explicit full-public-key approval on the Mac. Start with the [complete internet / Render / Firebase setup guide](https://github.com/vsvinav/notify/blob/feature/remote-native-identity/docs/remote-setup.md), or see the [hosted deployment contract](docs/render-hosting.md). Users joining an existing service do not need their own Firebase project. Native Android internet access is a separate versioned APK supplied by the operator; it is not the LAN web app.

## Keep work moving

- **Approve or deny from your phone.** Review the request and send your decision back to the waiting session.
- **See what matters first.** Exact URLs, commands and paths, with the project and agent clearly identified.
- **Answer in your own words.** Choices, multi-select and custom answers match what the agent supports.
- **Get a nudge when you're away.** Optional generic lock-screen alerts let you know Notify needs you, without putting commands or project details in the notification.
- **Know your answer arrived.** Sending is not success: Notify waits for the Mac's agent acknowledgment.
- **Follow your sessions.** Open Sessions for live status, main-agent and subagent chat, with tool and thinking updates kept separate.
- **See the real team.** The org chart groups idle helpers into one expandable tile and labels unreported parents instead of guessing.
- **Keep control on your Mac.** Confirm each phone before connecting, see its status, and revoke access whenever you want.
- **Make yourself at home.** Install to your Home Screen, with warm light and dark appearances that match Notify.

## A look inside

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/permission-dark.png">
    <img src="docs/images/permission-light.png" alt="Notify Mobile showing an exact preview URL, denial feedback and approval choices" width="280">
  </picture>
  <img src="docs/images/questions.png" alt="Notify Mobile showing multiple-choice answers and a custom reply field" width="280">
</p>

<p align="center"><sub>Actual phone web-app screens with example requests, captured at a phone-sized viewport. Not mockups or physical-device photos.</sub></p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/workspace-chat-dark.png">
    <img src="docs/images/workspace-chat-light.png" alt="Phone session chat with separate thinking updates and a fixed message composer" width="280">
  </picture>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/workspace-hierarchy-dark.png">
    <img src="docs/images/workspace-hierarchy-light.png" alt="Phone org chart showing the main agent, one working helper and a single expandable tile for nineteen idle helpers" width="280">
  </picture>
</p>

## Quickstart

You'll need **Notify running on your Mac**, a phone on the **same Wi-Fi**, and a few minutes for first-time setup. This LAN version installs as a web app from your Mac, not an App Store download.

1. **Enable your phone connection.** In Notify on the Mac, open **Settings > Phone connections**, enable **Allow phone connections**, and click **Pair a phone**.
2. **Scan the QR code.** Follow the local setup page to download Notify's certificate. Compare its full SHA-256 fingerprint with the one shown on your Mac before trusting it.
3. **Install Notify on your phone.** Trust the verified certificate, open the Mac's HTTPS app address, and add it to your Home Screen. Platform steps are below.
4. **Pair from the installed app.** Open the new Notify icon, enter the Mac's eight-digit pairing code and give your phone a name. Check that the six-digit confirmation matches on both devices, then choose **Confirm phone** on the Mac.
5. **Turn on alerts.** Open **Settings** in the phone app, tap **Enable alerts** and allow notifications. Use **Send test alert** on the Mac to try a generic notification.

**Need the Mac app first?** Choose the compatible build from [Mac releases](https://github.com/vsvinav/notify/releases) or follow the [Mac installation quickstart](https://github.com/vsvinav/notify#install-on-macos). If it is already installed, run `open ~/Applications/Notify.app`. The Mac download is not notarized; its included installation instructions explain Apple's manual approval. You do not run Node or build anything on your phone.

**Updating an existing phone installation:** update Notify on your Mac, then close and reopen the phone web app while connected to that Mac. The same HTTPS address retains pairing. If Sessions says the workspace is unavailable, check that the Mac app was updated; refreshing the phone alone cannot add Mac-side support.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/mac-pairing-dark.png">
  <img src="docs/images/mac-pairing-light.png" alt="Notify's native Mac phone-connection panel showing paired status, confirmation, setup QR and certificate fingerprint" width="520">
</picture>

<sub>The Mac pairing panel with example data. Generate your own QR and codes in Settings; the ones in this screenshot will not connect a phone.</sub>

### Install on iPhone

1. **Install the verified certificate.** In iPhone Settings, open **General > VPN & Device Management** and install the downloaded Notify certificate profile.
2. **Enable website trust.** Open **General > About > Certificate Trust Settings** and enable trust for that verified certificate.
3. **Add the app.** Open the Mac's HTTPS app address in **Safari**, choose **Share > Add to Home Screen**, then open the new Notify icon.
4. **Pair and allow alerts.** Enter the Mac's pairing code from inside the installed app, confirm the matching code on the Mac, then open **Settings > Enable alerts**.

Pair inside the installed app, not just in Safari: they can have separate storage. Background alerts require **iOS 16.4 or newer** and Home Screen installation.

### Install on Android

**These are LAN web-app instructions, not native APK installation.** Notify installs from Chrome as a Home Screen web app. Nothing needs to be built or run on your phone. The separate internet Android client requires its operator's versioned APK and matching service configuration.

1. **Start on the Mac.** Open Notify, then **Settings > Phone connections**. Turn on **Allow phone connections**, wait for the connection details, and click **Pair a phone**. Keep Notify running and the Mac awake.
2. **Allow Chrome to reach your Mac, then open setup.** Connect to the same regular Wi-Fi as the Mac. If Android asks for Chrome's **Nearby devices** or **Local network** permission, allow it. If previously denied, open **Android Settings > Apps > Chrome > Permissions** and allow that permission. Then scan Notify's QR with your camera, or type the complete **setup address** into Chrome. It starts with **`http://`** and normally ends in **`:8080/`**. Use the address currently shown on your Mac, not an address from a screenshot.
3. **Download and verify the certificate.** On the setup page, tap **Notify local CA certificate** to download `Notify-Local-CA.cer`. Before installing it, inspect the downloaded certificate with a trusted certificate viewer and compare its full **SHA-256 fingerprint** with Notify Settings on your Mac. A fingerprint shown by the HTTP setup page is not independent verification. If you cannot verify the certificate, stop.
4. **Install that verified certificate.** Open Android **Settings** and search for **Install a certificate** or **CA certificate**. A common path is **Security & privacy > More security settings > Encryption & credentials > Install a certificate > CA certificate**. Some Samsung phones use **Other security settings > Install from device storage**. Choose the downloaded `Notify-Local-CA.cer` and follow Android's confirmation/unlock steps. Menu names vary by Android version.
5. **Continue to the app and install it.** Return to the setup page in Chrome and tap **Continue to Notify**. The link shows your Mac's HTTPS app address, normally on port **8443**; installing a certificate does not move you there automatically. You can also find this address under **Connection address** in Notify on the Mac. The app must load without a certificate warning. In Chrome's **⋮** menu, choose **Add to Home screen > Install**, or **Install app**, then confirm. If Chrome offers only a shortcut, check that HTTPS trust is working before relying on background alerts.
6. **Open and pair Notify.** Open the new **Notify** icon from your Home Screen/app drawer. Enter the **eight-digit pairing code** shown on the Mac and name your phone. Compare the **six-digit confirmation code** on both screens, then click **Confirm phone** on the Mac. If the pairing code expired, click **Pair a phone** again.
7. **Enable notifications.** In the installed phone app, open **Settings**, tap **Enable alerts** and allow notifications. On the Mac, click **Send test alert**. Android's notification, Do Not Disturb and battery settings can affect delivery.

### If the phone says “Site can't be reached”

**Resolve this before installing certificates or pairing.** A certificate cannot fix an unreachable server.

| Address | Purpose |
| --- | --- |
| `http://YOUR-MAC-IP:8080/` | First-time setup and public certificate download |
| `https://YOUR-MAC-IP:8443/` | The actual app, after certificate trust |

Replace `YOUR-MAC-IP` with the address in Notify Settings. Keep the protocol and port together: HTTPS on port 8080, or HTTP on port 8443, will not work.

- Confirm **Allow phone connections** is on and no startup error is displayed on the Mac.
- **Android Chrome: check Nearby devices permission first.** In **Android Settings > Apps > Chrome > Permissions**, allow **Nearby devices** or **Local network**, if listed, so Chrome can reach your Mac. A denial can appear as **`ERR_TOO_MANY_RETRIES`**, including in Incognito, before any connection reaches Notify. This permission is separate from notifications; camera and location permission are not needed to type the setup address. [Android's local-network permission guidance](https://developer.android.com/privacy-and-security/local-network-permission).
- Keep both devices on the same Wi-Fi, not mobile data or an isolated guest network. Being on the same network name or subnet alone does not prove devices can reach each other.
- Check whether a phone VPN or the router's **client/AP isolation** blocks local connections. Ask the network administrator for managed networks; do not weaken managed security settings.
- If macOS asks about incoming connections for Notify's Node companion, local access must be allowed. Do not disable the entire firewall.
- Recheck the current address after changing networks. The Mac's IP address can change.

If the setup page opens on the Mac but not the phone, the listener is running; investigate the phone-to-Mac network path. If the HTTPS page instead shows a certificate warning, verify the certificate and trust setup rather than bypassing the warning.

> **Only trust your own Mac's certificate.** Compare the downloaded certificate's fingerprint using a trusted certificate viewer, not a fingerprint displayed by the HTTP download page itself. If you cannot verify it, stop. Installing a certificate is a trust decision, not just dismissing a browser warning.

## Using Notify

Use the bottom navigation to move between **Inbox**, **Sessions** and **Settings**. Alerts, phone information and installation help live in Settings, separate from requests and chat.

When an alert arrives, open **Inbox** to review one request at a time. Read the command, address or question, then approve, deny or answer. Scroll the request for longer details; decision buttons stay in the action area below. Use the request picker or **Next request** to switch without losing an unsent answer. **Add denial instructions** opens optional feedback. Custom input appears only when the agent allows it; permission scopes are the ones it actually offers.

Keep the app open until your reply is acknowledged. Completed requests disappear automatically and the next waiting request opens; there is no **Done** step. Requests answered elsewhere also disappear. Failed or unconfirmed replies stay visible while still pending. If the Mac is offline or the request has changed, Notify disables the action rather than queuing an approval for later.

### Sessions, chat and hierarchy

Open **Sessions**, choose a session, then select **Chat** or **Hierarchy**. Sessions without an active connection stay visible but cannot receive instructions. Chat uses the available screen space with its composer below the conversation. It shows recent reported messages, not a complete copy of terminal history; **Tools & thinking** starts collapsed and opens when needed. New replies do not pull you away from older messages: use **Jump to latest** to catch up. Copy buttons preserve message and code text.

Use **Chat with** or select an org-chart tile to choose the exact main agent or helper. **Send** uses that target only. Main-agent **Interrupt** and **Stop** ask for confirmation; stopping a helper can also stop its descendants. Controls are enabled only where the connection supports them. In particular, unsupported Claude connections remain read-only: Notify does not redirect a helper message to the main agent.

The org chart initially shows running helpers, with idle helpers grouped into **+N idle subagents**. Expand that tile to see them, then use **Hide idle** to collapse it. Ended helpers are in a separate inactive group. **Fit** shows the whole chart; **100%** restores readable-size tiles with scrolling. Parent relationships must be reported by the agent; missing or conflicting ancestry is shown separately.

Phone drafts stay separate for each target and do not overwrite Mac drafts. Switching views or using browser Back/Forward keeps them; they are held only in the open phone page, so reloading or losing pairing clears them. Sending instructions can use your existing model credits. **Queued** means accepted into the agent's queue, not finished; failures and uncertain delivery are shown explicitly, and instructions are never retried automatically.

The LAN browser's main-agent Send continues to queue. Updated native Mac and
Android clients can offer **Send** before Copilot's next model request, plus
explicit **Queue**, only with the matching updated helper and reloaded extension.
Older connections offer Queue instead. **Submitted** is acceptance, not
consumption; **Received** requires the runtime's matching message event. The
browser also displays these native-client receipts without changing how it sends.

**Android approval alerts:** Mac build 11 and the matching helper can send a
generic waiting-work nudge without an open encrypted phone conversation. Later
requests are coalesced across the service cooldown; failed/deferred nudges get a
bounded two-minute retry window while work remains waiting, including a brief
Mac sleep/wake. No conversation or command data is added to push. Android 0.3.1
also accepts foreground alerts and removes a redundant client cooldown.
An installed-build, real-internet locked-phone check confirmed delivery and
physical vibration; sound and other device/network configurations remain
unverified. Internet must be explicitly re-enabled after Notify launches, and
the Mac must be awake and online. These are native-helper/client changes, not a
requirement to redeploy the hosted service.

**Native Android source preview:** matching updated Android and Mac builds can
control the Mac-owned per-session Dangerous Auto-yes policy through this helper.
Enabling requires explicit high-risk confirmation; eligible waiting and future
tools may be approved, including destructive work, while questions remain manual.
Phone disconnect does not disable it. Android shows Mac-acknowledged state, a red
On indicator and direct Off; stale/unknown results are not replayed or shown as Off.
Off has reserved capacity through the authenticated command path. A definite
“not dispatched” rejection permits a fresh, explicit Off after refreshing;
an unknown outcome remains blocked for that policy epoch. Neither path retries automatically.
Old Mac/helper builds remain unsupported. This adds no automation engine to the
helper and no Dangerous Auto-yes UI to the LAN web app. It is not a published release.

**Native Android helper management (unpublished source preview):** matching updated
Mac/helper/Android builds expose **Add subagent**, ended-only **Remove from list**,
and confirmed **Stop idle >10 min** for one selected session. Types and optional
models come only from live native catalogs; an omitted model means **Configured
default**, never an invented catalog entry. Management uses its own live catalog
ticket, ordinary UUIDv4 command history and native audit/runtime acknowledgment.
Only `created`, `removed`, or the runtime’s existing `cleaned` status confirms the
corresponding action; cleanup detail includes actual counts and partial/uncertain
outcomes. No timeout is success or automatically retried. This does not consume
the reserved Dangerous Auto-yes Off lane, alter chat drafts, delete files, or
add a scheduler. Claude helper management remains unsupported.

**Native Android session settings (unpublished source preview):** matching updated
Mac/helper/Android builds expose Mac-synchronized session colors/reset and
same-group Move up/down, plus confirmed disconnected-cache removal and supported
saved-session resume. The helper advertises `sessionActionsControl`; each native
row supplies separate `sessionActions` admission metadata, its exact original
identity, current RGB/override, named palette, group, neighbors and resume status.
Old native/helper builds do not gain imaginary support. The existing control
dispatcher accepts only typed color/reset/move/remove/resume payloads, not client
shell commands, paths or arbitrary session orders.

Session actions retain the ordinary 256-UUID/eight-pending bounds, full-payload
deduplication, fresh authorization and revocation checks. The urgent Off ninth
slot is unchanged. Metadata changes do not invalidate runtime/management results.
An already-dispatched session action retains its original native ID, session,
action and metadata ticket through its exact result; snapshots can precede ACKs.
Timeout/channel loss stays unknown and is never replayed.
Definitive session-action admission failures return a correlated failed receipt
without native dispatch. Refresh and explicitly review a new command; the old UUID
remains consumed. After an actual launch owner is observed and later exits to
Saved, native `resumeAuthority` reports a scoped epoch and monotonic `retired`
high-water mark. Each reviewed attempt captures this metadata locally; a higher
mark in the same epoch can reopen a new review even after other phones' launches
or missed snapshots. It is not a client-supplied launch parameter. Color, order,
ordinary work updates and timeouts cannot advance it. The bounded native scope
follows the original agent/session/project through connected aliases, but resets
on identity removal/recreation, project replacement or Mac app replacement;
a different epoch cannot clear an old uncertain attempt.

Removal affects only a disconnected cached row: no owner is stopped, no CLI
history/project files are deleted, and discovery may restore it. Resume opens
the original supported saved CLI in iTerm2 on the Mac, with native history,
executable, live-owner and in-flight checks. Mac sign-in/Automation prompts may
need attention there. Saved CLI permissions can carry over; the action sends no
approvals and enables no session Auto-yes. `launched` confirms only terminal
launch, not an agent connection. Native metadata separately reports a detected
owner/connected session or the 30-second no-owner warning. Uncertain launch is
not a retry instruction. Android's System/Light/Dark setting is phone-local.

Updates arrive while Sessions is open; hidden pages stop watching. Details are loaded only for the selected session, and earlier messages or very large teams can be omitted with a visible notice. The **LAN web app** does not expose creation/removal/idle cleanup, these new session actions, or automation settings; use the Mac or the matching native Android source preview.

**Connected** means the phone app recently reached your Mac. **Push enabled** means a notification subscription exists, not that every alert has been delivered. Focus and battery settings can delay alerts.

To disconnect a phone, choose **Revoke** beside it in the Mac's Phone connections settings. If you're finished with Notify, also remove its Home Screen app and certificate profile from your phone.

## A few things to know

- **Same network for now.** Your Mac must be awake. An alert can arrive elsewhere, but reading and answering requests requires reaching the Mac on its local network.
- **Private request and conversation details.** Requests, session activity and instructions travel over local HTTPS and are not stored in the phone's offline cache. Generic background alerts use Apple, Google or Mozilla push services; there is no hosted Notify relay.
- **First-time setup is still hands-on.** Phone certificate trust, installation and real lock-screen delivery have not yet been verified on physical iPhone/Android devices. Try setup and a test alert on your own phone before relying on it.

---

[Get Notify for Mac](https://github.com/vsvinav/notify) · [Report an issue](https://github.com/vsvinav/notify-mobile/issues)

## Android background attention (hosted preview)

The hosted service can deliver generic FCM data messages to an explicitly opted-in,
locally approved Android device. Enable with `NOTIFY_FCM_ENABLED=true`, using the
existing explicit `NOTIFY_FIREBASE_PROJECT_ID` and
`NOTIFY_FIREBASE_CREDENTIALS_FILE`. No application-default credentials are used.
The matching Notify-only service account needs `cloudmessaging.messages.create`
(for example the Firebase Cloud Messaging API Admin role) in that project, and
the Firebase Cloud Messaging API must be enabled. Keep the credential file private;
never place it in source, logs or the Android APK. No new paid service is required.
When FCM is off/unconfigured, new token registration and attention fail closed;
signed token removal remains available.
Disable delivery using this flag while retaining the new server binary for rollback:
older binaries do not understand the added private trust-record fields and fail
closed rather than silently dropping routes. Do not edit production trust documents.

`POST /v1/remote/push/begin` uses the existing exact-origin account session and
`{macID, deviceID, token}` (`null` removes). Only the enrolled, Mac-approved
P-256 device key can finish `/push/finish` with `{id, signature}`. The existing
`Notify remote authorization v1\0` signature domain covers an exact `push`
challenge, origin, Mac/device IDs, raw token and nonce, expiring within 30 seconds.
Account proof is checked again at finish. Removing an already-revoked device is a
read-only owner-authorized absence confirmation, not a trust replacement.
Private routing is persisted inside the existing fenced trust record; public
Mac status and browser state contain no provider token.

The companion observes validated native `snapshot` messages. Only a newly waiting
request emits bearer-authenticated `/v1/remote/mac/attention` with a random
`eventID` and `issuedAt`. Requests/conversations never leave encrypted channels.
There is no Swift IPC extension and no status-poll-triggered FCM write or send.
The service persists a bounded two-minute event history and a 30-second per-Mac
send limit, then rechecks the current storage fence and device route immediately
before sending. Revocation/opt-out before that point prevents sending; already
issued provider messages may arrive for up to two minutes but carry no authority.
No provider-send retries, cached action buttons, or mutation replay are introduced.

FCM uses `google-auth-library` 11.3.4 (Apache-2.0, already present transitively)
with explicit service-account credentials. OAuth and FCM use Google's fixed
HTTPS endpoints; sends do not follow redirects or retry. Deployment acceptance
must separately verify Google authorization, public-service pairing/controller
paths, and physical Android delivery/channel settings. Local tests use synthetic
credentials and captured messages, never real FCM.
