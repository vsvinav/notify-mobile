# Notify Mobile

**Your coding agent needs you. Answer from your phone.**

Approve a command, pick an option, or write your own answer without returning to your terminal. Notify Mobile connects to your Copilot and Claude Code sessions through [Notify on your Mac](https://github.com/vsvinav/notify).

[Quickstart](#quickstart) · [Install on iPhone](#install-on-iphone) · [Install on Android](#install-on-android) · [Using the app](#using-notify)

## Keep work moving

- **Approve or deny from your phone.** Review the request and send your decision back to the waiting session.
- **See what matters first.** Exact URLs, commands and paths, with the project and agent clearly identified.
- **Answer in your own words.** Choices, multi-select and custom answers match what the agent supports.
- **Get a nudge when you're away.** Optional generic lock-screen alerts let you know Notify needs you, without putting commands or project details in the notification.
- **Know your answer arrived.** Sending is not success: Notify waits for the Mac's agent acknowledgment.
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

## Quickstart

You'll need **Notify running on your Mac**, a phone on the **same Wi-Fi**, and a few minutes for first-time setup. There is no App Store download yet: this version installs as a web app from your Mac.

1. **Enable your phone connection.** In Notify on the Mac, open **Settings > Phone connections**, enable **Allow phone connections**, and click **Pair a phone**.
2. **Scan the QR code.** Follow the local setup page to download Notify's certificate. Compare its full SHA-256 fingerprint with the one shown on your Mac before trusting it.
3. **Install Notify on your phone.** Trust the verified certificate, open the Mac's HTTPS app address, and add it to your Home Screen. Platform steps are below.
4. **Pair from the installed app.** Open the new Notify icon, enter the Mac's eight-digit pairing code and give your phone a name. Check that the six-digit confirmation matches on both devices, then choose **Confirm phone** on the Mac.
5. **Turn on alerts.** Tap **Enable alerts** in the phone app and allow notifications. Use **Send test alert** on the Mac to try a generic notification.

**Need the Mac app first?** Follow [Notify's Mac installation quickstart](https://github.com/vsvinav/notify#install-on-macos). If it is already installed, run `open ~/Applications/Notify.app`. The current release is a local build, not a notarized installer. You do not run Node or build anything on your phone.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/mac-pairing-dark.png">
  <img src="docs/images/mac-pairing-light.png" alt="Notify's native Mac phone-connection panel showing paired status, confirmation, setup QR and certificate fingerprint" width="520">
</picture>

<sub>The Mac pairing panel with example data. Generate your own QR and codes in Settings; the ones in this screenshot will not connect a phone.</sub>

### Install on iPhone

1. **Install the verified certificate.** In iPhone Settings, open **General > VPN & Device Management** and install the downloaded Notify certificate profile.
2. **Enable website trust.** Open **General > About > Certificate Trust Settings** and enable trust for that verified certificate.
3. **Add the app.** Open the Mac's HTTPS app address in **Safari**, choose **Share > Add to Home Screen**, then open the new Notify icon.
4. **Pair and allow alerts.** Enter the Mac's pairing code from inside the installed app, confirm the matching code on the Mac, then tap **Enable alerts**.

Pair inside the installed app, not just in Safari: they can have separate storage. Background alerts require **iOS 16.4 or newer** and Home Screen installation.

### Install on Android

1. **Install the verified certificate.** Open **Settings > Security > Encryption & credentials > Install a CA certificate**. Names vary; some phones use **More security settings**.
2. **Add the app.** Open the Mac's HTTPS app address in **Chrome**, then choose **Install app** or **Add to Home screen**.
3. **Pair and allow alerts.** Open the installed Notify app, enter the Mac's pairing code, confirm the matching code on the Mac, then tap **Enable alerts**.

Keep the Mac awake and both devices on the same network during setup.

> **Only trust your own Mac's certificate.** Compare the downloaded certificate's fingerprint using a trusted certificate viewer, not a fingerprint displayed by the HTTP download page itself. If you cannot verify it, stop. Installing a certificate is a trust decision, not just dismissing a browser warning.

## Using Notify

When an alert arrives, open Notify to fetch the current request. Read the command, address or question, then approve, deny or answer. Custom input appears only when the agent allows it; permission scopes are the ones it actually offers.

Keep the app open until your reply is acknowledged. If the Mac is offline or the request has changed, Notify disables the action rather than queuing an approval for later.

**Connected** means the phone app recently reached your Mac. **Push enabled** means a notification subscription exists, not that every alert has been delivered. Focus and battery settings can delay alerts.

To disconnect a phone, choose **Revoke** beside it in the Mac's Phone connections settings. If you're finished with Notify, also remove its Home Screen app and certificate profile from your phone.

## A few things to know

- **Same network for now.** Your Mac must be awake. An alert can arrive elsewhere, but reading and answering requests requires reaching the Mac on its local network.
- **Private request details.** Requests and replies travel over local HTTPS. Generic background alerts use Apple, Google or Mozilla push services; there is no hosted Notify relay.
- **First-time setup is still hands-on.** Phone certificate trust, installation and real lock-screen delivery have not yet been verified on physical iPhone/Android devices. Try setup and a test alert on your own phone before relying on it.

---

[Get Notify for Mac](https://github.com/vsvinav/notify) · [Report an issue](https://github.com/vsvinav/notify-mobile/issues)
