# Notify Mobile

**Your coding agent needs you. Answer from your phone.**

Approve a command, pick an option, or write your own answer without returning to your terminal. Notify Mobile connects to your Copilot and Claude Code sessions through [Notify on your Mac](https://github.com/vsvinav/notify).

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

<p align="center"><sub>Real app captures with fictional requests. Tap an image for a closer look.</sub></p>

## Quickstart

You'll need **Notify running on your Mac**, a phone on the **same Wi-Fi**, and a few minutes for first-time setup. There is no App Store download yet: this version installs as a web app from your Mac.

1. **Enable your phone connection.** In Notify on the Mac, open **Settings > Phone connections**, enable **Allow phone connections**, and click **Pair a phone**.
2. **Scan the QR code.** Follow the local setup page to download Notify's certificate. Compare its full SHA-256 fingerprint with the one shown on your Mac before trusting it.
3. **Install Notify on your phone.** Trust the verified certificate, open the Mac's HTTPS app address, and add it to your Home Screen. Platform steps are below.
4. **Pair from the installed app.** Open the new Notify icon, enter the Mac's eight-digit pairing code and give your phone a name. Check that the six-digit confirmation matches on both devices, then choose **Confirm phone** on the Mac.
5. **Turn on alerts.** Tap **Enable alerts** in the phone app and allow notifications. Use **Send test alert** on the Mac to try a generic notification.

**Need the Mac app first?** Follow [Notify's build and install quickstart](https://github.com/vsvinav/notify#try-it). The current release is a local build, not a notarized installer.

### Install on iPhone

Use **Safari**. Install the downloaded certificate profile in **Settings > General > VPN & Device Management**, then enable it under **General > About > Certificate Trust Settings**.

Open the HTTPS app address in Safari, choose **Share > Add to Home Screen**, and open Notify from its new icon. Pair **inside that installed app**, not just in Safari. Background alerts require **iOS 16.4 or newer** and Home Screen installation.

### Install on Android

Install the verified certificate through **Settings > Security > Encryption & credentials > Install a CA certificate**. Names vary by phone; some put this under **More security settings**.

Open the HTTPS app address in Chrome, choose **Install app** or **Add to Home screen**, then open the installed Notify app and pair it with your Mac.

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
