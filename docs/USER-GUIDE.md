# BioAudit — User Guide

BioAudit checks whether an Android app's biometric login is actually **secure**, not just
whether it works. You point it at an app you own or are allowed to test, and it reports
what an attacker could do, in plain language, with a fix for each problem.

This guide is for using the app. To change the code, see
[FRONTEND-GUIDE.md](FRONTEND-GUIDE.md) and [BACKEND-GUIDE.md](BACKEND-GUIDE.md).

---

## 1. What you need

| To do this | You need |
|---|---|
| Scan an APK file | Just BioAudit. No phone. |
| Test an app on a real phone | A physical Android phone with USB debugging on, plus `adb` |
| Anything at all | An account (free), and an internet connection |

**Why an account is required:** BioAudit does not keep a copy of your scans on your
computer. Every result is saved to your account on the server. That is what lets your
history follow you to a different computer, and what lets a team admin see that a scan
happened. With nobody signed in, there is nowhere for a result to go, so the app asks you
to sign in before it will scan anything.

There is nothing to install or configure for the server — the app already knows where to
find it.

### Getting `adb` (only for phone testing)

`adb` is Google's own tool for talking to an Android phone over USB. Download
[Android platform-tools](https://developer.android.com/tools/releases/platform-tools),
unzip it, and add that folder to your PATH. Check it worked:

```
adb devices
```

Your phone should appear in the list. If it says "unauthorized", unlock the phone and
accept the "Allow USB debugging?" prompt.

---

## 2. Starting the app

Double-click **BioAudit.exe**.

The first thing you see is a welcome screen with three tabs:

| Tab | Use it when |
|---|---|
| **Create account** | You are new. Email + password is all you need. |
| **Join with an invite** | An admin sent you an invitation token for their team. |
| **Sign in** | You already have an account. |

Tick **"Keep me signed in on this computer"** to skip this next time. It is off by
default on purpose: staying signed in writes a long-lived token to a file in your home
folder, which is worth knowing about rather than having happen quietly. Leave it off on a
shared or public computer.

Closing this screen without signing in closes the app, because there is nothing it can
do signed out.

### Setting up a team

Fill in the **Organisation** field when creating your account. That makes you the team's
admin and unlocks the Team tab, where you can invite colleagues. Leave it blank if you
are just testing your own apps — you can always join a team later from the Account menu.

---

## 3. Scanning an APK file (no phone needed)

Use this when you have the `.apk` file itself. It reads the app's settings and compiled
code without running it.

1. Go to the **Scan an APK** tab.
2. **Browse…** to your `.apk` file.
3. Click **Run static scan**.

While it runs you will see the current step ("Reading the app's settings", "Scanning the
app's code") and a **Cancel** button. Cancel stops the run after the step it is on
finishes — a step already reading the file cannot be interrupted part way, so give it a
moment.

When it finishes you get a list of findings, colour-coded badges showing how many of each
severity, and a PDF report written to `C:\Users\<you>\BioAudit\reports`.

### What it looks for

- The app is **debuggable** — anyone can attach a debugger and read its memory
- **`allowBackup` is on** — the app's private data can be copied off the phone with no root
- **Biometric result trusted without a bound key** — the app checks "did the fingerprint
  succeed?" and believes the answer, instead of requiring a key that only a real
  fingerprint can unlock. This is the big one, and it means the check can be bypassed.
- **Exported components with no permission guard** — screens or data providers other apps
  can reach directly

---

## 4. Testing an app on a real phone

This is the fuller test. It probes the running app on a real device, so it finds things
that reading the code cannot show.

1. Connect the phone by USB, with USB debugging on and the computer authorised.
2. Go to the **Assess a device** tab.
3. Click **Refresh** — your phone's serial should appear.
4. Click **Load apps** and pick the app, or type its package name
   (e.g. `com.example.myapp`).
5. Optionally point at the `.apk` too. **Recommended** — with it, the tool knows the full
   list of the app's entry points, which makes the headline check much more thorough.
6. **Tick the authorisation box.** The app will not proceed without it.
7. Click **Run full assessment**.

### The authorisation box is not a formality

Probing an app you do not own or have written permission to test can be a criminal
offence in many countries. The tick box is there so that confirmation is explicit and
recorded, and the server refuses to store a device assessment that does not carry it.
Only test apps you own or are explicitly authorised to test.

### What it adds over the APK scan

- **Opening the app's private screens directly** — the headline check. If a screen behind
  the login can be opened straight from outside, the biometric prompt is decorative.
- **Whether the app gives away answers to guesses** — the side-channel check. If the app
  answers a valid username differently from an invalid one, an attacker can work through
  a list and find real accounts, or brute-force a token, without ever logging in.
- **Reading the phone's log** for secrets the app leaked while running
- **Checking the backup setting** against the installed app rather than just the file

---

## 5. Reading your results

Findings are sorted most serious first and labelled:

| Severity | Meaning |
|---|---|
| **Critical** | Login can be fully bypassed |
| **High** | A secret or key is exposed, or the biometric check is decorative |
| **Medium** | A weakness that needs certain conditions to exploit |
| **Low** | Hardening gap — worth fixing, not urgent |
| **Info** | An observation, not a problem |

Findings from reading code are marked **"likely"** and dialled back one level, because
compiled code cannot be read with total certainty. Findings from probing the live app are
**"confirmed"** — the tool watched it happen.

### Getting a plain-language explanation

Click **Explain findings** after a run. The server writes an explanation and a specific
fix for each finding, aimed at a developer with no security background, naming the actual
Android setting or API to change. Explanations already written are reused, so clicking it
twice costs nothing.

### Reports

Every run writes a report automatically — a PDF if it can, HTML otherwise. **Open full
report** opens it. On a premium plan, **Save report from account** downloads the server's
copy, which is handy for sharing.

Where it lands depends on how you started BioAudit:

| Started from | Reports go to |
|---|---|
| The window (double-clicked exe) | `C:\Users\<you>\BioAudit\reports` |
| The command line | a `reports` folder next to wherever you ran the command |

The window uses your home folder because a double-clicked exe can start in a directory it
is not allowed to write to.

---

## 6. History

The **History** tab lists every run saved to your account, newest first — including runs
from other computers, since the account is the only place they live.

- Pick a run from the dropdown to see its full findings again
- **Reload** re-fetches from the server
- **Delete this run** / **Clear all history** remove them permanently from your account
- **Compare two runs…** (premium) shows what got fixed, what is new, and what is
  unchanged between two runs of the same app. Findings are matched by category and
  component, so a genuine fix shows as resolved even though each run generates fresh IDs.

**Free plan** keeps your 10 most recent runs and drops the oldest as you add more; the app
tells you when that happens. **Premium** keeps everything and adds run comparison and
server report export.

---

## 7. Teams

If you created your account with an organisation name, or joined one from an invite, the
**Team** tab is live. Otherwise it explains itself and stays empty.

As an admin you can:

| Sub-tab | What you can do |
|---|---|
| **Members** | See everyone, promote someone to admin, remove them, or delete their account |
| **Invitations** | Invite by email (creates a one-time token to send them), cancel pending invites |
| **Flagged runs** | Review scans you flagged as needing a look, then uphold or dismiss |
| **Activity log** | Every admin action, with who did it and when |

### What an admin can and cannot see

An admin sees **that** a member ran a scan, against which app, and **how many** problems
of each severity it found. An admin does **not** see the findings themselves — the actual
evidence pulled out of the member's app is never sent to them.

That line exists because the two needs are different. Oversight ("is my team testing
things they are authorised to test?") only needs to know a scan happened. Reading the
evidence would mean handing over potentially sensitive detail about someone else's app.
Every time an admin views a member's scan list, that read is written to the activity log.

---

## 8. Your account

Everything is under the **Account** menu.

- **Account details…** — who you are, your plan, your team
- **Account settings…** — change your display name, email address, or password, or delete
  your account
- **Join an organisation…** — redeem an invite token (only shown if you are not already
  in a team)
- **Upgrade to premium…** / **Cancel subscription…**
- **Sign out**

**Changing your password or email signs you out everywhere**, on purpose — if someone
else had your session, that ends it. Same for joining a team: your permissions change, so
the app signs you in again to pick them up.

**This build does not take payment.** "Upgrade to premium" flips your plan immediately so
the premium features can be demonstrated. Wiring in a real payment provider is outside
this project's scope.

---

## 9. Command line

Everything the window does, the terminal does too. Same exe.

```
BioAudit.exe login
BioAudit.exe scan-apk path\to\app.apk
BioAudit.exe assess --package com.example.app --apk path\to\app.apk --i-am-authorized
BioAudit.exe explain <scan-id>          # scan-apk and assess print the id
BioAudit.exe whoami
BioAudit.exe logout
```

`login` remembers you, so later commands just work. `--i-am-authorized` is the same
authorisation gate as the tick box, and `assess` refuses to run without it.

There is also `BioAudit.exe dashboard`, a browser view of your account's history (needs
`streamlit` installed and a `login` first).

---

## 10. When something goes wrong

**"Not signed in"** — run `login`, or sign in through the welcome screen. Nothing scans
without an account.

**"Not saved to your account", with a "Retry saving" button** — the findings are on
screen and the report is written, but the run is not stored anywhere yet, because there
is no local copy to fall back on. Check your connection and click **Retry saving** before
closing the run. On the command line, just run the same command again.

**"Too many attempts. Try again in a few minutes."** — the server limits sign-in attempts
to 20 per 15 minutes per computer, to stop password guessing. Wait it out.

**No device in the Assess tab** — check `adb devices` in a terminal. If it is empty:
confirm USB debugging is on, try a different cable or port, and unlock the phone to accept
the authorisation prompt. If it says "unauthorized", that prompt is what is missing.

**"Package ... is not installed"** — the package name is wrong. Use **Load apps** to pick
from the real list instead of typing it.

**A scan seems stuck** — look at the step text under the buttons. Reading a large APK
genuinely takes a while. **Cancel** stops it at the next step boundary.

**Explanations do nothing** — the AI layer needs a key configured on the server, not on
your computer. Check `/api/health` on the server; it reports `aiExplanations` as enabled
or disabled. Findings, severities, and fallback fixes all work regardless.

**The app crashed** — there is a log at `bioaudit-crash.log` in your home folder.

---

## 11. Ethics

BioAudit does no more to an app than is needed to *demonstrate* a finding, and every
runtime test is gated behind explicit authorisation. Test only what you own or are
explicitly permitted to test. Finding a real vulnerability in someone else's app means
reporting it to them, not using it.
