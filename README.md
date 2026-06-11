🇩🇪 [Deutsch](SecureBoot-Check_README_GitHub_DE.md) | 🇬🇧 **English**

---

# 🔐 Secure Boot Check

This PowerShell script checks whether your Windows PC is affected by known
UEFI certificate issues — and whether action is required.

---

## ⚠️ What is this about?

In 2026, Microsoft must replace important security certificates used during
the Windows boot process. PCs that have not received the new certificates via
Windows Update **may no longer start after Microsoft enforces a revocation** —
and that revocation can happen at any time.

> **Important to understand:** A certificate simply expiring does not immediately
> cause a boot failure. The real risk is when Microsoft actively blocks old
> certificates by adding them to the so-called "dbx" revocation list.
> The exact date of this revocation is unknown. Act now as a precaution.

Affected PCs:
- Windows 10 or Windows 11
- **Secure Boot** enabled (standard on modern PCs)

This script shows you the exact status of your PC within minutes — and
automatically creates a log file you can send to your IT service provider.

---

## ✅ Requirements

- **Operating system:** Windows 10 or Windows 11
- **User rights:** Administrator rights required
- **PowerShell:** Pre-installed — nothing to install

---

## 🚀 Step-by-Step Instructions

### Step 1 — Download the script

Click the green **`<> Code`** button at the top right of this page,
then click **`Download ZIP`**.

Extract the ZIP file to a folder, e.g. `C:\Temp\SecureBootCheck`.

> Extracting is important — the script cannot run directly from inside the ZIP file.

---

### Step 2 — Open PowerShell as Administrator

1. Press **`Windows key + X`**
2. Click **"Windows PowerShell (Administrator)"**
   or **"Terminal (Administrator)"**
3. Confirm the prompt with **"Yes"**

> ⚠️ PowerShell **must be run as Administrator**, otherwise the script cannot
> read the UEFI firmware data.

---

### Step 3 — Navigate to the folder

```powershell
cd C:\Temp\SecureBootCheck
```

---

### Step 4 — Run the script

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\SecureBoot-Check.ps1"
```

> **Why `-ExecutionPolicy Bypass`?**
> Windows blocks scripts downloaded from the internet by default.
> This parameter allows a one-time execution — without any permanent
> system changes.

The script shows the security assessment immediately. It then checks
Windows Update in the background (up to ~60 seconds) and displays the full details.

---

### Step 5 — Send the log file

After the run, you will find a file named after your PC in the
`C:\Temp\SecureBootCheck\log\` folder, e.g. `MY-PC.log`.

Please send this file by email to your IT service provider.

> The file contains only technical Secure Boot and Windows Update information —
> no personal data.

---

## 📊 Understanding the results

### ✅ All good — `OK`

```
=================================================================
 MY-PC  ->  OK  (Win 24H2, Build 26100)
 Alle Zertifikate gueltig, 2023er CA-Kette vorhanden, keine Sperrungen
=================================================================
```

Your PC is up to date. Please send the log file anyway — as confirmation.

---

### ℹ️ Notice — `INFO`

```
=================================================================
 MY-PC  ->  INFO  (Win 24H2, Build 26100)
 INFO: 1 relevante Updates ausstehend
=================================================================
```

A minor notice — usually a pending update.
Please run **Windows Update**: Start → Settings → Windows Update.
Then re-run the script and send the new log file.

---

### ⚠️ Action required — `WARNUNG`

```
=================================================================
 MY-PC  ->  WARNUNG  (Win 24H2, Build 26100)
 WARNUNG: Keine 2023er UEFI CA in Secure Boot db - Windows Update erforderlich
=================================================================
```

Your PC boots fine today. However, without the update it is **not prepared**
for the upcoming Microsoft certificate revocation.

**Action:**
1. Run Windows Update and install all updates
2. Restart the PC
3. Re-run the script and send the new log file

If Windows Update does not install the certificates (e.g. on an outdated
Windows version), the script will output specific commands for manual
remediation (see "Manual Method" below).

---

### 🔴 Immediate action required — `KRITISCH`

```
=================================================================
 MY-PC  ->  KRITISCH  (Win 24H2, Build 26100)
 KRITISCH: Microsoft Windows Production PCA 2011 ist in dbx GESPERRT
=================================================================
```

This indicates one or more serious problems:

- A certificate has already been actively revoked → Windows may fail to boot
  at the next cold start
- A test certificate from the hardware manufacturer is present (PKfail) →
  Secure Boot provides no protection
- The Boot Manager certificate expires within days

**Immediate action:** Run Windows Update and restart the PC.
If that does not help: contact your IT service provider immediately and send the log file.

---

## 🔧 Manual Method (when Windows Update is not sufficient)

If Windows Update does not automatically install the new certificates — for
example because updates failed or the Windows version is outdated — there is
a Microsoft-documented manual method (KB5025885).

The script automatically checks whether BitLocker is active on your PC and
only shows the BitLocker warning when it is relevant.

**If BitLocker is active — Step 1: Save the recovery key** (in PowerShell as Admin):

```powershell
Manage-bde -Protectors -Get C:
```

Note down the **48-digit recovery key** or save the output to a file on an
external drive.

**Step 2 — Manual certificate update** (in the same PowerShell):

```powershell
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
```

**Step 3 — Restart the PC**, then immediately **restart again** (the second
restart serves as a boot test).

**Step 4 — Re-run the script** and send the new log file.

> The script outputs these commands automatically when remediation is needed.

---

## 🔍 What does the script check?

The script reads system data in **read-only** mode. It does not change anything.

| Check | Description |
|---|---|
| Secure Boot | Is Secure Boot enabled? |
| Windows version | Does this version still receive security updates? |
| UEFI certificates (db) | Which certificates are in the allow list? |
| dbx revocation list | Are old certificates already actively blocked? (critical!) |
| PKfail | Is an unsafe test certificate present in the system? |
| Boot Manager | Which certificate is the Windows boot loader signed with? |
| Windows Update | Last installation, pending updates |

---

## ❓ Frequently asked questions

**The script window opens briefly and closes immediately.**
→ Do not double-click the script. Follow the instructions above (Steps 2–4).

**Error: "Running scripts is disabled on this system"**
→ Use exactly the command from Step 4 with `-ExecutionPolicy Bypass`.

**I only have a standard Windows account, not an Administrator.**
→ Right-click the Start button → "Terminal (Administrator)" or
"PowerShell (Administrator)". Enter your Windows password when prompted.

**The script pauses at "Pruefe Windows Update".**
→ This is normal. The Windows Update service can take up to 60 seconds.
The script waits and then shows the complete results.

**Where is the log file?**
→ In the `log\` subfolder of the folder where you extracted the script,
e.g. `C:\Temp\SecureBootCheck\log\MY-PC.log`.

**What does `BootMgr_NewChain: False` mean?**
→ The Windows boot loader is still using the old certificate chain. This is
normal after the June 2026 Windows Update — Microsoft will deliver the final
switch to the new chain before October 2026 via a further update.

**What is PKfail?**
→ Some manufacturers accidentally shipped hardware with test certificates in the
firmware that were never intended for end users. On such devices, Secure Boot
provides no real protection. The script detects this automatically.

**Do I need to run the script regularly?**
→ Once after each major Windows Update is sufficient. Run it again in
September 2026 at the latest to verify the final certificate transition
has completed, then send the new log file.

---

## 📅 Background: Key dates in 2026

| Date | Event |
|---|---|
| 27 June 2026 | Microsoft Corporation UEFI CA 2011 formally expires |
| October 2026 | Microsoft Windows Production PCA 2011 formally expires |
| **Unknown** | **Microsoft adds old certs to dbx → PCs without update will not boot** |

> A certificate formally expiring alone does **not** cause a boot failure.
> Only the active dbx revocation entry by Microsoft is critical.
> The script checks for this explicitly and raises an immediate `KRITISCH` alert
> if it has already occurred.

---

## 📄 License

This script is provided without warranty.
Use at your own risk.
Sources: c't 13/2026 (Axel Vahldiek), Microsoft KB5025885.

---

## 🤖 About this project

This script and the accompanying documentation were developed in collaboration
with **[Claude Cowork](https://claude.ai)** (Anthropic). The diagnostic approach,
binary EFI Signature List parser, risk assessment logic, and all written material