🇩🇪 **Deutsch** | 🇬🇧 [English](README.md)

---

# 🔐 Secure Boot Check

Dieses PowerShell-Skript prüft, ob Ihr Windows-PC von bekannten Problemen
mit UEFI-Zertifikaten betroffen ist — und ob Handlungsbedarf besteht.

---

## ⚠️ Worum geht es?

Microsoft muss im Jahr 2026 wichtige Sicherheitszertifikate ersetzen, die beim
Startvorgang von Windows-PCs verwendet werden. PCs, die noch kein Windows Update
mit den neuen Zertifikaten erhalten haben, können **nach einer Microsoft-Sperrung
nicht mehr starten** — und diese Sperrung kann jederzeit kommen.

> **Wichtig zu verstehen:** Das bloße Ablaufen eines Zertifikats führt nicht sofort
> zu einem Bootproblem. Erst wenn Microsoft alte Zertifikate aktiv sperrt (Eintrag
> in die sogenannte „dbx"-Verbotsliste), werden betroffene PCs nicht mehr starten.
> Der Zeitpunkt dieser Sperrung ist noch nicht bekannt. Handeln Sie deshalb jetzt
> vorsorglich.

Betroffen sind PCs mit:
- Windows 10 oder Windows 11
- aktiviertem **Secure Boot** (bei modernen PCs üblicherweise der Fall)

Dieses Skript zeigt Ihnen in wenigen Minuten den genauen Status Ihres PCs —
und erstellt automatisch eine Protokolldatei, die Sie an Ihren IT-Dienstleister senden können.

---

## ✅ Voraussetzungen

- **Betriebssystem:** Windows 10 oder Windows 11
- **Benutzerrechte:** Administrator-Rechte erforderlich
- **PowerShell:** Bereits vorinstalliert — nichts zu installieren

---

## 🚀 Schritt-für-Schritt-Anleitung

### Schritt 1 — Skript herunterladen

Klicken Sie oben rechts auf dieser Seite auf den grünen Button **`<> Code`**,
dann auf **`Download ZIP`**.

Entpacken Sie die ZIP-Datei in einen Ordner, z. B. `C:\Temp\SecureBootCheck`.

> Das Entpacken ist wichtig — das Skript funktioniert nicht direkt aus der ZIP-Datei heraus.

---

### Schritt 2 — PowerShell als Administrator öffnen

1. Drücken Sie **`Windows-Taste + X`**
2. Klicken Sie auf **„Windows PowerShell (Administrator)"**
   oder **„Terminal (Administrator)"**
3. Bestätigen Sie die Nachfrage mit **„Ja"**

> ⚠️ PowerShell **muss als Administrator** gestartet werden, sonst kann das Skript
> die UEFI-Firmware nicht auslesen.

---

### Schritt 3 — In den Ordner wechseln

```powershell
cd C:\Temp\SecureBootCheck
```

---

### Schritt 4 — Skript ausführen

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\SecureBoot-Check.ps1"
```

> **Warum `-ExecutionPolicy Bypass`?**
> Windows verhindert standardmäßig das Ausführen von Skripten aus dem Internet.
> Dieser Parameter erlaubt die einmalige Ausführung — ohne dauerhafte
> Systemänderungen.

Das Skript zeigt die Sicherheitsbewertung sofort an. Danach prüft es noch
Windows Update (max. ~60 Sekunden) und zeigt die vollständigen Details.

---

### Schritt 5 — Protokolldatei zusenden

Nach dem Durchlauf finden Sie im Ordner `C:\Temp\SecureBootCheck\log\` eine Datei
mit dem Namen Ihres PCs, z. B. `MEIN-PC.log`.

Senden Sie diese Datei per E-Mail an Ihren IT-Dienstleister.

> Die Datei enthält ausschließlich technische Systeminformationen zu Secure Boot
> und Windows Update — keine persönlichen Daten.

---

## 📊 Ergebnis verstehen

### ✅ Alles in Ordnung — `OK`

```
=================================================================
 MEIN-PC  ->  OK  (Win 24H2, Build 26100)
 Alle Zertifikate gueltig, 2023er CA-Kette vorhanden, keine Sperrungen
=================================================================
```

Ihr PC ist aktuell. Bitte senden Sie trotzdem die Protokolldatei zu — zur Bestätigung.

---

### ℹ️ Hinweis — `INFO`

```
=================================================================
 MEIN-PC  ->  INFO  (Win 24H2, Build 26100)
 INFO: 1 relevante Updates ausstehend
=================================================================
```

Ein kleiner Hinweis — meist ein ausstehendes Update.
Bitte **Windows Update** ausführen: Start → Einstellungen → Windows Update.
Danach Skript erneut starten und neue Protokolldatei zusenden.

---

### ⚠️ Handlungsbedarf — `WARNUNG`

```
=================================================================
 MEIN-PC  ->  WARNUNG  (Win 24H2, Build 26100)
 WARNUNG: Keine 2023er UEFI CA in Secure Boot db - Windows Update erforderlich
=================================================================
```

Ihr PC bootet heute noch problemlos. Ohne Update ist er aber **nicht vorbereitet**
für die bevorstehende Sperrung der alten Zertifikate durch Microsoft.

**Maßnahme:**
1. Windows Update ausführen und alle Updates installieren
2. PC neu starten
3. Skript erneut ausführen und neue Protokolldatei zusenden

Falls Windows Update die Zertifikate nicht einspielt (z. B. bei veraltetem
Windows), gibt das Skript konkrete Befehle zur manuellen Aktualisierung aus
(siehe Abschnitt „Manuelle Methode").

---

### 🔴 Sofortiger Handlungsbedarf — `KRITISCH`

```
=================================================================
 MEIN-PC  ->  KRITISCH  (Win 24H2, Build 26100)
 KRITISCH: Microsoft Windows Production PCA 2011 ist in dbx GESPERRT
=================================================================
```

Dies bedeutet eines von mehreren möglichen Problemen:

- Ein Zertifikat wurde bereits aktiv gesperrt → Windows könnte schon beim
  nächsten Start nicht mehr booten
- Ein Testzertifikat des Hardware-Herstellers steckt im System (PKfail) →
  Secure Boot bietet keinen Schutz
- Das Boot Manager-Zertifikat läuft in wenigen Tagen ab

**Sofortmaßnahme:** Windows Update ausführen und PC neu starten.
Falls das nicht hilft: IT-Dienstleister umgehend kontaktieren und Protokolldatei zusenden.

---

## 🔧 Manuelle Methode (wenn Windows Update nicht ausreicht)

Falls Windows Update die neuen Zertifikate nicht automatisch einspielt — etwa weil
Updates fehlschlugen oder die Windows-Version veraltet ist — gibt es eine von
Microsoft dokumentierte manuelle Methode (KB5025885).

Das Skript prüft automatisch, ob BitLocker auf Ihrem PC aktiv ist, und zeigt den
BitLocker-Hinweis nur dann an, wenn er relevant ist.

**Falls BitLocker aktiv ist — Schritt 1: Schlüssel sichern** (in PowerShell als Admin):

```powershell
Manage-bde -Protectors -Get C:
```

Notieren Sie den **48-stelligen Wiederherstellungsschlüssel** oder speichern Sie
die Ausgabe in eine Datei auf einem externen Laufwerk.

**Schritt 2 — Manuelle Zertifikatsaktualisierung** (in derselben PowerShell):

```powershell
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f
```

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
```

**Schritt 3 — PC neu starten**, dann sofort **nochmals neu starten** (zweiter
Neustart dient als Test ob Windows noch bootet).

**Schritt 4 — Skript erneut ausführen** und neue Protokolldatei zusenden.

> Das Skript gibt diese Befehle automatisch aus, wenn Handlungsbedarf erkannt wird.

---

## 🔍 Was prüft das Skript?

Das Skript liest ausschließlich **lesend** Systemdaten aus. Es verändert nichts.

| Prüfpunkt | Beschreibung |
|---|---|
| Secure Boot | Ist Secure Boot aktiviert? |
| Windows-Version | Erhält diese Version noch Update-Support? |
| UEFI-Zertifikate (db) | Welche Zertifikate sind in der Erlaubnisliste? |
| dbx-Sperrliste | Sind alte Zertifikate bereits aktiv gesperrt? (kritisch!) |
| PKfail | Steckt ein unsicheres Test-Zertifikat im System? |
| Boot Manager | Mit welchem Zertifikat ist der Windows-Starter signiert? |
| Windows Update | Letzte Installation, ausstehende Updates |

---

## ❓ Häufige Fragen

**Das Skript öffnet sich kurz und schließt sich sofort wieder.**
→ Bitte nicht per Doppelklick öffnen. Folgen Sie der Anleitung oben (Schritt 2–4).

**Fehlermeldung: „Die Ausführung von Skripts ist deaktiviert"**
→ Verwenden Sie exakt den Befehl aus Schritt 4 mit `-ExecutionPolicy Bypass`.

**Ich habe nur einen normalen Windows-Account, keinen Administrator.**
→ Rechtsklick auf das Start-Symbol → „Terminal (Administrator)" oder
„PowerShell (Administrator)". Bei Passwort-Abfrage: Ihr Windows-Passwort eingeben.

**Das Skript hängt kurz bei „Pruefe Windows Update".**
→ Das ist normal. Der Windows-Update-Dienst kann bis zu 60 Sekunden brauchen.
Das Skript wartet und gibt danach die vollständigen Ergebnisse aus.

**Wo finde ich die Protokolldatei?**
→ Im Unterordner `log\` des Ordners, in den Sie das Skript entpackt haben,
z. B. `C:\Temp\SecureBootCheck\log\MEIN-PC.log`.

**Was bedeutet `BootMgr_NewChain: False`?**
→ Der Windows-Starter verwendet noch die alte Zertifikatskette. Das ist nach dem
Windows Update vom Juni 2026 normal — Microsoft liefert die endgültige Umstellung
vor Oktober 2026 per weiterem Update aus.

**Was ist PKfail?**
→ Manche Hersteller haben versehentlich Testzertifikate in die Firmware eingebaut,
die nie für Endkunden bestimmt waren. Auf solchen Geräten bietet Secure Boot
keinen wirklichen Schutz. Das Skript erkennt dies automatisch.

**Muss ich das Skript regelmäßig ausführen?**
→ Einmal nach jedem größeren Windows-Update reicht. Spätestens im September 2026
nochmals ausführen und neue Protokolldatei zusenden.

---

## 📅 Hintergrund: Wichtige Termine 2026

| Datum | Ereignis |
|---|---|
| 27. Juni 2026 | Microsoft Corporation UEFI CA 2011 läuft formal ab |
| Oktober 2026 | Microsoft Windows Production PCA 2011 läuft formal ab |
| **Unbekannt** | **Microsoft sperrt alte Certs in dbx → PCs ohne Update booten nicht mehr** |

> Das formale Ablaufen eines Zertifikats führt allein noch **nicht** zum Bootproblem.
> Erst der aktive Eintrag in die dbx-Sperrliste durch Microsoft ist kritisch.
> Das Skript prüft dies und schlägt sofort Alarm, falls es bereits passiert ist.

---

## 📄 Lizenz

Dieses Skript wird ohne Gewähr zur Verfügung gestellt.
Die Ausführung erfolgt auf eigene Verantwortung.
Quellen: c't 13/2026 (Axel Vahldiek), Microsoft KB5025885.
