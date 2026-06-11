# Secure Boot / UEFI Certificate Health Check

## Hintergrund

Die Zertifikate **Microsoft Corporation UEFI CA 2011** und **Microsoft Corporation KEK CA 2011**
laufen im **Sommer 2026** formal ab. Wichtig (Quelle: c't 13/2026, Axel Vahldiek):

- Das bloße **Ablaufen** eines Zertifikats in der `db` bricht den Boot **nicht sofort** —
  Timestamp-Zertifikate in bestehenden Bootloadern sichern diese weiterhin ab.
- Das **echte Risiko**: Microsoft trägt alte Zertifikate in die `dbx`-Sperrliste ein
  (Datum unbekannt, im Zusammenhang mit KB5025885). Dann booten PCs ohne neue 2023er
  Zertifikate nicht mehr.
- Weiteres Risiko: **PKfail** — Hardware mit AMI/Phoenix-Testzertifikat im Platform Key,
  das Secure Boot wirkungslos macht.

Microsoft liefert die neuen Zertifikate über Windows Update aus. Diese Skripte prüfen,
ob die Migration auf jedem PC abgeschlossen ist.

---

## Dateien

| Datei | Zweck |
|---|---|
| `SecureBoot-Check.ps1` | Diagnose eines einzelnen PCs (lokal oder remote) |
| `SecureBoot-Network.ps1` | Netzwerk-Scanner: führt Check auf mehreren PCs aus, erstellt CSV-Bericht |

---

## Voraussetzungen

- Windows 10 / Windows 11 mit UEFI (kein Legacy BIOS)
- PowerShell 5.1 oder höher
- **Administrator-Rechte** (für UEFI-Variablen und ESP-Zugriff zwingend erforderlich)
- Für Remote-Scan: **WinRM / PSRemoting** auf den Ziel-PCs aktiv

WinRM auf Ziel-PCs aktivieren (einmalig, als Admin):
```powershell
winrm quickconfig -force
```

---

## SecureBoot-Check.ps1

Prüft einen einzelnen PC auf:
- Secure Boot Status und Windows-Version (Updatefähigkeit)
- UEFI-Zertifikate in `db`, `KEK`, `PK` (mit Ablaufdaten)
- `dbx`-Sperrliste: Sind 2011er Zertifikate bereits aktiv gesperrt? (Boot JETZT gefährdet)
- PKfail: Testzertifikat im Platform Key? (Secure Boot wirkungslos)
- Boot Manager (`bootmgfw.efi`) — Signatur und CA-Kette
- Ausstehende Windows Updates (läuft parallel, max. 60s)
- Gesamtrisiko-Bewertung: `OK` / `INFO` / `WARNUNG` / `KRITISCH`
- Automatische Log-Datei: `./log/[Hostname].log`

### Ablauf

Das Skript gibt die Sicherheitsbewertung **sofort** aus (nach ~5–10s). Der Windows-Update-Check
läuft im Hintergrund parallel und wird danach mit den Detailergebnissen angezeigt (max. 60s Wartezeit,
in der Praxis meist kürzer da WU parallel lief).

### Lokal ausführen

```powershell
# Konsolenausgabe + automatische Log-Datei in ./log/
.\SecureBoot-Check.ps1

# Mit zusätzlichem CSV-Export
.\SecureBoot-Check.ps1 -OutputPath "C:\Reports\SecureBoot.csv"

# Nur Objekt zurückgeben, keine farbige Ausgabe (für Weiterverarbeitung)
.\SecureBoot-Check.ps1 -Quiet
```

### Remote ausführen (einzelner PC)

```powershell
Invoke-Command -ComputerName PC01 -FilePath .\SecureBoot-Check.ps1
```

### Log-Dateien

Jeder Lauf speichert automatisch `.\log\[Hostname].log` relativ zum Skript-Verzeichnis.
Bestehende Logs werden überschrieben (kein Ansammeln von Duplikaten).
Der Ordner `log\` wird automatisch angelegt.

### Ausgabe-Felder

| Feld | Bedeutung |
|---|---|
| `Win_Version` | Windows-Version (z.B. `24H2`, `25H2`) |
| `Win_Build` | Build-Nummer (≥ 26100 = Win 11 24H2, unterstützt) |
| `Win_UpdateSupported` | `True` = erhält kostenlose Sicherheitsupdates |
| `SecureBoot` | Secure Boot aktiv (true/false) |
| `PKfail` | `True` = Testzertifikat im Platform Key erkannt |
| `PKfail_Detail` | Name des problematischen Zertifikats |
| `db_CA2011_Present` / `db_CA2011_Expiry` | Altes UEFI CA 2011 in db vorhanden + Ablaufdatum |
| `db_WinUEFI2023` / `db_MSFTUEFI2023` | Neue 2023er Zertifikate vorhanden |
| `db_WinPCA2011_Present` / `db_WinPCA2011_Expiry` | Windows Production PCA 2011 in db |
| `dbx_CA2011_Revoked` | `True` = UEFI CA 2011 in Sperrliste → Boot-Ausfall möglich |
| `dbx_WinPCA2011_Revoked` | `True` = Windows PCA 2011 in Sperrliste → Windows bootet nicht mehr |
| `KEK_2011_Expiry` / `KEK_2023_Present` | KEK-Zertifikate alt/neu |
| `BootMgr_Issuer` | Womit der Boot Manager aktuell signiert ist |
| `BootMgr_CertExpiry` / `BootMgr_DaysLeft` | Ablaufdatum + verbleibende Tage |
| `BootMgr_NewChain` | `True` = Boot Manager nutzt bereits neue 2023er CA-Kette |
| `WU_LastInstalled` | Letztes installiertes Windows Update |
| `WU_PendingCount` | Anzahl ausstehender relevanter Updates (Defender/MRT gefiltert) |
| `WU_PendingUpdates` | Titel der ausstehenden Updates |
| `RiskLevel` | Gesamtbewertung |
| `RiskDetail` | Detaillierte Begründung |
| `ManualFix` | KB5025885-Befehle, wenn Zertifikate fehlen und Windows Update nicht ausgereicht hat |

### Risikostufen

| Stufe | Auslöser | Maßnahme |
|---|---|---|
| `OK` | Alle Checks bestanden, 2023er CA-Kette vorhanden | Keiner |
| `INFO` | Secure Boot deaktiviert oder ausstehende Updates | Prüfen / Windows Update |
| `WARNUNG` | Keine 2023er Certs in db/KEK, Boot Manager auf alter Kette (< 90 Tage), Win-Version ohne Support | Windows Update |
| `KRITISCH` | dbx-Sperrung aktiv, PKfail erkannt, Boot Manager Cert < 14 Tage / abgelaufen | Sofort Windows Update + Neustart |
| `NICHT ERREICHBAR` | PC hat nicht geantwortet (nur Netzwerk-Scan) | WinRM prüfen |

**Wichtig:** `dbx_WinPCA2011_Revoked = True` bedeutet, dass Windows beim nächsten
Kaltstart möglicherweise nicht mehr bootet — sofortiger Handlungsbedarf.

### ManualFix (KB5025885)

Wird nur angezeigt wenn 2023er Zertifikate in `db` oder `KEK` fehlen **und** die
Windows-Version Sicherheitsupdates unterstützt. Nicht ausgelöst durch `BootMgr_NewChain = False`
(der Boot Manager wird durch ein separates Microsoft-Update aktualisiert, nicht durch KB5025885).

Das Skript prüft vorher automatisch ob BitLocker auf `C:` aktiv ist. Nur dann wird die
Sicherung des Wiederherstellungsschlüssels als erster Schritt eingeblendet.

---

## SecureBoot-Network.ps1

Führt `SecureBoot-Check.ps1` auf einer Liste von PCs parallel aus (via PSRemoting)
und erstellt einen CSV-Gesamtbericht.

### Parameter

| Parameter | Pflicht | Beschreibung |
|---|---|---|
| `-ComputerList` | Ja | Array `@("PC01","PC02")` oder Pfad zu TXT-Datei (ein Name pro Zeile) |
| `-CheckScript` | Ja | Pfad zu `SecureBoot-Check.ps1` |
| `-OutputCsv` | Nein | Pfad für CSV-Bericht (Standard: `SecureBoot-Report_DATUM.csv`) |
| `-Credential` | Nein | PSCredential für Remote-Verbindung (Standard: aktueller Benutzer) |
| `-MaxParallel` | Nein | Parallele Jobs (Standard: 10) |

### Beispiele

```powershell
# PC-Liste aus Datei, Ergebnis auf Desktop
.\SecureBoot-Network.ps1 `
    -ComputerList "C:\IT\PCs.txt" `
    -CheckScript  ".\SecureBoot-Check.ps1" `
    -OutputCsv    "$env:USERPROFILE\Desktop\SecureBoot-Report.csv"

# Explizite PC-Liste mit alternativen Credentials
.\SecureBoot-Network.ps1 `
    -ComputerList @("GSTCL70","GSTCL71","GSTCL72") `
    -CheckScript  ".\SecureBoot-Check.ps1" `
    -OutputCsv    ".\Report.csv" `
    -Credential   (Get-Credential "GUSTINI\Administrator")

# Nur kritische PCs aus Report filtern
Import-Csv ".\Report.csv" | Where-Object { $_.RiskLevel -eq "KRITISCH" } | Select-Object ComputerName, RiskDetail
```

### Format der PC-Liste (TXT)

```
GSTCL70
GSTCL71
GSTCL72
GSTSERVER01
```

---

## Enginsight-Einsatz

Falls PSRemoting nicht verfügbar ist, kann `SecureBoot-Check.ps1` über Enginsight
als Remote-Skript deployed werden:

1. Skript in Enginsight hochladen
2. Auf gewünschten Assets ausführen (als lokales Admin-Konto)
3. Ausgabe (stdout) enthält Risikostufe und Details im Klartext
4. Log-Dateien landen in `./log/` relativ zum Skript-Pfad auf dem jeweiligen PC

Für strukturierte Auswertung empfiehlt sich die `-Quiet`-Flag kombiniert mit
`-OutputPath` auf einem UNC-Pfad (sofern das Konto Schreibrechte hat).

---

## Typischer Ablauf Netzwerk-Prüfung

```
1. .\SecureBoot-Network.ps1 ausführen
2. CSV öffnen, nach RiskLevel sortieren
3. KRITISCHE PCs → sofort Windows Update + Neustart; bei dbx-Sperrung: IT-Eingriff
4. WARNUNG → Windows Update sicherstellen, vor Oktober erledigt
5. Scan wiederholen zur Verifikation
```

---

## Bekannte Deadlines (Stand Juni 2026)

| Datum | Ereignis |
|---|---|
| 24.06.2026 | Microsoft Corporation KEK CA 2011 läuft formal ab |
| 27.06.2026 | Microsoft Corporation UEFI CA 2011 (db) läuft formal ab |
| ~17.10.2026 | Boot Manager Zertifikat (aktuell ausgeliefert) läuft ab |
| 19.10.2026 | Microsoft Windows Production PCA 2011 (db) läuft formal ab |
| **Unbekannt** | **Microsoft trägt alte Certs in dbx ein → PCs ohne Update booten nicht mehr** |

Das formale Ablaufen eines Zertifikats löst **kein** sofortiges Bootproblem aus.
Erst der dbx-Eintrag durch Microsoft ist kritisch — das Skript prüft dies explizit
und meldet `KRITISCH` wenn dieser Fall bereits eingetreten ist.
