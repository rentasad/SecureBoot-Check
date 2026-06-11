#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Secure Boot / UEFI Certificate Health Check v2
    Remote-faehig via Invoke-Command oder Enginsight

.DESCRIPTION
    Prueft auf jedem PC:
    - Secure Boot Status und Windows-Version (Updatefaehigkeit)
    - UEFI-Zertifikate in db, KEK, PK (mit Ablaufdaten)
    - dbx-Sperrliste: Sind 2011er Certs bereits gesperrt? (Bootproblem JETZT)
    - PKfail: Testzertifikat im Platform Key? (Secure Boot wertlos)
    - Boot Manager Signatur und CA-Kette
    - Ausstehende Windows Updates
    - Gesamtrisiko-Bewertung mit konkreten Handlungsempfehlungen

.NOTES
    Hintergrund (c't 13/2026, Axel Vahldiek):
    - Cert-Ablauf in db bricht den Boot NICHT sofort (Timestamp-Certs sichern
      bestehende Bootmanager weiterhin ab)
    - ECHTES Risiko: Microsoft traegt alte Certs in dbx ein (Datum unbekannt,
      KB5025885) - DANN booten alte Bootmanager nicht mehr
    - Manueller Fix via KB5025885: reg add + Start-ScheduledTask

.PARAMETER OutputPath
    Optionaler Pfad fuer CSV-Append-Export

.PARAMETER Quiet
    Keine farbige Konsolenausgabe, nur das Result-Objekt
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [switch]$Quiet
)

# -----------------------------------------------------------------------
# Hilfsfunktion: EFI Signature List binaer parsen
# Gibt X509-Zertifikate aus der angegebenen UEFI-Variable zurueck
# -----------------------------------------------------------------------
function Get-UEFICerts {
    param([string]$VarName)
    $certs = @()
    try {
        $var   = Get-SecureBootUEFI -Name $VarName -ErrorAction Stop
        $bytes = $var.Bytes
        if (-not $bytes -or $bytes.Length -eq 0) { return $certs }

        # EFI_CERT_X509_GUID (little-endian): {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
        $x509Guid = [byte[]]@(0xa1,0x59,0xc0,0xa5, 0xe4,0x94, 0xa7,0x4a,
                               0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72)
        $offset = 0

        while ($offset + 28 -le $bytes.Length) {
            $guid     = $bytes[$offset..($offset+15)]
            $listSize = [BitConverter]::ToUInt32($bytes, $offset+16)
            $hdrSize  = [BitConverter]::ToUInt32($bytes, $offset+20)
            $sigSize  = [BitConverter]::ToUInt32($bytes, $offset+24)
            if ($listSize -eq 0) { break }

            $isX509 = -not (Compare-Object $guid $x509Guid)
            if ($isX509 -and $sigSize -gt 16) {
                $sigOffset = $offset + 28 + $hdrSize
                $listEnd   = $offset + $listSize

                while ($sigOffset + $sigSize -le $listEnd) {
                    $certStart = $sigOffset + 16
                    $certLen   = $sigSize - 16
                    [byte[]]$certBytes = $bytes[$certStart..($certStart + $certLen - 1)]
                    try {
                        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                        $col.Import($certBytes)
                        foreach ($c in $col) {
                            $certs += [PSCustomObject]@{
                                Variable   = $VarName
                                Subject    = $c.Subject
                                Issuer     = $c.Issuer
                                NotAfter   = $c.NotAfter
                                DaysLeft   = [int]($c.NotAfter - (Get-Date)).TotalDays
                                Thumbprint = $c.Thumbprint.ToUpper()
                            }
                        }
                    } catch {}
                    $sigOffset += $sigSize
                }
            }
            $offset += $listSize
        }
    } catch {}
    return $certs
}

# -----------------------------------------------------------------------
# Hauptpruefung
# -----------------------------------------------------------------------
$r = [ordered]@{
    ComputerName              = $env:COMPUTERNAME
    CheckTime                 = (Get-Date).ToString("yyyy-MM-dd HH:mm")
    OS                        = ""
    Win_Version               = ""
    Win_Build                 = $null
    Win_UpdateSupported       = $null   # false = kein kostenloser Update-Support

    SecureBoot                = $false

    # Platform Key (PK)
    PKfail                    = $false
    PKfail_Detail             = ""

    # Secure Boot DB (db)
    db_CA2011_Present         = $false
    db_CA2011_Expiry          = ""
    db_CA2011_DaysLeft        = $null
    db_WinUEFI2023            = $false
    db_MSFTUEFI2023           = $false
    db_WinPCA2011_Present     = $false
    db_WinPCA2011_Expiry      = ""
    db_WinPCA2011_DaysLeft    = $null

    # dbx: Sind alte Certs bereits GESPERRT?
    dbx_CA2011_Revoked        = $false   # JETZT kritisch wenn true
    dbx_WinPCA2011_Revoked    = $false

    # KEK
    KEK_2011_Present          = $false
    KEK_2011_Expiry           = ""
    KEK_2011_DaysLeft         = $null
    KEK_2023_Present          = $false

    # Boot Manager
    BootMgr_Issuer            = ""
    BootMgr_CertExpiry        = ""
    BootMgr_DaysLeft          = $null
    BootMgr_NewChain          = $false

    # Windows Update
    WU_LastInstalled          = ""
    WU_PendingCount           = $null
    WU_PendingUpdates         = ""

    # Ergebnis
    RiskLevel                 = "Unbekannt"
    RiskDetail                = ""
    ManualFix                 = ""    # KB5025885 Befehle wenn noetig
}

# 1. OS und Windows-Version
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $r.OS        = $osInfo.Caption
    $r.Win_Build = [int]$osInfo.BuildNumber

    # DisplayVersion aus Registry (z.B. "24H2")
    $displayVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
                    -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
    $r.Win_Version = if ($displayVer) { $displayVer } else { "unbekannt" }

    # Updatefaehigkeit pruefen:
    # Windows 11 Home/Pro braucht mind. 24H2 (Build 26100)
    # Windows 10 = Build 19000er = kein kostenloser Support mehr (ohne MSA)
    if ($r.Win_Build -ge 26100) {
        $r.Win_UpdateSupported = $true    # Win 11 24H2+
    } elseif ($r.Win_Build -ge 22000) {
        $r.Win_UpdateSupported = $false   # Win 11 < 24H2 (23H2, 22H2 etc.)
    } else {
        $r.Win_UpdateSupported = $false   # Windows 10
    }
} catch {}

# 2. Secure Boot Status
try {
    $r.SecureBoot = Confirm-SecureBootUEFI
} catch {
    $r.SecureBoot = $false
}

# Windows Update Background-Job so frueh wie moeglich starten (laeuft parallel zu allen anderen Checks)
$wuJob      = $null
$wuJobStart = Get-Date
try {
    $wuJob = Start-Job -ScriptBlock {
        $wuSession  = New-Object -ComObject Microsoft.Update.Session
        $wuSearcher = $wuSession.CreateUpdateSearcher()
        $wuResult   = $wuSearcher.Search("IsInstalled=0 and Type='Software'")
        $titles = @($wuResult.Updates | Where-Object {
            $_.Title -notmatch "Defender|b.sartig|Intelligence|KB890830"
        } | ForEach-Object { $_.Title })
        [PSCustomObject]@{ Total = $titles.Count; Relevant = $titles }
    }
} catch {}

if (-not $r.SecureBoot) {
    $r.RiskLevel  = "Info"
    $r.RiskDetail = "Secure Boot deaktiviert - kein Zertifikatsrisiko beim Booten, Schutzfunktion fehlt"
} else {

    # 3. UEFI-Zertifikate parsen (db, KEK, PK, dbx)
    $dbCerts  = Get-UEFICerts "db"
    $kekCerts = Get-UEFICerts "KEK"
    $pkCerts  = Get-UEFICerts "PK"
    $dbxCerts = Get-UEFICerts "dbx"

    # db auswerten
    foreach ($c in $dbCerts) {
        switch -Regex ($c.Subject) {
            "Microsoft Corporation UEFI CA 2011" {
                $r.db_CA2011_Present  = $true
                $r.db_CA2011_Expiry   = $c.NotAfter.ToString("yyyy-MM-dd")
                $r.db_CA2011_DaysLeft = $c.DaysLeft
            }
            "Windows UEFI CA 2023" { $r.db_WinUEFI2023  = $true }
            "Microsoft UEFI CA 2023" { $r.db_MSFTUEFI2023 = $true }
            "Microsoft Windows Production PCA 2011" {
                $r.db_WinPCA2011_Present   = $true
                $r.db_WinPCA2011_Expiry    = $c.NotAfter.ToString("yyyy-MM-dd")
                $r.db_WinPCA2011_DaysLeft  = $c.DaysLeft
            }
        }
    }

    # KEK auswerten
    foreach ($c in $kekCerts) {
        switch -Regex ($c.Subject) {
            "KEK CA 2011" {
                $r.KEK_2011_Present  = $true
                $r.KEK_2011_Expiry   = $c.NotAfter.ToString("yyyy-MM-dd")
                $r.KEK_2011_DaysLeft = $c.DaysLeft
            }
            "KEK.*(CA )?2023|KEK 2K CA" { $r.KEK_2023_Present = $true }
        }
    }

    # 4. PKfail-Check: Test-Zertifikate im Platform Key?
    $pkfailPatterns = @("DO NOT TRUST", "DO NOT SHIP", "NOT TRUST", "NOT SHIP",
                        "\bTEST\b", "TEST PK", "AMI TEST", "PHOENIX TEST")
    foreach ($c in $pkCerts) {
        $combined = "$($c.Subject) $($c.Issuer)".ToUpper()
        foreach ($pattern in $pkfailPatterns) {
            if ($combined -match $pattern) {
                $r.PKfail        = $true
                $r.PKfail_Detail = "PKfail: '$($c.Subject)' im Platform Key -- Secure Boot Schutz ausgehoelt!"
                break
            }
        }
    }

    # 5. dbx-Check: Sind 2011er Certs bereits gesperrt?
    # Bekannte Thumbprints der 2011er Certs (aus unseren bisherigen Tests bestaetigt)
    $knownCA2011Thumbprints    = @("46DEF63B5CE61CF8BA0DE2E6639C1019D0ED14F3")
    $knownWinPCA2011Thumbprints = @("580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D")

    # Auch dynamisch: Thumbprints aus db holen falls andere Variante
    if ($r.db_CA2011_Present) {
        $dbCA2011Thumb = ($dbCerts | Where-Object { $_.Subject -match "Microsoft Corporation UEFI CA 2011" }).Thumbprint
        if ($dbCA2011Thumb) { $knownCA2011Thumbprints += $dbCA2011Thumb }
    }
    if ($r.db_WinPCA2011_Present) {
        $dbWinPCAThumb = ($dbCerts | Where-Object { $_.Subject -match "Microsoft Windows Production PCA 2011" }).Thumbprint
        if ($dbWinPCAThumb) { $knownWinPCA2011Thumbprints += $dbWinPCAThumb }
    }

    foreach ($c in $dbxCerts) {
        if ($c.Thumbprint -in $knownCA2011Thumbprints -or $c.Subject -match "Microsoft Corporation UEFI CA 2011") {
            $r.dbx_CA2011_Revoked = $true
        }
        if ($c.Thumbprint -in $knownWinPCA2011Thumbprints -or $c.Subject -match "Microsoft Windows Production PCA 2011") {
            $r.dbx_WinPCA2011_Revoked = $true
        }
    }

    # 6. Boot Manager Signatur
    $espDrive   = "S:"
    $espMounted = $false
    if (-not (Test-Path "${espDrive}\")) {
        mountvol $espDrive /S 2>$null
        $espMounted = $true
    }
    $bootMgrPath = "${espDrive}\EFI\Microsoft\Boot\bootmgfw.efi"
    if (Test-Path $bootMgrPath) {
        try {
            $sig = Get-AuthenticodeSignature $bootMgrPath
            $bc  = $sig.SignerCertificate
            $r.BootMgr_Issuer     = ($bc.Issuer -split ',')[0] -replace 'CN=',''
            $r.BootMgr_CertExpiry = $bc.NotAfter.ToString("yyyy-MM-dd")
            $r.BootMgr_DaysLeft   = [int]($bc.NotAfter - (Get-Date)).TotalDays
            $r.BootMgr_NewChain   = $bc.Issuer -match "2023"
        } catch {
            $r.BootMgr_Issuer = "Lesefehler: $($_.Exception.Message)"
        }
    } else {
        $r.BootMgr_Issuer = "bootmgfw.efi nicht gefunden"
    }
    if ($espMounted) { mountvol $espDrive /D 2>$null }

    # 7. Letztes installiertes Windows Update (Get-HotFix ist schnell, kein COM)
    try {
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
        if ($hotfixes -and $hotfixes[0].InstalledOn) {
            $r.WU_LastInstalled = $hotfixes[0].InstalledOn.ToString("yyyy-MM-dd")
        }
    } catch {}

    # 8. Risikobewertung
    $risks = [System.Collections.Generic.List[string]]::new()

    # --- KRITISCHE Risiken ---

    # Alte Certs bereits in dbx gesperrt -> Boot JETZT gefaehrdet
    if ($r.dbx_WinPCA2011_Revoked) {
        $risks.Add("KRITISCH: Microsoft Windows Production PCA 2011 ist in dbx GESPERRT - Windows bootet moeglicherweise nicht!")
    }
    if ($r.dbx_CA2011_Revoked) {
        $risks.Add("KRITISCH: Microsoft UEFI CA 2011 ist in dbx GESPERRT - Linux/3rd-Party-Bootmanager booten nicht mehr!")
    }

    # PKfail
    if ($r.PKfail) {
        $risks.Add("KRITISCH: $($r.PKfail_Detail)")
    }

    # Boot Manager Cert sehr nah am Ablauf
    if ($null -ne $r.BootMgr_DaysLeft) {
        if ($r.BootMgr_DaysLeft -lt 0) {
            $risks.Add("KRITISCH: Boot Manager Signatur-Zertifikat abgelaufen ($($r.BootMgr_CertExpiry)) - Windows Update sofort!")
        } elseif ($r.BootMgr_DaysLeft -le 14) {
            $risks.Add("KRITISCH: Boot Manager Zertifikat laeuft in $($r.BootMgr_DaysLeft) Tagen ab - sofort Windows Update + Neustart!")
        }
    }

    # --- WARNUNGEN ---

    # Windows-Version ohne Update-Support
    if ($r.Win_UpdateSupported -eq $false) {
        if ($r.Win_Build -lt 22000) {
            $risks.Add("WARNUNG: Windows 10 (Build $($r.Win_Build)) - kein kostenloser Support mehr, keine Zertifikatsupdates")
        } else {
            $risks.Add("WARNUNG: Windows 11 $($r.Win_Version) (Build $($r.Win_Build)) - kein Support mehr, mind. 24H2 erforderlich")
        }
    }

    # Keine neuen 2023er Certs
    if (-not $r.db_WinUEFI2023 -and -not $r.db_MSFTUEFI2023) {
        $risks.Add("WARNUNG: Keine 2023er UEFI CA in Secure Boot db - Windows Update erforderlich")
    }
    if (-not $r.KEK_2023_Present) {
        $risks.Add("WARNUNG: Kein KEK 2023 vorhanden - Windows Update erforderlich")
    }

    # Boot Manager noch auf alter Kette
    if (-not $r.BootMgr_NewChain -and $null -ne $r.BootMgr_DaysLeft -and $r.BootMgr_DaysLeft -le 90) {
        $risks.Add("WARNUNG: Boot Manager auf alter CA-Kette (WinPCA2011), laeuft ab $($r.BootMgr_CertExpiry)")
    }

    # Boot Manager Cert bald ablaufend (Warnung-Schwelle)
    if ($null -ne $r.BootMgr_DaysLeft -and $r.BootMgr_DaysLeft -gt 14 -and $r.BootMgr_DaysLeft -le 60) {
        $risks.Add("WARNUNG: Boot Manager Zertifikat laeuft in $($r.BootMgr_DaysLeft) Tagen ab ($($r.BootMgr_CertExpiry))")
    }

    # --- Gesamtrisiko ---
    if ($risks.Count -eq 0) {
        $r.RiskLevel  = "OK"
        $r.RiskDetail = "Alle Zertifikate gueltig, 2023er CA-Kette vorhanden, keine Sperrungen"
    } elseif ($risks | Where-Object { $_ -match "^KRITISCH" }) {
        $r.RiskLevel  = "KRITISCH"
        $r.RiskDetail = $risks -join " | "
    } elseif ($risks | Where-Object { $_ -match "^WARNUNG" }) {
        $r.RiskLevel  = "WARNUNG"
        $r.RiskDetail = $risks -join " | "
    } else {
        $r.RiskLevel  = "INFO"
        $r.RiskDetail = $risks -join " | "
    }

    # 9. Manuellen Fix-Befehl einblenden wenn noetig (aus KB5025885)
    # KB5025885 aktualisiert die UEFI-Cert-Datenbanken (db/KEK), NICHT den Boot Manager selbst.
    # BootMgr_NewChain wird durch ein separates Microsoft-Update geliefert -> kein manueller Fix moeglich.
    $needsManualFix = (-not $r.db_WinUEFI2023) -or (-not $r.db_MSFTUEFI2023) -or
                      (-not $r.KEK_2023_Present)

    if ($needsManualFix -and $r.Win_UpdateSupported -eq $true) {
        # BitLocker-Status pruefen: Warnung nur bei aktiver Verschluesselung
        $bitlockerActive = $false
        try {
            $blv = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
            $bitlockerActive = ($blv.ProtectionStatus -eq "On")
        } catch {}

        $step1 = if ($bitlockerActive) {
            "  1. ZUERST BitLocker-Wiederherstellungsschluessel sichern:`n" +
            "     Manage-bde -Protectors -Get C:`n"
        } else {
            "  1. BitLocker ist nicht aktiv - kein Wiederherstellungsschluessel noetig`n"
        }

        $r.ManualFix = ("Wenn Windows Update die Zertifikate nicht automatisch einspielt (KB5025885):`n" +
            $step1 +
            "  2. Dann in PowerShell (Admin):`n" +
            "     reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f`n" +
            "     Start-ScheduledTask -TaskName `"\Microsoft\Windows\PI\Secure-Boot-Update`"`n" +
            "  3. PC neu starten, dann sofort nochmals neu starten (Test)")
    } elseif ($needsManualFix -and $r.Win_UpdateSupported -eq $false) {
        $r.ManualFix = "Windows-Version aktualisieren (mind. Win 11 24H2), dann KB5025885 anwenden."
    }
}

$result = [PSCustomObject]$r

# -----------------------------------------------------------------------
# Ausgabe Phase 1: Sicherheitsbewertung sofort zeigen
# -----------------------------------------------------------------------
if (-not $Quiet) {
    $color = switch ($result.RiskLevel) {
        "OK"       { "Green"  }
        "INFO"     { "Cyan"   }
        "WARNUNG"  { "Yellow" }
        "KRITISCH" { "Red"    }
        default    { "White"  }
    }
    Write-Host ""
    Write-Host ("=" * 65) -ForegroundColor DarkGray
    Write-Host " $($result.ComputerName)  ->  $($result.RiskLevel)  (Win $($result.Win_Version), Build $($result.Win_Build))" -ForegroundColor $color
    Write-Host " $($result.RiskDetail)" -ForegroundColor $color
    Write-Host ("=" * 65) -ForegroundColor DarkGray
    Write-Host ""
}

# -----------------------------------------------------------------------
# Windows Update Ergebnis einsammeln (laeuft seit Beginn im Hintergrund)
# -----------------------------------------------------------------------
if ($null -ne $wuJob) {
    $elapsed   = (Get-Date) - $wuJobStart
    $remaining = [Math]::Max(5, 60 - [int]$elapsed.TotalSeconds)
    if (-not $Quiet) {
        Write-Host "  Pruefe Windows Update (noch max. ${remaining}s) ..." -ForegroundColor DarkGray -NoNewline
    }
    $wuDone = Wait-Job -Job $wuJob -Timeout $remaining
    if ($wuDone) {
        if (-not $Quiet) { Write-Host " OK" -ForegroundColor DarkGray }
        $wuData = Receive-Job -Job $wuJob -ErrorAction SilentlyContinue
        if ($wuData) {
            $result.WU_PendingCount   = $wuData.Total
            $result.WU_PendingUpdates = ($wuData.Relevant) -join "; "
        }
    } else {
        if (-not $Quiet) { Write-Host " Timeout" -ForegroundColor DarkYellow }
        $result.WU_PendingCount   = -1
        $result.WU_PendingUpdates = "Timeout (WU-Dienst nicht erreichbar)"
    }
    Remove-Job -Job $wuJob -Force -ErrorAction SilentlyContinue

    # WU-INFO in Risikobewertung nachziehen
    if ($result.WU_PendingCount -gt 0 -and $result.WU_PendingUpdates -ne "") {
        $wuInfo = "INFO: $($result.WU_PendingCount) relevante Update(s) ausstehend"
        if ($result.RiskLevel -eq "OK") {
            $result.RiskLevel  = "INFO"
            $result.RiskDetail = $wuInfo
        } else {
            $result.RiskDetail = $result.RiskDetail + " | " + $wuInfo
        }
    }
}

# -----------------------------------------------------------------------
# Ausgabe Phase 2: Vollstaendige Detailliste
# -----------------------------------------------------------------------
if (-not $Quiet) {
    $result | Format-List

    if ($result.ManualFix -ne "") {
        Write-Host ""
        Write-Host "HANDLUNGSEMPFEHLUNG:" -ForegroundColor Yellow
        Write-Host $result.ManualFix -ForegroundColor Yellow
    }
}

if ($OutputPath -ne "") {
    $result | Export-Csv -Path $OutputPath -Append -NoTypeInformation -Encoding UTF8
    Write-Host "Gespeichert: $OutputPath" -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------
# Log-Datei speichern: .\log\[Hostname].log (relativ zum Skript-Verzeichnis)
# -----------------------------------------------------------------------
try {
    $logDir  = Join-Path $PSScriptRoot "log"
    $logFile = Join-Path $logDir "$($result.ComputerName).log"

    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $logLines = @()
    $logLines += "=" * 65
    $logLines += " $($result.ComputerName)  ->  $($result.RiskLevel)  (Win $($result.Win_Version), Build $($result.Win_Build))"
    $logLines += " $($result.RiskDetail)"
    $logLines += "=" * 65
    $logLines += ""
    $logLines += $result | Format-List | Out-String
    if ($result.ManualFix -ne "") {
        $logLines += "HANDLUNGSEMPFEHLUNG:"
        $logLines += $result.ManualFix
    }

    $logLines | Out-File -FilePath $logFile -Encoding UTF8 -Force
    Write-Host "  Log gespeichert: $logFile" -ForegroundColor DarkGray
} catch {
    Write-Host "  Log konnte nicht gespeichert werden: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# Kein 'return $result' -> verhindert doppelte Ausgabe bei powershell.exe -File
