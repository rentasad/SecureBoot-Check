#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Secure Boot Netzwerk-Scanner
    Fuehrt SecureBoot-Check.ps1 auf mehreren PCs aus und erstellt einen CSV-Bericht.

.DESCRIPTION
    Variante A: PSRemoting (Invoke-Command) - benoetigt WinRM auf den Ziel-PCs
    Variante B: Enginsight / lokale Ausfuehrung - Skript wird direkt deployed

.PARAMETER ComputerList
    Array von Computernamen, z.B. @("PC01","PC02") oder Pfad zu einer TXT-Datei (ein Name pro Zeile)

.PARAMETER CheckScript
    Pfad zu SecureBoot-Check.ps1

.PARAMETER OutputCsv
    Pfad fuer den CSV-Bericht (wird neu erstellt)

.PARAMETER Credential
    PSCredential fuer Remote-Verbindung. Wenn leer: aktueller Benutzer.

.PARAMETER MaxParallel
    Maximale parallele Jobs (Standard: 10)

.EXAMPLE
    # PCs aus Datei, Report nach Desktop
    .\SecureBoot-Network.ps1 `
        -ComputerList "C:\PCs.txt" `
        -CheckScript  ".\SecureBoot-Check.ps1" `
        -OutputCsv    "$env:USERPROFILE\Desktop\SecureBoot-Report.csv"

.EXAMPLE
    # Explizite Liste
    .\SecureBoot-Network.ps1 `
        -ComputerList @("GSTCL70","GSTCL71","GSTCL72") `
        -CheckScript  ".\SecureBoot-Check.ps1" `
        -OutputCsv    ".\SecureBoot-Report.csv" `
        -Credential   (Get-Credential)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    $ComputerList,

    [Parameter(Mandatory=$true)]
    [string]$CheckScript,

    [string]$OutputCsv = ".\SecureBoot-Report_$(Get-Date -f 'yyyyMMdd_HHmm').csv",

    [PSCredential]$Credential = $null,

    [int]$MaxParallel = 10
)

# -----------------------------------------------------------------------
# Vorbereitung
# -----------------------------------------------------------------------
# ComputerList: Datei oder Array
if ($ComputerList -is [string] -and (Test-Path $ComputerList)) {
    $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
} else {
    $computers = @($ComputerList)
}

if (-not (Test-Path $CheckScript)) {
    Write-Error "SecureBoot-Check.ps1 nicht gefunden: $CheckScript"
    exit 1
}

Write-Host "Starte Scan fuer $($computers.Count) Computer..." -ForegroundColor Cyan
Write-Host "Ausgabe: $OutputCsv`n"

# CSV-Header vorbereiten (leere Datei)
if (Test-Path $OutputCsv) { Remove-Item $OutputCsv -Force }

# -----------------------------------------------------------------------
# Remote-Scan via PSRemoting (Invoke-Command)
# -----------------------------------------------------------------------
$invokeParams = @{
    ComputerName = $computers
    FilePath     = $CheckScript
    ArgumentList = @("", $true)   # OutputPath="", Quiet=$true
    ThrottleLimit= $MaxParallel
    ErrorAction  = "SilentlyContinue"
}
if ($Credential) { $invokeParams.Credential = $Credential }

$results = @()
$failed  = @()

Write-Host "Verbinde via PSRemoting..." -ForegroundColor DarkGray
try {
    $remoteResults = Invoke-Command @invokeParams
    $results += $remoteResults
} catch {
    Write-Warning "PSRemoting-Fehler: $_"
}

# PCs die nicht geantwortet haben
$responded = $results | ForEach-Object { $_.ComputerName }
$failed    = $computers | Where-Object { $_ -notin $responded }

# Fehlgeschlagene PCs als Eintraege mit Fehler-Status
foreach ($pc in $failed) {
    $results += [PSCustomObject]@{
        ComputerName          = $pc
        CheckTime             = (Get-Date).ToString("yyyy-MM-dd HH:mm")
        OS                    = ""
        SecureBoot            = $null
        db_CA2011_Present     = $null
        db_CA2011_Expiry      = ""
        db_CA2011_DaysLeft    = $null
        db_WinUEFI2023        = $null
        db_MSFTUEFI2023       = $null
        db_WinPCA2011_Present = $null
        db_WinPCA2011_Expiry  = ""
        db_WinPCA2011_DaysLeft= $null
        KEK_2011_Present      = $null
        KEK_2011_Expiry       = ""
        KEK_2011_DaysLeft     = $null
        KEK_2023_Present      = $null
        BootMgr_Issuer        = ""
        BootMgr_CertExpiry    = ""
        BootMgr_DaysLeft      = $null
        BootMgr_NewChain      = $null
        WU_LastInstalled      = ""
        WU_PendingCount       = $null
        WU_PendingUpdates     = ""
        RiskLevel             = "NICHT ERREICHBAR"
        RiskDetail            = "PSRemoting fehlgeschlagen - WinRM aktiv? Firewall? Admin-Rechte?"
    }
}

# -----------------------------------------------------------------------
# Ergebnisse sortieren und ausgeben
# -----------------------------------------------------------------------
$sorted = $results | Sort-Object RiskLevel, ComputerName

# Konsolenausgabe (Zusammenfassung)
Write-Host "`n===== ERGEBNIS =====" -ForegroundColor Cyan
$sorted | ForEach-Object {
    $color = switch ($_.RiskLevel) {
        "OK"              { "Green"  }
        "INFO"            { "Cyan"   }
        "WARNUNG"         { "Yellow" }
        "KRITISCH"        { "Red"    }
        "NICHT ERREICHBAR"{ "Magenta"}
        default           { "White"  }
    }
    $line = "{0,-20} {1,-12} {2}" -f $_.ComputerName, $_.RiskLevel, $_.RiskDetail
    Write-Host $line -ForegroundColor $color
}

# Statistik
Write-Host "`n===== STATISTIK =====" -ForegroundColor Cyan
$sorted | Group-Object RiskLevel | Sort-Object Name |
    ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" }

# CSV-Export
$sorted | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "`nCSV-Bericht: $OutputCsv" -ForegroundColor Green

# Kritische PCs hervorheben
$critical = $sorted | Where-Object { $_.RiskLevel -eq "KRITISCH" }
if ($critical) {
    Write-Host "`nSOFORTMASSNAHME erforderlich bei:" -ForegroundColor Red
    $critical | ForEach-Object { Write-Host "  -> $($_.ComputerName): $($_.RiskDetail)" -ForegroundColor Red }
}

return $sorted
