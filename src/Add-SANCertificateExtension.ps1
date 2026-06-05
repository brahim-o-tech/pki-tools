#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Generates a Certificate Signing Request (CSR) with Subject Alternative Names (SANs)
    using a graphical Windows Forms interface.

.DESCRIPTION
    This script provides a user-friendly GUI to collect certificate subject fields and SAN
    entries, then generates a standards-compliant CSR using certreq.exe.

    Workflow:
      1. Collects subject info (CN, O, OU, L, S, C) and SANs (DNS + IP) via GUI
      2. Dynamically builds a certreq-compatible .inf configuration file
      3. Runs certreq.exe to generate the CSR
      4. Optionally parses the CSR with certutil for validation
      5. Optionally copies the CSR to clipboard or saves it to disk
      6. Cleans up temporary files

.PARAMETER OutputPath
    Directory where the CSR file will be saved if the user chooses to save it.
    Defaults to C:\.

.EXAMPLE
    .\Submit-CSRToEnterpriseCA.ps1

.EXAMPLE
    .\Submit-CSRToEnterpriseCA.ps1 -OutputPath "D:\PKI\CSRs"

.NOTES
    Author  : Brahim O.
    Version : 1.1
    Requires: PowerShell 5.1+, Windows, certreq.exe, certutil.exe
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ============================================================
#  FUNCTIONS
# ============================================================

function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Assert-CertTools {
    # FIX BUG 5 — Verify certreq and certutil are available before use
    foreach ($tool in @('certreq.exe', 'certutil.exe')) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "$tool not found in PATH. This script requires Windows with AD CS tools or RSAT."
        }
    }
}

function Show-CsrInputForm {

    $form                 = New-Object System.Windows.Forms.Form
    $form.Text            = "CSR Generator — Certificate Request with SAN"
    $form.Size            = New-Object System.Drawing.Size(620, 580)
    $form.StartPosition   = "CenterScreen"
    $form.Topmost         = $true
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox     = $false

    [int]$y                  = 15
    [int]$txtLeft            = 165
    [int]$controlWidth       = 430
    [int]$controlHeightMulti = 90
    [int]$vSpacing           = 33

    function Add-LabeledTextBox {
        param([string]$LabelText, [int]$PosY, [string]$DefaultText = "")
        $label          = New-Object System.Windows.Forms.Label
        $label.Text     = $LabelText
        $label.Location = New-Object System.Drawing.Point(10, [int]$PosY)
        $label.AutoSize = $true
        $textbox          = New-Object System.Windows.Forms.TextBox
        $textbox.Location = New-Object System.Drawing.Point([int]$txtLeft, [int]($PosY - 3))
        $textbox.Width    = $controlWidth
        if ($DefaultText) { $textbox.Text = $DefaultText }
        return @($label, $textbox)
    }

    $tmp = Add-LabeledTextBox "Common Name (CN):"         $y;          $labelCN = $tmp[0]; $txtCN = $tmp[1]; $y += $vSpacing
    $tmp = Add-LabeledTextBox "Organization (O):"         $y "Your Organization"; $labelO  = $tmp[0]; $txtO  = $tmp[1]; $y += $vSpacing
    $tmp = Add-LabeledTextBox "Organizational Unit (OU):" $y "IT";     $labelOU = $tmp[0]; $txtOU = $tmp[1]; $y += $vSpacing
    $tmp = Add-LabeledTextBox "Locality (L):"             $y "City";   $labelL  = $tmp[0]; $txtL  = $tmp[1]; $y += $vSpacing
    $tmp = Add-LabeledTextBox "State or Province (S):"    $y "Province"; $labelS = $tmp[0]; $txtS = $tmp[1]; $y += $vSpacing
    $tmp = Add-LabeledTextBox "Country (C):"              $y "CA";     $labelC  = $tmp[0]; $txtC  = $tmp[1]; $y += $vSpacing + 5

    $labelDNS          = New-Object System.Windows.Forms.Label
    $labelDNS.Text     = "SAN DNS (1 per line):"
    $labelDNS.Location = New-Object System.Drawing.Point(10, [int]$y)
    $labelDNS.AutoSize = $true
    $txtDNS            = New-Object System.Windows.Forms.TextBox
    $txtDNS.Location   = New-Object System.Drawing.Point([int]$txtLeft, [int]($y - 3))
    $txtDNS.Size       = New-Object System.Drawing.Size($controlWidth, $controlHeightMulti)
    $txtDNS.Multiline  = $true
    $txtDNS.ScrollBars = 'Vertical'
    $txtDNS.Font       = New-Object System.Drawing.Font("Consolas", 9)
    $y += $controlHeightMulti + 12

    $labelIP           = New-Object System.Windows.Forms.Label
    $labelIP.Text      = "SAN IP (1 per line):"
    $labelIP.Location  = New-Object System.Drawing.Point(10, [int]$y)
    $labelIP.AutoSize  = $true
    $txtIP             = New-Object System.Windows.Forms.TextBox
    $txtIP.Location    = New-Object System.Drawing.Point([int]$txtLeft, [int]($y - 3))
    $txtIP.Size        = New-Object System.Drawing.Size($controlWidth, $controlHeightMulti)
    $txtIP.Multiline   = $true
    $txtIP.ScrollBars  = 'Vertical'
    $txtIP.Font        = New-Object System.Drawing.Font("Consolas", 9)

    $btnY              = $y + $controlHeightMulti + 15
    $btnOK             = New-Object System.Windows.Forms.Button
    $btnOK.Text        = "Generate CSR"
    $btnOK.Location    = New-Object System.Drawing.Point(370, [int]$btnY)
    $btnOK.Width       = 110
    $btnOK.Height      = 30
    $btnClose          = New-Object System.Windows.Forms.Button
    $btnClose.Text     = "Cancel"
    $btnClose.Location = New-Object System.Drawing.Point(490, [int]$btnY)
    $btnClose.Width    = 80
    $btnClose.Height   = 30

    # DialogResult set explicitly so ShowDialog() return value is reliable
    $btnOK.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtCN.Text)) {
            [System.Windows.Forms.MessageBox]::Show(
                "The Common Name (CN) is required.",
                "Validation Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            return
        }

        # Validate IP entries
        $rawIPs = @($txtIP.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
        foreach ($ip in $rawIPs) {
            $parsed = $null
            if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) {
                [System.Windows.Forms.MessageBox]::Show(
                    "'$ip' is not a valid IP address.",
                    "Validation Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
                return
            }
        }

        $form.Tag = [PSCustomObject]@{
            CN      = $txtCN.Text.Trim()
            O       = $txtO.Text.Trim()
            OU      = $txtOU.Text.Trim()
            L       = $txtL.Text.Trim()
            S       = $txtS.Text.Trim()
            C       = $txtC.Text.Trim()
            SAN_DNS = @($txtDNS.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
            SAN_IP  = $rawIPs
        }

        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })

    $btnClose.Add_Click({
        $form.Tag = $null
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })

    $form.Controls.AddRange(@(
        $labelCN, $txtCN, $labelO, $txtO, $labelOU, $txtOU,
        $labelL, $txtL, $labelS, $txtS, $labelC, $txtC,
        $labelDNS, $txtDNS, $labelIP, $txtIP, $btnOK, $btnClose
    ))

    $form.CancelButton = $btnClose
    $form.Add_Shown({ $form.Activate(); $txtCN.Focus() })

    # FIX BUG 2 — Check DialogResult, not just Tag
    $result = $form.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    return $form.Tag
}

function Build-InfContent {
    param([PSCustomObject]$CsrInfo)

    # FIX BUG 3 — Proper ASCII quotes + real newlines (no typographic chars)
    # FIX BUG 6 — KeyUsage = 0xa0 (DigitalSignature + KeyEncipherment)
    $sanBlock = ""
    if (($CsrInfo.SAN_DNS.Count + $CsrInfo.SAN_IP.Count) -gt 0) {
        $nl        = [Environment]::NewLine
        $sanBlock  = "2.5.29.17 = `"{text}`"$nl"
        foreach ($dns in $CsrInfo.SAN_DNS) { $sanBlock += "_continue_ = `"dns=$dns&`"$nl" }
        foreach ($ip  in $CsrInfo.SAN_IP)  { $sanBlock += "_continue_ = `"ipaddress=$ip&`"$nl" }
    }

    return @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject         = "CN=$($CsrInfo.CN),OU=$($CsrInfo.OU),O=$($CsrInfo.O),L=$($CsrInfo.L),S=$($CsrInfo.S),C=$($CsrInfo.C)"
KeyLength       = 2048
Exportable      = TRUE
MachineKeySet   = TRUE
SMIME           = FALSE
RequestType     = PKCS10
ProviderName    = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType    = 12
HashAlgorithm   = sha256
KeyUsage        = 0xa0

[RequestAttributes]

[Extensions]
$($sanBlock.TrimEnd())

; References:
; certreq syntax : https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1
; CSR decoder    : https://certlogik.com/decoder/
"@
}

# ============================================================
#  MAIN
# ============================================================

try {

    Assert-CertTools

    if (-not (Test-IsAdmin)) {
        Write-Host "Relaunching as Administrator..." -ForegroundColor Yellow
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }

    $csrInfo = Show-CsrInputForm

    # FIX BUG 2 — Covers Cancel click AND window X button
    if ($null -eq $csrInfo) {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit
    }

    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  CSR Request Summary"  -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  CN : $($csrInfo.CN)"
    Write-Host "  O  : $($csrInfo.O)"
    Write-Host "  OU : $($csrInfo.OU)"
    Write-Host "  L  : $($csrInfo.L)"
    Write-Host "  S  : $($csrInfo.S)"
    Write-Host "  C  : $($csrInfo.C)"
    if ($csrInfo.SAN_DNS.Count -gt 0) {
        Write-Host "  SAN DNS :" -ForegroundColor White
        $csrInfo.SAN_DNS | ForEach-Object { Write-Host "    - $_" }
    }
    if ($csrInfo.SAN_IP.Count -gt 0) {
        Write-Host "  SAN IP  :" -ForegroundColor White
        $csrInfo.SAN_IP  | ForEach-Object { Write-Host "    - $_" }
    }
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""

    $infContent = Build-InfContent -CsrInfo $csrInfo
    $tempInf    = Join-Path $env:TEMP ("csr_" + [guid]::NewGuid().ToString('N') + ".inf")
    $tempCsr    = Join-Path $env:TEMP ("csr_" + [guid]::NewGuid().ToString('N') + ".csr")

    $infContent | Out-File -Encoding ASCII -FilePath $tempInf

    Write-Host "Generating CSR via certreq..." -ForegroundColor Cyan

    # FIX BUG 7 — Capture stderr, check exit code explicitly
    $certreqErr = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process 'certreq.exe' `
            -ArgumentList "-new `"$tempInf`" `"$tempCsr`"" `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardError $certreqErr

        if ($proc.ExitCode -ne 0) {
            $errMsg = Get-Content $certreqErr -Raw
            throw "certreq.exe failed (exit code $($proc.ExitCode)): $errMsg"
        }
    }
    finally {
        Remove-Item $certreqErr -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path $tempCsr)) {
        throw "certreq failed — output CSR file not found. INF retained at: $tempInf"
    }

    $csrContent = Get-Content $tempCsr -Raw

    Write-Host ""
    Write-Host "CSR generated successfully:" -ForegroundColor Green
    Write-Host ""
    Write-Output $csrContent

    $parseCsr = Read-Host "Parse and validate CSR with certutil? (Y/N)"
    if ($parseCsr -match '^[Yy]') {
        Write-Host ""
        Write-Host "certutil output:" -ForegroundColor Cyan
        Write-Host ""
        certutil -dump $tempCsr
        Write-Host ""
        Write-Host "Press any key to continue..." -ForegroundColor Gray
        [System.Windows.Forms.MessageBox]::Show(
            "Click OK to continue.",
            "Information",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }

    $copy = Read-Host "Copy CSR to clipboard? (Y/N)"
    if ($copy -match '^[Yy]') {
        $csrContent | Set-Clipboard
        Write-Host "CSR copied to clipboard." -ForegroundColor Green
    }

    $save = Read-Host "Save CSR to disk? (Y/N)"
    if ($save -match '^[Yy]') {
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $safeCN    = $csrInfo.CN -replace '[^a-zA-Z0-9\-]', '-'
        $filePath  = Join-Path $OutputPath "CSR-$safeCN-$timestamp.txt"
        $csrContent | Out-File -Encoding ASCII -FilePath $filePath
        Write-Host "CSR saved to: $filePath" -ForegroundColor Green
    }

    # FIX BUG 2 — Cleanup logic was INVERTED in original (Remove-Item was in the wrong branch)
    $answer = Read-Host "Remove temporary files? (Y/N — default: Y)"
    if ($answer -match '^[Nn]') {
        Write-Host "Temporary files retained:" -ForegroundColor Yellow
        Write-Host "  INF : $tempInf"          -ForegroundColor Yellow
        Write-Host "  CSR : $tempCsr"          -ForegroundColor Yellow
    }
    else {
        Remove-Item -Path $tempInf, $tempCsr -Force -ErrorAction SilentlyContinue
        Write-Host "Temporary files removed." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host "  Workflow completed successfully." -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "  [FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Error $_.Exception.Message
}
