
<#
.SYNOPSIS
    Import a CER certificate, export it as PFX, and optionally extract PEM + KEY files.
    Requires -RunAsAdministrator

.DESCRIPTION
    This script automates the following certificate workflow:
      1. Imports a CER certificate into the LocalMachine\My store
      2. Verifies the certificate has an associated private key
      3. Generates a secure random PFX password
      4. Exports the certificate as a PFX file
      5. Validates the exported PFX
      6. Saves the password as a DPAPI-protected file (bound to current user/machine)
      7. Optionally extracts PEM + KEY files using OpenSSL

    All operations are logged to a per-certificate log file.
    The PFX password is never passed as a visible process argument.

.PARAMETER CertificatePath
    Full path to the CER file to import.

.PARAMETER CertificateName
    Name used for folder creation, output files, and log file.
    Will be converted to uppercase automatically.

.PARAMETER WorkingDirectory
    Root directory where the certificate subfolder will be created.
    Defaults to C:\TEMP\SSLFolder.

.PARAMETER ExtractPem
    Switch. If set, automatically extracts PEM + KEY files using OpenSSL
    without prompting.

.EXAMPLE
    .\Export-CertificateToPfxAndPem.ps1 `
        -CertificatePath "C:\certs\mycert.cer" `
        -CertificateName "MYCERT" `
        -ExtractPem

.EXAMPLE
    .\Export-CertificateToPfxAndPem.ps1 `
        -CertificatePath "C:\certs\mycert.cer" `
        -CertificateName "MYCERT" `
        -WorkingDirectory "D:\PKI\Output"

.NOTES
    Author      : Brahim O.
    Version     : 1.1
    Requires    : PowerShell 5.1+, OpenSSL in PATH (only if -ExtractPem or PEM extraction chosen)

    SECURITY NOTE — Password protection:
    The .pwd file is encrypted using Windows DPAPI via ConvertFrom-SecureString
    without an explicit AES key. This means the file can only be decrypted by
    the same Windows user account on the same machine. It is NOT portable across
    machines or accounts. Store it accordingly.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CertificatePath,

    [Parameter(Mandatory)]
    [string]$CertificateName,

    [string]$WorkingDirectory = 'C:\TEMP\SSLFolder',

    [switch]$ExtractPem
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Utility Functions

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [string]$LogPath,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $directory = Split-Path -Path $LogPath -Parent

    if (-not (Test-Path -Path $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry     = "$timestamp [$Level] $Message"

    Add-Content -Path $LogPath -Value $entry

    switch ($Level) {
        'ERROR'   { Write-Host $entry -ForegroundColor Red    }
        'WARN'    { Write-Host $entry -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $entry -ForegroundColor Green  }
        default   { Write-Host $entry                         }
    }
}

function New-PfxPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CertificateName
    )

    $randomPart = [Guid]::NewGuid().ToString('N').Substring(0, 12)
    return "$CertificateName-$randomPart!"
}

function Protect-PfxPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Password
    )

    $secureString = ConvertTo-SecureString -String $Password -AsPlainText -Force
    return ConvertFrom-SecureString -SecureString $secureString
}

function Assert-OpenSslAvailable {
    if (-not (Get-Command 'openssl.exe' -ErrorAction SilentlyContinue)) {
        throw 'openssl.exe not found in PATH. Please install OpenSSL or add it to your PATH before using PEM extraction.'
    }
}

#endregion Utility Functions

#region Certificate Functions

function Import-CertificateToStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CertificatePath
    )

    if (-not (Test-Path -Path $CertificatePath)) {
        throw "Certificate file not found: $CertificatePath"
    }

    return Import-Certificate `
        -FilePath          $CertificatePath `
        -CertStoreLocation 'Cert:\LocalMachine\My'
}

function Get-CertificateByThumbprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    $certificate = Get-ChildItem -Path 'Cert:\LocalMachine\My' |
        Where-Object { $_.Thumbprint -eq $Thumbprint }

    if (-not $certificate) {
        throw "Certificate with thumbprint [$Thumbprint] not found in LocalMachine\My."
    }

    # FIX BUG 3 — A CER file is public only. Export-PfxCertificate requires a private key.
    if (-not $certificate.HasPrivateKey) {
        throw "Certificate [$Thumbprint] does not have an associated private key. " +
              "PFX export requires the private key to be present in the store. " +
              "Ensure the certificate was issued and the private key was not removed."
    }

    return $certificate
}

function Export-CertificateToPfx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory)]
        [string]$PfxPath,

        [Parameter(Mandatory)]
        [securestring]$Password
    )

    Export-PfxCertificate `
        -Cert     $Certificate `
        -FilePath $PfxPath `
        -Password $Password | Out-Null

    if (-not (Test-Path -Path $PfxPath)) {
        throw "PFX export failed — output file not found at: $PfxPath"
    }
}

function Test-PfxCertificate {
    # FIX BUG 1 — Renamed from Validate-PfxCertificate to use approved verb
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PfxPath,

        [Parameter(Mandatory)]
        [string]$Password
    )

    if (-not (Test-Path -Path $PfxPath)) {
        throw "PFX file not found at: $PfxPath"
    }

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

    $cert.Import(
        $PfxPath,
        $Password,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
    )

    return $cert
}

#endregion Certificate Functions

#region OpenSSL Functions

function Export-PemFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PfxPath,

        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [string]$OutputDirectory,

        [Parameter(Mandatory)]
        [string]$CertificateName
    )

    $privateKeyPath     = Join-Path $OutputDirectory "$CertificateName-privatekey.key"
    $certificatePemPath = Join-Path $OutputDirectory "$CertificateName-certificate.pem"

    # FIX BUG 6 — Password passed via temp file to avoid exposure in process list
    $passFile = [System.IO.Path]::GetTempFileName()

    try {
        Set-Content -Path $passFile -Value $Password -NoNewline

        $privateKeyArgs = @(
            'pkcs12'
            '-in',     $PfxPath
            '-nocerts'
            '-nodes'
            '-out',    $privateKeyPath
            '-passin', "file:$passFile"
        )

        $certArgs = @(
            'pkcs12'
            '-in',     $PfxPath
            '-clcerts'
            '-nokeys'
            '-out',    $certificatePemPath
            '-passin', "file:$passFile"
        )

        # FIX BUG 5 — Capture stderr for meaningful error messages on failure
        $pkErrFile   = [System.IO.Path]::GetTempFileName()
        $certErrFile = [System.IO.Path]::GetTempFileName()

        try {
            $pkProcess = Start-Process 'openssl.exe' `
                -ArgumentList $privateKeyArgs `
                -NoNewWindow -Wait -PassThru `
                -RedirectStandardError $pkErrFile

            if ($pkProcess.ExitCode -ne 0) {
                $errMsg = Get-Content -Path $pkErrFile -Raw
                throw "Private key extraction failed (exit code $($pkProcess.ExitCode)): $errMsg"
            }

            $certProcess = Start-Process 'openssl.exe' `
                -ArgumentList $certArgs `
                -NoNewWindow -Wait -PassThru `
                -RedirectStandardError $certErrFile

            if ($certProcess.ExitCode -ne 0) {
                $errMsg = Get-Content -Path $certErrFile -Raw
                throw "Certificate PEM extraction failed (exit code $($certProcess.ExitCode)): $errMsg"
            }
        }
        finally {
            Remove-Item -Path $pkErrFile   -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $certErrFile -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        # Always clean up the password temp file
        Remove-Item -Path $passFile -Force -ErrorAction SilentlyContinue
    }

    return [PSCustomObject]@{
        PrivateKeyPath = $privateKeyPath
        CertificatePem = $certificatePemPath
    }
}

#endregion OpenSSL Functions

#region Main

try {

    # Input validation
    if (-not (Test-Path -Path $CertificatePath)) {
        throw "CER file does not exist: $CertificatePath"
    }

    $CertificateName   = $CertificateName.ToUpperInvariant()
    $certificateFolder = Join-Path $WorkingDirectory $CertificateName

    if (-not (Test-Path -Path $certificateFolder)) {
        New-Item -Path $certificateFolder -ItemType Directory -Force | Out-Null
    }

    $logFilePath = Join-Path $certificateFolder "$CertificateName.log"

    Write-Log -Message "Starting certificate workflow for: $CertificateName" `
              -LogPath $logFilePath -Level 'INFO'
    Write-Log -Message "Input CER  : $CertificatePath"  -LogPath $logFilePath
    Write-Log -Message "Output dir : $certificateFolder" -LogPath $logFilePath

    # Step 1 — Import CER into store
    Write-Log -Message 'Importing CER into LocalMachine\My...' -LogPath $logFilePath

    $importedCertificate = Import-CertificateToStore -CertificatePath $CertificatePath

    Write-Log -Message "Certificate imported. Thumbprint: $($importedCertificate.Thumbprint)" `
              -LogPath $logFilePath -Level 'SUCCESS'

    # Step 2 — Retrieve certificate (with private key check)
    $certificate = Get-CertificateByThumbprint -Thumbprint $importedCertificate.Thumbprint

    Write-Log -Message 'Private key confirmed present.' -LogPath $logFilePath -Level 'SUCCESS'

    # Step 3 — Generate PFX password
    $pfxPassword       = New-PfxPassword -CertificateName $CertificateName
    $protectedPassword = Protect-PfxPassword -Password $pfxPassword
    $securePassword    = ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force

    # Step 4 — Export PFX
    $pfxPath = Join-Path $certificateFolder "$CertificateName.pfx"

    Export-CertificateToPfx `
        -Certificate $certificate `
        -PfxPath     $pfxPath `
        -Password    $securePassword

    Write-Log -Message "PFX exported successfully: $pfxPath" -LogPath $logFilePath -Level 'SUCCESS'

    # Step 5 — Save DPAPI-protected password file
    $passwordFilePath = Join-Path $certificateFolder "$CertificateName.pwd"
    Set-Content -Path $passwordFilePath -Value $protectedPassword

    Write-Log -Message "DPAPI-protected password file saved: $passwordFilePath" `
              -LogPath $logFilePath -Level 'SUCCESS'
    Write-Log -Message 'SECURITY NOTE: The .pwd file is DPAPI-encrypted and can only be decrypted by the same Windows user account on this machine.' `
              -LogPath $logFilePath -Level 'WARN'

    # Step 6 — Validate PFX
    # FIX BUG 1 — Call renamed function Test-PfxCertificate
    $validatedCert = Test-PfxCertificate -PfxPath $pfxPath -Password $pfxPassword

    Write-Log -Message "PFX validation successful. Subject: $($validatedCert.Subject)" `
              -LogPath $logFilePath -Level 'SUCCESS'

    # Step 7 — PEM extraction (via parameter or interactive prompt)
    $doPemExtraction = $ExtractPem.IsPresent

    if (-not $doPemExtraction) {
        $answer = Read-Host 'Extract PEM and KEY files using OpenSSL? (Y/N)'
        $doPemExtraction = $answer -match '^[Yy]$'
    }

    if ($doPemExtraction) {

        # FIX BUG 4 — Check OpenSSL availability before attempting extraction
        Assert-OpenSslAvailable

        Write-Log -Message 'Starting PEM + KEY extraction via OpenSSL...' -LogPath $logFilePath

        $pemResult = Export-PemFiles `
            -PfxPath         $pfxPath `
            -Password        $pfxPassword `
            -OutputDirectory $certificateFolder `
            -CertificateName $CertificateName

        Write-Log -Message "Private key exported    : $($pemResult.PrivateKeyPath)"  -LogPath $logFilePath -Level 'SUCCESS'
        Write-Log -Message "PEM certificate exported: $($pemResult.CertificatePem)"  -LogPath $logFilePath -Level 'SUCCESS'
    }

    # Summary
    Write-Host ''
    Write-Host ('=' * 65) -ForegroundColor Green
    Write-Host '  Workflow completed successfully.' -ForegroundColor Green
    Write-Host ('=' * 65) -ForegroundColor Green
    Write-Host ''
    Write-Host "  Certificate  : $($validatedCert.Subject)"    -ForegroundColor Cyan
    Write-Host "  Thumbprint   : $($validatedCert.Thumbprint)" -ForegroundColor Cyan
    Write-Host "  Expiry       : $($validatedCert.NotAfter)"   -ForegroundColor Cyan
    Write-Host "  PFX          : $pfxPath"                     -ForegroundColor Cyan
    Write-Host "  Password file: $passwordFilePath"            -ForegroundColor Cyan
    Write-Host "  Log          : $logFilePath"                  -ForegroundColor Cyan
    Write-Host ''

    Write-Log -Message 'Workflow completed successfully.' -LogPath $logFilePath -Level 'SUCCESS'
}
catch {
    # FIX BUG — Errors now logged to file in addition to screen
    $errorMessage = $_.Exception.Message

    if ($logFilePath -and (Test-Path -Path (Split-Path $logFilePath -Parent))) {
        Write-Log -Message "FATAL ERROR: $errorMessage" -LogPath $logFilePath -Level 'ERROR'
    }

    Write-Error $errorMessage
}
finally {
    Write-Host ''
    Write-Host 'Script execution finished.' -ForegroundColor Gray
}

#endregion Main
