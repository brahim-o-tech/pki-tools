# pki-tools

> A collection of PowerShell scripts for PKI operations — CSR generation, PFX/PEM export, and SAN injection on pending certificate requests.

---

## Origin & Disclaimer

These scripts are derived from production scripts used in real enterprise environments.
They have been anonymized, refactored, and generalized for public release.

**They are provided as-is, without warranty of any kind, and have not been tested in this exact form.**
Always validate in a lab environment before using in production.
Use at your own risk.

---

## Scripts

### 1. `New-CSRWithSAN.ps1`
Generates a Certificate Signing Request (CSR) with Subject Alternative Names (SANs) using a graphical Windows Forms interface.

**Features:**
- GUI form for subject fields (CN, O, OU, L, S, C) and SAN entries (DNS + IP)
- Dynamically builds a `certreq`-compatible `.inf` file
- Generates the CSR via `certreq.exe`
- Optionally validates the CSR with `certutil -dump`
- Optionally copies the CSR to clipboard or saves it to disk
- Cleans up temporary files after execution

**Requirements:** Windows, PowerShell 5.1+, `certreq.exe`, `certutil.exe`

**Usage:**
```powershell
.\New-CSRWithSAN.ps1
.\New-CSRWithSAN.ps1 -OutputPath "D:\PKI\CSRs"
```

---

### 2. `Export-CertificateToPfxAndPem.ps1`
Imports a CER certificate into the local machine store, exports it as a PFX, and optionally extracts PEM + KEY files using OpenSSL.

**Features:**
- Imports CER into `LocalMachine\My`
- Verifies private key presence before attempting PFX export
- Generates a secure random PFX password
- Saves a DPAPI-protected password file (bound to current user/machine)
- Validates the exported PFX
- Optionally extracts PEM + KEY via OpenSSL (password passed via temp file — never exposed in process list)
- Full transcript + per-step logging

**Requirements:** Windows, PowerShell 5.1+, Administrator rights, OpenSSL in PATH (PEM extraction only)

> **Security note:** The `.pwd` file is DPAPI-encrypted and can only be decrypted by the same Windows user account on the same machine. It is not portable across machines or accounts.

**Usage:**
```powershell
.\Export-CertificateToPfxAndPem.ps1 `
    -CertificatePath "C:\certs\mycert.cer" `
    -CertificateName "MYCERT" `
    -ExtractPem

.\Export-CertificateToPfxAndPem.ps1 `
    -CertificatePath "C:\certs\mycert.cer" `
    -CertificateName "MYCERT" `
    -WorkingDirectory "D:\PKI\Output"
```

---

### 3. `Add-SANCertificateExtension.ps1`
Injects Subject Alternative Name (SAN) extensions into a pending certificate request on an Enterprise CA, using Windows COM objects.

**Features:**
- Works on requests in **Pending** state only (not Issued or Denied)
- Uses `X509Enrollment.CX509ExtensionAlternativeNames` COM objects for correct DER encoding
- Explicit COM object release via `Marshal.ReleaseComObject`
- Enriched error output including `HResult` for COM failures
- DNS SAN type only (type `0x3` — `XCN_CERT_ALT_NAME_DNS_NAME`)

**Requirements:** Windows, PowerShell 5.1+, Administrator rights, AD CS tools or RSAT

> **Prerequisite:** The certificate template must be configured for CA Manager approval (manual issuance). V1 templates are not supported — use V2 or V3 templates.

**Usage:**
```powershell
Add-SANCertificateExtension `
    -BSTRCA "CA01\MyCompany-IssuingCA" `
    -RequestID 48 `
    -AlternativeNames "srv01.corp.com","srv01","srv01.internal.corp.com"

$sans = @("web01.corp.com", "web01", "www.corp.com")
Add-SANCertificateExtension `
    -BSTRCA "CA01\MyCompany-IssuingCA" `
    -RequestID 112 `
    -AlternativeNames $sans
```

---

## Typical PKI workflow

| Step | Script |
|---|---|
| 1. Generate a CSR with SANs | `New-CSRWithSAN.ps1` |
| 2. Submit CSR to CA — request goes Pending | Manual via `certreq` or CA web enrollment |
| 3. Inject additional SANs on the pending request | `Add-SANCertificateExtension.ps1` |
| 4. Issue the certificate from certsrv.msc | Manual — CA Manager approval |
| 5. Export PFX + PEM from the issued CER | `Export-CertificateToPfxAndPem.ps1` |

---

## Requirements summary

| Requirement | Details |
|---|---|
| OS | Windows (all scripts) |
| PowerShell | 5.1 or later |
| Privileges | Administrator (all scripts) |
| `certreq.exe` | `New-CSRWithSAN.ps1` |
| `certutil.exe` | `Submit-CSRToEnterpriseCA.ps1` |
| OpenSSL in PATH | `Export-CertificateToPfxAndPem.ps1` (PEM only) |
| AD CS / RSAT | `Add-SANCertificateExtension.ps1` |

---

## Repository structure

| Path | Description |
|---|---|
| `src/New-CSRWithSAN.ps1` | CSR generation GUI |
| `src/Export-CertificateToPfxAndPem.ps1` | PFX + PEM export |
| `src/Add-SANCertificateExtension.ps1` | SAN injection on pending request |
| `examples/` | Example invocations |
| `LICENSE` | License file |
| `README.md` | This file |

---

## Author

**Brahim O.**
`Add-SANCertificateExtension` is based on original work by [Vadim Podans](https://www.sysadmins.lv), extended and improved.

Feel free to open issues or submit pull requests.

---

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
