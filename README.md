# ADPrincipalCertificate

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)](https://docs.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/richardhicks/adprincipalcertificate/blob/main/LICENSE)
[![Version](https://img.shields.io/badge/Version-1.1-blue)](https://github.com/richardhicks/adprincipalcertificate)

A PowerShell module for managing and reporting on certificates attached to Active Directory principals (users, computers, and service accounts).

## Overview

The ADPrincipalCertificate module provides cmdlets for discovering, viewing, and managing certificates stored in the `userCertificate` attribute of Active Directory objects. This is particularly useful for organizations using certificate-based authentication, smart cards, or other PKI-enabled services.

## Requirements

- PowerShell 5.1 or later
- Active Directory PowerShell module
- Appropriate permissions to read/write AD objects

## Installation

### PowerShell Gallery (Recommended)

The ADPrincipalCertificate module is available on the [PowerShell Gallery](https://www.powershellgallery.com/packages/ADPrincipalCertificate). Install it using the following command:

```powershell
Install-Module -Name ADPrincipalCertificate
```

To install for the current user only (no admin rights required):

```powershell
Install-Module -Name ADPrincipalCertificate -Scope CurrentUser
```

To update to the latest version:

```powershell
Update-Module -Name ADPrincipalCertificate
```

### Manual Installation

Alternatively, copy the `ADPrincipalCertificate` folder to one of your PowerShell module paths:

```powershell
# User-specific module path
$env:USERPROFILE\Documents\WindowsPowerShell\Modules\

# System-wide module path
$env:ProgramFiles\WindowsPowerShell\Modules\
```

Then import the module:

```powershell
Import-Module ADPrincipalCertificate
```

## Functions

| Function | Description |
|----------|-------------|
| `Show-ADPrincipalCertificate` | Enumerates AD principals that have certificates attached |
| `Get-ADPrincipalCertificate` | Retrieves and displays detailed certificate information for AD principals |
| `Add-ADPrincipalCertificate` | Adds certificates to AD principals from certificate files |
| `Remove-ADPrincipalCertificate` | Removes certificates from AD principals |
| `Find-CertificateTemplateWithPublishInAD` | Finds certificate templates with "Publish in Active Directory" enabled |

## Usage Examples

### Show-ADPrincipalCertificate

Use `Show-ADPrincipalCertificate` to enumerate AD principals that have certificates attached. This is useful for discovering which users, computers, or service accounts have certificates before retrieving detailed certificate information. The output can be piped to `Get-ADPrincipalCertificate` for detailed certificate analysis.

```powershell
# Show all principals with certificates
Show-ADPrincipalCertificate

# Show only users with certificates
Show-ADPrincipalCertificate -PrincipalType User

# Show only computers with certificates
Show-ADPrincipalCertificate -PrincipalType Computer

# Show only service accounts with certificates
Show-ADPrincipalCertificate -PrincipalType ServiceAccount

# Show members of a specific group that have certificates
Show-ADPrincipalCertificate -PrincipalType Group -GroupName 'VPN Users'

# Show principals with CA-issued certificates only (exclude self-signed)
Show-ADPrincipalCertificate -ExcludeSelfSignedCertificate

# Show users with CA-issued certificates
Show-ADPrincipalCertificate -PrincipalType User -ExcludeSelfSignedCertificate
```

#### Piping to Get-ADPrincipalCertificate

Enumerate principals with certificates, then retrieve detailed certificate information:

```powershell
# Find all users with certificates and get their certificate details
Show-ADPrincipalCertificate -PrincipalType User | Select-Object -ExpandProperty AccountName | Get-ADPrincipalCertificate

# Find all computers with certificates and get their certificate details
Show-ADPrincipalCertificate -PrincipalType Computer | Select-Object -ExpandProperty AccountName | Get-ADPrincipalCertificate

# Find all principals with CA-issued certificates and get details
Show-ADPrincipalCertificate -ExcludeSelfSignedCertificate | Select-Object -ExpandProperty AccountName | Get-ADPrincipalCertificate
```

### Get-ADPrincipalCertificate

Retrieves detailed certificate information including subject, issuer, thumbprint, validity dates, key type, and more.

#### Basic Usage

```powershell
# Get certificates for a specific user
Get-ADPrincipalCertificate -Identity 'jsmith'

# Get certificates for a computer account
Get-ADPrincipalCertificate -Identity 'YOURPC01'

# Get certificates for multiple principals
Get-ADPrincipalCertificate -Identity 'jsmith', 'jdoe', 'YOURPC01'
```

#### Pipeline Input from Get-ADUser

```powershell
# Get certificates for a single user via pipeline
Get-ADUser -Identity 'jsmith' | Get-ADPrincipalCertificate

# Get certificates for all users in a department
Get-ADUser -Filter {Department -eq 'Human Resources'} | Get-ADPrincipalCertificate

# Get certificates for users in a specific OU
Get-ADUser -Filter * -SearchBase 'OU=Executives,DC=contoso,DC=com' | Get-ADPrincipalCertificate

# Get certificates for users with a specific title
Get-ADUser -Filter {Title -like '*Manager*'} | Get-ADPrincipalCertificate
```

#### Pipeline Input from Get-ADComputer

```powershell
# Get certificates for a single computer via pipeline
Get-ADComputer -Identity 'YOURPC01' | Get-ADPrincipalCertificate

# Get certificates for all computers in an OU
Get-ADComputer -Filter * -SearchBase 'OU=Servers,DC=contoso,DC=com' | Get-ADPrincipalCertificate

# Get certificates for computers matching a name pattern
Get-ADComputer -Filter {Name -like 'WKS*'} | Get-ADPrincipalCertificate
```

#### Pipeline Input from Get-ADServiceAccount

```powershell
# Get certificates for a service account
Get-ADServiceAccount -Identity 'svc_webapp' | Get-ADPrincipalCertificate

# Get certificates for all service accounts
Get-ADServiceAccount -Filter * | Get-ADPrincipalCertificate
```

#### Reading Identities from a Text File

```powershell
# Read user names from a text file (one per line)
Get-Content -Path .\users.txt | Get-ADPrincipalCertificate

# Read computer names from a text file
Get-Content -Path .\computers.txt | Get-ADPrincipalCertificate

# Read mixed principal names from a file
Get-Content -Path .\principals.txt | Get-ADPrincipalCertificate
```

#### Filtering for Expired Certificates

```powershell
# Find expired user certificates
Get-ADUser -Filter * | Get-ADPrincipalCertificate | Where-Object { $_.Expires -lt (Get-Date) }

# Find expired computer certificates
Get-ADComputer -Filter * | Get-ADPrincipalCertificate | Where-Object { $_.Expires -lt (Get-Date) }

# Find certificates expiring within the next 30 days
Get-ADUser -Filter * | Get-ADPrincipalCertificate | Where-Object {
    $_.Expires -ge (Get-Date) -and $_.Expires -lt (Get-Date).AddDays(30)
}

# Find certificates expiring within the next 90 days for a specific department
Get-ADUser -Filter {Department -eq 'IT'} | Get-ADPrincipalCertificate | Where-Object {
    $_.Expires -ge (Get-Date) -and $_.Expires -lt (Get-Date).AddDays(90)
}

# Get all expired certificates and export to CSV
Get-ADUser -Filter * | Get-ADPrincipalCertificate | Where-Object { $_.Expires -lt (Get-Date) } |
    Export-Csv -Path 'C:\Temp\ExpiredUserCertificates.csv' -NoTypeInformation

# Find expired device certificates from computers in a specific OU
Get-ADComputer -Filter * -SearchBase 'OU=Workstations,DC=contoso,DC=com' |
    Get-ADPrincipalCertificate | Where-Object { $_.Expires -lt (Get-Date) }
```

#### Exporting Certificate Data

```powershell
# Export certificate details to CSV
Get-ADUser -Filter * | Get-ADPrincipalCertificate -OutCsv 'C:\Temp\AllUserCertificates.csv'

# Generate an HTML report
Get-ADUser -Filter * | Get-ADPrincipalCertificate -GenerateReport 'C:\Temp\CertificateReport.html'

# Export certificates to files
Get-ADUser -Identity 'jsmith' | Get-ADPrincipalCertificate -OutFile
```

#### Excluding Self-Signed Certificates

```powershell
# Get only CA-issued certificates (exclude self-signed)
Get-ADPrincipalCertificate -Identity 'jsmith' -ExcludeSelfSignedCertificate

# Find expired CA-issued certificates only
Get-ADUser -Filter * | Get-ADPrincipalCertificate -ExcludeSelfSignedCertificate |
    Where-Object { $_.Expires -lt (Get-Date) }
```

### Add-ADPrincipalCertificate

Adds certificates from file(s) to the `userCertificate` attribute of AD principals. Supports DER-encoded (.cer, .crt, .der) and PEM/Base64-encoded (.pem, .crt) certificate files.

#### Basic Usage

```powershell
# Add a certificate to a user
Add-ADPrincipalCertificate -Identity 'jsmith' -Certificate 'C:\Certs\user.cer'

# Add multiple certificates to a user
Add-ADPrincipalCertificate -Identity 'jsmith' -Certificate 'cert1.cer', 'cert2.cer'

# Add a certificate to multiple principals
Add-ADPrincipalCertificate -Identity 'jsmith', 'jdoe' -Certificate 'C:\Certs\shared.cer'
```

#### Pipeline Input from AD Cmdlets

```powershell
# Pipe a user object and add a certificate
Get-ADUser -Identity 'jsmith' | Add-ADPrincipalCertificate -Certificate 'C:\Certs\user.cer'

# Pipe a computer object and add a certificate
Get-ADComputer -Identity 'YOURPC01' | Add-ADPrincipalCertificate -Certificate 'C:\Certs\computer.cer'

# Pipe a service account and add a certificate
Get-ADServiceAccount -Identity 'svc_webapp' | Add-ADPrincipalCertificate -Certificate 'C:\Certs\svc.cer'

# Add a certificate to all users in a department
Get-ADUser -Filter {Department -eq 'Human Resources'} | Add-ADPrincipalCertificate -Certificate 'C:\Certs\hr.cer'
```

#### Piping Certificate File Paths

```powershell
# Pipe certificate file paths to add multiple certificates to a user
'cert1.cer', 'cert2.cer' | Add-ADPrincipalCertificate -Identity 'jsmith'

# Read certificate file paths from a text file (one per line)
Get-Content -Path .\certs.txt | Add-ADPrincipalCertificate -Identity 'jsmith'

# Pipe certificate files using Get-ChildItem
(Get-ChildItem -Path C:\Certs\*.cer).FullName | Add-ADPrincipalCertificate -Identity 'jsmith'
```

#### Using WhatIf

```powershell
# Preview what would happen without making changes
Add-ADPrincipalCertificate -Identity 'YOURPC01' -Certificate 'C:\Certs\computer.cer' -WhatIf
```

### Remove-ADPrincipalCertificate

Removes certificates from AD principals. **Use with caution - this is a destructive operation.**

```powershell
# Remove managed certificates from a user (preserves self-signed)
Remove-ADPrincipalCertificate -Identity 'jsmith'

# Remove certificates via pipeline
Get-ADUser -Identity 'jsmith' | Remove-ADPrincipalCertificate

# Preview what would be removed without making changes
Get-ADComputer -Identity 'YOURPC01' | Remove-ADPrincipalCertificate -WhatIf

# Remove certificates without confirmation prompts (use carefully)
Remove-ADPrincipalCertificate -Identity 'jsmith' -Force -Confirm:$false

# Remove ALL certificates including self-signed
Remove-ADPrincipalCertificate -Identity 'jsmith' -IncludeSelfSignedCertificate
```

### Find-CertificateTemplateWithPublishInAD

Finds certificate templates configured to publish certificates to Active Directory.

```powershell
# Find all templates with "Publish in Active Directory" enabled
Find-CertificateTemplateWithPublishInAD

# Find templates with verbose output
Find-CertificateTemplateWithPublishInAD -Verbose
```

## Common Scenarios

### Audit All Expired Certificates in the Domain

```powershell
# Create a comprehensive report of all expired certificates
$ExpiredCerts = @()

# Get expired user certificates
$ExpiredCerts += Get-ADUser -Filter * | Get-ADPrincipalCertificate |
    Where-Object { $_.Expires -lt (Get-Date) }

# Get expired computer certificates
$ExpiredCerts += Get-ADComputer -Filter * | Get-ADPrincipalCertificate |
    Where-Object { $_.Expires -lt (Get-Date) }

# Get expired service account certificates
$ExpiredCerts += Get-ADServiceAccount -Filter * | Get-ADPrincipalCertificate |
    Where-Object { $_.Expires -lt (Get-Date) }

# Export the results
$ExpiredCerts | Export-Csv -Path 'C:\Temp\AllExpiredCertificates.csv' -NoTypeInformation
```

### Find Certificates Expiring Soon

```powershell
# Find all certificates expiring in the next 30 days
$ExpiringCerts = Get-ADUser -Filter * | Get-ADPrincipalCertificate |
    Where-Object { $_.Expires -ge (Get-Date) -and $_.Expires -lt (Get-Date).AddDays(30) } |
    Sort-Object Expires

# Display results sorted by expiration date
$ExpiringCerts | Format-Table AccountName, Subject, Expires -AutoSize
```

### Process Principals from a Text File

Create a text file (`principals.txt`) with one principal name per line:

```
jsmith
jdoe
YOURPC01
svc_webapp
```

Then process the file:

```powershell
# Get certificate details for all principals in the file
Get-Content -Path .\principals.txt | Get-ADPrincipalCertificate

# Find expired certificates for principals in the file
Get-Content -Path .\principals.txt | Get-ADPrincipalCertificate |
    Where-Object { $_.Expires -lt (Get-Date) }

# Export results to CSV
Get-Content -Path .\principals.txt | Get-ADPrincipalCertificate -OutCsv 'C:\Temp\Results.csv'
```

### Clean Up Expired Certificates

```powershell
# Find users with expired certificates
$UsersWithExpired = Get-ADUser -Filter * | Get-ADPrincipalCertificate |
    Where-Object { $_.Expires -lt (Get-Date) } |
    Select-Object -ExpandProperty AccountName -Unique

# Preview the removal
$UsersWithExpired | ForEach-Object { Remove-ADPrincipalCertificate -Identity $_ -WhatIf }

# Remove the expired certificates (after verification)
$UsersWithExpired | ForEach-Object { Remove-ADPrincipalCertificate -Identity $_ }
```

## Output Properties

The `Get-ADPrincipalCertificate` cmdlet returns objects with the following properties:

| Property | Description |
|----------|-------------|
| `AccountName` | The SamAccountName of the AD principal |
| `AccountType` | The object class (user, computer, etc.) |
| `CertificateNumber` | The certificate index (when multiple certificates exist) |
| `Subject` | The certificate subject |
| `Issuer` | The certificate issuer |
| `SerialNumber` | The certificate serial number |
| `Thumbprint` | The certificate thumbprint |
| `Issued` | The certificate's NotBefore date |
| `Expires` | The certificate's NotAfter date |
| `Policies` | Enhanced Key Usage / Application Policies |
| `KeyType` | The public key algorithm |
| `KeyLength` | The key size in bits |
| `SignatureAlgorithm` | The signature algorithm used |

## Author

Richard M. Hicks Consulting, Inc.

- Website: [https://www.richardhicks.com/](https://www.richardhicks.com/)
- GitHub: [@richardhicks](https://github.com/richardhicks)
- X: [@richardhicks](https://x.com/richardhicks)

## License

This project is provided as-is without warranty. Please test thoroughly in a non-production environment before use.

