<#

.SYNOPSIS
    Display certificate details for Active Directory principals.

.DESCRIPTION
    This function retrieves and displays detailed certificate information for AD principals (users, computers, service accounts, or other AD objects) that have certificates attached. The script accepts pipeline input from Get-ADUser, Get-ADComputer, Get-ADServiceAccount, or Get-ADObject cmdlets.

.PARAMETER Identity
    One or more AD principal identities. This can be a Distinguished Name, SamAccountName, ObjectGUID, or SID. This parameter accepts pipeline input and multiple values.

.PARAMETER OutFile
    When specified, exports the certificate(s) to file(s). Files are named using the AccountName with a .crt extension. Multiple certificates are numbered sequentially (e.g., AccountName_001.crt, AccountName_002.crt).

.PARAMETER OutCsv
    Specifies the path to a CSV file where certificate information will be exported. The CSV file will contain all certificate details for the queried principals.

.PARAMETER GenerateReport
    Specifies the path to an HTML file where a formatted certificate report will be generated. The report includes a styled table with all certificate details and summary statistics.

.PARAMETER ExcludeSelfSignedCertificate
    When specified, excludes self-signed certificates (where Subject equals Issuer) from the output.

.INPUTS
    Microsoft.ActiveDirectory.Management.ADUser, Microsoft.ActiveDirectory.Management.ADComputer, Microsoft.ActiveDirectory.Management.ADServiceAccount, Microsoft.ActiveDirectory.Management.ADObject, or String values.

.OUTPUTS
    Custom objects containing certificate details including AccountName, AccountType, Subject, Issuer, Thumbprint, Issued, Expires, EKU (Enhanced Key Usage/Application Policies), SerialNumber, KeyType, KeyLength, and SignatureAlgorithm.

.EXAMPLE
    Get-ADPrincipalCertificate -Identity 'juser'

    Displays certificate details for user juser.

.EXAMPLE
    Get-ADUser juser | Get-ADPrincipalCertificate

    Pipes a user object to display certificate details.

.EXAMPLE
    Get-ADComputer 'app1' | Get-ADPrincipalCertificate

    Pipes a computer object to display certificate details.

.EXAMPLE
    Get-ADServiceAccount 'svc_app' | Get-ADPrincipalCertificate

    Pipes a service account object to display certificate details.

.EXAMPLE
    Get-ADUser -Filter {Department -eq 'Human Resources'} | Get-ADPrincipalCertificate

    Displays certificate details for all users in the Human Resources department.

.EXAMPLE
    Get-ADServiceAccount -Filter * | Get-ADPrincipalCertificate

    Displays certificate details for all service accounts that have certificates.

.EXAMPLE
    Get-ADPrincipalCertificate -Identity 'juser' -OutFile

    Displays certificate details for user juser and exports the certificate(s) to file(s).

.EXAMPLE
    Get-ADUser juser | Get-ADPrincipalCertificate -OutFile

    Pipes a user object, displays certificate details, and exports to juser.crt (or juser_001.crt, juser_002.crt for multiple certificates).

.EXAMPLE
    Get-ADPrincipalCertificate -Identity 'juser' -OutCsv 'C:\Temp\certificates.csv'

    Displays certificate details for user juser and exports the information to a CSV file.

.EXAMPLE
    Get-ADUser -Filter {Department -eq 'Human Resources'} | Get-ADPrincipalCertificate -OutCsv 'C:\Temp\hr_certificates.csv'

    Exports certificate details for all users in the Human Resources department to a CSV file.

.EXAMPLE
    Get-ADPrincipalCertificate -Identity 'juser' -GenerateReport 'C:\Temp\certificates.html'

    Displays certificate details for user juser and generates an HTML report.

.EXAMPLE
    Get-ADUser -Filter * | Get-ADPrincipalCertificate -GenerateReport 'C:\Temp\all_certificates.html'

    Generates an HTML report containing certificate details for all users in Active Directory.

.EXAMPLE
    Get-ADPrincipalCertificate -Identity 'app1', 'app2'

    Displays certificate details for multiple computers app1 and app2.

.EXAMPLE
    Get-Content -Path .\users.txt | Get-ADPrincipalCertificate

    Reads principal identities from a text file (one per line) and displays certificate details for each.

.EXAMPLE
    Get-ADPrincipalCertificate -Identity 'juser' -ExcludeSelfSignedCertificate

    Displays certificate details for user juser, excluding any self-signed certificates.

.EXAMPLE
    Get-ADComputer -Filter * | Get-ADPrincipalCertificate -ExcludeSelfSignedCertificate

    Displays certificate details for all computer accounts, excluding self-signed certificates.

.LINK
    https://github.com/richardhicks/adprincipalcertificate/blob/main/Functions/Get-ADPrincipalCertificate.ps1

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:        1.0
    Creation Date:  February 7, 2026
    Last Updated:   February 7, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

Function Get-ADPrincipalCertificate {

    # Prerequisites
    #Requires -Module ActiveDirectory

    [CmdletBinding()]

    Param (

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0, HelpMessage = 'Specify one or more AD principal identities')]
        [Alias('DistinguishedName', 'SamAccountName', 'ObjectGUID', 'SID', 'Name')]
        [ValidateNotNullOrEmpty()]
        $Identity,
        [switch]$OutFile,
        [Parameter(HelpMessage = 'Specify a path to export certificate information to a CSV file')]
        [ValidateNotNullOrEmpty()]
        [string]$OutCsv,
        [Parameter(HelpMessage = 'Specify a path to generate an HTML certificate report')]
        [ValidateNotNullOrEmpty()]
        [string]$GenerateReport,
        [Parameter(HelpMessage = 'Exclude self-signed certificates from the output')]
        [switch]$ExcludeSelfSignedCertificate

    )

    Begin {

        Write-Verbose 'Begin certificate detail retrieval...'

        # Define required properties once in Begin block for efficiency
        $Script:RequiredProperties = @('userCertificate', 'SamAccountName', 'ObjectClass', 'DistinguishedName')

        # Initialize collection to store results for CSV export or HTML report
        If ($OutCsv -or $GenerateReport) {

            $Script:CollectedResults = [System.Collections.Generic.List[PSCustomObject]]::new()

        }

    }

    Process {

        # Handle both single and array inputs correctly
        $IdsToProcess = If ($Identity -is [array]) { $Identity } Else { , $Identity }

        # Notify user if no identity was provided
        If ($null -eq $Identity) {

            Write-Warning 'No input provided. Specify an identity using -Identity or pipe AD objects to this script.'
            Return

        }

        ForEach ($Id in $IdsToProcess) {

            Try {

                $Principal = $null

                # Check if this is already an AD object with required properties
                If ($Id.PSObject.TypeNames -match 'Microsoft\.ActiveDirectory\.Management\.AD(User|Computer|ServiceAccount|Object)') {

                    # If piped object already has userCertificate with data, use it directly
                    If ($Id.userCertificate -and $Id.userCertificate.Count -gt 0) {

                        Write-Verbose "Using piped AD object: $($Id.SamAccountName)"
                        $Principal = $Id

                    }

                    Else {

                        # Re-query to get userCertificate property
                        Write-Verbose "Re-querying AD object for certificate data: $($Id.DistinguishedName)"
                        $IdentityValue = $Id.DistinguishedName
                        $ObjectClass = $Id.ObjectClass

                    }

                }

                Else {

                    Write-Verbose "Retrieving AD principal `"$Id`"..."
                    $IdentityValue = $Id
                    $ObjectClass = $null

                }

                # Query AD if we don't already have the complete object
                If (-not $Principal) {

                    Switch ($ObjectClass) {

                        'User' {

                            $Principal = Get-ADUser -Identity $IdentityValue -Properties $Script:RequiredProperties -ErrorAction Stop

                        }

                        'Computer' {

                            $Principal = Get-ADComputer -Identity $IdentityValue -Properties $Script:RequiredProperties -ErrorAction Stop

                        }

                        { $_ -in 'msDS-ManagedServiceAccount', 'msDS-GroupManagedServiceAccount' } {

                            $Principal = Get-ADServiceAccount -Identity $IdentityValue -Properties $Script:RequiredProperties -ErrorAction Stop

                        }

                        Default {

                            # Try to find the object using cascading approach
                            Try {

                                $Principal = Get-ADUser -Identity $IdentityValue -Properties $Script:RequiredProperties -ErrorAction Stop
                                Write-Verbose "Found user account `"$IdentityValue`"."

                            }

                            Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

                                Try {

                                    $Principal = Get-ADComputer -Identity $IdentityValue -Properties $Script:RequiredProperties -ErrorAction Stop
                                    Write-Verbose "Found computer account `"$IdentityValue`"."

                                }

                                Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

                                    Try {

                                        $Principal = Get-ADServiceAccount -Identity $IdentityValue -Properties $Script:RequiredProperties -ErrorAction Stop
                                        Write-Verbose "Found service account `"$IdentityValue`"."

                                    }

                                    Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

                                        $Principal = Get-ADObject -Identity $IdentityValue -Properties $Script:RequiredProperties -ErrorAction Stop
                                        Write-Verbose "Found AD object `"$IdentityValue`"."

                                    }

                                }

                            }

                        }

                    }

                }

                # Validate certificate presence
                If (-not $Principal.userCertificate -or $Principal.userCertificate.Count -eq 0) {

                    Write-Verbose "No certificates found for principal `"$($Principal.SamAccountName)`"."
                    Continue

                }

                Write-Verbose "Found $($Principal.userCertificate.Count) certificate(s) for $($Principal.SamAccountName)"

                # Determine account name for file naming
                $BaseFileName = If ([string]::IsNullOrWhiteSpace($Principal.SamAccountName)) {

                    If ($Principal.DistinguishedName -match 'CN=([^,]+)') {

                        $Matches[1].TrimEnd('$')

                    }

                    Else {

                        Write-Warning "Unable to determine account name for principal: $($Principal.DistinguishedName)"
                        Continue

                    }

                }

                Else {

                    $Principal.SamAccountName.TrimEnd('$')

                }

                # Process each certificate
                $CertificateCount = $Principal.userCertificate.Count
                $CertificateNumber = 0
                $NonSelfSignedCertFound = $False

                ForEach ($CertBytes in $Principal.userCertificate) {

                    $CertificateNumber++

                    Try {

                        # Create X509Certificate2 object from binary data
                        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)

                        # Skip self-signed certificates if ExcludeSelfSignedCertificate is specified
                        If ($ExcludeSelfSignedCertificate -and $Certificate.Subject -eq $Certificate.Issuer) {

                            Write-Verbose "Skipping self-signed certificate for $($Principal.SamAccountName) (Thumbprint: $($Certificate.Thumbprint))"
                            Continue

                        }

                        # Track that we found at least one non-self-signed certificate
                        $NonSelfSignedCertFound = $True

                        # Export certificate if requested
                        If ($OutFile) {

                            $FileName = If ($CertificateCount -eq 1) {

                                "$BaseFileName.crt"

                            }

                            Else {

                                '{0}_{1:D3}.crt' -f $BaseFileName, $CertificateNumber

                            }

                            Try {

                                # Export in PEM format
                                $PemCert = @(

                                    '-----BEGIN CERTIFICATE-----'
                                    [Convert]::ToBase64String($CertBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
                                    '-----END CERTIFICATE-----'

                                )

                                -join "`r`n"

                                $PemCert | Out-File -FilePath $FileName -Encoding ASCII -Force
                                Write-Verbose "Certificate exported to `"$FileName`"."

                            }

                            Catch {

                                Write-Warning "Error exporting certificate to file '$FileName': $_"

                            }

                        }

                        # Extract Enhanced Key Usage (EKU) / Application Policies
                        $EkuExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
                        $EkuList = If ($EkuExtension) {

                            $EkuExtension.EnhancedKeyUsages | ForEach-Object {

                                If ($_.FriendlyName) { $_.FriendlyName } Else { $_.Value }

                            }

                        }

                        Else {

                            $null

                        }

                        # Build certificate details object
                        $CertDetails = [PSCustomObject]@{

                            AccountName        = $Principal.SamAccountName
                            AccountType        = $Principal.ObjectClass
                            CertificateNumber  = $CertificateNumber
                            Subject            = $Certificate.Subject
                            Issuer             = $Certificate.Issuer
                            SerialNumber       = $Certificate.SerialNumber
                            Thumbprint         = $Certificate.Thumbprint
                            Issued             = $Certificate.NotBefore
                            Expires            = $Certificate.NotAfter
                            Policies           = If ($EkuList) { $EkuList -join '; ' } Else { $null }
                            KeyType            = $Certificate.PublicKey.Oid.FriendlyName
                            KeyLength          = $Certificate.PublicKey.Key.KeySize
                            SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName

                        }

                        # Add to collection if exporting to CSV or generating report
                        If ($OutCsv -or $GenerateReport) {

                            $Script:CollectedResults.Add($CertDetails)

                        }

                        # Output certificate details
                        $CertDetails

                    }

                    Catch {

                        Write-Warning "Error processing certificate $CertificateNumber for '$($Principal.SamAccountName)': $_"

                    }

                }

                # Warn if ExcludeSelfSignedCertificate was specified and all certificates were self-signed
                If ($ExcludeSelfSignedCertificate -and -not $NonSelfSignedCertFound) {

                    Write-Warning "No managed certificates matching the specified criteria were found for principal `"$($Principal.SamAccountName)`"."

                }

            }

            Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

                Write-Warning "AD principal not found: $Id"

            }

            Catch {

                Write-Warning "Error retrieving certificate details for '$Id': $_"

            }

        }

    }

    End {

        # Export to CSV if requested
        If ($OutCsv -and $Script:CollectedResults.Count -gt 0) {

            Try {

                $Script:CollectedResults | Export-Csv -Path $OutCsv -NoTypeInformation -Force
                Write-Verbose "Certificate information exported to `"$OutCsv`"."

            }

            Catch {

                Write-Warning "Error exporting to CSV file '$OutCsv': $_"

            }

        }
        ElseIf ($OutCsv -and $Script:CollectedResults.Count -eq 0) {

            Write-Warning "No certificate data to export to CSV file."

        }

        # Generate HTML report if requested
        If ($GenerateReport -and $Script:CollectedResults.Count -gt 0) {

            Try {

                # Calculate summary statistics
                $TotalCertificates = $Script:CollectedResults.Count
                $UniqueAccounts = ($Script:CollectedResults | Select-Object -Property AccountName -Unique).Count
                $ExpiredCertificates = ($Script:CollectedResults | Where-Object { $_.Expires -lt (Get-Date) }).Count
                $ExpiringIn30Days = ($Script:CollectedResults | Where-Object { $_.Expires -ge (Get-Date) -and $_.Expires -lt (Get-Date).AddDays(30) }).Count
                $ExpiringIn90Days = ($Script:CollectedResults | Where-Object { $_.Expires -ge (Get-Date) -and $_.Expires -lt (Get-Date).AddDays(90) }).Count
                $SelfSignedCertificates = ($Script:CollectedResults | Where-Object { $_.Subject -eq $_.Issuer }).Count

                # Build HTML content
                $HtmlHead = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Principal Certificate Report</title>
    <style>
        body {
            font-family: Segoe UI, Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        .summary {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .summary-item {
            background-color: #3498db;
            color: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .summary-item.warning {
            background-color: #f39c12;
        }
        .summary-item.danger {
            background-color: #e74c3c;
        }
        .summary-item.info {
            background-color: #95a5a6;
        }
        .summary-item .number {
            font-size: 2em;
            font-weight: bold;
        }
        .summary-item .label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th {
            background-color: #2c3e50;
            color: white;
            padding: 12px 8px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 10px 8px;
            border-bottom: 1px solid #ecf0f1;
            font-size: 0.9em;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        tr.expired {
            background-color: #fadbd8;
        }
        tr.expiring-soon {
            background-color: #fdebd0;
        }
        tr.self-signed {
            background-color: #d5d8dc;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.85em;
            margin-top: 20px;
        }
        .thumbprint {
            font-family: Consolas, monospace;
            font-size: 0.85em;
        }
    </style>
</head>
<body>
    <h1>AD Principal Certificate Report</h1>
"@

                $HtmlSummary = @"
    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="number">$TotalCertificates</div>
                <div class="label">Total Certificates</div>
            </div>
            <div class="summary-item">
                <div class="number">$UniqueAccounts</div>
                <div class="label">Unique Accounts</div>
            </div>
            <div class="summary-item info">
                <div class="number">$SelfSignedCertificates</div>
                <div class="label">Self-Signed</div>
            </div>
            <div class="summary-item danger">
                <div class="number">$ExpiredCertificates</div>
                <div class="label">Expired</div>
            </div>
            <div class="summary-item warning">
                <div class="number">$ExpiringIn30Days</div>
                <div class="label">Expiring in 30 Days</div>
            </div>
            <div class="summary-item warning">
                <div class="number">$ExpiringIn90Days</div>
                <div class="label">Expiring in 90 Days</div>
            </div>
        </div>
    </div>
"@

                # Build table rows
                $TableRows = ForEach ($Cert in $Script:CollectedResults) {

                    $RowClass = ''
                    If ($Cert.Expires -lt (Get-Date)) {

                        $RowClass = ' class="expired"'

                    }
                    ElseIf ($Cert.Expires -lt (Get-Date).AddDays(30)) {

                        $RowClass = ' class="expiring-soon"'

                    }
                    ElseIf ($Cert.Subject -eq $Cert.Issuer) {

                        $RowClass = ' class="self-signed"'

                    }

                    $ExpiresFormatted = $Cert.Expires.ToString('yyyy-MM-dd HH:mm')
                    $IssuedFormatted = $Cert.Issued.ToString('yyyy-MM-dd HH:mm')

                    @"
        <tr$RowClass>
            <td>$([System.Web.HttpUtility]::HtmlEncode($Cert.AccountName))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($Cert.AccountType))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($Cert.Subject))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($Cert.Issuer))</td>
            <td class="thumbprint">$([System.Web.HttpUtility]::HtmlEncode($Cert.Thumbprint))</td>
            <td>$IssuedFormatted</td>
            <td>$ExpiresFormatted</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($Cert.KeyType))</td>
            <td>$($Cert.KeyLength)</td>
        </tr>
"@

                }

                $HtmlTable = @"
    <h2>Certificate Details</h2>
    <table>
        <thead>
            <tr>
                <th>Account Name</th>
                <th>Account Type</th>
                <th>Subject</th>
                <th>Issuer</th>
                <th>Thumbprint</th>
                <th>Issued</th>
                <th>Expires</th>
                <th>Key Type</th>
                <th>Key Length</th>
            </tr>
        </thead>
        <tbody>
$($TableRows -join "`n")
        </tbody>
    </table>
"@

                $HtmlFooter = @"
    <p class="timestamp">Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
</body>
</html>
"@

                # Combine and write HTML
                $HtmlContent = $HtmlHead + $HtmlSummary + $HtmlTable + $HtmlFooter
                $HtmlContent | Out-File -FilePath $GenerateReport -Encoding UTF8 -Force
                Write-Verbose "HTML report generated: `"$GenerateReport`"."

                # Open the report in the default browser
                Invoke-Item -Path $GenerateReport

            }

            Catch {

                Write-Warning "Error generating HTML report '$GenerateReport': $_"

            }

        }
        ElseIf ($GenerateReport -and $Script:CollectedResults.Count -eq 0) {

            Write-Warning "No certificate data to generate HTML report."

        }

        Write-Verbose 'Certificate detail retrieval completed.'

    }

}

# SIG # Begin signature block
# MIIf2QYJKoZIhvcNAQcCoIIfyjCCH8YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBOAHQE0MqXdzSE
# 31pIT0mBtUqCrmMKTOLQoVgWj3rGNqCCGpkwggNZMIIC36ADAgECAhAPuKdAuRWN
# A1FDvFnZ8EApMAoGCCqGSM49BAMDMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMT
# F0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMB4XDTIxMDQyOTAwMDAwMFoXDTM2MDQy
# ODIzNTk1OVowZDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9iYWwgRzMgQ29kZSBTaWduaW5nIEVDQyBT
# SEEzODQgMjAyMSBDQTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS7tKwnpUgNolNf
# jy6BPi9TdrgIlKKaqoqLmLWx8PwqFbu5s6UiL/1qwL3iVWhga5c0wWZTcSP8GtXK
# IA8CQKKjSlpGo5FTK5XyA+mrptOHdi/nZJ+eNVH8w2M1eHbk+HejggFXMIIBUzAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSbX7A2up0GrhknvcCgIsCLizh3
# 7TAfBgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxLxjAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcnQw
# QgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0R2xvYmFsUm9vdEczLmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEE
# ATAKBggqhkjOPQQDAwNoADBlAjB4vUmVZXEB0EZXaGUOaKncNgjB7v3UjttAZT8N
# /5Ovwq5jhqN+y7SRWnjsBwNnB3wCMQDnnx/xB1usNMY4vLWlUM7m6jh+PnmQ5KRb
# qwIN6Af8VqZait2zULLd8vpmdJ7QFmMwggP+MIIDhKADAgECAhANSjTahpCPwBMs
# vIE3k68kMAoGCCqGSM49BAMDMGQxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQgR2xvYmFsIEczIENvZGUgU2ln
# bmluZyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMB4XDTI0MTIwNjAwMDAwMFoXDTI3MTIy
# NDIzNTk1OVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
# FAYDVQQHEw1NaXNzaW9uIFZpZWpvMSQwIgYDVQQKExtSaWNoYXJkIE0uIEhpY2tz
# IENvbnN1bHRpbmcxJDAiBgNVBAMTG1JpY2hhcmQgTS4gSGlja3MgQ29uc3VsdGlu
# ZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFCbtcqpc7vGGM4hVM79U+7f0tKz
# o8BAGMJ/0E7JUwKJfyMJj9jsCNpp61+mBNdTwirEm/K0Vz02vak0Ftcb/3yjggHz
# MIIB7zAfBgNVHSMEGDAWgBSbX7A2up0GrhknvcCgIsCLizh37TAdBgNVHQ4EFgQU
# KIMkVkfISNUyQJ7bwvLm9sCIkxgwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBqwYDVR0fBIGjMIGgME6gTKBKhkho
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWdu
# aW5nRUNDU0hBMzg0MjAyMUNBMS5jcmwwTqBMoEqGSGh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEczQ29kZVNpZ25pbmdFQ0NTSEEzODQyMDIx
# Q0ExLmNybDCBjgYIKwYBBQUHAQEEgYEwfzAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFcGCCsGAQUFBzAChktodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWduaW5nRUNDU0hBMzg0MjAy
# MUNBMS5jcnQwCQYDVR0TBAIwADAKBggqhkjOPQQDAwNoADBlAjBMOsBb80qx6E6S
# 2lnnHafuyY2paoDtPjcfddKaB1HKnAy7WLaEVc78xAC84iW3l6ECMQDhOPD5JHtw
# YxEH6DxVDle5pLKfuyQHiY1i0I9PrSn1plPUeZDTnYKmms1P66nBvCkwggWNMIIE
# daADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAe
# Fw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC
# 4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWl
# fr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1j
# KS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dP
# pzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3
# pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJ
# pMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aa
# dMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXD
# j/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB
# 4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ
# 33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amy
# HeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYD
# VR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcN
# AQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxpp
# VCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6
# mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPH
# h6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCN
# NWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg6
# 2fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8h
# mS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0z
# ODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGP
# NRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1I
# pYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5A
# vftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDRe
# b6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBUR
# Jg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/ao
# fEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQ
# skBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJ
# lIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev
# +7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6B
# aaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IB
# XTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQ
# VvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9
# vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwb
# SI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTL
# xLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD
# 8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVk
# o43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRa
# Ps+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8
# cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRz
# W6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KC
# LPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau
# 1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPS
# xyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0
# aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1w
# aW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2
# MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAg
# UmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdw
# bHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9
# RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrU
# cCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iU
# SROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw
# 2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe4
# 6YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seA
# O+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSH
# lq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6
# EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDch
# Ic2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAM
# BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNV
# HSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3Rh
# bXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezR
# CESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0
# k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFO
# tj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLW
# U0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2n
# HkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIF
# eRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqR
# hoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7
# roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47Cdx
# VRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/r
# ptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL
# 6vdCvHlshtjdNXOCIUjsarfNZzGCBJYwggSSAgEBMHgwZDELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9i
# YWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEzODQgMjAyMSBDQTECEA1KNNqGkI/A
# Eyy8gTeTryQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgtwTGWgh2X29xurLZgx6SSiNQ
# ziEUBjsqMdCjFB3ecRIwCwYHKoZIzj0CAQUABEYwRAIgdLnmNlkqVZeoOehmoLZn
# DzIJLkW5Em4LsrqDL3LW8XcCICiMbqjxKz9VHOJ0h/vcq8xTKt6x+ucxL6lnECQZ
# 2ceaoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQ
# CoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDIwNzIxMzU1MFowLwYJKoZI
# hvcNAQkEMSIEICYWU1OcdMFXzFx/Li1s4Mo3pef1Y55Bv4peaQh/qqsEMA0GCSqG
# SIb3DQEBAQUABIICALLCSfhdTBfgfJj5mMCxqLMdZXZwXENP+K5/ytSug4SlRXmc
# hJv21IA2djcpzV/GQB+7CcYWMPxRQAL3e3GNA8Sw/VzBcfu3OdDjFutYG+imQOER
# Alb3o2iZNFHr9+KVFF5rI/+61N3BGpF87JdLvO3ETDXiUVfrTtn8B4kqsNTooejB
# isd29pFsKnYvi6pqoc6vHZ6X8BqXSPZZIsruf8T3rR+IPgAe8CK2ewelx0kfsswu
# uw2XSrgdBfIUtM1DHk0sXdZ4h3DN7z1C0yj/6lMXpGaoIt3Lkk2fUgCsKBlgmDK4
# rcN868uu29sAY8Ffm500JjJlXrE0GaKBxeJXZcswZi1WU307GXBgyeWGoC037T7a
# c3qRYovFw212gdIa+tjO0jrO4kpdTNYrBbAYN+FKdUZ3yl0d2BnAVLMQHpYgSlV4
# RTNF+OBsBpF5J1RGB+hrqdfoRssIcnj2iD7ujXyGd+UZqClKngY9s3K/5QyHiw7m
# gfn0ahcPkD3VKsJgAoVt4GKnVuISy5AF3+tjQSeoGxrB3Dd8oDTOUdEWEO/FwZYw
# yEY8uBac/xC98y27c2IqerdSGyn+yMA8V69nM3LfPdnsrgQb9v9mMJ4FO0JleeLm
# PO2V5Nn3BMXvfsbSa1F/eoeiRXH245LM7kaS+UpfOlXvLpbmGC5FlqK2hk+L
# SIG # End signature block
