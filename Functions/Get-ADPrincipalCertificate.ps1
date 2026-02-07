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
    https://github.com/richardhicks/ADPrincipalCertificate/main/functions/Get-ADPrincipalCertificate.ps1

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
