<#

.SYNOPSIS
    Enumerate Active Directory principals that have certificates attached.

.DESCRIPTION
    This function retrieves AD principals (users, computers, or service accounts) that have certificates attached. The user can filter by principal type or specify a security group to check. Only principals with certificates are returned.

.PARAMETER PrincipalType
    Specifies the type of principals to enumerate. Acceptable values are 'All', 'User', 'Computer', 'ServiceAccount', or 'Group'. Default is 'All'. The -GroupName parameter is required when PrincipalType is set to 'Group'.

.PARAMETER GroupName
    The name of the security group to check. Required when PrincipalType is set to 'Group'.

.PARAMETER ExcludeSelfSignedCertificate
    When specified, excludes principals that only have self-signed certificates (where Subject equals Issuer).

.INPUTS
    None.

.OUTPUTS
    Custom objects containing AccountName and AccountType properties for principals with certificates.

.EXAMPLE
    Show-ADPrincipalCertificate

    Returns all AD principals (users, computers, and service accounts) that have certificates attached.

.EXAMPLE
    Show-ADPrincipalCertificate -PrincipalType All

    Returns all AD principals (users, computers, and service accounts) that have certificates attached.

.EXAMPLE
    Show-ADPrincipalCertificate -PrincipalType User

    Returns only user accounts that have certificates attached.

.EXAMPLE
    Show-ADPrincipalCertificate -PrincipalType Computer

    Returns only computer accounts that have certificates attached.

.EXAMPLE
    Show-ADPrincipalCertificate -PrincipalType ServiceAccount

    Returns only service accounts that have certificates attached.

.EXAMPLE
    Show-ADPrincipalCertificate -PrincipalType Group -GroupName 'Management Workstations'

    Returns members of the 'Management Workstations' group that have certificates attached.

.EXAMPLE
    Show-ADPrincipalCertificate -ExcludeSelfSignedCertificate

    Returns all AD principals that have certificates attached, excluding those with only self-signed certificates.

.EXAMPLE
    Show-ADPrincipalCertificate -PrincipalType User -ExcludeSelfSignedCertificate

    Returns user accounts that have certificates attached, excluding those with only self-signed certificates.

.LINK
    https://github.com/richardhicks/ADPrincipalCertificate/main/functions/Show-ADPrincipalCertificate.ps1

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

Function Show-ADPrincipalCertificate {

    # Prerequisites
    #Requires -Module ActiveDirectory

    [CmdletBinding()]

    Param (

        [Parameter(HelpMessage = 'Specify the type of principals to enumerate')]
        [ValidateSet('All', 'User', 'Computer', 'ServiceAccount', 'Group')]
        [Alias('Type')]
        [string]$PrincipalType = 'All',
        [Parameter(HelpMessage = "Specify the security group name (required when PrincipalType is 'Group')")]
        [string]$GroupName,
        [Parameter(HelpMessage = 'Exclude principals with only self-signed certificates')]
        [switch]$ExcludeSelfSignedCertificate

    )

    # Validate that GroupName is provided when PrincipalType is Group
    If ($PrincipalType -eq 'Group' -and [string]::IsNullOrWhiteSpace($GroupName)) {

        Write-Warning "The -GroupName parameter is required when PrincipalType is set to 'Group'."
        Return

    }

    # Function to process and output principals with certificates
    Function Get-PrincipalWithCertificate {

        [CmdletBinding()]

        Param (

            [Parameter(Mandatory)]
            [array]$Principals,
            [switch]$ExcludeSelfSigned

        )

        $Counter = 0
        $Total = $Principals.Count

        ForEach ($Principal in $Principals) {

            $Counter++

            # Show progress for better user experience
            If ($Total -gt 10) {

                Write-Progress -Activity "Checking principals for certificates" `
                    -Status "Processing $Counter of $Total" `
                    -PercentComplete (($Counter / $Total) * 100)

            }

            # Check if userCertificate attribute exists and has values
            If ($Principal.userCertificate.Count -gt 0) {

                # If ExcludeSelfSigned is specified, check if the principal has any non-self-signed certificates
                If ($ExcludeSelfSigned) {

                    $HasNonSelfSignedCert = $False

                    ForEach ($CertBytes in $Principal.userCertificate) {

                        Try {

                            $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($CertBytes)

                            # A certificate is self-signed if Subject equals Issuer
                            If ($Cert.Subject -ne $Cert.Issuer) {

                                $HasNonSelfSignedCert = $True
                                Break

                            }

                        }

                        Catch {

                            Write-Verbose "Unable to parse certificate for $($Principal.SamAccountName): $_"

                        }

                    }

                    # Skip this principal if all certificates are self-signed
                    If (-not $HasNonSelfSignedCert) {

                        Continue

                    }

                }

                # Output directly to pipeline (no array building)
                [PSCustomObject]@{

                    AccountName = $Principal.SamAccountName
                    AccountType = $Principal.ObjectClass -replace '^msDS-', ''

                }

            }

        }

        If ($Total -gt 10) {

            Write-Progress -Activity "Checking principals for certificates" -Completed

        }

    }

    # Main script logic
    Try {

        Write-Verbose "Retrieving AD principals with certificate information..."

        # Properties to retrieve
        $Properties = @('SamAccountName', 'userCertificate', 'ObjectClass', 'DistinguishedName')

        Switch ($PrincipalType) {

            'All' {

                # Retrieve principals with certificate property in single query (more efficient)
                Write-Verbose "Enumerating all principals (users, computers, and service accounts)..."
                $Users = Get-ADUser -Filter * -Properties $Properties
                $Computers = Get-ADComputer -Filter * -Properties $Properties
                $ServiceAccounts = Get-ADServiceAccount -Filter * -Properties $Properties
                $Principals = $Users + $Computers + $ServiceAccounts

            }

            'User' {

                Write-Verbose "Enumerating user accounts..."
                $Principals = Get-ADUser -Filter * -Properties $Properties

            }

            'Computer' {

                Write-Verbose "Enumerating computer accounts..."
                $Principals = Get-ADComputer -Filter * -Properties $Properties

            }

            'ServiceAccount' {

                Write-Verbose "Enumerating service accounts..."
                $Principals = Get-ADServiceAccount -Filter * -Properties $Properties

            }

            'Group' {

                Write-Verbose "Enumerating members of group '$GroupName'..."
                Try {

                    # Verify group exists
                    $Group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
                    $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction Stop

                    # Filter to users, computers, and service accounts, then get full objects with certificate property
                    $UserMembers = $Members | Where-Object { $_.objectClass -eq 'user' }
                    $ComputerMembers = $Members | Where-Object { $_.objectClass -eq 'computer' }
                    $ServiceAccountMembers = $Members | Where-Object { $_.objectClass -eq 'msDS-ManagedServiceAccount' -or $_.objectClass -eq 'msDS-GroupManagedServiceAccount' }

                    # Build principals array
                    $Principals = @(

                        # Get full AD objects with properties for users
                        If ($UserMembers.Count -gt 0) {

                            $UserMembers | ForEach-Object {

                                Get-ADUser -Identity $_.DistinguishedName -Properties $Properties

                            }

                        }

                        # Get full AD objects with properties for computers
                        If ($ComputerMembers.Count -gt 0) {

                            $ComputerMembers | ForEach-Object {

                                Get-ADComputer -Identity $_.DistinguishedName -Properties $Properties

                            }

                        }

                        # Get full AD objects with properties for service accounts
                        If ($ServiceAccountMembers.Count -gt 0) {

                            $ServiceAccountMembers | ForEach-Object {

                                Get-ADServiceAccount -Identity $_.DistinguishedName -Properties $Properties

                            }

                        }

                    )

                    If ($Principals.Count -eq 0) {

                        Write-Warning "No user, computer, or service account principals found in group '$GroupName'."
                        Return

                    }

                }

                Catch {

                    Write-Warning "Error retrieving group '$GroupName': $_"
                    Exit 1

                }

            }

        }

        If ($Principals.Count -eq 0) {

            Write-Warning 'No principals found matching the specified criteria.'
            Return

        }

        Write-Verbose "Found $($Principals.Count) principal(s). Checking for certificates..."

        # Process principals and output those with certificates directly to pipeline. Pipeline automatically sorts and formats results
        $Results = Get-PrincipalWithCertificate -Principals $Principals -ExcludeSelfSigned:$ExcludeSelfSignedCertificate | Sort-Object -Property AccountType, AccountName

        # Warn if no principals with certificates were found
        If (-not $Results) {

            Write-Warning 'No certificates found for any of the specified principals.'

        }

        Else {

            $Results

        }

    }

    Catch {

        Write-Warning "Operation failed: $($_.Exception.Message)"
        Throw $_

    }

}
