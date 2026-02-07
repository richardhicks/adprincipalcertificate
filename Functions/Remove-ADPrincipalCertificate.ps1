<#

.SYNOPSIS
    Remove certificates from an Active Directory principal's userCertificate attribute.

.DESCRIPTION
    This function removes certificates from the userCertificate attribute of AD principals (users, computers, service accounts, or other AD objects). By default, self-signed (non-managed) certificates are preserved and only managed certificates are removed. Use the -IncludeSelfSignedCertificate switch to also remove self-signed certificates. This is a destructive operation that permanently deletes certificate data from Active Directory. The script accepts pipeline input from Get-ADUser, Get-ADComputer, Get-ADServiceAccount, or Get-ADObject cmdlets.

    WARNING: This operation is irreversible without an Active Directory backup. Ensure you have a current AD backup before running this command.

.PARAMETER Identity
    One or more AD principal identities. This can be a Distinguished Name, SamAccountName, ObjectGUID, or SID. This parameter accepts pipeline input and multiple values.

.PARAMETER Force
    Bypasses the initial warning prompt. The -Confirm prompt will still be displayed unless -Confirm:$false is also specified.

.PARAMETER IncludeSelfSignedCertificate
    When specified, includes self-signed certificates (where Subject equals Issuer) in the removal operation. By default, self-signed certificates are preserved and only managed certificates are removed.

.INPUTS
    Microsoft.ActiveDirectory.Management.ADUser, Microsoft.ActiveDirectory.Management.ADComputer, Microsoft.ActiveDirectory.Management.ADServiceAccount, Microsoft.ActiveDirectory.Management.ADObject, or String values.

.OUTPUTS
    None.

.EXAMPLE
    Remove-ADPrincipalCertificate -Identity 'juser'

    Removes managed certificates from user juser after confirmation. Self-signed certificates are preserved.

.EXAMPLE
    Get-ADUser juser | Remove-ADPrincipalCertificate

    Pipes a user object to remove managed certificates after confirmation. Self-signed certificates are preserved.

.EXAMPLE
    Get-ADComputer 'app1' | Remove-ADPrincipalCertificate -WhatIf

    Shows what would happen if managed certificates were removed from computer app1 without actually removing them.

.EXAMPLE
    Get-ADServiceAccount 'svc_app' | Remove-ADPrincipalCertificate -Confirm:$false -Force

    Removes managed certificates from service account svc_app without any prompts (use with caution). Self-signed certificates are preserved.

.EXAMPLE
    Get-ADUser -Filter {Department -eq 'Contractors'} | Remove-ADPrincipalCertificate

    Removes managed certificates from all users in the Contractors department after confirmation for each.

.EXAMPLE
    Remove-ADPrincipalCertificate -Identity 'app1', 'app2' -Force

    Removes managed certificates from multiple computers app1 and app2, bypassing the backup warning.

.EXAMPLE
    Remove-ADPrincipalCertificate -Identity 'juser' -IncludeSelfSignedCertificate

    Removes ALL certificates from user juser, including self-signed certificates.

.EXAMPLE
    Get-ADComputer -Filter * | Remove-ADPrincipalCertificate -IncludeSelfSignedCertificate -Force

    Removes ALL certificates from all computer accounts, including self-signed certificates.

.LINK
    https://github.com/richardhicks/adprincipalcertificate/blob/main/Functions/Remove-ADPrincipalCertificate.ps1

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

Function Remove-ADPrincipalCertificate {

    # Prerequisites
    #Requires -Module ActiveDirectory

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([System.Void])]

    Param (

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0, HelpMessage = 'Specify one or more AD principal identities')]
        [Alias('DistinguishedName', 'SamAccountName', 'ObjectGUID', 'SID', 'Name')]
        [ValidateNotNullOrEmpty()]
        $Identity,

        [Parameter(HelpMessage = 'Bypass the initial backup warning prompt')]
        [switch]$Force,

        [Parameter(HelpMessage = 'Include self-signed certificates in the removal')]
        [switch]$IncludeSelfSignedCertificate

    )

    Begin {

        Write-Verbose 'Begin certificate removal process...'

        # Define required properties once in Begin block for efficiency
        $RequiredProperties = @('userCertificate', 'SamAccountName', 'ObjectClass', 'DistinguishedName')

        # Check if Identity parameter was provided (non-pipeline input)
        # Note: Pipeline input won't be available until Process block
        If (-not $Identity -and -not $MyInvocation.ExpectingInput) {

            Write-Warning 'No input provided. Specify an identity using -Identity or pipe AD objects to this script.'
            $Script:OperationCancelled = $true
            Return

        }

        # Display warning unless -Force is specified
        If (-not $Force -and -not $WhatIfPreference) {

            Write-Warning '*** CRITICAL OPERATION ***'

            If ($IncludeSelfSignedCertificate) {

                Write-Warning 'This operation will permanently remove ALL certificates from the specified AD principal(s).'
                Write-Warning 'This includes self-signed certificates.'

            }

            Else {

                Write-Warning 'This operation will permanently remove managed certificates from the specified AD principal(s).'
                Write-Warning 'Self-signed certificates will be preserved.'

            }

            $Confirmation = Read-Host 'Do you wish to continue? (Yes/No)'

            If ($Confirmation -notmatch '^y(es)?$') {

                Write-Warning 'Operation cancelled by user.'
                $Script:OperationCancelled = $true
                Return

            }

            Write-Verbose 'Confirmation prompt accepted by user. Proceeding with operation...'

        }

        $Script:OperationCancelled = $false

        # Helper function to convert certificate data to a consistent list format
        Function Get-CertificateList {

            Param (
                [Parameter(Mandatory)]
                $CertificateData
            )

            $UserCertType = $CertificateData.GetType()
            Write-Verbose "userCertificate type: $($UserCertType.FullName)"

            If ($UserCertType.FullName -eq 'System.Byte[]') {

                # Single certificate stored as byte array
                Return , @(, $CertificateData)

            }

            ElseIf ($UserCertType.FullName -eq 'System.Byte[][]') {

                # Multiple certificates stored as array of byte arrays
                Return , $CertificateData

            }

            ElseIf ($UserCertType.FullName -like '*ADPropertyValueCollection*') {

                # ADPropertyValueCollection - use .Value property to get the raw data
                $RawValue = $CertificateData.Value

                If ($RawValue -is [byte[]]) {

                    Return , @(, $RawValue)

                }

                ElseIf ($RawValue -is [System.Object[]]) {

                    Return , $RawValue

                }

                Else {

                    # Fallback: convert collection to array
                    Return , @($CertificateData)

                }

            }

            Else {

                # Unknown type - wrap in array
                Write-Verbose "Unknown userCertificate type: $($UserCertType.FullName). Attempting to process..."
                Return , @(, $CertificateData)

            }

        }

        # Helper function to check if AD object has all required properties
        Function Test-HasRequiredProperty {

            Param (
                [Parameter(Mandatory)]
                $AdObject,
                [Parameter(Mandatory)]
                [string[]]$Properties
            )

            ForEach ($Prop in $Properties) {

                If (-not $AdObject.PSObject.Properties.Name.Contains($Prop)) {

                    Return $false

                }

            }

            Return $true

        }

    }

    Process {

        # Exit if operation was cancelled in Begin block
        If ($Script:OperationCancelled) {

            Return

        }

        # Handle both single and array inputs correctly
        $IdsToProcess = If ($Identity -is [array]) { $Identity } Else { , $Identity }

        ForEach ($Id in $IdsToProcess) {

            Try {

                $Principal = $null

                # Check if this is already an AD object with required properties
                If ($Id.PSObject.TypeNames -match 'Microsoft\.ActiveDirectory\.Management\.AD(User|Computer|ServiceAccount|Object)') {

                    # Check if the piped object already has all required properties
                    If ((Test-HasRequiredProperty -AdObject $Id -Properties $RequiredProperties) -and $null -ne $Id.userCertificate) {

                        Write-Verbose "Using piped AD object with existing properties: $($Id.DistinguishedName)"
                        $Principal = $Id

                    }

                    Else {

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

                        'user' {

                            $Principal = Get-ADUser -Identity $IdentityValue -Properties $RequiredProperties -ErrorAction Stop

                        }

                        'computer' {

                            $Principal = Get-ADComputer -Identity $IdentityValue -Properties $RequiredProperties -ErrorAction Stop

                        }

                        { $_ -in 'msDS-ManagedServiceAccount', 'msDS-GroupManagedServiceAccount' } {

                            $Principal = Get-ADServiceAccount -Identity $IdentityValue -Properties $RequiredProperties -ErrorAction Stop

                        }

                        Default {

                            # Try to find the object using cascading approach
                            Try {

                                $Principal = Get-ADUser -Identity $IdentityValue -Properties $RequiredProperties -ErrorAction Stop
                                Write-Verbose "Found user account `"$IdentityValue`"."

                            }

                            Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

                                Try {

                                    $Principal = Get-ADComputer -Identity $IdentityValue -Properties $RequiredProperties -ErrorAction Stop
                                    Write-Verbose "Found computer account `"$IdentityValue`"."

                                }

                                Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

                                    Try {

                                        $Principal = Get-ADServiceAccount -Identity $IdentityValue -Properties $RequiredProperties -ErrorAction Stop
                                        Write-Verbose "Found service account `"$IdentityValue`"."

                                    }

                                    Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

                                        $Principal = Get-ADObject -Identity $IdentityValue -Properties $RequiredProperties -ErrorAction Stop
                                        Write-Verbose "Found AD object `"$IdentityValue`"."

                                    }

                                }

                            }

                        }

                    }

                }

                # Validate certificate presence
                If (-not $Principal.userCertificate) {

                    Write-Warning "No certificates found for principal `"$($Principal.SamAccountName)`"."
                    Continue

                }

                # Get certificate list using helper function
                $CertificateList = Get-CertificateList -CertificateData $Principal.userCertificate

                $TotalCertificates = $CertificateList.Count
                Write-Verbose "Processing $TotalCertificates certificate(s) for $($Principal.SamAccountName)."

                # Separate non-managed certificates (self-signed) from managed certificates
                # Use Generic List for better performance with large datasets
                $CertificatesToRemove = [System.Collections.Generic.List[byte[]]]::new()
                $SelfSignedCount = 0

                # Use for loop with explicit indexing to prevent byte array unrolling
                For ($i = 0; $i -lt $CertificateList.Count; $i++) {

                    $CertBytes = $CertificateList[$i]
                    $Certificate = $null

                    Try {

                        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)

                        # Check if certificate is self-signed (Subject equals Issuer)
                        If ($Certificate.Subject -eq $Certificate.Issuer) {

                            # If IncludeSelfSignedCertificate is specified, include self-signed certificates in removal
                            If ($IncludeSelfSignedCertificate) {

                                $CertificatesToRemove.Add($CertBytes)
                                Write-Verbose "Marking self-signed certificate for removal: $($Certificate.Subject) (Thumbprint: $($Certificate.Thumbprint))"

                            }

                            Else {

                                # By default, preserve self-signed certificates
                                $SelfSignedCount++
                                Write-Verbose "Preserving self-signed certificate: $($Certificate.Subject) (Thumbprint: $($Certificate.Thumbprint))"

                            }

                        }

                        Else {

                            $CertificatesToRemove.Add($CertBytes)
                            Write-Verbose "Marking managed certificate for removal: $($Certificate.Subject) (Issuer: $($Certificate.Issuer))"

                        }

                    }

                    Catch {

                        Write-Warning "Unable to parse certificate for '$($Principal.SamAccountName)'. Skipping certificate to be safe: $_"
                        $SelfSignedCount++

                    }

                    Finally {

                        # Dispose of certificate object to prevent memory leaks
                        If ($null -ne $Certificate) {

                            $Certificate.Dispose()

                        }

                    }

                }

                # Check if there are any certificates to remove
                If ($CertificatesToRemove.Count -eq 0) {

                    If (-not $IncludeSelfSignedCertificate) {

                        Write-Warning "No certificates matching the specified criteria were found for principal `"$($Principal.SamAccountName)`"."

                    }

                    Else {

                        Write-Warning "No certificates found for principal `"$($Principal.SamAccountName)`"."

                    }

                    Continue

                }

                $RemoveCount = $CertificatesToRemove.Count
                $PreserveCount = $SelfSignedCount

                Write-Verbose "Certificates to remove: $RemoveCount | Self-signed certificates to preserve: $PreserveCount"

                # Perform the removal with ShouldProcess support
                If (-not $IncludeSelfSignedCertificate -and $PreserveCount -gt 0) {

                    $ConfirmMessage = "Remove $RemoveCount managed certificate(s) from '$($Principal.SamAccountName)' ($($Principal.ObjectClass))? ($PreserveCount self-signed certificate(s) will be preserved)"
                    $WhatIfMessage = "Removing $RemoveCount managed certificate(s) from '$($Principal.SamAccountName)' ($($Principal.ObjectClass)). Preserving $PreserveCount self-signed certificate(s)"

                }

                Else {

                    $ConfirmMessage = "Remove $RemoveCount certificate(s) from '$($Principal.SamAccountName)' ($($Principal.ObjectClass))?"
                    $WhatIfMessage = "Removing $RemoveCount certificate(s) from '$($Principal.SamAccountName)' ($($Principal.ObjectClass))"

                }

                If ($PSCmdlet.ShouldProcess($WhatIfMessage, $ConfirmMessage, 'Remove AD Principal Certificate(s)')) {

                    Try {

                        # Remove certificates in a single AD operation for better performance
                        # Build hashtable with array of certificates to remove
                        $CertsToRemoveArray = $CertificatesToRemove.ToArray()
                        Set-ADObject -Identity $Principal.DistinguishedName -Remove @{ userCertificate = $CertsToRemoveArray } -ErrorAction Stop

                        Write-Verbose "Successfully removed $RemoveCount certificate(s) from '$($Principal.SamAccountName)'."

                        # Output success message
                        If ($PreserveCount -gt 0) {

                            Write-Output "Removed $RemoveCount certificate(s) from '$($Principal.SamAccountName)'. Preserved $PreserveCount self-signed certificate(s)."

                        }

                        Else {

                            Write-Output "Removed $RemoveCount certificate(s) from principal '$($Principal.SamAccountName)'."

                        }

                    }

                    Catch {

                        Write-Error "Failed to remove certificates from '$($Principal.SamAccountName)': $_"

                    }

                }

            }

            Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

                Write-Warning "AD principal not found: $Id"

            }

            Catch {

                Write-Warning "Error processing principal '$Id': $_"

            }

        }

    }

    End {

        If (-not $Script:OperationCancelled) {

            Write-Verbose 'Certificate removal process completed.'

        }

    }

}

# SIG # Begin signature block
# MIIf2wYJKoZIhvcNAQcCoIIfzDCCH8gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB3h77jHMu+X36M
# m3mreCTF3YSfN8emEyLuxWemiLDERKCCGpkwggNZMIIC36ADAgECAhAPuKdAuRWN
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
# 6vdCvHlshtjdNXOCIUjsarfNZzGCBJgwggSUAgEBMHgwZDELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9i
# YWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEzODQgMjAyMSBDQTECEA1KNNqGkI/A
# Eyy8gTeTryQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgk54zV9m58M+ArqiKl3CMTaB1
# NaqgdAApqgDtDYioc+cwCwYHKoZIzj0CAQUABEgwRgIhANjyHtN+SHL0KnemjrFR
# mD77mfhGVRUVeiQ+n0Y+LR2BAiEAjIZdADMpCSbDrGnXb9HX4mNg/RTLjENFtmHs
# Gi1l1PChggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwMjA3MjEzNTUwWjAvBgkq
# hkiG9w0BCQQxIgQgpLXfUOUpz/CWmyQq8Tsr+p1NkWseDx6pXkavvUGxDSowDQYJ
# KoZIhvcNAQEBBQAEggIAGFb61p6z5gSSzBwEPL8EBs15n72/DO+i6L9SWW1g/GEG
# zetVAvLfqjVlJFUeA9QRbPsqRiFu+Gcjt7zNHR3RIMx+2wrXZr1kYwNw/wmt46qn
# 6JgyM79/XUgyjbPAiZu3a8lCPPEVLVHBxMacE44EObw05sqiUc/C3GO80fxCfAOm
# evhQhn+eTmgvaHjgSG31DqT1On8fZzByvMLxOmHf7QIsK+a5Ytz+4d5WjBGgtwBJ
# swfXdGpcmwCiqHdLQ4tFruqDcSmas7gUkKBwpgSdcFpZDh0v+oslzcW6P/4NseeT
# k+TwTEruCTIpjcJ1y+Vk25YnRyBrKtopjWvfCRtJl7xEDe3Cv4PX6hM6zStHLWr9
# bC2v0aTZEcJYeY/UHcZE6KRgWLXcaj13zAQl6VuVEeLO0gTMO8NaBQNo6jclIhIg
# X+kOxPp579pUp6dCTdporfNOJbtMPiTu8GdsrE2LYi1ssarTqNdDJ2oGntl5xFmm
# uwrYqYfDXo1Eq5cuTbzxyMDXGJV4we/qW3c/7mwhUB6/vUHXKh/wgaNVB4GpRMDr
# mH/hJZFonjdoCrApS0chOWrHUjrI02rc2PxEupkMoJxzB2i2Xrlp4SnuKPqfRWzR
# dDk0dDqNJ3n6frYChr8b4VUtURpWNPepPur4Z4Em48CAw02OW6cui5f6g0RNWtA=
# SIG # End signature block
