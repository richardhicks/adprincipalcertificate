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
    https://github.com/richardhicks/ADPrincipalCertificate/main/functions/Remove-ADPrincipalCertificate.ps1

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
