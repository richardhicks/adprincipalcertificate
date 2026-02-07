<#

.SYNOPSIS
    Find certificate templates published on enterprise CA servers that have the 'Publish in Active Directory' option enabled.

.DESCRIPTION
    This script enumerates all published certificate templates for all enterprise issuing CA servers and filters them to only include templates that have the 'Publish certificate in Active Directory' option enabled on the Request Handling tab of the template. This option corresponds to the CT_FLAG_PUBLISH_TO_DS flag (bit 3, value 8) in the msPKI-Enrollment-Flag attribute.

.EXAMPLE
    Find-CertificateTemplateWithPublishInAD

    This command retrieves all certificate templates published on enterprise CA servers that have the 'Publish in Active Directory' option enabled.

.EXAMPLE
    Find-CertificateTemplateWithPublishInAD -Verbose

    This command retrieves all certificate templates with verbose output showing the discovery process.

.OUTPUTS
    PSCustomObject

.LINK
    https://github.com/richardhicks/ADPrincipalCertificate/main/functions/Find-CertificateTemplateWithPublishInAD.ps1

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

Function Find-CertificateTemplateWithPublishInAD {

    # Prerequisites
    #Requires -Module ActiveDirectory

    [CmdletBinding()]
    [OutputType([PSCustomObject])]

    Param (

    )

    # Define the CT_FLAG_PUBLISH_TO_DS flag value
    $CT_FLAG_PUBLISH_TO_DS = 0x00000008

    # Retrieve the configuration naming context
    Write-Verbose 'Retrieving Active Directory configuration naming context...'
    $ConfigNC = (Get-ADRootDSE).ConfigurationNamingContext

    # Retrieve the PKI container DN
    Write-Verbose 'Retrieving PKI container DN...'
    $PkiContainerDN = "CN=Public Key Services,CN=Services,$ConfigNC"
    Write-Verbose "PKI container DN is $PkiContainerDN."

    # Retrieve the certificate templates container DN
    $TemplatesContainerDN = "CN=Certificate Templates,$PkiContainerDN"
    Write-Verbose "Certificate Templates container DN is $TemplatesContainerDN."

    # Retrieve the enrollment servers and the certificate templates they have published
    Write-Verbose 'Retrieving enrollment servers and published certificate templates...'
    $EnrollmentServers = Get-ADObject -Filter { ObjectClass -eq 'pKIEnrollmentService' } -SearchBase $PkiContainerDN -Properties DnsHostName, CertificateTemplates | Sort-Object DnsHostName

    If (-Not $EnrollmentServers) {

        Write-Warning 'No enterprise CA enrollment servers found in Active Directory.'
        Return

    }

    Write-Verbose "Found $($EnrollmentServers.Count) enrollment server(s)."

    # Build a hashtable of issuing CAs and their published templates
    $TemplateToCAMap = @{}

    ForEach ($CA in $EnrollmentServers) {

        ForEach ($Template in $CA.CertificateTemplates) {

            If (-Not $TemplateToCAMap.ContainsKey($Template)) {

                $TemplateToCAMap[$Template] = [System.Collections.Generic.List[String]]::New()

            }

            $TemplateToCAMap[$Template].Add($CA.DnsHostName)

        }

    }

    # Get unique published template names
    $PublishedTemplateNames = $TemplateToCAMap.Keys | Sort-Object

    If ($PublishedTemplateNames.Count -eq 0) {

        Write-Warning 'No published certificate templates found on any enrollment server.'
        Return

    }

    Write-Verbose "Found $($PublishedTemplateNames.Count) unique published certificate template(s)."

    # Build LDAP filter to retrieve all published templates in a single query
    $LdapFilter = '(|' + (($PublishedTemplateNames | ForEach-Object { "(cn=$_)" }) -Join '') + ')'
    Write-Verbose "Retrieving certificate templates from Active Directory..."

    # Retrieve all published templates in a single batch query for performance
    Try {

        $Templates = Get-ADObject -SearchBase $TemplatesContainerDN -LDAPFilter $LdapFilter -Properties 'displayName', 'msPKI-Enrollment-Flag', 'cn' -ErrorAction Stop

    }

    Catch {

        Write-Warning "Failed to retrieve certificate templates: $_"
        Return

    }

    Write-Verbose "Retrieved $($Templates.Count) certificate template(s) from Active Directory."

    # Process each template and filter for CT_FLAG_PUBLISH_TO_DS
    ForEach ($Template in $Templates) {

        $TemplateName = $Template.cn
        $EnrollmentFlag = $Template.'msPKI-Enrollment-Flag'

        Write-Verbose "Processing template: $TemplateName"

        If ($Null -eq $EnrollmentFlag) {

            Write-Verbose "Template '$TemplateName' does not have msPKI-Enrollment-Flag attribute set."
            Continue

        }

        # Check if the CT_FLAG_PUBLISH_TO_DS flag is set using bitwise AND
        If ($EnrollmentFlag -band $CT_FLAG_PUBLISH_TO_DS) {

            Write-Verbose "Template '$TemplateName' has 'Publish in Active Directory' option enabled."

            # Output the result (stream directly to pipeline for memory efficiency)
            [PSCustomObject]@{

                TemplateName = $TemplateName
                DisplayName  = $Template.displayName
                IssuingCA    = $TemplateToCAMap[$TemplateName]

            }

        }

        Else {

            Write-Verbose "Template '$TemplateName' does not have 'Publish in Active Directory' option enabled."

        }

    }

}
