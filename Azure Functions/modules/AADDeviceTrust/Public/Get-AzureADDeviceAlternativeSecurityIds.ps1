function Get-AzureADDeviceAlternativeSecurityIds {
    <#
    .SYNOPSIS
        Decodes Key property of an Azure AD device record into prefix, thumbprint and publickeyhash values.
    
    .DESCRIPTION
        Decodes Key property of an Azure AD device record into prefix, thumbprint and publickeyhash values.

    .PARAMETER Key
        Specify the 'key' property of the alternativeSecurityIds property retrieved from the Get-AzureADDeviceRecord function.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the 'key' property of the alternativeSecurityIds property retrieved from the Get-AzureADDeviceRecord function.")]
        [ValidateNotNullOrEmpty()]
        [string]$Key
    )
    Process {
        $DecodedKey = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Key))
        $PSObject = [PSCustomObject]@{
            "Prefix" = $DecodedKey.SubString(0,21)
            "Thumbprint" = $DecodedKey.Split(">")[1].SubString(0,40)
            "PublicKeyHash" = $DecodedKey.Split(">")[1].SubString(40)
        }

        # Handle return response
        return $PSObject
    }
}