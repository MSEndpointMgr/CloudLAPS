function New-HashString {
    <#
    .SYNOPSIS
        Compute has from input value and return encoded Base64 string.
    
    .DESCRIPTION
        Compute has from input value and return encoded Base64 string.

    .PARAMETER Value
        Specify a Base64 encoded value for which a hash will be computed.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-08-23
        Updated:     2021-08-23
    
        Version history:
        1.0.0 - (2021-08-23) Function created
    #>
    param(    
        [parameter(Mandatory = $true, HelpMessage = "Specify a Base64 encoded value for which a hash will be computed.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    Process {
        # Convert from Base64 string to byte array
        $DecodedBytes = [System.Convert]::FromBase64String($Value)
    
        # Construct a new SHA256Managed object to be used when computing the hash
        $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

        # Compute the hash
        [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($DecodedBytes)

        # Convert computed hash to Base64 string
        $ComputedHashString = [System.Convert]::ToBase64String($ComputedHash)

        # Handle return value
        return $ComputedHashString
    }
}