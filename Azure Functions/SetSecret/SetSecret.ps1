using namespace System.Net

# Input bindings are passed in via param block.
param(
    [Parameter(Mandatory = $true)]
    $Request,

    [Parameter(Mandatory = $false)]
    $TriggerMetadata
)

# Functions
function Get-AuthToken {
    <#
    .SYNOPSIS
        Retrieve an access token for the Managed System Identity.
    
    .DESCRIPTION
        Retrieve an access token for the Managed System Identity.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    Process {
        # Get Managed Service Identity details from the Azure Functions application settings
        $MSIEndpoint = $env:MSI_ENDPOINT
        $MSISecret = $env:MSI_SECRET

        # Define the required URI and token request params
        $APIVersion = "2017-09-01"
        $ResourceURI = "https://graph.microsoft.com"
        $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"

        # Call resource URI to retrieve access token as Managed Service Identity
        $Response = Invoke-RestMethod -Uri $AuthURI -Method "Get" -Headers @{ "Secret" = "$($MSISecret)" }

        # Construct authentication header to be returned from function
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($Response.access_token)"
            "ExpiresOn" = $Response.expires_on
        }

        # Handle return value
        return $AuthenticationHeader
    }
}

function Get-AzureADDeviceRecord {
    <#
    .SYNOPSIS
        Retrieve an Azure AD device record.
    
    .DESCRIPTION
        Retrieve an Azure AD device record.

    .PARAMETER DeviceID
        Specify the Device ID of an Azure AD device record.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Device ID of an Azure AD device record.")]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceID
    )
    Process {
        $GraphURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($DeviceID)'"
        $GraphResponse = (Invoke-RestMethod -Method "Get" -Uri $GraphURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value
        
        # Handle return response
        return $GraphResponse
    }
}

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

function Test-AzureADDeviceAlternativeSecurityIds {
    <#
    .SYNOPSIS
        Validate the thumbprint and publickeyhash property values of the alternativeSecurityIds property from the Azure AD device record.
    
    .DESCRIPTION
        Validate the thumbprint and publickeyhash property values of the alternativeSecurityIds property from the Azure AD device record.

    .PARAMETER AlternativeSecurityIdKey
        Specify the alternativeSecurityIds.Key property from an Azure AD device record.

    .PARAMETER Type
        Specify the type of the AlternativeSecurityIdsKey object, e.g. Thumbprint or Hash.

    .PARAMETER Value
        Specify the value of the type to be validated.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the alternativeSecurityIds.Key property from an Azure AD device record.")]
        [ValidateNotNullOrEmpty()]
        [string]$AlternativeSecurityIdKey,

        [parameter(Mandatory = $true, HelpMessage = "Specify the type of the AlternativeSecurityIdsKey object, e.g. Thumbprint or Hash.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Thumbprint", "Hash")]
        [string]$Type,

        [parameter(Mandatory = $true, HelpMessage = "Specify the value of the type to be validated.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    Process {
        # Construct custom object for alternativeSecurityIds property from Azure AD device record, used as reference value when compared to input value
        $AzureADDeviceAlternativeSecurityIds = Get-AzureADDeviceAlternativeSecurityIds -Key $AlternativeSecurityIdKey
        
        switch ($Type) {
            "Thumbprint" {
                # Validate match
                if ($Value -match $AzureADDeviceAlternativeSecurityIds.Thumbprint) {
                    return $true
                }
                else {
                    return $false
                }
            }
            "Hash" {
                # Convert from Base64 string to byte array
                $DecodedBytes = [System.Convert]::FromBase64String($Value)
                
                # Construct a new SHA256Managed object to be used when computing the hash
                $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

                # Compute the hash
                [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($DecodedBytes)

                # Convert computed hash to Base64 string
                $ComputedHashString = [System.Convert]::ToBase64String($ComputedHash)

                # Validate match
                if ($ComputedHashString -like $AzureADDeviceAlternativeSecurityIds.PublicKeyHash) {
                    return $true
                }
                else {
                    return $false
                }
            }
        }
    }
}

function Test-Encryption {
    <#
    .SYNOPSIS
        Test the signature created with the private key by using the public key.
    
    .DESCRIPTION
        Test the signature created with the private key by using the public key.

    .PARAMETER PublicKeyEncoded
        Specify the Base64 encoded string representation of the Public Key.

    .PARAMETER Signature
        Specify the Base64 encoded string representation of the signature coming from the inbound request.

    .PARAMETER Content
        Specify the content string that the signature coming from the inbound request is based upon.
    
    .NOTES
        Author:      Nickolaj Andersen / Thomas Kurth
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created

        Credits to Thomas Kurth for sharing his original C# code.
    #>
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Base64 encoded string representation of the Public Key.")]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKeyEncoded,

        [parameter(Mandatory = $true, HelpMessage = "Specify the Base64 encoded string representation of the signature coming from the inbound request.")]
        [ValidateNotNullOrEmpty()]
        [string]$Signature,

        [parameter(Mandatory = $true, HelpMessage = "Specify the content string that the signature coming from the inbound request is based upon.")]
        [ValidateNotNullOrEmpty()]
        [string]$Content
    )
    Process {
        # Convert from Base64 string to byte array
        $PublicKeyBytes = [System.Convert]::FromBase64String($PublicKeyEncoded)

        # Convert signature from Base64 string
        [byte[]]$Signature = [System.Convert]::FromBase64String($Signature)

        # Extract the modulus and exponent based on public key data
        $ExponentData = [System.Byte[]]::CreateInstance([System.Byte], 3)
        $ModulusData = [System.Byte[]]::CreateInstance([System.Byte], 256)
        [System.Array]::Copy($PublicKeyBytes, $PublicKeyBytes.Length - $ExponentData.Length, $ExponentData, 0, $ExponentData.Length)
        [System.Array]::Copy($PublicKeyBytes, 9, $ModulusData, 0, $ModulusData.Length)

        # Construct RSACryptoServiceProvider and import modolus and exponent data as parameters to reconstruct the public key from bytes
        $PublicKey = [System.Security.Cryptography.RSACryptoServiceProvider]::Create(2048)
        $RSAParameters = $PublicKey.ExportParameters($false)
        $RSAParameters.Modulus = $ModulusData
        $RSAParameters.Exponent = $ExponentData
        $PublicKey.ImportParameters($RSAParameters)

        # Construct a new SHA256Managed object to be used when computing the hash
        $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

        # Construct new UTF8 unicode encoding object
        $UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8

        # Convert content to byte array
        [byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)

        # Compute the hash
        [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)

        # Verify the signature with the computed hash of the content using the public key
        $PublicKey.VerifyHash($ComputedHash, $Signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
}

Write-Output -InputObject "Inbound request from IP: $($TriggerMetadata.'$Request'.headers.'x-forwarded-for'.Split(":")[0])"

# Read application settings for Key Vault values
$KeyVaultName = $env:KeyVaultName
$KeyVaultUpdateFrequencyDays = if (-not([string]::IsNullOrEmpty($env:UpdateFrequencyDays))) { $env:UpdateFrequencyDays } else { 3 }
$PasswordLength = if (-not([string]::IsNullOrEmpty($env:PasswordLength))) { $env:PasswordLength } else { 16 }
$PasswordAllowedCharacters = if (-not([string]::IsNullOrEmpty($env:PasswordAllowedCharacters))) { $env:PasswordAllowedCharacters } else { "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789" }
$DebugLogging = if (-not([string]::IsNullOrEmpty($env:DebugLogging))) { $env:DebugLogging } else { $false }

# Retrieve authentication token
$Script:AuthToken = Get-AuthToken

# Initate variables
$StatusCode = [HttpStatusCode]::OK
$Body = [string]::Empty
$HeaderValidation = $true

# Assign incoming request properties to variables
$DeviceName = $Request.Body.DeviceName
$DeviceID = $Request.Body.DeviceID
$SerialNumber = $Request.Body.SerialNumber
$Type = $Request.Body.Type
$Signature = $Request.Body.Signature
$Thumbprint = $Request.Body.Thumbprint
$PublicKey = $Request.Body.PublicKey
$ContentType = $Request.Body.ContentType
$UserName = $Request.Body.UserName

# Validate request header values
$HeaderValidationList = @(@{ "DeviceName" = $DeviceName }, @{ "DeviceID" = $DeviceID }, @{ "SerialNumber" = $SerialNumber }, @{ "Type" = $Type }, @{ "Signature" = $Signature }, @{ "Thumbprint" = $Thumbprint }, @{ "PublicKey" = $PublicKey }, @{ "ContentType" = $ContentType }, @{ "UserName" = $UserName })
foreach ($HeaderValidationItem in $HeaderValidationList) {
    foreach ($HeaderItem in $HeaderValidationItem.Keys) {
        if ([string]::IsNullOrEmpty($HeaderValidationItem[$HeaderItem])) {
            Write-Warning -Message "Header validation for '$($HeaderItem)' failed, request will not be handled"
            $StatusCode = [HttpStatusCode]::BadRequest
            $HeaderValidation = $false
            $Body = "Header validation failed"
        }
        else {
            if ($HeaderItem -in @("Signature", "PublicKey")) {
                if ($DebugLogging -eq $true) {
                    Write-Output -InputObject "Header validation succeeded for '$($HeaderItem)' with value: $($HeaderValidationItem[$HeaderItem])"
                }
                else {
                    Write-Output -InputObject "Header validation succeeded for '$($HeaderItem)' with value: <redacted>"
                }
            }
            else {
                Write-Output -InputObject "Header validation succeeded for '$($HeaderItem)' with value: $($HeaderValidationItem[$HeaderItem])"
            }
        }
    }  
}

if ($HeaderValidation -eq $true) {
    # Initiate request handling
    Write-Output -InputObject "Initiating request handling for device named as '$($DeviceName)' with identifier: $($DeviceID)"

    $AzureADDeviceRecord = Get-AzureADDeviceRecord -DeviceID $DeviceID
    if ($AzureADDeviceRecord -ne $null) {
        Write-Output -InputObject "Found trusted Azure AD device record with object identifier: $($AzureADDeviceRecord.id)"

        # Get required validation data for debug logging when enabled
        if ($DebugLogging -eq $true) {
            $AzureADDeviceAlternativeSecurityIds = Get-AzureADDeviceAlternativeSecurityIds -Key $AzureADDeviceRecord.alternativeSecurityIds.key
        }

        # Validate thumbprint from input request with Azure AD device record's alternativeSecurityIds details
        if ($DebugLogging -eq $true) {
            Write-Output -InputObject "ValidatePublicKeyThumbprint: Value from param 'Thumbprint': $($Thumbprint)"
            Write-Output -InputObject "ValidatePublicKeyThumbprint: Value from AAD device record: $($AzureADDeviceAlternativeSecurityIds.Thumbprint)"
        }
        if (Test-AzureADDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $AzureADDeviceRecord.alternativeSecurityIds.key -Type "Thumbprint" -Value $Thumbprint) {
            Write-Output -InputObject "Successfully validated certificate thumbprint from inbound request"

            # Validate public key hash from input request with Azure AD device record's alternativeSecurityIds details
            if ($DebugLogging -eq $true) {
                $ComputedHashString = New-HashString -Value $PublicKey
                Write-Output -InputObject "ValidatePublicKeyHash: Encoded hash from param 'PublicKey': $($ComputedHashString)"
                Write-Output -InputObject "ValidatePublicKeyHash: Encoded hash from AAD device record: $($AzureADDeviceAlternativeSecurityIds.PublicKeyHash)"
            }
            if (Test-AzureADDeviceAlternativeSecurityIds -AlternativeSecurityIdKey $AzureADDeviceRecord.alternativeSecurityIds.key -Type "Hash" -Value $PublicKey) {
                Write-Output -InputObject "Successfully validated certificate SHA256 hash value from inbound request"

                $EncryptionVerification = Test-Encryption -PublicKeyEncoded $PublicKey -Signature $Signature -Content $AzureADDeviceRecord.deviceId
                if ($EncryptionVerification -eq $true) {
                    Write-Output -InputObject "Successfully validated inbound request came from a trusted Azure AD device record"

                    # Validate that the inbound request came from a trusted device that's not disabled
                    if ($AzureADDeviceRecord.accountEnabled -eq $true) {
                        Write-Output -InputObject "Azure AD device record was validated as enabled"

                        # Determine parameter input variable to use for secret name
                        switch ($Type) {
                            "NonVM" {
                                $SecretName = $SerialNumber
                            }
                            "VM" {
                                $SecretName = $DeviceName
                            }
                        }
            
                        # Validate that request to set or update key vault secret for provided secret name hasn't already been updated within the amount of days set in UpdateFrequencyDays application setting
                        Write-Output -InputObject "Attempting to retrieve secret from vault with name: $($SecretName)"
                        $KeyVaultSecretUpdateAllowed = $false
                        $KeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -ErrorAction SilentlyContinue
                        if ($KeyVaultSecret -ne $null) {
                            Write-Output -InputObject "Existing secret was last updated on (UTC): $(($KeyVaultSecret.Updated).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))"
                            if ((Get-Date).ToUniversalTime() -ge ($KeyVaultSecret.Updated).ToUniversalTime().AddDays($KeyVaultUpdateFrequencyDays)) {
                                $KeyVaultSecretUpdateAllowed = $true
                            }
                            else {
                                Write-Output -InputObject "Secret update will be allowed first after (UTC): $(($KeyVaultSecret.Updated).ToUniversalTime().AddDays($KeyVaultUpdateFrequencyDays).ToString("yyyy-MM-dd HH:mm:ss"))"
                                $KeyVaultSecretUpdateAllowed = $false
                            }
                        }
                        else {
                            Write-Output -InputObject "Existing secret was not found, secret update will be allowed"
                            $KeyVaultSecretUpdateAllowed = $true
                        }
            
                        # Continue if update of existing secret was allowed or if new should be created
                        if ($KeyVaultSecretUpdateAllowed -eq $true) {
                            # Generate a random password
                            $Password = Invoke-PasswordGeneration -Length $PasswordLength -AllowedCharacters $PasswordAllowedCharacters
                            $SecretValue = ConvertTo-SecureString -String $Password -AsPlainText -Force
                
                            # Construct hash-table for Tags property
                            $Tags = @{
                                "UserName" = $UserName
                                "AzureADDeviceID" = $DeviceID
                                "DeviceName" = $DeviceName
                            }

                            try {
                                # Attempt to add secret to Key Vault
                                Write-Output -InputObject "Attempting to commit secret with name '$($SecretName)' to vault"
                                Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -SecretValue $SecretValue -ContentType $ContentType -Tags $Tags -ErrorAction Stop
                                Write-Output -InputObject "Successfully committed secret to vault"
                                $Body = $Password
                            }
                            catch [System.Exception] {
                                Write-Warning -Message "Failed to commit key vault secret. Error message: $($_.Exception.Message)"
                                $StatusCode = [HttpStatusCode]::BadRequest
                                $Body = "Failed to commit secret to key vault"
                            }
                        }
                        else {
                            $StatusCode = [HttpStatusCode]::Forbidden
                            $Body = "Secret update not allowed"
                        }
                    }
                    else {
                        Write-Output -InputObject "Trusted Azure AD device record validation for inbound request failed, record with deviceId '$($DeviceID)' is disabled"
                        $StatusCode = [HttpStatusCode]::Forbidden
                        $Body = "Disabled device record"
                    }
                }
                else {
                    Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate signed content from client"
                    $StatusCode = [HttpStatusCode]::Forbidden
                    $Body = "Untrusted request"
                }
            }
            else {
                Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate certificate SHA256 hash value"
                $StatusCode = [HttpStatusCode]::Forbidden
                $Body = "Untrusted request"
            }
        }
        else {
            Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not validate certificate thumbprint"
            $StatusCode = [HttpStatusCode]::Forbidden
            $Body = "Untrusted request"
        }
    }
    else {
        Write-Warning -Message "Trusted Azure AD device record validation for inbound request failed, could not find device with deviceId: $($DeviceID)"
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = "Untrusted request"
    }
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $Body
})