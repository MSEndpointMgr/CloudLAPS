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

function Send-LogAnalyticsPayload {
    <#
    .SYNOPSIS
        Send data to Log Analytics Collector API through a web request.
        
    .DESCRIPTION
        Send data to Log Analytics Collector API through a web request.
        
    .PARAMETER WorkspaceID
        Specify the Log Analytics workspace ID.

    .PARAMETER SharedKey
        Specify either the Primary or Secondary Key for the Log Analytics workspace.

    .PARAMETER Body
        Specify a JSON representation of the data objects.

    .PARAMETER LogType
        Specify the name of the custom log in the Log Analytics workspace.

    .PARAMETER TimeGenerated
        Specify a custom date time string to be used as TimeGenerated value instead of the default.
        
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-04-20
        Updated:     2021-04-20

        Version history:
        1.0.0 - (2021-04-20) Function created
    #>  
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the Log Analytics workspace ID.")]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceID,

        [parameter(Mandatory = $true, HelpMessage = "Specify either the Primary or Secondary Key for the Log Analytics workspace.")]
        [ValidateNotNullOrEmpty()]
        [string]$SharedKey,

        [parameter(Mandatory = $true, HelpMessage = "Specify a JSON representation of the data objects.")]
        [ValidateNotNullOrEmpty()]
        [string]$Body,

        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the custom log in the Log Analytics workspace.")]
        [ValidateNotNullOrEmpty()]
        [string]$LogType,

        [parameter(Mandatory = $false, HelpMessage = "Specify a custom date time string to be used as TimeGenerated value instead of the default.")]
        [ValidateNotNullOrEmpty()]
        [string]$TimeGenerated = [string]::Empty
    )
    Process {
        # Construct header string with RFC1123 date format for authorization
        $RFC1123Date = [DateTime]::UtcNow.ToString("r")
        $Header = -join@("x-ms-date:", $RFC1123Date)

        # Convert authorization string to bytes
        $ComputeHashBytes = [Text.Encoding]::UTF8.GetBytes(-join@("POST", "`n", $Body.Length, "`n", "application/json", "`n", $Header, "`n", "/api/logs"))

        # Construct cryptographic SHA256 object
        $SHA256 = New-Object -TypeName "System.Security.Cryptography.HMACSHA256"
        $SHA256.Key = [System.Convert]::FromBase64String($SharedKey)

        # Get encoded hash by calculated hash from bytes
        $EncodedHash = [System.Convert]::ToBase64String($SHA256.ComputeHash($ComputeHashBytes))

        # Construct authorization string
        $Authorization = 'SharedKey {0}:{1}' -f $WorkspaceID, $EncodedHash

        # Construct Uri for API call
        $Uri = -join@("https://", $WorkspaceID, ".ods.opinsights.azure.com/", "api/logs", "?api-version=2016-04-01")

        # Construct headers table
        $HeaderTable = @{
            "Authorization" = $Authorization
            "Log-Type" = $LogType
            "x-ms-date" = $RFC1123Date
            "time-generated-field" = $TimeGenerated
        }

        # Invoke web request
        $WebResponse = Invoke-WebRequest -Uri $Uri -Method "POST" -ContentType "application/json" -Headers $HeaderTable -Body $Body -UseBasicParsing

        $ReturnValue = [PSCustomObject]@{
            StatusCode = $WebResponse.StatusCode
            PayloadSizeKB = ($Body.Length/1024).ToString("#.#")
        }
        
        # Handle return value
        return $ReturnValue
    }
}


Write-Output -InputObject "Inbound request from IP: $($TriggerMetadata.'$Request'.headers.'x-forwarded-for'.Split(":")[0])"

# Read application settings for internal variables
$WorkspaceID = if (-not([string]::IsNullOrEmpty($env:WorkspaceId))) { $env:WorkspaceId } else { "InvalidWorkspace" }
$SharedKey = if (-not([string]::IsNullOrEmpty($env:SharedKey))) { $env:SharedKey } else { "InvalidSharedKey" }
$LogType = if (-not([string]::IsNullOrEmpty($env:LogTypeClient))) { $env:LogTypeClient } else { "CloudLAPSClient" }
$DebugLogging = if (-not([string]::IsNullOrEmpty($env:DebugLogging))) { $env:DebugLogging } else { $false }

# Retrieve authentication token
$AuthToken = Get-AuthToken

# Initate variables
$StatusCode = [HttpStatusCode]::OK
$Body = [string]::Empty
$HeaderValidation = $true

# Assign incoming request properties to variables
$DeviceName = $Request.Body.DeviceName
$DeviceID = $Request.Body.DeviceID
$SerialNumber = $Request.Body.SerialNumber
$Signature = $Request.Body.Signature
$Thumbprint = $Request.Body.Thumbprint
$PublicKey = $Request.Body.PublicKey
$PasswordRotationResult = $Request.Body.PasswordRotationResult
$DateTimeUtc = $Request.Body.DateTimeUtc
$ClientEventMessage = $Request.Body.ClientEventMessage

$WorkspaceBody = @{
    SerialNumber = $SerialNumber
    AzureADDeviceId = $DeviceID
    PasswordRotationResult = $PasswordRotationResult
    DateTimeUtc = $DateTimeUtc
    Message = $ClientEventMessage
}

# Validate request header values
$HeaderValidationList = @(@{ "DeviceName" = $DeviceName }, @{ "DeviceID" = $DeviceID }, @{ "SerialNumber" = $SerialNumber }, @{ "Signature" = $Signature }, @{ "Thumbprint" = $Thumbprint }, @{ "PublicKey" = $PublicKey }, @{ "PasswordRotationResult" = $PasswordRotationResult }, @{ "DateTimeUtc" = $DateTimeUtc }, @{ "ClientEventMessage" = $ClientEventMessage })
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

    $AzureADDeviceRecord = Get-AzureADDeviceRecord -DeviceID $DeviceID -AuthToken $AuthToken
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

                        # Send client event message details to Log Analytics workspace
                        $LogAnalyticsAPIResponse = Send-LogAnalyticsPayload -WorkspaceID $WorkspaceID -SharedKey $SharedKey -Body ($WorkspaceBody | ConvertTo-Json) -LogType $LogType
                        if ($LogAnalyticsAPIResponse.StatusCode -like "200") {
                            Write-Output -InputObject "Successfully sent client message to workspace"
                        }
                        else {
                            Write-Warning -Message "Failed to send client message to workspace"
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