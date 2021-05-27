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

function New-Password {
    # Function source code: https://github.com/jseerden/SLAPS/blob/master/Set-KeyVaultSecret.ps1
    $Alphabets = 'a,b,c,d,e,f,g,h,i,j,k,m,n,p,q,r,t,u,v,w,x,y,z'
    $Numbers = 2..9
    $SpecialCharacters = '!,@,#,$,%,&,*,?,+'
    $Array = @()
    $Array += $Alphabets.Split(',') | Get-Random -Count 10
    $Array[0] = $Array[0].ToUpper()
    $Array[-1] = $Array[-1].ToUpper()
    $Array += $Numbers | Get-Random -Count 3
    $Array += $SpecialCharacters.Split(',') | Get-Random -Count 3
    
    return ($Array | Get-Random -Count $Array.Count) -join ""
}

# Define Azure Key Vault name
$KeyVaultName = "CloudLAPSVault"
$KeyVaultUpdateFrequencyDays = 1

# Retrieve authentication token
$AuthToken = Get-AuthToken

# Initate variables
$StatusCode = [HttpStatusCode]::OK
$Body = [string]::Empty
$HeaderValidation = $true

# Assign incoming request properties to variables
$ComputerName = $Request.Body.ComputerName
$ContentType = $Request.Body.ContentType
$UserName = $Request.Body.Tags.UserName
$DeviceID = $Request.Body.Tags.DeviceID
$SerialNumber = $Request.Body.Tags.SerialNumber

# Validate request header values
$HeaderValidationList = @($ComputerName, $ContentType, $UserName, $DeviceID, $SerialNumber)
foreach ($HeaderValidationItem in $HeaderValidationList) {
    if ([string]::IsNullOrEmpty($HeaderValidationItem)) {
        Write-Output -InputObject "Header validation failed, request will not be handled"
        $StatusCode = [HttpStatusCode]::BadRequest
        $HeaderValidation = $false
        $Body = "Header validation failed"
    }    
}

if ($HeaderValidation -eq $true) {
    # Initiate request handling
    Write-Output -InputObject "Initiating inbound request from device with identifier: $($DeviceID)"

    try {
        $GraphURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($DeviceID)'"
        $AzureADDevice = (Invoke-RestMethod -Method "Get" -Uri $GraphURI -ContentType "application/json" -Headers $AuthToken -ErrorAction Stop).value
    }
    catch [System.Exception] {
        Write-Output -InputObject "Azure AD device record was not found for deviceId from inbound request: $($DeviceID)"
    }
    
    if ($AzureADDevice -ne $null) {
        Write-Output -InputObject "Successfully validated inbound request came from a trusted Azure AD device record"

        # Validate that request to set or update key vault secret for provided computer hasn't already been updated within the amount of days set in $KeyVaultUpdateFrequencyDays
        $KeyVaultSecretUpdateAllowed = $false
        $KeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ComputerName -ErrorAction SilentlyContinue
        if ($KeyVaultSecret -ne $null) {
            if ((Get-Date) -ge ($KeyVaultSecret.Updated).AddDays($KeyVaultUpdateFrequencyDays)) {
                $KeyVaultSecretUpdateAllowed = $true
            }
            else {
                $KeyVaultSecretUpdateAllowed = $false
            }
        }
        else {
            $KeyVaultSecretUpdateAllowed = $true
        }

        # Generate a random password
        $Password = New-Password
        $SecretValue = ConvertTo-SecureString -String $Password -AsPlainText -Force

        # Construct hash-table for Tags property
        $Tags = @{
            "UserName" = $UserName
            "AzureADDeviceID" = $DeviceID
            "SerialNumber" = $SerialNumber
        }

        try {
            # Attempt to add secret to Key Vault
            if ($KeyVaultSecretUpdateAllowed -eq $true) {
                Write-Output -InputObject "Secret update allowed, setting new value for secret"
                Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ComputerName -SecretValue $SecretValue -ContentType $ContentType -Tags $Tags -ErrorAction Stop
                $Body = $Password
            }
            else {
                Write-Output -InputObject "Secret update not allowed"
                $StatusCode = [HttpStatusCode]::Forbidden
                $Body = "Secret update not allowed"
            }
        }
        catch [System.Exception] {
            Write-Output -InputObject "Failed to commit key vault secret. Error message: $($_.Exception.Message)"
            $StatusCode = [HttpStatusCode]::BadRequest
            $Body = "Failed to commit secret to key vault"
        }
    }
    else {
        Write-Output -InputObject "Trusted Azure AD device record validation for inbound request failed, could not find device with deviceId: $($DeviceID)"
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = "Untrusted request"
    }
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $Body
})