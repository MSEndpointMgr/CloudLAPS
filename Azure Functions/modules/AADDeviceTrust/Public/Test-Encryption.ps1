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