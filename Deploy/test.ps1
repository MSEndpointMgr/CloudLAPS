$Key = ""
$DecodedKey = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Key))
$PSObject = [PSCustomObject]@{
    "Prefix" = $DecodedKey.SubString(0,21)
    "Thumbprint" = $DecodedKey.Split(">")[1].SubString(0,40)
    "PublicKeyHash" = $DecodedKey.Split(">")[1].SubString(40)
}
$PSObject