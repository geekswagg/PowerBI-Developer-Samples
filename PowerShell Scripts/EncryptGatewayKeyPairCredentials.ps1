<#
.SYNOPSIS
    Encrypts KeyPair credentials for a Fabric / Power BI on-premises gateway.

.DESCRIPTION
    Implements the full AES-256-CBC + RSA-OAEP-SHA256 + HMAC-SHA256 encryption
    pipeline required by the Power BI REST API when updating gateway data-source
    credentials of type KeyPair (username + private key, optional passphrase).

    Credential type : KeyPair
    Required fields : username, privatekey
    Optional fields : passphrase  (omit or leave empty if the key is unprotected)

    Authentication  : Azure token via Az PowerShell module.
                      Run `Connect-AzAccount` before executing this script.

.PREREQUISITE
    Install-Module -Name Az -Scope CurrentUser

.EXAMPLE
    # With passphrase
    $result = Encrypt-Credentials -gateway_id "<guid>" -username "myuser" `
                                  -privatekey "<pem>" -passphrase "<secret>"

    # Without passphrase
    $result = Encrypt-Credentials -gateway_id "<guid>" -username "myuser" `
                                  -privatekey "<pem>"
#>

function Get-PublicKeyFromGateway {
    param (
        [string]$gateway_id
    )
    $secureToken = (Get-AzAccessToken -ResourceUrl 'https://api.fabric.microsoft.com').Token
    $fabricToken = [System.Net.NetworkCredential]::new('', $secureToken).Password
    $url = "https://api.fabric.microsoft.com/v1/gateways/$gateway_id"
    $headers = @{
        'Authorization' = "Bearer $fabricToken"
        'Accept' = 'application/json'
    }
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
    return @{
        Exponent = $response.publicKey.exponent
        Modulus = $response.publicKey.modulus
    }
}

function Add-PKCS7Padding {
    param ([byte[]]$data, [int]$blockSize = 16)
    $padLen = $blockSize - ($data.Length % $blockSize)
    return $data + ([byte[]]@($padLen) * $padLen)
}

function Concat-Bytes {
    param ([byte[][]]$arrays)
    $totalLength = ($arrays | Measure-Object -Property Length -Sum).Sum
    $result = New-Object byte[] $totalLength
    $offset = 0
    foreach ($arr in $arrays) {
        [Array]::Copy($arr, 0, $result, $offset, $arr.Length)
        $offset += $arr.Length
    }
    return $result
}

function Get-SignedPayload {
    param (
        [byte[]]$ciphertext,
        [byte[]]$iv,
        [byte[]]$signKey
    )

    $algorithms = [byte[]](0, 0)
    $toSign = Concat-Bytes @($algorithms, $iv, $ciphertext)

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $signKey
    $signature = $hmac.ComputeHash($toSign)

    $fullPayload = Concat-Bytes @($algorithms, $signature, $iv, $ciphertext)
    return [Convert]::ToBase64String($fullPayload)
}

function Encrypt-Keys {
    param (
        [string]$modulus_b64,
        [string]$exponent_b64,
        [byte[]]$symmetricKey,
        [byte[]]$signKey
    )

    $modulus = [Convert]::FromBase64String($modulus_b64)
    $exponent = [Convert]::FromBase64String($exponent_b64)

    $rsa = New-Object System.Security.Cryptography.RSACng
    $rsa.ImportParameters([System.Security.Cryptography.RSAParameters]@{
        Modulus = $modulus
        Exponent = $exponent
    })

    if ($symmetricKey.Length -eq 32) { $symLength = 0 }
    elseif ($symmetricKey.Length -eq 64) { $symLength = 1 }
    else { throw "Unsupported key length: $($symmetricKey.Length)" }

    if ($signKey.Length -eq 32) { $signLength = 0 }
    elseif ($signKey.Length -eq 64) { $signLength = 1 }
    else { throw "Unsupported key length: $($signKey.Length)" }

    $lengths = [byte[]]@($symLength, $signLength)
    $combined = Concat-Bytes @($lengths, $symmetricKey, $signKey)
    $encrypted = $rsa.Encrypt($combined, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    return [Convert]::ToBase64String($encrypted)
}


function Encrypt-Credentials {
    param (
        [Parameter(Mandatory = $true)]
        [string]$gateway_id,

        [Parameter(Mandatory = $true)]
        [string]$username,

        [Parameter(Mandatory = $true)]
        [string]$privatekey,

        # Leave empty string if the private key has no passphrase
        [Parameter(Mandatory = $false)]
        [string]$passphrase = ""
    )

    $publicKey   = Get-PublicKeyFromGateway -gateway_id $gateway_id
    $modulus_b64  = $publicKey.Modulus
    $exponent_b64 = $publicKey.Exponent

    $credentials = @{
        credentialData = @(
            @{ name = "username";   value = $username },
            @{ name = "privatekey"; value = $privatekey },
            @{ name = "passphrase"; value = $passphrase }
        )
    } | ConvertTo-Json -Depth 3 -Compress

    $aesKey = New-Object byte[] 32
    $iv = New-Object byte[] 16
    $signKey = New-Object byte[] 64
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($aesKey)
    $rng.GetBytes($iv)
    $rng.GetBytes($signKey)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'
    $aes.Key = $aesKey
    $aes.IV = $iv
    $aes.Padding = 'None'

    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($credentials)
    $padded = Add-PKCS7Padding -data $plainBytes

    $encryptor = $aes.CreateEncryptor()
    $ciphertext = $encryptor.TransformFinalBlock($padded, 0, $padded.Length)

    $signed = Get-SignedPayload -ciphertext $ciphertext -iv $iv -signKey $signKey
    $encryptedKeys = Encrypt-Keys -modulus_b64 $modulus_b64 -exponent_b64 $exponent_b64 -symmetricKey $aesKey -signKey $signKey

    [Array]::Clear($signKey, 0, $signKey.Length)
    return $encryptedKeys + $signed
}

# ---------------------------------------------------------------------------
# Example execution  –  fill in values before running
# ---------------------------------------------------------------------------
# Required
$gateway_id    = ""  # Fabric / Power BI gateway ID (GUID)
$username      = ""  # Username associated with the private key
$privatekey    = ""  # Private key content (PEM string)
$outputFilePath = ""  # File path to write the encrypted payload

# Optional – leave empty string if the private key has no passphrase
$passphrase = ""

$result = Encrypt-Credentials -gateway_id $gateway_id -username $username `
                               -privatekey $privatekey -passphrase $passphrase
$result | Set-Content -Path $outputFilePath -Encoding UTF8
Write-Host "Encrypted payload written to: $outputFilePath"
