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
        [string]$gateway_id,
        [string]$username,
        [string]$privatekey,
        [string]$passphrase
    )

    $publicKey = Get-PublicKeyFromGateway -gateway_id $gateway_id
    $modulus_b64 = $publicKey.Modulus
    $exponent_b64 = $publicKey.Exponent

    $credentials = @{
        credentialData = @(
            @{ name = "username"; value = $username },
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

# Example execution:
$gateway_id = ""
$username = ""
$privatekey = ""
$passphrase = ""

$outputFilePath = ""
$result = Encrypt-Credentials -gateway_id $gateway_id -username $username -privatekey $privatekey -passphrase $passphrase
$result | Set-Content -Path $outputFilePath -Encoding UTF8
