<#
.SYNOPSIS
connect to the Graph environment and return the connection as an object
containing a token and it's lifecycle (expiry date/time)
.LINK
https://tech.nicolonsky.ch/explaining-microsoft-graph-access-token-acquisition/
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory)]$TenantID,
    [Parameter()]$AppRegistrationID,
    [Parameter()]$AppSecret,
    [Parameter()]$CertificatePath,
    [Parameter(DontShow, ValueFromRemainingArguments)]$Superfluous
)

process {
    Write-Verbose -Message "Trying to get a REST token to be used for a connection to MS Graph..."
    try {
        $GraphConnection = Invoke-RestMethod @PostSplat
        Write-Verbose -Message "Token is acquired and valid until $((Get-Date).AddSeconds($GraphConnection.expires_in))"
    }
    catch { Write-Error -Message "ERROR: $($_.Exception)" }
}

begin {
    [version]$ScriptVersion = '1.0.0.1'
    Write-Verbose -Message "Ignoring superfluous params: $($Superfluous -join ' ')"
    #Get access without a user:
    #https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
    #https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands?view=graph-powershell-1.0
    $ExecutingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $ScriptDescription = "ConnectTo-Graph v$($ScriptVersion) run by $($ExecutingUser)"
    Write-Verbose -Message $ScriptDescription
    $AuthUri = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token"
    if (-not [string]::IsNullOrEmpty($CertificatePath)) {
        #use certificate for app authentication when run in production environment
        #https://learn.microsoft.com/en-us/powershell/microsoftgraph/app-only?tabs=azure-portal&view=graph-powershell-1.0
        #https://adamtheautomator.com/powershell-graph-api/#Acquire_an_Access_Token_Using_a_Certificate
        try { 
            $Certificate = Get-Item $CertificatePath
            $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash()) -replace '\+', '-' -replace '/', '_' -replace '=' 
        }
        catch { Write-Error -Message "Error processing certificate: $($CertificatePath), exiting script..."; exit }
        # replace/strip to match web encoding of base64
        $JWTHeader = @{
            alg = "RS256"
            typ = "JWT"
            x5t = $CertificateBase64Hash 
        }
        # Create JWT timestamp for expiration
        $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
        $Now = (Get-Date).ToUniversalTime()
        $NotBefore = [math]::Round((New-TimeSpan -Start $StartDate -End $Now).TotalSeconds, 0)
        $JWTExpiration = $NotBefore + 120 # add 2 minutes
        # Create JWT payload
        $JWTPayLoad = @{
            aud = $AuthUri # allowed endpoint to use this JWT
            exp = $JWTExpiration # Expiration timestamp
            iss = $AppRegistrationID # Issuer = your application
            jti = [guid]::NewGuid() # JWT ID: random guid
            nbf = $NotBefore # Not to be used before 
            sub = $AppRegistrationID # JWT Subject
        }
        # Convert header and payload to base64
        $EncodedHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json)))
        $EncodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json)))
        # Join header and Payload with "." to create a valid (unsigned) JWT
        $JWT = [System.Text.Encoding]::UTF8.GetBytes($EncodedHeader + "." + $EncodedPayload)
        # Get the private key object of your certificate
        $PrivateKey = $Certificate.PrivateKey
        # Define RSA signature and hashing algorithm
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
        # Create a signature of the JWT
        $Signature = [Convert]::ToBase64String($PrivateKey.SignData($JWT, $HashAlgorithm, $RSAPadding)) -replace '\+', '-' -replace '/', '_' -replace '='
        # Join the signature to the JWT with "."
        $JWT = $JWT + "." + $Signature
        # Create a hash with body parameters
        $Body = @{
            Grant_Type            = "client_credentials"
            Client_Id             = $AppRegistrationID
            Client_Assertion      = $JWT
            Client_Assertion_Type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            Scope                 = "https://graph.microsoft.com/.default"
        }
        # Use the self-generated JWT as Authorization in Headers parameter
        # Splat the parameters for Invoke-Restmethod for cleaner code
        $script:PostSplat = @{
            ContentType = 'application/x-www-form-urlencoded'
            Method      = 'POST'
            Body        = $Body
            Uri         = $AuthUri
            Headers     = @{ Authorization = "Bearer $JWT" }
        }
    }
    else {
        $body = @{ 
            Grant_Type    = "client_credentials"
            Client_Id     = $AppRegistrationID
            Client_Secret = $AppSecret
            Scope         = "https://graph.microsoft.com/.default"
        }
        $script:PostSplat = @{
            Uri    = $AuthUri
            Method = 'POST'
            Body   = $Body
        }
    }
}

end { return $GraphConnection }
