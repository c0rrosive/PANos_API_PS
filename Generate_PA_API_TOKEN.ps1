add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$API_TOKEN=$null;
$URL = $(read-host -Prompt 'Firewall URL');
Add-Type -AssemblyName System.Web;
$URI_USER = [System.Web.HTTPUtility]::UrlEncode($(read-host -Prompt 'User' ));
$URI_PASS = [System.Web.HTTPUtility]::UrlEncode($(read-host -Prompt 'Pass'));
(((Invoke-RestMethod -Uri ($URL + 'esp/restapi.esp?type=keygen&user='+ $URI_USER +'&password=' + $URI_PASS)).response).result).key | out-file -FilePath .\API_token.txt;
$KEY_CONTENT = Get-Content .\API_token.txt
write-host ('Result: '+ $KEY_CONTENT);
