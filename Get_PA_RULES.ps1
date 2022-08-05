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

$API_TOKEN = Get-Content .\API_token.txt;
$URL = read-host -Prompt 'Firewall URL';
$vsys_num = read-host -Prompt 'VSYS#';
$Customer = read-host -Prompt 'Customer';
$filebase = ($Customer + '_vsys' + $vsys_num + '_');
Invoke-RestMethod -Uri ($URL + 'esp/restapi.esp?type=config&key='+ $API_TOKEN +'&action=show&xpath=/config/devices/entry/vsys/entry[@name=%27vsys' + $vsys_num +'%27]/rulebase/security') -OutFile ($filebase + '_SEC_rules_raw.xml');
Invoke-RestMethod -Uri ($URL + 'esp/restapi.esp?type=config&key='+ $API_TOKEN +'&action=show&xpath=/config/devices/entry/vsys/entry[@name=%27vsys' + $vsys_num +'%27]/rulebase/nat') -OutFile ($filebase + '_NAT_rules_raw.xml');
#(Get-Content ($filebase + '_NAT_rules_raw.xml')) | Foreach-Object{$_ -replace "<response status=`"success`">","" -replace "<nat>","" -replace "<result>", ""  -replace "<member>",""` -replace "</member>"-replace "</response>","" -replace "</nat>","" -replace "</result>", "" -replace " ", ""} | Out-File -FilePath ($filebase + 'NAT_clean.xml');
#(Get-Content ($filebase + '_SEC_rules_raw.xml')) | Foreach-Object{$_ -replace "<response status=`"success`">","" -replace "<security>","" -replace "<result>", ""  -replace "<member>",""` -replace "</member>"-replace "</response>","" -replace "</security>","" -replace "</result>", "" -replace " ", ""} | Out-File -FilePath ($filebase + 'sec_clean.xml');
(Get-Content ($filebase + '_NAT_rules_raw.xml')) | Foreach-Object{$_ -replace "<response status=`"success`">","" -replace "<nat>","" -replace "<result>", ""  -replace "<member>",""` -replace "</member>"-replace "</response>","" -replace "</nat>","" -replace "</result>", ""} | Out-File -FilePath ($filebase + 'NAT_clean.xml');
(Get-Content ($filebase + '_SEC_rules_raw.xml')) | Foreach-Object{$_ -replace "<response status=`"success`">","" -replace "<security>","" -replace "<result>", ""  -replace "<member>",""` -replace "</member>"-replace "</response>","" -replace "</security>","" -replace "</result>", ""} | Out-File -FilePath ($filebase + 'sec_clean.xml');