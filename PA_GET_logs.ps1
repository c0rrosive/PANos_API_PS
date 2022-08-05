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
$Customer = read-host -Prompt 'Customer';
$filebase = ($Customer + '_vsys' +((get-date).tostring("yyyyMMddhhmm")));
$query = read-host -Prompt 'Query';                                                                                                                                                                                                                         
$uri_query = [uri]::EscapeDataString($query)
$filtered_response = Invoke-RestMethod -Uri ($URL + 'api/?type=log&log-type=traffic&query=' + $uri_query + '&key='+ $API_TOKEN +'&nlogs=5000');
write-host `n'sleeping for 10 seconds!!!!!!!'`n ; Start-Sleep -s 10;
$filtered_result_data = Invoke-RestMethod -Uri ($URL + 'api/?type=log&log-type=traffic&key='+ $API_TOKEN +'&action=get&job-id='+ $filtered_response.response.result.job) -OutFile ($filebase + '_traffic_raw.xml');
$result_delete = Invoke-RestMethod -Uri ($URL + 'api/?type=log&key='+ $API_TOKEN +'&log-type=traffic&action=finish&job-id=' + $filtered_response.response.result.job);
write-output $result_delete.response.msg
do
 {
     
     $option = Read-Host "show output?(y/n/q)"
     switch ($option)
     {
         'y' {
          #$filtered_result_data.response.result.log.logs.entry | ft -auto -Property receive_time,action,src,from,dst,to,rule,app,dport,proto;
         ([XML](Get-Content ($filebase + '_traffic_raw.xml'))).response.result.log.logs.entry | ft -auto -Property receive_time,action,src,from,dst,to,rule,app,dport,proto;
		 } 'q' {
             exit 0;
         } 'n' {
			exit 0;
         }
     }
 }
 until ($option -eq 'q');
 exit 0;