<#
.SYNOPSIS
    Displays IP addresses of systems with common open ports based on Nmap's XML formatted output.  It also displays systems that have more than one port open for protocols common to printing.
.DESCRIPTION
    This script uses the Parse-Nmap.ps1 cmdlet written by @JasonFossen of Enclave Consulting to parse Nmap's XML output file.  That script, among others, is available to download from <https://github.com/EnclaveConsulting/SANS-SEC505>.  This script then displays a summary of IP addresses for common ports that are open as well as hosts that report having open ports for protocols commmon to printing.  The list of common ports that are checked are: ftp (21), ssh (22), telnet (23), smtp (25), dns (53), http (80), and https (443).  The list of common printing protocol ports that are checked are: printer (515), ipp (631), and jetdirect (9100).

    Nmap needs to be run first to generate the source data.  There are many ways to do this but one such option is: nmap -sS -O -F -oX nmapData.xml <network>/<mask>
.PARAMETER Path
    The name of the Nmap XML data file        
.NOTES
    Version 1.0
    Sam Pursglove
    Last modified: 19 JUL 2018
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 nmapData.xml
#>

Param (
    [Parameter(Position=0, 
               Mandatory=$True,
               ValueFromPipeline=$True,
               HelpMessage='The name of the Nmap XML data file')]
    [String]$Path
)

$parsed = .\Parse-Nmap.ps1 $Path

$ftp         = 'open:tcp:21:ftp'
$ssh         = 'open:tcp:22:ssh'
$telnet      = 'open:tcp:23:telnet'
$smtp        = 'open:tcp:25:smtp'
$dns         = 'open:tcp:53:domain'
$http        = 'open:tcp:80:http'
$kerberos    = 'open:tcp:88:kerberos-sec'
$rpcbind     = 'open:tcp:111:rpcbind'
$ms_rpc      = 'open:tcp:135:msrpc'
$netbios_tcp = 'open:tcp:139:netbios-ssn'
$srvloc      = 'open:tcp:427:svrloc'
$https       = 'open:tcp:443:https'
$ms_dirsvrs  = 'open:tcp:445:microsoft-ds'
$printer     = 'open:tcp:515:printer'
$ipp         = 'open:tcp:631:ipp'
$upnp1900    = 'open:tcp:1900'      
$remotedesk  = 'open:tcp:3389:ms-wbt-server'
$upnp5000    = 'open:tcp:5000:upnp'
$vnc         = 'open:tcp:5900:vnc'
$ms_net_dscvr= 'open:tcp:5357:wsdapi'
$althttp     = 'open:tcp:8081'
$jetdirect   = 'open:tcp:9100:jetdirect'

function SearchFor-Port {

    param($port)
    
    $parsed | Where-Object { $_.Ports -match $port }
}

function SearchFor-Printer {

    $parsed | Where-Object { (($_.Ports -match $printer) -and ($_.Ports -match $ipp)) -or (($_.Ports -match $printer) -and ($_.Ports -match $jetdirect)) -or (($_.Ports -match $ipp) -and ($_.Ports -match $jetdirect)) }
}

# identify listening ports of some common protocols
$individualPorts = @($ftp, $ssh, $telnet, $smtp, $dns, $http, $https)

ForEach ($port in $IndividualPorts) {
    [regex]$extractPort = "(?<currentPort>\d+)"
    $currentPort = $extractPort.match($port).Groups["currentPort"].Value
     
    $portMatches = SearchFor-Port $port  
    Write-Output "Port $currentPort is open on the following $($portMatches.length) IPs"
    $portMatches | Format-Wide IPv4 -AutoSize   
}

# find printers
if (!$ExcludePrintersScanners) {
    $printerMatches = SearchFor-Printer
    Write-Output "These $($printerMatches.length) IPs are listening on at least one common printer port"
    $printerMatches | Format-Wide IPv4 -AutoSize
}