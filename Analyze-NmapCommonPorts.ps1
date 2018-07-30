<#
.SYNOPSIS
    Displays IP addresses of systems with common open ports based on Nmap's XML formatted output.  It also displays systems that have more than one port open for protocols common to printing.
.DESCRIPTION
    This script uses the Parse-Nmap.ps1 cmdlet written by @JasonFossen of Enclave Consulting to parse Nmap's XML output file.  That script, among others, is available to download from <https://github.com/EnclaveConsulting/SANS-SEC505>.  This script then displays a summary of IP addresses for common ports that are open as well as hosts that report having open ports for protocols commmon to printing.  The list of common ports that are checked are: ftp (21), ssh (22), telnet (23), smtp (25), dns (53), http (80), https (443), and UPnP ports (1900, 5000).  The list of common printing protocol ports that are checked are: printer (515), ipp (631), and jetdirect (9100).

    An option also exists to add return the Fully Qualified Domain Name (FQDN) of the host as well.

    Nmap needs to be run first to generate the source data.  There are many ways to do this but one such option is: nmap -sS -O -F -oX nmapData.xml <network>/<mask>
.PARAMETER NmapXml
    The name of the Nmap XML data file
.PARAMETER ExcludePrinter
    Use this switch to exclude the analysis of hosts running more than one of the common printing protocols (e.g., LPD, IPP, Jetdirect)
.PARAMETER AddFQDN
    Adds the fully qualifed domain name as captured by Nmap to the output.  Or if none is present it will attempt to query it again via DNS.
.PARAMETER SortByHost
    Displays the output of open ports grouped by IP/Host.
.NOTES
    Version 1.0
    Sam Pursglove
    Last modified: 30 JUL 2018
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 nmapData.xml

    Runs the script with only the XML data as input
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml -ExcludePrinters

    Runs the script with XML data as input and skips the analysis of hosts running more than one of the common printing protocols
#>

[CmdletBinding()]
param (
    [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, HelpMessage='The name of the Nmap XML data file')]
    [String]
    $NmapXml,
    
    [Parameter(Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Remove the analysis of common printing protocol ports')]
    [Switch]
    $ExcludePrinters,

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Adds the Nmap FQDN field to the output')]
    [Switch]
    $AddFQDN,

    [Parameter(Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Displays open ports grouped by IP/Host instead of by port')]
    [Switch]
    $SortByHost
)


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

    param($Port)
    
    $Parsed | Where-Object { $_.Ports -match $Port }
}

function SearchFor-Printer {

    $Parsed | Where-Object { (($_.Ports -match $printer) -and ($_.Ports -match $ipp)) -or (($_.Ports -match $printer) -and ($_.Ports -match $jetdirect)) -or (($_.Ports -match $ipp) -and ($_.Ports -match $jetdirect)) }
}

function Resolve-IP {
    
    param($Computers)

    $Computers | 
    
        # attempt to resolve IPs that were not resolved during the original Nmap scan
        Where-Object { $_.FQDN -match "<no-fullname>" } |

            ForEach-Object {
                $DnsName = $(Resolve-DnsName -Name $_.IPv4 -QuickTimeout -ErrorAction Ignore).NameHost
                if ($DnsName -ne $null) {
                    $_.FQDN = $(Resolve-DnsName -Name $_.IPv4 -QuickTimeout -ErrorAction Ignore).NameHost
                } else {
                    $_.FQDN = 'Does Not Resolve'
                }
            }

        $Computers
}

$Parsed = Invoke-Expression ((Join-Path $PSScriptRoot Parse-Nmap.ps1) + " -Path $NmapXml")


# identify listening ports of some common protocols
$IndividualPorts = @($ftp, $ssh, $telnet, $smtp, $dns, $http, $https, $upnp1900, $upnp5000)


if ($SortByHost) {

    $Parsed | ForEach-Object {

                    [string]$FoundPorts = ""
                    
                    if ($_.Ports -match $ftp) {
                        $FoundPorts += "`t21 (FTP)`n"
                    }
                    if ($_.Ports -match $ssh) {
                        $FoundPorts += "`t22 (SSH)`n"
                    }
                    if ($_.Ports -match $telnet) {
                        $FoundPorts += "`t23 (Telnet)`n"
                    }
                    if ($_.Ports -match $smtp) {
                        $FoundPorts += "`t25 (SMTP)`n"
                    }
                    if ($_.Ports -match $dns) {
                        $FoundPorts += "`t53 (DNS)`n"
                    }
                    if ($_.Ports -match $http) {
                        $FoundPorts += "`t80 (HTTP)`n"
                    }
                    if ($_.Ports -match $https) {
                        $FoundPorts += "`t443 (HTTPS)`n"
                    }
                    if ($_.Ports -match $printer) {
                        $FoundPorts += "`t515 (LPD)`n"
                    }
                    if ($_.Ports -match $ipp) {
                        $FoundPorts += "`t631 (IPP)`n"
                    }
                    if ($_.Ports -match $upnp1900) {
                        $FoundPorts += "`t1900 (UPnP)`n"
                    }
                    if ($_.Ports -match $upnp5000) {
                        $FoundPorts += "`t5000 (UPnP)`n"
                    }
                    if ($_.Ports -match $jetdirect) {
                        $FoundPorts += "`t9100 (Jetdirect)`n"
                    }
                    
                    if ($FoundPorts.Length -gt 0) {
                        
                        Write-Output "$($_.IPv4) ($($_.FQDN))"
                        Write-Output $FoundPorts
                    }
              }
} else {

    foreach ($Port in $IndividualPorts) {
        
        $CurrentPort = [regex]::Match($Port, "\d{1,5}").Value
     
        $PortIpMatches = SearchFor-Port $Port  
    
        # ensure there is at least one open port for a given protocol before printing any information about it
        if ($PortIpMatches.length -gt 0) {
        
            Write-Output "Port $CurrentPort is open on the following $($PortIpMatches.length) hosts"
        
            if ($AddFQDN) {
                Resolve-IP $PortIpMatches | Sort-Object FQDN | Format-Table FQDN,IPv4 -AutoSize
            } else {
                $PortIpMatches | Format-Wide IPv4 -AutoSize
            }
        } else {
        
            Write-Output "Port $CurrentPort is not open on any hosts"
        }
    }

    # find printers
    if (!$ExcludePrinters) {
    
        $printerIpMatches = SearchFor-Printer
    
        Write-Output "These $($printerIpMatches.length) IPs are listening on more than one common printer port (e.g., 515, 631, 9100)"
    
        if ($AddFQDN) {
            Resolve-IP $printerIpMatches | Sort-Object FQDN | Format-Table FQDN,IPv4 -AutoSize
        } else {
            $printerIpMatches | Format-Wide IPv4 -AutoSize
        }
    }
}