<#
.SYNOPSIS
    When the output is grouped by port it displays IP addresses of systems with common open ports based on Nmap's XML formatted output.  It also displays systems that have more than one port open for protocols common to printing.

    When the output is grouped by host IP it displays common open ports for each given host.
.DESCRIPTION
    This script displays a summary of IP addresses for common ports that are open as well as hosts that report having open ports for protocols commmon to printing.  The list of common ports that are checked are: ftp (21), ssh (22), telnet (23), smtp (25), dns (53), http (80), https (443), and UPnP ports (1900, 5000).  The list of common printing protocol ports that are checked are: lpd (515), ipp (631), and jetdirect (9100).

    An option is available to return the Fully Qualified Domain Name (FQDN), if it exists, of the host as well.  Another option exists that displays the output of common open ports grouped by host IP.

    Nmap needs to be run first to generate the source data.  There are many ways to do this but one such option is: nmap -sS -F -oX nmapData.xml <network>/<mask>
.PARAMETER NmapXml
    The name of the Nmap XML data file
.PARAMETER ExcludePrinter
    Use this switch to exclude the analysis of hosts running more than one of the common printing protocols (e.g., LPD, IPP, Jetdirect)
.PARAMETER AddFQDN
    Adds the fully qualifed domain name as captured by Nmap to the output.  Or if none is present it will attempt to query it again via DNS.
.PARAMETER SortByHost
    Displays the output of open ports grouped by IP/Host.
.PARAMETER CountOpenPorts
    Displays the output of open ports grouped by IP/Host.
.NOTES
    This script uses the Parse-Nmap.ps1 cmdlet written by @JasonFossen of Enclave Consulting to parse Nmap's XML output file.  That script, among others, is available to download from <https://github.com/EnclaveConsulting/SANS-SEC505>.
    
    Version 1.0
    Sam Pursglove
    Last modified: 31 JUL 2018
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml

    Runs the script with only the XML data as input
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml -ExcludePrinters

    Runs the script with XML data as input and skips the analysis of hosts running more than one of the common printing protocols
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml -AddFQDN

    Runs the script with XML data as input and displays the output with the host FQDN (if it exists) along with the IP.
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml -SortByHost

    Runs the script with XML data as input and displays each host with a list of any common open ports.
#>

[CmdletBinding(DefaultParameterSetName='GroupByPort')]
param (
    [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, HelpMessage='The name of the Nmap XML data file')]
    [String]
    $NmapXml,
    
    [Parameter(ParameterSetName='GroupByPort', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Remove the analysis of common printing protocol ports')]
    [Switch]
    $ExcludePrinters,

    [Parameter(ParameterSetName='GroupByPort', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Adds the Nmap FQDN field to the output')]
    [Switch]
    $AddFQDN,

    [Parameter(ParameterSetName='GroupByHost', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Displays open ports grouped by IP/Host instead of by port')]
    [Switch]
    $SortByHost,

    [Parameter(ParameterSetName='OpenPortCount', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Counts the total number of open ports')]
    [Switch]
    $CountOpenPorts
)

# many of these variables are not used by default but are here for reference should they be needed
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
$lpd         = 'open:tcp:515:printer'
$ipp         = 'open:tcp:631:ipp'
$upnp1900    = 'open:tcp:1900:upnp'      
$remotedesk  = 'open:tcp:3389:ms-wbt-server'
$upnp5000    = 'open:tcp:5000:upnp'
$vnc         = 'open:tcp:5900:vnc'
$ms_net_dscvr= 'open:tcp:5357:wsdapi'
$althttp     = 'open:tcp:8081:blackice-icecap'
$jetdirect   = 'open:tcp:9100:jetdirect'


# function that looks for open ports grouped by port
function SearchFor-PortByGroup {

    param($Port)
    
    $Parsed | Where-Object { $_.Ports -match $Port }
}


# function that looks for open ports grouped by host
function SearchFor-PortByHost {

    param($HostPorts, $PortSearch)

    $ReturnString = ""

    if ($HostPorts -match $PortSearch) {
        
        # extract the service name and corresponding port number for output purposes
        $PortSearch -match "^open\:tcp\:(?<PortNumber>\d{1,5})\:(?<ServiceName>\w*-?\w*-?\w+$)" | Out-Null

        $ReturnString = "`t$($Matches.PortNumber) ($($Matches.ServiceName.ToUpper()))`n"
    }

    $ReturnString
}


# checks for hosts that have more than one common printer port open
function SearchFor-PrinterPorts {

    $Parsed | Where-Object { ($_.Ports -split '\n' -match "$lpd|$ipp|$jetdirect").count -gt 1 }
}


# attempt to resolve IPs that were not resolved during the original Nmap scan
function Resolve-IP {
    
    param($Computers)

    $Computers | 
    
        Where-Object { $_.FQDN -match "<no-fullname>" } | ForEach-Object {
                
                $DnsName = $(Resolve-DnsName -Name $_.IPv4 -QuickTimeout -ErrorAction Ignore).NameHost
                if ($DnsName -ne $null) {
                    $_.FQDN = $(Resolve-DnsName -Name $_.IPv4 -QuickTimeout -ErrorAction Ignore).NameHost
                } else {
                    $_.FQDN = 'Does Not Resolve'
                }
            }
    
    $Computers
}


$Parsed = & $PSScriptRoot\Parse-Nmap.ps1 -Path $NmapXml

# identify listening ports of some common protocols

# modify this variable to add/remove ports for output groups sorted by port number
$IndividualPorts = @($ftp, $ssh, $telnet, $smtp, $dns, $http, $https, $upnp1900, $upnp5000)

# modify this variable to add/remove ports for output groups sorted by host
$IndividualPortsPlusPrinters = @($ftp, $ssh, $telnet, $smtp, $dns, $http, $https, $upnp1900, $upnp5000, $lpd, $ipp, $jetdirect)


if ($SortByHost) {

    $Parsed | ForEach-Object {

                [string]$FoundPorts = ""

                foreach ($Port in $IndividualPortsPlusPrinters) {

                    $FoundPorts += (SearchFor-PortByHost -Host $_.Ports -PortSearch $Port)
                }
                    
                if ($FoundPorts.Length -gt 0) {
                        
                    Write-Output "$($_.IPv4) ($($_.FQDN))"
                    Write-Output $FoundPorts
                }
              }
} elseif ($CountOpenPorts) {

   $PortTracker = @{}
   
   $Parsed | ForEach-Object {
                
                $AllOpenPorts = $_.Ports.Split()

                foreach ($OpenPort in $AllOpenPorts) {
                
                    $OpenPort -match "open\:tcp\:(?<PortNumber>\d{1,5})\:" | Out-Null
                
                    $Port = [int]$Matches.PortNumber

                    if($PortTracker.ContainsKey($Port)) {

	                    $PortTracker.Set_Item($Port, $PortTracker.($Port) + 1)
        
                    }else{
                        $PortTracker.Add($Port, 1)
                    }
                }
            }
        
    $PortTracker.GetEnumerator() | Sort-Object Key | Format-Table -AutoSize -Property @{Label="Port";Expression={$_.Name}},@{Label="Count";Expression={$_.Value}}

} else {

    foreach ($Port in $IndividualPorts) {
        
        $CurrentPort = [regex]::Match($Port, "\d{1,5}").Value
     
        $PortIpMatches = SearchFor-PortByGroup $Port  
    
        # ensure there is at least one open port for a given protocol before printing any information about it
        if ($PortIpMatches.length -gt 0) {
        
            Write-Output "Port $CurrentPort is open on the following $($PortIpMatches.length) hosts"
        
            if ($AddFQDN) {
                Resolve-IP $PortIpMatches | Sort-Object FQDN | Format-Table FQDN,IPv4 -AutoSize
            } else {
                $PortIpMatches | Format-Wide IPv4 -AutoSize
            }
        } else {
        
            Write-Output "Port $CurrentPort is not open on any hosts`n"
        }
    }

    # find printers
    if (!$ExcludePrinters) {
    
        $PrinterIpMatches = SearchFor-PrinterPorts
    
        Write-Output "These $($PrinterIpMatches.length) IPs are listening on more than one common printer port (e.g., 515, 631, 9100)"
    
        if ($AddFQDN) {
            Resolve-IP $PrinterIpMatches | Sort-Object FQDN | Format-Table FQDN,IPv4 -AutoSize
        } else {
            $PrinterIpMatches | Format-Wide IPv4 -AutoSize
        }
    }
}