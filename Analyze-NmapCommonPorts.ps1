<#
.SYNOPSIS
    When the output is grouped by port it displays IP addresses of systems with common open ports based on Nmap's XML formatted output.  It also displays systems that have more than one port open for protocols common to printing.

    When the output is grouped by host IP it displays common open ports for each given host.

    An option exists to produce a total count of open ports for each unique TCP or UDP port. There is another option that converts the XML data to the TSV format.
.DESCRIPTION
    This script displays a summary of IP addresses for common TCP or UDP ports that are open as well as hosts that report having open ports for protocols commmon to printing.  The list of common ports that are checked are: ftp (21, tcp), ssh (22, tcp), telnet (23, tcp), smtp (25, tcp), dns (53, tcp/udp), http (80, tcp), ntp (123, udp), smtp (161, udp), smtp traps (162, udp), https (443, tcp), and UPnP ports (1900, tcp/udp; 5000, tcp).  The list of common printing protocol ports that are checked are: lpd (515, tcp), ipp (631, tcp), and jetdirect (9100, tcp).

    An option is available to return the Fully Qualified Domain Name (FQDN), if it exists, of the host as well.  Another option exists that displays the output of common open ports grouped by host IP.

    The last option converts the XML data to the Tab Separated Value (TSV) format to aid in further analysis using spreadsheet software.  A unique entry will exist for every port regardless of its status.  Matt Johnson provided contributions to this code.

    Nmap needs to be run first to generate the source data.  There are many ways to do this but one such option running SYN and UDP scans for the 100 most common ports is: nmap -sS -sU -F -oX nmapData.xml <network>/<mask>
.PARAMETER NmapXml
    The name of the Nmap XML data file
.PARAMETER ExcludePrinter
    Use this switch to exclude the analysis of hosts running more than one of the common TCP printing protocols (e.g., LPD, IPP, Jetdirect)
.PARAMETER AddFQDN
    Adds the fully qualifed domain name as captured by Nmap to the output.  Or if none is present it will attempt to query it again via DNS.
.PARAMETER SortByHost
    Displays the output of open ports grouped by IP/Host.
.PARAMETER CountOpenPorts
    Displays the output of open ports grouped by IP/Host.
.PARAMETER CreateTsv
    Converts the XML data to a TSV format for use in spreadsheet software.  There is a unique entry for every port regardless of its status.
.PARAMETER ExcludeFields
    List of fields to exclude from the TSV output file. The default option removes: Status, IPv6, MAC, Services, OS, Script. To include all fields use the <-ExcludedOutput ''> option.
    Valid options include: FQDN, Status, IPv4, IPv6, MAC, Services, OS, Script, PortStatus, Transport, Port, PortService
.PARAMETER OutputFile
    Name of the converted Nmap TSV output file. Will default to NmapData.tsv if no value is given.
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
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml -CreateTsv -OutputFile PortScanData.tsv

    Will convert the Nmap XML data file into a TSV formatted file named <PortScanData.tsv>
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml -CreateTsv -ExcludedOutput IPv6, MAC

    Filters the IPv6 and the MAC address fields from the TSV output file, NmapData.tsv.
.EXAMPLE
    Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml -CreateTsv -ExcludedOutput ''
    
    Filters no fields and outputs all data to the TSV output file, NmapData.tsv.
.NOTES
    This script uses the Parse-Nmap.ps1 cmdlet written by @JasonFossen of Enclave Consulting to parse Nmap's XML output file.  That script, among others, is available to download from <https://github.com/EnclaveConsulting/SANS-SEC505>.
    
    Version 1.1.3
    Sam Pursglove
    Matt Johnson - Export to CSV contributions
    Last modified: 10 AUG 2023
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
    $CountOpenPorts,

    [Parameter(ParameterSetName='CreateTsv', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Creates a TSV file from the XML data')]
    [Switch]
    $CreateTsv,

    [Parameter(ParameterSetName='CreateTsv', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Nmap fields to removed from the output (default fields: Status, IPv6, MAC, Services, OS, Script)')]
    [String[]]
    $ExcludeFields = @('Status','IPv6','MAC','Services','OS','Script'),

    [Parameter(ParameterSetName='CreateTsv', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Name of the output TSV file (default: NmapData.tsv)')]
    [String]
    $OutputFile = 'NmapData.tsv'
)

# many of these variables are not used by default but are here for reference should they be needed
$ftp           = 'open:tcp:21:ftp'
$ssh           = 'open:tcp:22:ssh'
$telnet        = 'open:tcp:23:telnet'
$smtp          = 'open:tcp:25:smtp'
$dns_t         = 'open:tcp:53:domain'
$dns_u         = 'open:udp:53:domain'
$tftp_u        = 'open:udp:69:tftp'
$finger        = 'open:tcp:79:finger'
$http          = 'open:tcp:80:http'
$kerberos      = 'open:tcp:88:kerberos-sec'
$rpcbind_t     = 'open:tcp:111:rpcbind'
$rpcbind_u     = 'open:udp:111:rpcbind'
$ntp_u         = 'open:udp:123:ntp'
$ms_rpc        = 'open:tcp:135:msrpc'
$netbios_ns_u  = 'open:udp:137:netbios-ns'
$netbios_data_u= 'open:udp:138:netbios-dgm'
$netbios_tcp   = 'open:tcp:139:netbios-ssn'
$snmp_u        = 'open:udp:161:snmp'
$snmp_trap_u   = 'open:udp:162:snmp'
$srvloc        = 'open:tcp:427:svrloc'
$https         = 'open:tcp:443:https'
$ms_dirsvrs    = 'open:tcp:445:microsoft-ds'
$isakmp_u      = 'open:udp:500:isakmp'
$lpd           = 'open:tcp:515:printer'
$ipp           = 'open:tcp:631:ipp'
$upnp1900_t    = 'open:tcp:1900:upnp'
$upnp1900_u    = 'open:udp:1900:upnp'
$networkfs     = 'open:udp:2049:nfs'       
$remotedesk    = 'open:tcp:3389:ms-wbt-server'
$upnp5000      = 'open:tcp:5000:upnp'
$vnc           = 'open:tcp:5900:vnc'
$ms_net_dscvr  = 'open:tcp:5357:wsdapi'
$althttp       = 'open:tcp:8081:blackice-icecap'
$jetdirect     = 'open:tcp:9100:jetdirect'


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
        
        # extract the service name and corresponding TCP port number for output purposes
        if ($PortSearch -match "^open:tcp:(?<PortNumber>\d{1,5}):(?<ServiceName>\w*-?\w*-?\w+$)") {

            $ReturnString = "`t$($Matches.PortNumber) ($($Matches.ServiceName.ToUpper()))`n"
        
        # extract the service name and corresponding UDP port number for output purposes
        } elseif ($PortSearch -match "^open:udp:(?<PortNumber>\d{1,5}):(?<ServiceName>\w*-?\w*-?\w+$)") {
            
            $ReturnString = "`t$($Matches.PortNumber) ($($Matches.ServiceName.ToUpper()))`n"
        }
    }

    $ReturnString
}


# checks for hosts that have more than one common printer port open
function SearchFor-PrinterPorts {

    $Parsed | Where-Object { ($_.Ports -split '\n' -match "$lpd|$ipp|$jetdirect").count -ge 1 }
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
$IndividualPorts = @($ftp, $ssh, $telnet, $smtp, $dns_t, $dns_u, $tftp_u, $finger, $http, $ntp_u, $snmp_u, $snmp_trap_u, $https, $upnp1900_t, $upnp1900_u, $upnp5000)

# modify this variable to add/remove ports for output groups sorted by host
$IndividualPortsPlusPrinters = @($ftp, $ssh, $telnet, $smtp, $dns_t, $dns_u, $tftp_u, $finger, $http, $ntp_u, $snmp_u, $snmp_trap_u, $https, $upnp1900_t, $upnp1900_u, $upnp5000, $lpd, $ipp, $jetdirect)


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
            
                $AllOpenPorts = $_.Ports.Split() # split each entry to its own line

                foreach ($OpenPort in $AllOpenPorts) {

                    if ($OpenPort -match "^open:tcp:(?<PortNumber>\d{1,5}):") { 
             
                        $Port = [int]$Matches.PortNumber

                        if($PortTracker.ContainsKey("tcp $Port")) {
                            
	                        $PortTracker.Set_Item("tcp $Port", $PortTracker.("tcp $Port") + 1)
        
                        }else{
                            $PortTracker.Add("tcp $Port", 1)
                        }
                    }

                    if ($OpenPort -match "^open:udp:(?<PortNumber>\d{1,5}):") { 
             
                        $Port = [int]$Matches.PortNumber

                        if($PortTracker.ContainsKey("udp $Port")) {
                            
	                        $PortTracker.Set_Item("udp $Port", $PortTracker.("udp $Port") + 1)
        
                        }else{
                            $PortTracker.Add("udp $Port", 1)
                        }
                    }
                }
            }
        
    $PortTracker.GetEnumerator() | Sort-Object Key | Format-Table -Property @{Label="Port";Expression={$_.Name}},@{Label="Count";Expression={$_.Value}}

} elseif ($CreateTsv) {

    $NmapCsv = @()

    foreach($entry in $Parsed) {
                
        $AllPorts = $($entry.Ports).Split() # split each entry to its own line

        $Properties = @{Hostname=   $entry.HostName
                        FQDN=       $entry.FQDN
                        Status=     $entry.Status
                        IPv4=       $entry.IPv4
                        IPv6=       $entry.IPv6
                        MAC=        $entry.MAC
                        Services=   $entry.Services
                        OS=         $entry.OS
                        Script=     $entry.Script}

        foreach($port in $AllPorts) {

            $Properties.Add('PortStatus',$port.split(':')[0])
            $Properties.Add('Transport',$port.split(':')[1])
            $Properties.Add('Port',$port.split(':')[2])
            $Properties.Add('PortService',$port.split(':')[3])
        
            # add the current port data as a new object
            $NmapObject = New-Object -TypeName psobject -Property $Properties
            $NmapCsv += $NmapObject

            # remove these properties so they can be added for the next object
            $Properties.Remove('PortStatus')
            $Properties.Remove('Transport')
            $Properties.Remove('Port')
            $Properties.Remove('PortService')
        }
    }

    $NmapCsv | Select-Object -Property * -ExcludeProperty $ExcludeFields | Export-Csv -Delimiter `t -Path $OutputFile -NoTypeInformation

} else {

    foreach ($Port in $IndividualPorts) {
        
        $PortIpMatches = SearchFor-PortByGroup $Port

        # parse the port number used
        $CurrentPort = [regex]::Match($Port, "\d{1,5}").Value       
    
        # parse the transport protocol used: TCP, UDP
        $Transport = [regex]::Match($Port, "\w\wp").Value

        # count the total number of returned matches for the given port
        $ObjectCount = ($PortIpMatches | Measure-Object).Count

        # ensure there is at least one open port for a given protocol before printing any information about it
        
        if ($ObjectCount -gt 1) {
        
            Write-Output "Port $CurrentPort $($Transport.ToUpper()) is open on the following $ObjectCount hosts"
            
            # attempt to resolve any unresolved IPs (if Nmap was unsuccessful doing so)
            if ($AddFQDN) {
                Resolve-IP $PortIpMatches | Sort-Object FQDN | Format-Table FQDN,IPv4 -AutoSize
            } else {
                $PortIpMatches | Format-Wide IPv4 -AutoSize
            }
        } elseif ($ObjectCount -eq 1) {
        
            Write-Output "Port $CurrentPort $($Transport.ToUpper()) is open on the following $ObjectCount host"
        
            # attempt to resolve any unresolved IPs (if Nmap was unsuccessful doing so)
            if ($AddFQDN) {
                Resolve-IP $PortIpMatches | Sort-Object FQDN | Format-Table FQDN,IPv4 -AutoSize
            } else {
                $PortIpMatches | Format-Wide IPv4 -AutoSize
            }
        } else {
        
            Write-Output "Port $CurrentPort $($Transport.ToUpper()) is not open on any hosts`n"
        }
    }

    # find printers
    if (!$ExcludePrinters) {
    
        $PrinterIpMatches = SearchFor-PrinterPorts
    
        Write-Output "These $($PrinterIpMatches.length) IPs are listening on more than one common TCP printer port (e.g., 515, 631, 9100)"
    
        # attempt to resolve any unresolved IPs (if Nmap was unsuccessful doing so)
        if ($AddFQDN) {
            Resolve-IP $PrinterIpMatches | Sort-Object FQDN | Format-Table FQDN,IPv4 -AutoSize
        } else {
            $PrinterIpMatches | Format-Wide IPv4 -AutoSize
        }
    }
}
