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
    
    Version 1.1.5
    Sam Pursglove
    Matt Johnson - Export to CSV contributions
    Last modified: 24 OCT 2025
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


####################################################################################
#.Synopsis 
#    Parse XML output files of the nmap port scanner (www.nmap.org). 
#
#.Description 
#    Parse XML output files of the nmap port scanner (www.nmap.org) and  
#    emit custom objects with properties containing the scan data. The 
#    script can accept either piped or parameter input.  The script can be
#    safely dot-sourced without error as is. 
#
#.Parameter Path  
#    Either 1) a string with or without wildcards to one or more XML output
#    files, or 2) one or more FileInfo objects representing XML output files.
#
#.Parameter OutputDelimiter
#    The delimiter for the strings in the OS, Ports and Services properties. 
#    Default is a newline.  Change it when you want single-line output. 
#
#.Parameter RunStatsOnly
#    Only displays general scan information from each XML output file, such
#    as scan start/stop time, elapsed time, command-line arguments, etc.
#
#.Example 
#    dir *.xml | .\parse-nmap.ps1
#
#.Example 
#	 .\parse-nmap.ps1 -path onefile.xml
#    .\parse-nmap.ps1 -path *files.xml 
#
#.Example 
#    $files = dir *some.xml,others*.xml 
#    .\parse-nmap.ps1 -path $files    
#
#.Example 
#    .\parse-nmap.ps1 -path scanfile.xml -runstatsonly
#
#.Example 
#    .\parse-nmap.ps1 scanfile.xml -OutputDelimiter " "
#
#Requires -Version 2 
#
#.Notes 
#  Author: Enclave Consulting LLC, Jason Fossen (http://www.sans.org/sec505)  
# Version: 4.6
# Updated: 27.Feb.2016
#   LEGAL: PUBLIC DOMAIN.  SCRIPT PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF 
#          ANY KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR
#          A PARTICULAR PURPOSE.  ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF
#          THE AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF
#          ANY SUCH DAMAGE.  IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
#          LIABILITY, THEN DELETE THIS FILE SINCE YOU ARE NOW PROHIBITED TO HAVE IT.
####################################################################################

function parse-nmap 
{
	param ($Path, [String] $OutputDelimiter = "`n", [Switch] $RunStatsOnly)
	
	if ($Path -match '/\?|/help|--h|--help') 
	{ 
        $MyInvocation = (Get-Variable -Name MyInvocation -Scope Script).Value
        get-help -full ($MyInvocation.MyCommand.Path)   
		exit 
	}

	if ($Path -eq $null) {$Path = @(); $input | foreach { $Path += $_ } } 
	if (($Path -ne $null) -and ($Path.gettype().name -eq "String")) {$Path = dir $path} #To support wildcards in $path.  
	$1970 = [DateTime] "01 Jan 1970 01:00:00 GMT"

	if ($RunStatsOnly)
	{
		ForEach ($file in $Path) 
		{
			$xmldoc = new-object System.XML.XMLdocument
			$xmldoc.Load($file)
			$stat = ($stat = " " | select-object FilePath,FileName,Scanner,Profile,ProfileName,Hint,ScanName,Arguments,Options,NmapVersion,XmlOutputVersion,StartTime,FinishedTime,ElapsedSeconds,ScanTypes,TcpPorts,UdpPorts,IpProtocols,SctpPorts,VerboseLevel,DebuggingLevel,HostsUp,HostsDown,HostsTotal)
			$stat.FilePath = $file.fullname
			$stat.FileName = $file.name
			$stat.Scanner = $xmldoc.nmaprun.scanner
			$stat.Profile = $xmldoc.nmaprun.profile
			$stat.ProfileName = $xmldoc.nmaprun.profile_name
			$stat.Hint = $xmldoc.nmaprun.hint
			$stat.ScanName = $xmldoc.nmaprun.scan_name
			$stat.Arguments = $xmldoc.nmaprun.args
			$stat.Options = $xmldoc.nmaprun.options
			$stat.NmapVersion = $xmldoc.nmaprun.version
			$stat.XmlOutputVersion = $xmldoc.nmaprun.xmloutputversion
			$stat.StartTime = $1970.AddSeconds($xmldoc.nmaprun.start) 	
			$stat.FinishedTime = $1970.AddSeconds($xmldoc.nmaprun.runstats.finished.time)
			$stat.ElapsedSeconds = $xmldoc.nmaprun.runstats.finished.elapsed
            
            $xmldoc.nmaprun.scaninfo | foreach {
                $stat.ScanTypes += $_.type + " "
                $services = $_.services  #Seems unnecessary, but solves a problem. 

                if ($services -ne $null -and $services.contains("-"))
                {
                    #In the original XML, ranges of ports are summarized, e.g., "500-522", 
                    #but the script will list each port separately for easier searching.
                    $array = $($services.replace("-","..")).Split(",")
                    $temp  = @($array | where { $_ -notlike "*..*" })  
                    $array | where { $_ -like "*..*" } | foreach { invoke-expression "$_" } | foreach { $temp += $_ } 
                    $temp = [Int32[]] $temp | sort 
                    $services = [String]::Join(",",$temp) 
                } 
                    
                switch ($_.protocol)
                {
                    "tcp"  { $stat.TcpPorts  = $services ; break }
                    "udp"  { $stat.UdpPorts  = $services ; break }
                    "ip"   { $stat.IpProtocols = $services ; break }
                    "sctp" { $stat.SctpPorts = $services ; break }
                }
            } 
            
            $stat.ScanTypes = $($stat.ScanTypes).Trim()
            
			$stat.VerboseLevel = $xmldoc.nmaprun.verbose.level
			$stat.DebuggingLevel = $xmldoc.nmaprun.debugging.level		
			$stat.HostsUp = $xmldoc.nmaprun.runstats.hosts.up
			$stat.HostsDown = $xmldoc.nmaprun.runstats.hosts.down		
			$stat.HostsTotal = $xmldoc.nmaprun.runstats.hosts.total
			$stat 			
		}
		return #Don't process hosts.  
	}
	

    # Not doing just -RunStats, so process hosts from XML file.
	ForEach ($file in $Path) 
    {
		Write-Verbose -Message ("[" + (get-date).ToLongTimeString() + "] Starting $file" )
        $StartTime = get-date  

		$xmldoc = new-object System.XML.XMLdocument
		$xmldoc.Load($file)
		
		# Process each of the <host> nodes from the nmap report.
		$i = 0  #Counter for <host> nodes processed.

        foreach ($hostnode in $xmldoc.nmaprun.host) 
        { 
            # Init some variables, with $entry being the custom object for each <host>. 
	        $service = " " #service needs to be a single space.
	        $entry = ($entry = " " | select-object HostName, FQDN, Status, IPv4, IPv6, MAC, Ports, Services, OS, Script) 

			# Extract state element of status:
			if ($hostnode.Status -ne $null -and $hostnode.Status.length -ne 0) { $entry.Status = $hostnode.status.state.Trim() }  
			if ($entry.Status.length -lt 2) { $entry.Status = "<no-status>" }

			# Extract computer names provided by user or through PTR record, but avoid duplicates and allow multiple names.
            # Note that $hostnode.hostnames can be empty, and the formatting of one versus multiple names is different.
            # The crazy foreach-ing here is to deal with backwards compatibility issues...
            $tempFQDN = $tempHostName = ""
			ForEach ($hostname in $hostnode.hostnames)
            {
                ForEach ($hname in $hostname.hostname)
                {
                    ForEach ($namer in $hname.name)
                    {
                        if ($namer -ne $null -and $namer.length -ne 0 -and $namer.IndexOf(".") -ne -1) 
                        {
                            #Only append to temp variable if it would be unique.
                            if($tempFQDN.IndexOf($namer.tolower()) -eq -1)
                            { $tempFQDN = $tempFQDN + " " + $namer.tolower() }
                        }
                        elseif ($namer -ne $null -and $namer.length -ne 0)
                        {
                            #Only append to temp variable if it would be unique.
                            if($tempHostName.IndexOf($namer.tolower()) -eq -1)
                            { $tempHostName = $tempHostName + " " + $namer.tolower() } 
                        }
                    }
                }
            }

            $tempFQDN = $tempFQDN.Trim()
            $tempHostName = $tempHostName.Trim()

            if ($tempHostName.Length -eq 0 -and $tempFQDN.Length -eq 0) { $tempHostName = "<no-hostname>" } 

            #Extract hostname from the first (and only the first) FQDN, if FQDN present.
            if ($tempFQDN.Length -ne 0 -and $tempHostName.Length -eq 0) 
            { $tempHostName = $tempFQDN.Substring(0,$tempFQDN.IndexOf("."))  } 

            if ($tempFQDN.Length -eq 0) { $tempFQDN = "<no-fullname>" }

            $entry.FQDN = $tempFQDN
            $entry.HostName = $tempHostName  #This can be different than FQDN because PTR might not equal user-supplied hostname.
            


			# Process each of the <address> nodes, extracting by type.
			ForEach ($addr in $hostnode.address)
            {
				if ($addr.addrtype -eq "ipv4") { $entry.IPv4 += $addr.addr + " "}
				if ($addr.addrtype -eq "ipv6") { $entry.IPv6 += $addr.addr + " "}
				if ($addr.addrtype -eq "mac")  { $entry.MAC  += $addr.addr + " "}
			}        
			if ($entry.IPv4 -eq $null) { $entry.IPv4 = "<no-ipv4>" } else { $entry.IPv4 = $entry.IPv4.Trim()}
			if ($entry.IPv6 -eq $null) { $entry.IPv6 = "<no-ipv6>" } else { $entry.IPv6 = $entry.IPv6.Trim()}
			if ($entry.MAC  -eq $null) { $entry.MAC  = "<no-mac>"  } else { $entry.MAC  = $entry.MAC.Trim() }


			# Process all ports from <ports><port>, and note that <port> does not contain an array if it only has one item in it.
            # This could be parsed out into separate properties, but that would be overkill.  We still want to be able to use
            # simple regex patterns to do our filtering afterwards, and it's helpful to have the output look similar to
            # the console output of nmap by itself for easier first-time comprehension.  
			if ($hostnode.ports.port -eq $null) { $entry.Ports = "<no-ports>" ; $entry.Services = "<no-services>" } 
			else 
			{
				ForEach ($porto in $hostnode.ports.port)
                {
					if ($porto.service.name -eq $null) { $service = "unknown" } else { $service = $porto.service.name } 
					$entry.Ports += $porto.state.state + ":" + $porto.protocol + ":" + $porto.portid + ":" + $service + $OutputDelimiter 
                    # Build Services property. What a mess...but exclude non-open/non-open|filtered ports and blank service info, and exclude servicefp too for the sake of tidiness.
                    if ($porto.state.state -like "open*" -and ($porto.service.tunnel.length -gt 2 -or $porto.service.product.length -gt 2 -or $porto.service.proto.length -gt 2)) { $entry.Services += $porto.protocol + ":" + $porto.portid + ":" + $service + ":" + ($porto.service.product + " " + $porto.service.version + " " + $porto.service.tunnel + " " + $porto.service.proto + " " + $porto.service.rpcnum).Trim() + " <" + ([Int] $porto.service.conf * 10) + "%-confidence>$OutputDelimiter" }
				}
				$entry.Ports = $entry.Ports.Trim()
                if ($entry.Services -eq $null) { $entry.Services = "<no-services>" } else { $entry.Services = $entry.Services.Trim() }
                if ($entry.Services -ne $null) { $entry.Services = $entry.Services.Trim() } 
			}


			# Extract fingerprinted OS type and percent of accuracy.
			ForEach ($osm in $hostnode.os.osmatch) {$entry.OS += $osm.name + " <" + ([String] $osm.accuracy) + "%-accuracy>$OutputDelimiter"} 
            ForEach ($osc in $hostnode.os.osclass) {$entry.OS += $osc.type + " " + $osc.vendor + " " + $osc.osfamily + " " + $osc.osgen + " <" + ([String] $osc.accuracy) + "%-accuracy>$OutputDelimiter"}  
            if ($entry.OS -ne $null -and $entry.OS.length -gt 0)
            {
               $entry.OS = $entry.OS.Replace("  "," ")
               $entry.OS = $entry.OS.Replace("<%-accuracy>","") #Sometimes no osmatch.
			   $entry.OS = $entry.OS.Trim()
            }
			if ($entry.OS.length -lt 16) { $entry.OS = "<no-os>" }

            
            # Extract script output, first for port scripts, then for host scripts.
            ForEach ($pp in $hostnode.ports.port)
            {
                if ($pp.script -ne $null) { 
                    $entry.Script += "<PortScript id=""" + $pp.script.id + """>$OutputDelimiter" + ($pp.script.output -replace "`n","$OutputDelimiter") + "$OutputDelimiter</PortScript> $OutputDelimiter $OutputDelimiter" 
                }
            } 
            
            if ($hostnode.hostscript -ne $null) {
                ForEach ($scr in $hostnode.hostscript.script)
                {
                    $entry.Script += '<HostScript id="' + $scr.id + '">' + $OutputDelimiter + ($scr.output.replace("`n","$OutputDelimiter")) + "$OutputDelimiter</HostScript> $OutputDelimiter $OutputDelimiter" 
                }
            }
            
            if ($entry.Script -eq $null) { $entry.Script = "<no-script>" } 
    
    
			# Emit custom object from script.
			$i++  #Progress counter...
			$entry
		}

		Write-Verbose -Message ( "[" + (get-date).ToLongTimeString() + "] Finished $file, processed $i entries." ) 
        Write-Verbose -Message ('Total Run Time: ' + ( [MATH]::Round( ((Get-date) - $StartTime).TotalSeconds, 3 )) + ' seconds')
        Write-Verbose -Message ('Entries/Second: ' + ( [MATH]::Round( ($i / $((Get-date) - $StartTime).TotalSeconds), 3 ) ) )  
	}
}


$Parsed = parse-nmap -Path $NmapXml

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
