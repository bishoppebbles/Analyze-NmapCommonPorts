# Analyze-NmapCommonPorts
Displays IP addresses of systems with common open TCP or UDP ports based on Nmap's XML formatted output.  It also displays systems that have more than one port open for protocols common to printing.  This is my attempt to summarize Nmap results and make the date more actionable to remedy.

Other features include:
* An option to produce a total count of open ports for each unique TCP or UDP port
* An option that converts the XML data to the Tab Separated Value (TSV) format

This script calls the [Parse-Nmap.ps1](https://github.com/EnclaveConsulting/SANS-SEC505) cmdlet by @JasonFossen of Enclave Consulting to parse Nmap's XML output file.  His cmdlet nicely creates PowerShell objects to work with.  This also requires XML formatted Nmap output.

The XML to TSV converter has contributions from Matt Johnson.

## Nmap Usage:
You need the XML formatted output from a Nmap scan.  The `-oA` option can do this by providing all three Nmap output option types or the `-oX` option will produce the XML exclusively.  An example of latter running a SYN scan and only probing the top 100 most common  ports is:

```console
.\Nmap.exe -sS -sU -F -oX nmapData.xml <network>/<mask>
```

## Grouped by Port (IP only):
After you have the XML data the simplest option to run the script within PowerShell is as follows:

```console
.\Analyze-NmapCommonPorts.ps1 –NmapXml <nmapData.xml>
```

It groups the output by some common port numbers and lists all IPs that are open for the given protocol.  The last section display IPs for printers if they have more than one of the common printing protocol ports open (e.g., 515, 631, or 9100).  If you don’t care for this and want to suppress that output use the `-ExcludePrinter` option.

## Grouped by Port (IP and FQDN):
If you prefer to see the output with the Fully Qualified Domain Name (FQDN) of the host add the –AddFQDN option to the above:

```console
.\Analyze-NmapCommonPorts.ps1 –NmapXml <nmapData.xml> -AddFQDN
```

Note that this option will use the FQDN provided from the Nmap scan.  If there isn’t one it will then attempt to resolve the name again in real time.  This may take some additional time while the script is querying the system IPs for names via DNS.  If it looks like it froze it most likely didn’t.  From my tests the success of doing this has been limited as a lot the hosts without a name are often printers and they are not properly configured.  I wouldn't expect a bunch of IPs to resolve that didn’t before.

## Grouped by Host
Both of the above methods display the results grouped by port number.  If you want to see the results based on each host use the `–SortByHost` option.  This output is essentially a consolidated version of how the Nmap output groups the data but only lists the specified ports:

```console
.\Analyze-NmapCommonPorts.ps1 –NmapXml <nmapData.xml> -SortByHost
```

## Open Port Count Totals:
The last main option gives you a summarized count of every single port that is open using the `-CountOpenPorts` option:

```console
.\Analyze-NmapCommonPorts.ps1 –NmapXml <nmapData.xml> -CountOpenPorts
```

I’d personally pay attention to any unknown services that are only running on a few systems.  These are the outliers which should generally not be common to the enterprise.  Feel free to google these or perform more in-depth Nmap scanning (e.g., `-sV`, `-O`, `-A` options, etc.) to try to determine the service.

## Convert XML Data to the TSV Format
Converts the XML data to the TSV format.  The `-ExcludeFields` option removes any specified output fields.  Valid options include:
* FQDN, Status, IPv4, IPv6, MAC, Services, OS, Script, PortStatus, Transport, Port, PortService

The `-OutputFile` option writes the TSV output file to the given name.  Otherwise  a file named `NmapData.tsv` is the default.

```console
Analyze-NmapCommonPorts.ps1 -NmapXml nmapData.xml -CreateTsv -OutputFile PortScanData.tsv
```

#### For a complete listing of help directly within Powershell run:

```console
Get-Help .\Analyze-NmapCommonPorts.ps1 -Full
```
