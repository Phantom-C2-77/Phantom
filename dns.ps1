$interface = "Ethernet"

Set-DNSClientServerAddress -InterfaceAlias $interface -ServerAddresses ("127.0.0.1", "127.0.0.2");
$adapter = Get-NetAdapter | Where-Object { $_.InterfaceAlias -eq $interface }
if ($null -eq $adapter) {
    Break;
}
$zonename = "puppet.vl"
$ip = (Get-NetIPAddress -InterfaceAlias $interface -AddressFamily IPv4).IPAddress
$octets = $ip -split '\.'

if($octets[0] -eq "192"){
    Write-Host "Local Environment - Exitting"
    Break;
}

$decimalIP = [System.Convert]::ToUInt32($octets[3]) -bor ([System.Convert]::ToUInt32($octets[2]) -shl 8) -bor ([System.Convert]::ToUInt32($octets[1]) -shl 16) -bor ([System.Convert]::ToUInt32($octets[0]) -shl 24)

$decimalIP++; 

$updatedOctets = @(
    ([System.Convert]::ToByte(($decimalIP -shr 24) -band 255)),
    ([System.Convert]::ToByte(($decimalIP -shr 16) -band 255)),
    ([System.Convert]::ToByte(($decimalIP -shr 8) -band 255)),
    ([System.Convert]::ToByte($decimalIP -band 255))
)
$targetIP = $updatedOctets -join '.'
$hostname = "File01"
$oldobj = Get-DnsServerResourceRecord -ZoneName $zonename -Name $hostname -RRType "A"
$newobj = Get-DnsServerResourceRecord -ZoneName $zonename -Name $hostname -RRType "A"
$newobj[0].recorddata.ipv4address=[System.Net.IPAddress]::parse($targetIP)
Set-dnsserverresourcerecord -newinputobject $newobj[0] -oldinputobject $oldobj[0] -zonename $zonename -passthru

$decimalIP++; 
$updatedOctets = @(
    ([System.Convert]::ToByte(($decimalIP -shr 24) -band 255)),
    ([System.Convert]::ToByte(($decimalIP -shr 16) -band 255)),
    ([System.Convert]::ToByte(($decimalIP -shr 8) -band 255)),
    ([System.Convert]::ToByte($decimalIP -band 255))
)
$targetIP = $updatedOctets -join '.'
$hostname = "puppet"
$oldobj = Get-DnsServerResourceRecord -ZoneName $zonename -Name $hostname -RRType "A"
$newobj = Get-DnsServerResourceRecord -ZoneName $zonename -Name $hostname -RRType "A"
$newobj[0].recorddata.ipv4address=[System.Net.IPAddress]::parse($targetIP)
Set-dnsserverresourcerecord -newinputobject $newobj[0] -oldinputobject $oldobj[0] -zonename $zonename -passthru

Disable-NetAdapterBinding –InterfaceAlias $interface –ComponentID ms_tcpip6

cmd /c ipconfig /flushdns