$dc01 = [System.Net.IPAddress]::Parse("172.16.40.5")
$ports = @(22,80,88,135,139,389,443,445,464,636,1433,3389,5985,8080,49152)
foreach ($p in $ports) {
    try {
        $t = New-Object System.Net.Sockets.TcpClient
        $r = $t.BeginConnect($dc01, $p, $null, $null)
        $w = $r.AsyncWaitHandle.WaitOne(2000, $false)
        if ($w -and $t.Connected) { Write-Host "[+] DC01 Port $p OPEN" }
        $t.Close()
    } catch {}
}
Write-Host "DC01 scan DONE"
