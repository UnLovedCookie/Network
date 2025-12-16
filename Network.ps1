# irm https://raw.githubusercontent.com/UnLovedCookie/Network/refs/heads/main/Network.ps1 | iex
# https://discord.gg/dptDHp9p9k
# https://github.com/UnLovedCookie/Network

$ErrorActionPreference = "SilentlyContinue"

# Elevated Script
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $script = if ($PSCommandPath) { "& `'$PSCommandPath`'" } else { "&([ScriptBlock]::Create((irm https://raw.githubusercontent.com/UnLovedCookie/Network/refs/heads/main/Network.ps1)))" };
    $pwsh = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

    $args = "-ExecutionPolicy Bypass -NoProfile -Command `"$script`""

    if (Get-Command wt.exe -ErrorAction SilentlyContinue) {
        Start-Process wt.exe -ArgumentList "$pwsh $args" -Verb RunAs
    }
    else {
        Start-Process $pwsh -ArgumentList $args -Verb RunAs
    }

    exit
}

# Functions
function Set-NICProperty {
    param($Keyword,$Value)
    Get-NetAdapterAdvancedProperty |
      Where-Object { $_.RegistryKeyword -like "$Keyword*" -or $_.RegistryKeyword -like "*$Keyword" } |
      ForEach-Object {
          $need = [string]$Value
          if ([string]$_.RegistryValue -eq $need) {
              Write-Host "- $($_.Name) $($_.RegistryKeyword) already $need" -ForegroundColor Blue
              return
          }
          try {
              Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword $_.RegistryKeyword -RegistryValue $Value -NoRestart -ErrorAction Stop
              $now = [string](Get-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword $_.RegistryKeyword).RegistryValue
              if ($now -eq $need) {
                  Write-Host "* $($_.Name) $($_.RegistryKeyword) set to $need" -ForegroundColor Green
              } else {
                  Write-Host "X $($_.Name) $($_.RegistryKeyword) not set" -ForegroundColor Red
              }
          } catch {
              Write-Host "X $($_.Name) $($_.RegistryKeyword) error: $($_.Exception.Message)" -ForegroundColor Red
          }
      }
}


function Set-TCPSetting {
  param([string]$Setting,[int]$Value)
  $paths=@(
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
  )
  foreach($p in $paths){
    try{$cur=Get-ItemPropertyValue -Path $p -Name $Setting -ErrorAction SilentlyContinue}catch{$cur=$null}
    if($cur -eq $Value){Write-Host "- $p\$Setting already $Value" -ForegroundColor Blue;continue}
    try{
      New-ItemProperty -Path $p -Name $Setting -Value $Value -PropertyType DWord -Force|Out-Null
      if((Get-ItemPropertyValue -Path $p -Name $Setting) -eq $Value){
        Write-Host "* $p\$Setting set to $Value" -ForegroundColor Green
      }else{
        Write-Host "X $p\$Setting not set" -ForegroundColor Red
      }
    }catch{
      Write-Host "X $p\$Setting error: $($_.Exception.Message)" -ForegroundColor Red
    }
  }
}

function Show-Menu {
  param([string]$Title,[object[]]$Options)  # "Label" or @("Label","Description")
  $i=0
  while($true){
    cls; Write-Host "$Title`n"
    for($x=0;$x -lt $Options.Length;$x++){
      $o=$Options[$x]; if($o -isnot [array]){$o=@($o,'')}
      $sel=if($x -eq $i){">> "}else{"   "}
      Write-Host "$sel$($o[0])" -ForegroundColor ($(if($x -eq $i){"Cyan"}else{"White"}))
      if($o[1]){ Write-Host "$($o[1])" }
    }
    switch([console]::ReadKey($true).Key){
      'UpArrow'   { if($i){$i--} }
      'DownArrow' { if($i -lt $Options.Length-1){$i++} }
      'Enter'     { return $i+1 }
    }
  }
}

# User Input
$ConnectionType = Show-Menu "Connection Type:" @(
  @("Fiber (100+ mbps)","Best for very high speeds"),
  @("VDSL (20-100 mbps)","Balanced speed & stability"),
  @("ADSL (<20 mbps)","For slower lines")
)


$OptimizeFor = Show-Menu "Optimize For:" @(
  @("Throughput (Higher Speeds)","Enable Packet Coalescing, LSO, & Throughput Booster; Normal AutoTuning; Max Rx/Tx Buffers"),
  @("Latency (Lower Ping)","Disable Packet Coalescing, LSO, & Throughput Booster; Highly Restricted AutoTuning; 128B Rx/Tx Buffers")
)

$Stability = Show-Menu "Stability:" @(
  @("Stable Connection (No Lag Spikes)","Disable Interrupt Moderation, & Flow Control"),
  @("Unstable Connection (Lag Spikes)","Enable Interrupt Moderation, & Flow Control")
)
cls

<#


Advanced Network Adapter Settings


#>

# Reset Advanced Network Adapter Options
Reset-NetAdapterAdvancedProperty -DisplayName '*' -NoRestart
Write-Host "Reset Advanced Network Adapter Options"

# Throughput Booster
if ($OptimizeFor -eq 1) {
    Set-NICProperty "ThroughputBoosterEnabled" "1"
    Write-Host "Enable Throughput Booster"
} else {
    Set-NICProperty "ThroughputBoosterEnabled" "0"
    Write-Host "Disable Throughput Booster"
}

# Flow Control
if ($Stability -eq 1) {
    Set-NICProperty "FlowControl" "0"
    Write-Host "Disable Flow Control"
} else {
    Set-NICProperty "FlowControl" "3"
    Write-Host "Enable Flow Control"
}

# Packet Coalescing
if ($OptimizeFor -eq 1) {
    Set-PacketCoalescingFilter Disabled
    Set-NICProperty "Packet Coalescing" "0"
    Write-Host "Disable Packet Coalescing"
} else {
    Set-PacketCoalescingFilter Enabled
    Set-NICProperty "Packet Coalescing" "1"
    Write-Host "Enable Packet Coalescing"
}

# Interrupt Moderation
if ($Stability -eq 1) {
    Set-NICProperty "InterruptModeration" "0"
    Write-Host "Disable Interrupt Moderation"
} else {
    Set-NICProperty "InterruptModeration" "1"
    Write-Host "Enable Interrupt Moderation"
}

# Large Send Offload (LSO)
if ($OptimizeFor -eq 1) {
    Set-NICProperty "LsoV1IPv4" "1"
    Set-NICProperty "LsoV2IPv4" "1"
    Set-NICProperty "LsoV2IPv6" "1"
    Write-Host "Enable Large Send Offload (LSO)"
} else {
    Set-NICProperty "LsoV1IPv4" "0"
    Set-NICProperty "LsoV2IPv4" "0"
    Set-NICProperty "LsoV2IPv6" "0"
    Write-Host "Disable Large Send Offload (LSO)"
}

# Enable All Wireless Modes
Set-NetAdapterAdvancedProperty -RegistryKeyword WirelessMode -RegistryValue 34 -NoRestart
Set-NetAdapterAdvancedProperty -RegistryKeyword IEEE11nMode -RegistryValue 3 -NoRestart
Write-Host "Enable All Wireless Modes"

# Disable Jumbo Packets
Set-NICProperty "JumboPacket" "1514"
Write-Host "Disable Jumbo Packets"

# Disable Direct Memory Access (DMA) Coalescing
Set-NICProperty "DMACoalescing" "0"
Write-Host "Disable Direct Memory Access (DMA) Coalescing"

# Disable Receive Segment Coalescing (RSC)
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
Set-NICProperty "RscIPv4" "0"
Set-NICProperty "RscIPv6" "0"
Write-Host "Disable Receive Segment Coalescing State (RSC)"

# Disable TCP Chimney Offload
Set-NetOffloadGlobalSetting -Chimney Disabled
Write-Host "Disable TCP Chimney Offload"

# Enable Network Task Offloading
Set-NetOffloadGlobalSetting -TaskOffload Enabled
Write-Host "Enable Network Task Offloading"

# Enable Address Resolution Protocol (ARP) Offload
Set-NICProperty "PMARPOffload" "1"
Write-Host "Enable Address Resolution Protocol (ARP) Offload"

# Disable IPsec Offload
Disable-NetAdapterIPsecOffload -Name *
Set-NICProperty "IPsecOffloadV1IPv4" "0"
Set-NICProperty "IPsecOffloadV2" "0"
Set-NICProperty "IPsecOffloadV2IPv4" "0"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Ipsec" -Name "EnabledOffload" -Value 0 -Type DWord
Write-Host "Disable IPsec Offload"

# Optimize Receive Side Scaling (RSS)
Set-NetOffloadGlobalSetting -ReceiveSideScaling Enabled
$MaxRssProc = [Environment]::ProcessorCount - 2
if ($MaxRssProc -lt 1) { $MaxRssProc = 1 }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Ndis\Parameters" -Name "RssBaseCpu" -Value 1 -Type DWord
$rssSettings = @(
    @{Keyword="RSS"; Value="1"},
    @{Keyword="NumRssQueues"; Value="4"},
    @{Keyword="RSSProfile"; Value="4"},
    @{Keyword="NumaNodeId"; Value="0"},
    @{Keyword="RssBaseProcGroup"; Value="0"},
    @{Keyword="RssMaxProcGroup"; Value="0"},
    @{Keyword="RssBaseProcNumber"; Value="0"},
    @{Keyword="RssMaxProcNumber"; Value="$MaxRssProc"},
    @{Keyword="MaxRssProcessors"; Value="$MaxRssProc"},
    @{Keyword="RssV2"; Value="1"},
    @{Keyword="ValidateRssV2"; Value="1"}
)
foreach ($setting in $rssSettings) {
    Set-NICProperty $setting.Keyword $setting.Value
}
Write-Host "Optimize Receive Side Scaling (RSS)"

# Enable UDP and TCP Checksums
Enable-NetAdapterChecksumOffload -Name *
$checksumSettings = @(
    @{Keyword="TCPUDPChecksumOffloadIPv4"; Value="3"},
    @{Keyword="TCPUDPChecksumOffloadIPv6"; Value="3"},
    @{Keyword="UDPChecksumOffloadIPv4"; Value="3"},
    @{Keyword="UDPChecksumOffloadIPv6"; Value="3"},
    @{Keyword="TCPChecksumOffloadIPv4"; Value="3"},
    @{Keyword="TCPChecksumOffloadIPv6"; Value="3"},
    @{Keyword="IPChecksumOffloadIPv4"; Value="3"}
)
foreach ($setting in $checksumSettings) {
    Set-NICProperty $setting.Keyword $setting.Value
}
Write-Host "Enable UDP and TCP Checksums"

# Disable Network Adapter Power Management
Disable-NetAdapterPowerManagement -Name * -NoRestart
Write-Host "Disable Network Adapter Power Management"

# Disable Network Adapter Power Saving Features
$powerSettings = @(
    # Disable Wake Features
    @{Keyword="WakeOnMagicPacket"; Value="0"},
    @{Keyword="WakeOnPattern"; Value="0"},
    @{Keyword="WakeOnLink"; Value="0"},
    @{Keyword="WakeOnLinkChange"; Value="0"},
    @{Keyword="S5WakeOnLan"; Value="0"},
    @{Keyword="WolShutdownLinkSpeed"; Value="2"},
    @{Keyword="ModernStandbyWoLMagicPacket"; Value="0"},
    @{Keyword="DeviceSleepOnDisconnect"; Value="0"},
    # Disable Energy Efficient Ethernet
    @{Keyword="EEE"; Value="0"},
    @{Keyword="EEEPhyEnable"; Value="0"},
    @{Keyword="EnableGreenEthernet"; Value="0"},
    @{Keyword="EEELinkAdvertisement"; Value="0"},
    @{Keyword="AdvancedEEE"; Value="0"},
    # Disable Ultra Low Power Mode
    @{Keyword="ULPMode"; Value="0"},
    # Disable Wi-Fi capability that saves power consumption
    @{Keyword="uAPSDSupport"; Value="0"},
    # Max Transmit Power
    @{Keyword="Transmit Power"; Value="100"},
    # Disable Power Saving Features
    @{Keyword="NicAutoPowerSaver"; Value="0"},
    @{Keyword="SelectiveSuspend"; Value="0"},
    @{Keyword="EnablePME"; Value="0"},
    @{Keyword="ReduceSpeedOnPowerDown"; Value="0"},
    @{Keyword="PowerSavingMode"; Value="0"},
    @{Keyword="SavePowerNowEnabled"; Value="0"},
    @{Keyword="GigaLite"; Value="0"},
    @{Keyword="EnableSavePowerNow"; Value="0"},
    @{Keyword="bLowPowerEnable"; Value="0"},
    @{Keyword="EnablePowerManagement"; Value="0"},
    @{Keyword="EnableDynamicPowerGating"; Value="0"},
    @{Keyword="DisableDelayedPowerUp"; Value="1"},
    @{Keyword="EnableConnectedPowerGating"; Value="0"},
    @{Keyword="AutoPowerSaveModeEnabled"; Value="0"},
    @{Keyword="PowerSaveMode"; Value="0"},
    @{Keyword="AutoDisableGigabit"; Value="0"},
    @{Keyword="PowerDownPll"; Value="0"},
    @{Keyword="S5NicKeepOverrideMacAddrV2"; Value="0"},
    @{Keyword="MIMOPowerSaveMode"; Value="3"},
    @{Keyword="AlternateSemaphoreDelay"; Value="0"},
    @{Keyword="SipsEnabled"; Value="0"},
    # Access Point Compatibility Mode: 'High Performance'
    @{Keyword="ApCompatMode"; Value="0"},
    # Disable network adapter power management
    @{Keyword="PnPCapabilities"; Value="24"}
)
foreach ($setting in $powerSettings) {
    Set-NICProperty $setting.Keyword $setting.Value
}
Write-Host "Disable Network Adapter Power Saving Features"

# Set Max Receive/Transmit Buffers
if ($OptimizeFor -eq 1) {
    foreach ($nic in Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards' | 
    ForEach-Object { (Get-ItemProperty $_.PSPath).Description }) {
        Get-ChildItem 'HKLM:\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}' -Recurse |
        Get-ItemProperty |
        Where-Object { $_.DriverDesc -eq $nic } |
        ForEach-Object {
            $deviceKeyPath = $_.PSPath
            foreach ($bufType in 'Receive','Transmit') {
                $paramPath = Join-Path $deviceKeyPath "Ndi\params\*${bufType}Buffers"
                if (Test-Path $paramPath) {
                    $max = (Get-ItemProperty $paramPath -Name Max -ErrorAction SilentlyContinue).Max
                    if ($max) { Set-NICProperty "$bufType`Buffers" $max }
                }
            }
        }
    }
    Write-Host "Set Max Receive/Transmit Buffers"
} else {
    Set-NICProperty "ReceiveBuffers" 128
    Set-NICProperty "TransmitBuffers" 128
    Write-Host "Set Receive/Transmit Buffers to 128"
}

<#


TCP/IP Settings


#>


# Reset TCP/IP Settings
@(
    "netsh int tcp reset",
    "netsh winsock reset",
    "netsh int ip reset",
    "netsh int ipv4 reset",
    "netsh int ipv6 reset"
) | ForEach-Object { Invoke-Expression $_ *>$null }
Write-Host "Reset TCP/IP Settings"

# Configure Autotuning
if ($OptimizeFor -eq 1) {
    Set-NetTCPSetting -AutoTuningLevelLocal normal
    Write-Host "Enable Autotuning"
} else {
    Set-NetTCPSetting -AutoTuningLevelLocal highlyrestricted
    Write-Host "Enable Highly Restricted Autotuning"
}

# Enable Winsock/HTTP Autotuning
netsh winsock set autotuning on | Out-Null
$httpSettings = @(
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"; Name="TcpAutotuning"},
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="TcpAutotuning"}
)
foreach ($setting in $httpSettings) {
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value 1 -Type DWord
}
Write-Host "Enable Winsock/HTTP Autotuning"

# Optimize Time To Live (TTL)
$DefaultTTL = switch ($ConnectionType) {
    1 { 255 }
    2 { 128 }
    3 { 64 }
    default { 128 }
}
Get-NetIPInterface | Set-NetIPInterface -CurrentHopLimit $DefaultTTL
Write-Host "Set Time To Live (TTL) To $DefaultTTL"

# Disable Window Scaling Heuristics
Set-NetTCPSetting -ScalingHeuristics Disabled
Write-Host "Disable Window Scaling Heuristics"

# Enable TCP Window Scaling, Disable TCP 1323 Timestamps
Set-NetTCPSetting -Timestamps Disabled
Set-TCPSetting "Tcp1323Opts" 1
Write-Host "Enable TCP Window Scaling"
Write-Host "Disable TCP 1323 Timestamps"

# IPv4 Maximum Transmission Unit (MTU)
$mtu=1500; Get-NetIPInterface|Set-NetIPInterface -NlMtuBytes $mtu -AddressFamily IPv4
do { $ping=ping 8.8.8.8 -f -n 1 -4 -l $mtu -w 750; $mtu-- } while($ping -match 'fragmented')
$mtu++; if($ping -match 'fragmented' -or $mtu -ge 1472){ $mtu=1500 }
Get-NetIPInterface|Set-NetIPInterface -NlMtuBytes $mtu -AddressFamily IPv4
Write-Host "Set IPv4 MTU to $mtu"

# IPv6 Maximum Transmission Unit (MTU)
$mtu=1500; Get-NetIPInterface|Set-NetIPInterface -NlMtuBytes $mtu -AddressFamily IPv6
do { $ping=ping 2001:4860:4860::8888 -n 1 -6 -l $mtu -w 750; $mtu-- } while($ping -match 'too big')
$mtu++; if($ping -match 'too big' -or $mtu -ge 1452){$mtu=1500}
Get-NetIPInterface|Set-NetIPInterface -NlMtuBytes $mtu -AddressFamily IPv6
Write-Host "Set IPv6 MTU to $mtu"

# Set Fast Send Datagram
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "FastSendDatagramThreshold" -Value $MTU -Type DWord
Write-Host "Set Fast Send Datagram To $MTU"

# Increase Address Resolution Protocol (ARP) Cache Size To 4096
Set-NetIPv6Protocol -NeighborCacheLimitEntries 4096
Set-NetIPv4Protocol -NeighborCacheLimitEntries 4096
Write-Host "Increase Address Resolution Protocol (ARP) Cache Size to 4096"

# Enable Explicit Congestion Notification (ECN)
netsh int tcp set global ecn=enabled | Out-Null
Set-NetTCPSetting -EcnCapability Enabled
Write-Host "Enable Explicit Congestion Notification (ECN)"

# Disable Large MTU on The Loopback Interface
# Fix BBR2 breaking sunshine, steam, and badlion
netsh int ipv4 set global loopbacklargemtu=disabled | Out-Null
netsh int ipv6 set global loopbacklargemtu=disabled | Out-Null
Write-Host "Disable Large MTU on The Loopback Interface"

# Set Congestion Provider To BBR2/CTCP
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
if ($osInfo.Caption -match "Windows 11") {
    netsh int tcp set supplemental Internet CongestionProvider=bbr2 | Out-Null
    Write-Host "Set Congestion Provider To BBR2"
} else {
    netsh int tcp set supplemental Internet CongestionProvider=CTCP | Out-Null
    Write-Host "Set Congestion Provider To CTCP"
}

# Increase the TCP Initial Congestion Window
netsh int tcp set supplemental Internet icw=10 | Out-Null
Write-Host "Increase the TCP Initial Congestion Window"

# Disable Proportional Rate Reduction
netsh int tcp set global prr=disabled | Out-Null
Write-Host "Disable Proportional Rate Reduction"

# Enable Weak Host Model
Get-NetIPInterface | Set-NetIPInterface -WeakHostReceive Enabled -WeakHostSend Enabled
Write-Host "Enable Weak Host Model"

# Disable Memory Pressure Protection (MPP)
Set-NetTCPSetting -MemoryPressureProtection Disabled
Write-Host "Disable Memory Pressure Protection (MPP)"

# Set Dynamic Port Range to Max
Set-NetTCPSetting -DynamicPortRangeStartPort 1024 -DynamicPortRangeNumberOfPort 64512
Write-Host "Set Dynamic Port Range to Max"

# Enable Direct Cache Access (DCA)
netsh int tcp set global dca=enabled | Out-Null
Write-Host "Enable Direct Cache Access (DCA)"

# Enable TCP Fast Open
netsh int tcp set global fastopen=enabled | Out-Null
Write-Host "Enable TCP Fast Open"

# Enable Network Direct Memory Access (NetDMA)
netsh int tcp set global netdma=enabled | Out-Null
Write-Host "Enable NetDMA"

<#


Registy Settings


#>


# Enable SMBv2 / SMBv3
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 1 -Type DWord
Write-Host "Enable SMBv2 / SMBv3"

# Enable Large MTU
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableLargeMTU" -Value 0 -Type DWord
Write-Host "Enable Large MTU"

# Enable Large System Cache
$cacheSettings = @(
    @{Path="HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management"; Name="LargeSystemCache"; Value=1},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="Size"; Value=3}
)
foreach ($setting in $cacheSettings) {
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord
}
Write-Host "Enable Large System Cache"

# Optimize SMB Parameters
$smbParams = @(
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="IRPStackSize"; Value=50},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RequireSecuritySignature"; Value=0},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SizReqBuf"; Value=17424},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="MaxCmds"; Value=10},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="MaxMpxCt"; Value=10},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="MaxWorkItems"; Value=512},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="MinFreeConnections"; Value=4},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"; Name="MaxFreeConnections"; Value=8},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="MaxThreads"; Value=30},
    @{Path="HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="MaxCollectionCount"; Value=32}
)
foreach ($param in $smbParams) {
    Set-ItemProperty -Path $param.Path -Name $param.Name -Value $param.Value -Type DWord
}
Write-Host "Optimize SMB Parameters"

# Disable NetBIOS Over TCP/IP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -Name "NetBiosOptions" -Value 2 -Type DWord
(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True").SetTcpipNetbios(2) | Out-Null
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord
Write-Host "Disable NetBIOS Over TCP/IP"

# Disable LLMNR
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "Disable LLMNR"

# Disable Delivery Optimization
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" -Name "DownloadMode" -Value 0 -Type DWord
Set-Service -Name "DoSvc" -StartupType Manual
Write-Host "Disable Delivery Optimization"

# Disable Network Throttling
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 4294967295 -Type DWord
Write-Host "Disable Network Throttling"

# Increase Concurrent Connections Limit
$conSettings = @(
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="MaxConnectionsPerServer"; Value=10},
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"; Name="MaxConnectionsPer1_0Server"; Value=10}
)
foreach ($setting in $conSettings) {
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord
}
Write-Host "Increase Concurrent Connections Limit"

# Enable Path Maximum Transfer Unit (PMTU)
Set-TCPSetting "EnablePMTUDiscovery" 1
Write-Host "Enable Path Maximum Transfer Unit (PMTU)"

# Enable Path Maximum Transfer Unit (PMTU) Black Hole Detection
Set-TCPSetting "EnablePMTUBHDetect" 1
Write-Host "Enable Path Maximum Transfer Unit (PMTU) Black Hole Detection"

# Set Default TCP Window Size
Set-TCPSetting "GlobalMaxTcpWindowSize" 65536
Set-TCPSetting "TcpWindowSize" 65536
Write-Host "Set Default TCP Window Size"

# Disable NDIS Power Management
Set-TCPSetting "DisablePowerManagement" 1
Write-Host "Disable NDIS Power Management"

# Remove TCP Connection Limit
Set-TCPSetting "EnableConnectionRateLimiting" 0
Write-Host "Disable TCP Connection Limit"

# Unlimited Outstanding Send Packets
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "MaxOutstandingSends" -ErrorAction SilentlyContinue
Write-Host "Disable Outstanding Send Packets Limit"

# Swuab Timeout Settings
Set-TCPSetting "KeepAliveTime" 300000
Set-TCPSetting "KeepAliveInterval" 1000
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -Value "86400" -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxNegativeCacheTtl" -Value "0" -Type DWord
Write-Host "Swuab Timeout Settings"

# Set Network Level Priorities
$prioritySettings = @(
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"; Name="LocalPriority"; Value=4},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"; Name="HostsPriority"; Value=5},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"; Name="DnsPriority"; Value=6},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"; Name="NetBtPriority"; Value=7},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider"; Name="Class"; Value=8}
)
foreach ($setting in $prioritySettings) {
    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type DWord
}
Write-Host "Set Network Level Priorities"

# Optimize TCP Acks, Sacks, and Syns
$networkInterfaces = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" | 
                    ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object ServiceName }

foreach ($interface in $networkInterfaces) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($interface.ServiceName)"
    
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "TCPNoDelay" -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name "TCPAckFrequency" -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name "TCPDelAckTicks" -Value 0 -Type DWord
        Set-ItemProperty -Path $path -Name "TcpInitialRTT" -Value 2000 -Type DWord
    }
}

# Disable Nagle's Algorithm
Set-TCPSetting "TCPNoDelay" 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Value 1 -Type DWord
Write-Host "Disable Nagle's Algorithm"

# Disable TCP Ack Delays
Set-TCPSetting "TCPAckFrequency" 1
Set-TCPSetting "TCPDelAckTicks" 0
Write-Host "Disable TCP Ack Delays"

# Lower Initial Round-Trip Time (RTT)
Set-TCPSetting "TCPInitialRTT" 300
Write-Host "Lower Initial Round-Trip Time (RTT)"

# Lower Initial Retransmission Timeout (RTO)
Set-NetTCPSetting -InitialRtoMs 2000
Write-Host "Lower Initial Retransmission Timeout (RTO)"

# Lower Minimum Retransmission Timeout (RTO)
# Hard Coded
# Set-NetTCPSetting -MinRtoMs 20 | Out-Null
# Write-Host "Lower Minimum Retransmission Timeout (RTO)"

# Decrease Max SYN Retransmissions
Set-NetTCPSetting -MaxSynRetransmissions 2
Write-Host "Decrease Max SYN Retransmissions"

# Decrease Max SYN/SYN-Ack Retransmissions
Set-TCPSetting "TcpMaxConnectRetransmissions" 2
Write-Host "Decrease Max SYN/SYN-Ack Retransmissions"

# Decrease Max Data Packet Retransmissions
Set-TCPSetting "TcpMaxDataRetransmissions" 2
Write-Host "Decrease Max Data Packet Retransmissions"

# Enable TCP Selective Acks (SACK) Support
Set-TCPSetting "SackOpts" 1
Write-Host "Enable TCP Selective Acks (SACK) Support"

# Disable RTT Resiliency for Non-SACK Clients
Set-NetTCPSetting -NonSackRttResiliency Disabled
Write-Host "Disable RTT Resiliency for Non-SACK Clients"

# Set TIME_WAIT Length to Minimum
Set-TCPSetting "TcpTimedWaitDelay" 30
Write-Host "Set TIME_WAIT Length to Minimum"

<#


Miscellaneous


#>

# Disable Auto Configuration Logic on All Interfaces
<# Disables Network Discovery
Get-NetAdapter | ForEach-Object {
    netsh wlan set autoconfig enabled=no interface="$($_.Name)" | Out-Null
}
Write-Host "Disable Auto Configuration Logic on All Interfaces"
#>

# Disable Connected Standby
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Power" -Name "EnforceDisconnectedStandby" -Value 0 -Type DWord
powercfg /setacvalueindex scheme_current sub_none connectivityinstandby 0
powercfg /s scheme_current
Write-Host "Disable Connected Standby"

# Enable QoS
Enable-NetAdapterBinding -Name * -ComponentID Ms_Pacer
Set-Service -Name "Psched" -StartupType Automatic
Start-Service -Name "Psched"

# Enable QoS Policies on Home Computers
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\QoS" -Name "Do not use NLA" -Value "1" -Type String
Write-Host "Enable QoS Policies on Home Computers"

# Optimize DSCP for gaming apps
$apps = @("csgo", "VALORANT-Win64-Shipping", "javaw", "FortniteClient-Win64-Shipping", 
          "ModernWarfare", "r5apex", "Marvel-Win64-Shipping", "ExitLag")

foreach ($app in $apps) {
    Remove-NetQosPolicy -Name $app -ErrorAction SilentlyContinue -Confirm:$false
    Remove-NetQosPolicy -Name $app -PolicyStore ActiveStore -ErrorAction SilentlyContinue -Confirm:$false
    New-NetQosPolicy -Name $app -AppPathNameMatchCondition "$app.exe" -DscpAction 46 | Out-Null
    New-NetQosPolicy -Name $app -AppPathNameMatchCondition "$app.exe" -DscpAction 46 -PolicyStore ActiveStore | Out-Null
}
Write-Host "Optimize DSCP For Certain Applications"

# Disable Java Firewall
Get-NetFirewallRule -DisplayName "Minecraft*" | Remove-NetFirewallRule
"Inbound","Outbound" | ForEach-Object { New-NetFirewallRule -DisplayName "Minecraft $_" -Direction $_ -Program ($env:JAVA_HOME + "javaw.exe") -Action Allow } | Out-Null
Write-Host "Disable Java Firewall"

# Lower QoS TimerResolution
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Psched" -Name "TimerResolution" -Value 1 -Type DWord
Write-Host "Lower QoS TimerResolution"

# Configure Network Adapter Device Parameters
$netDevices = Get-PnpDevice -Class Net | Where-Object { $_.InstanceId -like "PCI\VEN*" }
foreach ($device in $netDevices) {
    $devicePath = "HKLM:\System\CurrentControlSet\Enum\$($device.InstanceId)\Device Parameters\Interrupt Management\Affinity Policy"
    
    # Remove Network Adapter Interrupt Priority
    Remove-ItemProperty -Path $devicePath -Name "DevicePriority" -ErrorAction SilentlyContinue
    
    # Set Network Adapter Policy to IrqPolicySpreadMessagesAcrossAllProcessors
    Set-ItemProperty -Path $devicePath -Name "DevicePolicy" -Value 5 -Type DWord
    
    # Enable Network Adapter MSI Mode
    $msiPath = "HKLM:\System\CurrentControlSet\Enum\$($device.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
    Set-ItemProperty -Path $msiPath -Name "MSISupported" -Value 1 -Type DWord
}
Write-Host "Configure Network Adapter Device Parameters"

# Flush DNS Cache
Clear-DnsClientCache
Write-Host "Flush DNS Cache"

# Prompt to Restart Network
$restart = Read-Host "Operations complete, would you like to restart your network adapter? (y/n)"
if ($restart -eq 'y') {
    # Release/Renew IP address
    Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
        $interface = $_.InterfaceAlias
        ipconfig /release $interface | Out-Null
        ipconfig /renew $interface | Out-Null
    }
    Write-Host "Renew IP address"

    # Restart Network Adapter
    Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Restart-NetAdapter
    Write-Host "Restart Network Adapter"
}

Write-Host "Network optimization complete! Press any key to exit."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
