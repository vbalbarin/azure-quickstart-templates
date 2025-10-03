function Convert-CIDRToSubnetMask {
   [CmdletBinding()]
   
   param (
       [Parameter(Mandatory = $true)]
       [ValidateRange(0, 32)]
       [int]$CIDR
   )

   $mask = ([math]::Pow(2, $CIDR) - 1) * [math]::Pow(2, (32 - $CIDR))
   $bytes = [BitConverter]::GetBytes([UInt32]$mask)
   (($bytes.Count - 1)..0 | ForEach-Object { [String]$bytes[$_] }) -join '.'
}

function Get-IPFilter {
    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true)]
        [string]$VirtualNetwork
    )

    $IPFilter = @('*', '*', '*', '*')
    $Network = $VirtualNetwork.Split('/')[0]
    $CIDR = $VirtualNetwork.Split('/')[1]
    $NetworkMask = Convert-CIDRToSubnetMask -CIDR $CIDR

    Write-Verbose $("Network: {0}" -f $Network)
    Write-Verbose -Message $("CIDR: {0}" -f $CIDR)
    Write-Verbose -Message $("Network Mask: {0}" -f $NetworkMask)

    $NetworkMaskOctets = $NetworkMask.Split('.')
    $NetworkOctets = $Network.Split('.')

    $Idx = 0
    foreach ($Octet in $NetworkOctets) {
        $ValNetMaskOct = [int] $NetworkMaskOctets[$Idx]
        Write-Verbose -Message ("NetworkMask Octet: {0}" -f $ValNetMaskOct)
        
        # NB, Technically, we should be returning a range of octet values if the netmask octet is in 1..254
        # But this would be difficult to create a regex to specify this range
        # Returning an * is good enough resolution.
        
        $IPFilter[$Idx] = if ($ValNetMaskOct -eq 255)
        {
            $NetworkOctets[$Idx]
        } 
        # elseif ($ValNetMaskOct -in 1..254)
        # {
        #     [string] (255 - $ValNetMaskOct)
        # } 
        # elseif ($ValNetMaskOct -eq 0) 
        # {
        #     '*'
        # }
        else 
        {
            '*'
        }

        $Idx++
    }

    return $IPFilter -join '.'

}

configuration CreateADPDC 
{ 
    param 
    ( 
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter()]
        [String]$VirtualNetwork = "",

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Int]$RetryCount = 60,
        [Int]$RetryIntervalSec = 60
    ) 
    
    Import-DscResource -ModuleName xActiveDirectory, StorageDsc, xNetworking, PSDesiredStateConfiguration, xPendingReboot
    [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    
    if ($VirtualNetwork.Length -eq 0) {
        $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
        $InterfaceAlias = $($Interface.Name)
    } else {
        $InterfaceAlias = (Get-NetIpAddress -IPAddress $(Get-IPFilter -VirtualNetwork $VirtualNetwork)).InterfaceAlias
        #$Interface = Get-NetAdapter | Where-Object Name -Like $(Get-IPFilter -VirtualNetwork $VirtualNetwork) | Select-Object -First 1
    }

    $EphemeralRawDisk = (Get-Disk | Where-Object {($_.FriendlyName -ilike 'Microsoft NVMe Direct Disk*') -and ($_.PartitionStyle -eq 'RAW')})
    $ManagedRawDisk = (Get-Disk | Where-Object {!($_.FriendlyName -ilike 'Microsoft NVMe Direct Disk*') -and ($_.PartitionStyle -eq 'RAW')})

    # $EphemeralRawDiskNum = $EphemeralRawDisk.Number | % {if ($_ -ne $null) {$_} else {$null}}
    # $ManagedRawDiskNum = $ManagedRawDisk.Number | % {if ($_ -ne $null) {$_} else {$null}}

    $EphemeralRawDiskUniqueId = $EphemeralRawDisk.UniqueId | % {if ($_ -ne $null) {$_} else {$null}}
    $ManagedRawDiskUniqueId = $ManagedRawDisk.UniqueId | % {if ($_ -ne $null) {$_} else {$null}}

    Node localhost
    {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }

        WindowsFeature DNS { 
            Ensure = "Present" 
            Name   = "DNS"		
        }

        Script GuestAgent
        {
            SetScript  = {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WindowsAzureGuestAgent' -Name DependOnService -Type MultiString -Value DNS
                Write-Verbose -Verbose "GuestAgent depends on DNS"
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = "[WindowsFeature]DNS"
        }
        
        Script EnableDNSDiags {
            SetScript  = { 
                Set-DnsServerDiagnostics -All $true
                Write-Verbose -Verbose "Enabling DNS client diagnostics" 
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = "[WindowsFeature]DNS"
        }

        WindowsFeature DnsTools {
            Ensure    = "Present"
            Name      = "RSAT-DNS-Server"
            DependsOn = "[WindowsFeature]DNS"
        }

        xDnsServerAddress DnsServerAddress 
        { 
            Address        = '127.0.0.1' 
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn      = "[WindowsFeature]DNS"
        }

        WaitforDisk ManagedRawDisk
        {
            DiskId = $ManagedRawDiskUniqueId
            DiskIdType = 'UniqueId'
            RetryIntervalSec =$RetryIntervalSec
            RetryCount = $RetryCount
        }

        Disk ADDataDisk {
            DiskId  = $ManagedRawDiskUniqueId
            DiskIdType = 'UniqueId'
            DriveLetter = "F"
            DependsOn   = "[WaitForDisk]ManagedRawDisk"
        }

        WindowsFeature ADDSInstall { 
            Ensure    = "Present" 
            Name      = "AD-Domain-Services"
            DependsOn = "[WindowsFeature]DNS" 
        } 

        WindowsFeature ADDSTools {
            Ensure    = "Present"
            Name      = "RSAT-ADDS-Tools"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WindowsFeature ADAdminCenter {
            Ensure    = "Present"
            Name      = "RSAT-AD-AdminCenter"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }
         
        xADDomain FirstDS 
        {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = "F:\NTDS"
            LogPath                       = "F:\NTDS"
            SysvolPath                    = "F:\SYSVOL"
            DependsOn                     = @("[Disk]ADDataDisk", "[WindowsFeature]ADDSInstall")
        } 

    }
} 
