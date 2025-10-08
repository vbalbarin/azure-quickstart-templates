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
    
    Import-DscResource -ModuleName ActiveDirectoryDsc, StorageDsc, xNetworking, PSDesiredStateConfiguration, ComputerManagementDsc
    
    [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    
    if ($VirtualNetwork.Length -eq 0) {
        $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
        $InterfaceAlias = $($Interface.Name)
    } else {
        $InterfaceAlias = (Get-NetIpAddress -IPAddress $(Get-IPFilter -VirtualNetwork $VirtualNetwork)).InterfaceAlias
    }

    # Because PowerShell 5 doesn't support [char] range operator
    $AllDriveLettersCtoZ = 67..90 | % {[char] $_}
    $UsedDriveLetters = (Get-Volume | Where-Object DriveLetter).DriveLetter
    $AvailableDriveLetters = $AllDriveLettersCtoZ | Where-Object { $_ -notin $UsedDriveLetters }

    $EphemeralRawDisk = (Get-Disk | Where-Object {($_.FriendlyName -ilike 'Microsoft NVMe Direct Disk*') -and ($_.PartitionStyle -eq 'RAW')})
    $EphemeralRawDiskUniqueId = $EphemeralRawDisk.UniqueId | % {if ($_ -ne $null) {$_} else {$null}}
    $EphemeralRawDiskNumber = $EphemeralRawDisk.Number | % {if ($_ -ne $null) {$_} else {$null}}
    
    $ManagedRawDisk = (Get-Disk | Where-Object {!($_.FriendlyName -ilike 'Microsoft NVMe Direct Disk*') -and ($_.PartitionStyle -eq 'RAW')})
    $ManagedRawDiskUniqueId = $ManagedRawDisk.UniqueId | % {if ($_ -ne $null) {$_} else {$null}}
    $ManagedRawDiskNumber = $ManagedRawDisk.Number | % {if ($_ -ne $null) {$_} else {$null}}

    if ($EphemeralRawDiskUniqueId) {
        $EphemeralDiskDriveLetter = $AvailableDriveLetters[0]
        $ManagedDiskDriveLetter = $AvailableDriveLetters[1]
    } else {
        $EphemeralDiskDriveLetter = $null
        $ManagedDiskDriveLetter = $AvailableDriveLetters[0]
    }

    Node localhost
    {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }

        if ($EphemeralRawDiskUniqueId)
        {
            WaitforDisk EphemeralRawDisk
            {
                # DiskId = $EphemeralRawDiskUniqueId
                # DiskIdType = 'UniqueId'
                DiskId = $EphemeralRawDiskNumber
                DiskIdType = 'Number'
                RetryIntervalSec =$RetryIntervalSec
                RetryCount = $RetryCount
            }

            Disk PageFileDisk
            {
                # DiskId      = $EphemeralRawDiskUniqueId
                # DiskIdType  = 'UniqueId'
                DiskId      = $EphemeralRawDiskNumber
                DiskIdType  = 'Number'
                DriveLetter = $EphemeralDiskDriveLetter
                DependsOn   = "[WaitForDisk]EphemeralRawDisk"
            }

            VirtualMemory PagingSettings
            {
                Type        = 'CustomSize'
                Drive       = $EphemeralDiskDriveLetter
                InitialSize = '2048'
                MaximumSize = '2048'
                DependsOn = "[Disk]PageFileDisk"
            }
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
            # DiskId           = $ManagedRawDiskUniqueId
            # DiskIdType       = 'UniqueId'
            DiskId           = $ManagedRawDiskNumber
            DiskIdType       = 'Number'
            RetryIntervalSec = $RetryIntervalSec
            RetryCount       = $RetryCount
        }

        Disk ADDataDisk {
            # DiskId      = $ManagedRawDiskUniqueId
            # DiskIdType  = 'UniqueId'
            DiskId      = $ManagedRawDiskNumber
            DiskIdType       = 'Number'
            DriveLetter = $ManagedDiskDriveLetter
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
         
        ADDomain FirstDS 
        {
            DomainName                    = $DomainName
            Credential                    = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = $("{0}:\NTDS" -f $ManagedDiskDriveLetter)
            LogPath                       = $("{0}:\NTDS" -f $ManagedDiskDriveLetter)
            SysvolPath                    = $("{0}:\SYSVOL" -f $ManagedDiskDriveLetter)
            DependsOn                     = @("[Disk]ADDataDisk", "[WindowsFeature]ADDSInstall")
        } 

    }
} 
