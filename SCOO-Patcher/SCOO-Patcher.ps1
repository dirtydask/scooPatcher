#region - Load Prereqs
#Elevate if not running as Admin
Param([switch]$Elevated)
Function Check-Admin {
        $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
        $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)}
        if ((Check-Admin) -eq $false){
            if ($elevated)
            {# could not elevate, quit
            }
        else {Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))}
        exit}
        
Function Install-RSJob{
 
 if   (Get-Module -ListAvailable -Name PoshRSJob) {Write-Host "PoshRSJob module already installed" -ForegroundColor Green }
 else {Write-Host "PoshRSJob Module was not found, installing now.... " -ForegroundColor Yellow
       Copy-Item -Path "$PSScriptRoot\PoshRSJob" -Recurse  -Destination "\\$env:COMPUTERNAME\c$\Program Files\WindowsPowerShell\Modules\PoshRSJob" -Force
       Import-Module –Name PoshRSJob
       cls
 if    (Get-Module -ListAvailable -Name PoshRSJob) {Write-Host "PoshRSJob successfully installed." -ForegroundColor Green}
 else  {"ERROR, PoshRSJob unable to be installed...."}}
 Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules\PoshRSJob" -Recurse | Unblock-File}
         Install-RSJob
function Show-Final {
    Write-Host ""
    Write-Host ""
    Write-Host "[*] Install Completed" 
    Write-Host ""
    Write-Host "[*] Log saved in $($PSScriptRoot)\Logs"
}
function Show-ProgressBar {
    
    cls
                    Write-Host ""
                    Write-Host ""
                    Write-Host ""
                    Write-Host ""
                    Write-Host ""
                    Write-Host ""
                    Write-Host ""
                    Write-Host ""

"                   _______________________ 
          (__)    /                        \         
          (oo)   (       SCOO Patcher!      )
   /-------\/  --'\________________________/        
  / |     ||
 *  ||----||             Created by SSgt Daskalakis [52 CS/SCP]
    ^^    ^^ "
    do {
	    [int]$completed = (get-rsjob -state completed).count
	    [int]$total = (get-rsjob).count
	    [string]$names = get-rsjob -state running | select -expandproperty name
	    Write-Progress -activity "Installing Patches" -percentcomplete ($completed/$total * 100) -status "Installing on $names"
    }
    until ($completed -eq $total)


}
$Computers = Get-Content "$PSScriptRoot\computers.txt"
#endregion - Prereqs Loaded

#region - Menu's

Function Menu{
    cls
    function Menu-HBSS {
              param (
                    [string]$Title = 'Choose an Option Below:'
              )
              cls
"                   _______________________ 
          (__)    /                        \         
          (oo)   (       SCOO Patcher!      )
   /-------\/  --'\________________________/        
  / |     ||
 *  ||----||             Created by SSgt Daskalakis [52 CS/SCP]
    ^^    ^^ "
              Write-Host "================ $Title ================="
              Write-Host ""
              Write-Host " [1] Help"
              Write-Host " [2] Install Agents"
              Write-Host " [3] Computers"
              Write-Host " [4] Framepkg Location"
              Write-Host " [5] Results"
              Write-Host " [Q] Main menu."
              Write-Host ""

                $input = Read-Host " Please make a selection"
                switch ($input)
                {
                    '1' {
                            cls
                            ""
                            "================ McAfee Agent Install ================="
                            Write-Host 
                            
"Script will Uninstall, Install, then Collect and Send Props to McAfee Agents on list of target machines.   

This is a multithreaded script that will attempt to patch every computer listed in the Computers.txt file with any Frampkg that exists in the <2.Patches> folder.

    Instructions:

    1. Prereq - Script requires use of PSexec (place in Windows\System32 of admin machine)
    2. Prereq - Script requires Powershell 5.0 to be installed on admin machine
    3. Create a Computers.txt file in same directory as this script
    4. Populate Computers.txt with list of computers to run against, one per line
	5. Right click the script and select Run with PowerShell
    6. CSV Log file will be created in same directory as script once install is complete
    7. To view the status of your running jobs, use the commands below.

A PatchReport.csv log file will be created and updated in <$($PSScriptRoot)\Logs> folder as each computer finishes. Please do not open the csv file while the script is still running to assure that each computer can update this file as they finish.


SSgt Daskalakis, Stilianos
52 CS/SCP
452-2888

"
                 
                            write-host ""
                    } '2' {
                 
                            cls

                            Install-HBSS  

                            Show-ProgressBar
                            Show-Final
                            Write-Host ""

                    } '3' {
                 
                        
                            Set-Location $PSScriptRoot
                            notepad .\computers.txt
                            $Computers = Get-Content "$PSScriptRoot\computers.txt"

                    } '4' {
                 
                        Set-Location $PSScriptRoot
                        explorer.exe '.\2. Patches'
                        Write-Host ""
                        Write-Host ""
                        Write-Host "[*] Please wait..."
                        Write-Host ""

                    } '5' {
                 
                        cls
                            Set-Location $PSScriptRoot\Logs
                            $csv = ls -ErrorAction SilentlyContinue| where name -match "McAfee_Results" | sort LastWriteTime | select -Last 1
                            if (!$csv){
                                Write-Host ""
                                Write-Host ""
                                Write-Host "[*] No log file created."
                                Write-Host ""
                            } else {
                                Import-Csv $csv -ErrorAction SilentlyContinue| select select -Property PSComputername,DisplayName,Version,InstallDate | where {$_.displayname -eq "mcafee agent"} |  ft -AutoSize -Wrap
                            }

                    }'q' {Show-Menu}
                }
          
         

    }
    function Menu-Patching {
              param (
                    [string]$Title = 'Choose an Option Below:'
              )
              cls
"                   _______________________ 
          (__)    /                        \         
          (oo)   (       SCOO Patcher!      )
   /-------\/  --'\________________________/        
  / |     ||
 *  ||----||             Created by SSgt Daskalakis [52 CS/SCP]
    ^^    ^^ "
              Write-Host "================ $Title ================="
              Write-Host ""
              Write-Host " [1] Help"
              Write-Host " [2] Install Patches"
              Write-Host " [3] Computers"
              Write-Host " [4] Patches"
              Write-Host " [5] Results"
              Write-Host " [Q] Main menu."
              Write-Host ""

                $input = Read-Host " Please make a selection"
                switch ($input)
                {
                    '1' {
                            
                        cls
                        ""
                        "================ Patch Installer ================="
                        Write-Host 
                        
"Script will only work for MICROSOFT PATCHES!   

This is a multithreaded script that will attempt to patch every computer listed in the Computers.txt file with any Microsoft patch that exists in the <2.Patches> folder.

    Instructions:

1. Open Prereqs folder and follow instructions to install PSexec and Powershell 5.0 on your admin computer

2. Download the patches you intend to push with script from https://patches.csd.disa.mil/Default.aspx , https://catalog.update.microsoft.com or from one of your local patch repositories

3. Paste patches into local <2.Patches> folder

4. Optional - Run the CheckforPMOandServers script to purge your list of target computers of any computers that do not belong to your specified OU. An Instructional txt file is included.

5. Populate the Computers.txt file with your list of target computers if you skipped step 4 and didn't need to purge your target list for computers belonging to any unwanted OU's.

6. Right-click <SCOO-Patcher> , select Run with PowerShell



A PatchReport.csv log file will be created and updated in <$($PSScriptRoot)\Logs> folder as each computer finishes. Please do not open the csv file while the script is still running to assure that each computer can update this file as they finish.


SSgt Daskalakis, Stilianos
52 CS/SCP
452-2888

"
                 
                            write-host ""
                    } '2' {
                 
                            cls

                            Install-Patch  

                            Show-ProgressBar
                            Show-Final
                            Write-Host ""

                    } '3' {
                 
                        
                            Set-Location $PSScriptRoot
                            notepad .\computers.txt
                            $Computers = Get-Content "$PSScriptRoot\computers.txt"

                    } '4' {
                 
                        Set-Location $PSScriptRoot
                        explorer.exe '.\2. Patches'
                        Write-Host ""
                        Write-Host ""
                        Write-Host "[*] Place patches in selected folder..."
                        Write-Host ""

                    } '5' {
                 
                        cls
                            Set-Location $PSScriptRoot\Logs
                            $csv = ls -ErrorAction SilentlyContinue | where name -Match "PatchReport" | sort LastWriteTime | select -Last 1
                            if (!$csv){
                                Write-Host ""
                                Write-Host ""
                                Write-Host "[*] No log file created."
                                Write-Host ""
                            } else {
                                Import-Csv $csv -ErrorAction SilentlyContinue| select Computer,"OS Version", "New Patches Installed","Previously Installed","Skipped/Doesn't Apply" |  ft -AutoSize -Wrap
                            }

                    }'q' {Show-Menu}
                }
          
         

    }
    function Menu-ACT {
        param (
            [string]$Title = 'Choose an Option Below:'
        )
        cls
"                   _______________________ 
          (__)    /                        \         
          (oo)   (       SCOO Patcher!      )
   /-------\/  --'\________________________/        
  / |     ||
 *  ||----||             Created by SSgt Daskalakis [52 CS/SCP]
    ^^    ^^ "
              Write-Host "================ $Title ================="
              Write-Host ""
              Write-Host " [1] Help"
              Write-Host " [2] Search Patches"
              Write-Host " [3] Search IAVA"
              Write-Host " [Q] Main menu."
              Write-Host ""

                $input = Read-Host " Please make a selection"
                switch ($input)
                {
                    '1' {
                            
                        cls
                        ""
                        "================ ACT ================"
                        Write-Host
"This tools is used to query TCNOs for related IAVAs and patches.

SSgt Daskalakis, Stilianos
52 CS/SCP
452-2888
"

                    } '2' {
                        cls
                        Get-Patch
                        ""
                    } '3' {
                        cls
                        Get-IAVA
                        ""
                    } 'q' {Show-Menu}
        
                }
         
    }
    function Menu-Tools {
         param (
            [string]$Title = 'Choose an Option Below:'
        )
        cls
"                   _______________________ 
          (__)    /                        \         
          (oo)   (       SCOO Patcher!      )
   /-------\/  --'\________________________/        
  / |     ||
 *  ||----||             Created by SSgt Daskalakis [52 CS/SCP]
    ^^    ^^ "
              Write-Host "================ $Title ================="
              Write-Host ""
              Write-Host " [1] Help"
              Write-Host " [2] Computers"
              Write-Host " [3] Parallel Ping"
              Write-Host " [4] User Sessions"
              Write-Host " [Q] Main menu"
              Write-Host ""

                $input = Read-Host " Please make a selection"
                switch ($input)
                {
                    '1' {
                        cls
                        ""
                        "================ Tools ================"
                        Write-Host
"This is a collection of tools designed to help with common administrative functions.

SSgt Daskalakis, Stilianos
52 CS/SCP
452-2888
"
                        ""
                } '2' {
                    Set-Location $PSScriptRoot
                    notepad .\computers.txt
                    $Computers = Get-Content "$PSScriptRoot\computers.txt"
                
                } '3' {
                    cls
                    ""
                    ""
                    Write-Host "[*] Running..."
                    $ping = Invoke-Ping -computers $Computers
                    $ping | sort status | ft -AutoSize -Wrap
                    ""
                    Write-Host "[*] Log saved in $($PSScriptRoot)\Logs"
                    $ping | Export-Csv $PSScriptRoot\Logs\$(Get-Date -Format ddMMMyyyy)_Ping.csv -NoClobber -NoTypeInformation -Append

                } '4' {
                    cls
                    ""
                    ""
                    Write-Host "[*] Running..."
                    Get-UserSession
                
                } 'q' {Show-Menu}
    }


 }
    function Show-Menu {
        param (
            [string]$Title = 'Choose an Option Below:'
        )
        cls
"                   _______________________ 
          (__)    /                        \         
          (oo)   (       SCOO Patcher!      )
   /-------\/  --'\________________________/        
  / |     ||
 *  ||----||             Created by SSgt Daskalakis [52 CS/SCP]
    ^^    ^^ "
              Write-Host "================ $Title ================="
              Write-Host ""
              Write-Host " [1] Help"
              Write-Host " [2] Patch Deployment"
              Write-Host " [3] HBSS"
              Write-Host " [4] ACT"
              Write-Host " [5] Tools"
              Write-Host " [Q] Exit"
    
    }
    do {
        cls
        Show-Menu
        Write-Host ""
        $input = Read-Host " Please make a selection"
        switch ($input) {
                '1' {
                    cls
                    ""
                    "================ SCOO Patcher ================"
                    Write-Host 
"
This is a multithreaded script developed by 52 CS/SCP to assist with common CS functions.

For any questions please contact:

SSgt Daskalakis, Stilianos
52 CS/SCP
452-2888
"
                }
                '2' {cls; Menu-Patching; ""}
                '3' {cls; Menu-HBSS; ""}
                '4' {cls; Menu-ACT;""}
                '5' {cls; Menu-Tools;""}
                'q' {return}
        }
        pause
        cls
    
    }
    until ($input -eq 'q')
}

 #endregion 

#region - Engines

function Install-Patch {
$Computers | Start-RSJob -Name {"$($_)"} -Throttle 15 -ScriptBlock{
Param($computer)


#region ---------- Ping Check
$starttimer= Get-Date
$ConnCheck = Test-Connection $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue
         if ($ConnCheck -eq $false)
            {Write-Verbose "$computer is offline" -Verbose
                               
$stoptimer = Get-Date   #------Collects end time
$ReportDate = Get-Date -Format ("yyyy-MM-dd")
$resultsarray = @()

$eachcomputer = [ordered]@{ "Computer"               = $computer
                            "SysArch"                = "offline"
                            "OS Version"             = "offline"
                            "OS Build"               = "offline"
                            "Start Time"             = $starttimer
                            "Stop Time"              = $stoptimer
                            "Elapsed Time in Hours"  = [math]::round(($stoptimer - $starttimer).TotalHours , 2)
                            "New Patches Installed"  = "offline" 
                            "Previously Installed"   = "offline"
                            "Skipped/Doesn't Apply"  = "offline" }

$newobj = New-Object psobject -Property $eachcomputer
$resultsarray += $newobj

Write-Verbose "Attempting to grab mutex" -Verbose
    $mtx = New-Object System.Threading.Mutex($false, "Global\TestMutex")
    If ($mtx.WaitOne(500)) 
        { 
        Write-Verbose "Recieved mutex!" -Verbose
        $log = "$using:psscriptroot\Logs\$ReportDate -PatchReport.csv"
        Write-Verbose "Writing data to $log" -Verbose
        $resultsarray | Export-Csv -Path $log -NoTypeInformation -Append
        Write-Verbose "Releasing mutex" -Verbose
        [void]$mtx.ReleaseMutex() } 
    Else { Write-Warning "Timed out acquiring mutex!" }
    Return
} 
#endregion - Ping Check

Else{

psexec 2> $null \\$computer -s -d powershell Enable-PSRemoting -force
Start-Sleep -Seconds 5

$remotearray = @()
$InstalledPatches = @()
$SkippedCounter = 0
$SkippedArray = @()
$PrevInstallPatches = @()
$kbArticlearray = @()

    Function mAdSwitch{
    Param(
        [String]$Switch,
        [String]$InstallLine,
        [String]$InstallPath,
        [String]$File
        )

    #------Exit command for installation commands
    $exitline = "exit"

    #------Passed Switch parameter to remove files within Local Repository
    if($Switch -eq "Cleanup"){
        Remove-Item $InstallPath\mAd.cmd -Force -ErrorAction SilentlyContinue
        Remove-Item $InstallPath\$File -ErrorAction SilentlyContinue
        }
    
    #------Passed Switch parameter to prepare Local Repository for an installation
    if($Switch -eq "Install"){
        
        #------Checks if mAd.cmd exists on target computer
        $CMDchecker = Test-Path $InstallPath\mAd.cmd

        if($CMDchecker -eq $True){
            
            #------Clears computers Local Repository for installation
            Clear-Content -Path $InstallPath\mAd.cmd -ea SilentlyContinue
            }
        else{
            
            #------Creates cmd file if it does not exist
            New-Item -Path "$InstallPath\mAd.cmd" -ItemType File
            }

        #------Populates cmd file with installation commands
        Add-Content -Value $InstallLine -Path $InstallPath\mAd.cmd
        Add-Content -Value $exitline -Path $InstallPath\mAd.cmd
        }
    }

    Function Check-Mutex{
    #check for existing Mutex file
    $Mutex = "\\$computer\c$\Local_Repository\Mutex.csv"
    if((Test-Path $Mutex) -eq $false){New-Item -ItemType File -Path $Mutex -ErrorAction SilentlyContinue}
    
    #Attempt to grab Mutex
    

        Write-Verbose "Attempting to grab mutex" -Verbose
        $checkmutex = (Get-Content "\\$computer\c$\Local_Repository\Mutex.csv")
        $timestart = Get-Date
        if($checkmutex -eq "ON")
        {Write-Verbose "Mutex currently ON, waiting 5 seconds..." -Verbose
            do{ sleep -Seconds 5
                $timecheck = Get-Date
                $timealive = ($timecheck - $timestart).Minutes
                $checkmutex = Get-Content "\\$computer\c$\Local_Repository\Mutex.csv"}
            until(($checkmutex -eq "OFF") -or ($timealive -ge "15") -eq $true)
            $timealive = ($timecheck - $timestart).seconds
        if($timealive -ge "10" -eq $true){Write-Verbose "Timed out waiting on Mutex" -Verbose}}
        else{
        Write-Verbose "Turning Mutex ON" -Verbose
        Set-Content -Path $Mutex -Value ON
        Write-Verbose "Recieved mutex!" -Verbose}
        }
        
    Function Close-Mutex{
        #Closing Mutex
        $checkmutex = Get-Content "\\$computer\c$\Local_Repository\Mutex.csv"
        $checkmutex | Set-Content -Value "OFF"
        Write-Verbose "Turned Mutex OFF" -Verbose}

#region - KBCollector

#       Hotfix Collector
#===============================#
$KBArray = @()
$Hotfix = Get-Hotfix -ComputerName $Computer -ErrorAction SilentlyContinue | Select -expandProperty HotFixID
$KBArray += $HotFix  


#        WMI Collector
#===============================#
function CheckWMI{
            $Regex = 'KB\d+'
            $WMIRecord = Get-WmiObject win32_reliabilityrecords -ComputerName $Computer
    foreach($WMIArticle in $WMIRecord){
     
        #------If WMI article contains a KB - Select only the KB name
        if($WMIArticle.message -match "$Regex"){
            $KBMatch = select-string -InputObject ($WMIArticle.message) -Pattern "$Regex" | select Matches
            $WMIUser = $WMIArticle.User.Split("=")[0]
            $KBMatch = $KBMatch.Matches
            $KBMatch = $KBMatch | Select Value
            $WMIKB = $KBMatch.Value
            
            #------Checks for installed WMI KB not already found via Get-Hotfix
            if($WMIKB -like $kbarticle){$kbarticle}}}}

#       Registry Collector
#===============================#


Try{
    $RegQuery = Invoke-Command -ComputerName $Computer -ScriptBlock {
        $OSArc = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        if($OSArc -eq "64-bit"){$KeyPath = "hklm:\SOFTWARE\Wow6432Node\Microsoft\Updates"}
        else{$KeyPath = "hklm:\SOFTWARE\Microsoft\Updates"}
        #------Regular expression to capture KB articles
        $KB7regex = 'KB(\d{7}$)'
        $ResultArray = @()
        $NDPregArray = @()
        Get-ChildItem -path $KeyPath -Recurse | Select -Property Name | foreach{$NDPregArray += [string]$_.Name}
        #------Collects KB articles from subkey names
        foreach($Item in $NDPregArray){
            if($Item -match "$KB7regex"){
                $ResultArray += $Matches[0]
                $Matches.Clear()}}
        #------Returns results
        Return $ResultArray }
    #------Stores returned KB articles if $KBArray does not already contain them
    foreach($Item in $RegQuery){
        if(!($KBArray.Contains($Item))){$KBArray += $Item }}}

Catch{ "Unable to query $Computer registry for installed NDP patches. Installation will continue."}

function CheckRegistry{
        $RegQuery = Invoke-Command -ComputerName $Computer -ScriptBlock {
        $OSArc = (Get-WmiObject Win32_OperatingSystem).OSArchitecture 
        if($OSArc -eq "64-bit"){$KeyPath = "hklm:\SOFTWARE\Wow6432Node\Microsoft\Updates"}
        else{$KeyPath = "hklm:\SOFTWARE\Microsoft\Updates"}
        #------Regular expression to capture KB articles
        $KB7regex = 'KB(\d{7}$)'
        $ResultArray = @()
        $NDPregArray = @()
        Get-ChildItem -path $KeyPath -Recurse | Select -Property Name | foreach{$NDPregArray += [string]$_.Name}
        #------Collects KB articles from subkey names
        foreach($Item in $NDPregArray){
            if($Item -match "$KB7regex"){
                $ResultArray += $Matches[0]
                $Matches.Clear()}}
        #------Returns results
        Return $ResultArray }
    #------Stores returned KB articles if $KBArray does not already contain them
    if($RegQuery -contains $kbarticle){$kbarticle}}
#endregion - KBCollector

#region - Gather SysInfo

#       Local Respository
#===============================#

#------Checks if Local Repository directory exists
$LocalRepositoryPath = "\\$Computer\c$\Local_Repository"
$LPcheck = Test-Path $LocalRepositoryPath
$localrepo = "C:\Local_Repository"

if($LPcheck -eq $False){ New-Item -Path $LocalRepositoryPath -ItemType Directory }
Get-Item -Path "$LocalRepositoryPath\*" | where {$_.Name -notmatch ".csv"} -ErrorAction SilentlyContinue | Remove-Item


Try{
    $sysArch = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer).OSArchitecture
    $sysversion = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer).Version
    $OSversion = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer).Caption
    }
Catch{    Continue    }

#------Sets OS architecture variable for future search parameters
If($sysArch -eq "64-bit"){    $sysArch = "x64"    }
If($sysarch -eq "32-bit"){    $sysArch = "x86"    }

#------Determines computer's viable Cab and Office patches based of installed OS version (6.1 = Windows 7 ; 8.1 = Windows 8)
If($sysversion -like "*6.1*"){    $CabVer = "6.1"    }
If($sysversion -like "*6.3*"){    $CabVer = "8.1"    }
If($sysversion -like "*10*"){     $CabVer = "10.0"    }
#endregion - Gather SysInfo


#Open remote session
$session = New-PSSession -ComputerName $computer -Name $computer


#region##################### MSU #########################

#------Collets all patch viable .msu files that match computer's architecture
$MSUPatchFiles = Get-Childitem -Path $using:ServerRepo -Recurse | Where{($_.Name -like "*$sysArch*") -and ($_.Name -like "*$CabVer*") -and ($_.Name -match ".msu")}

Foreach ($MSU in $MSUPatchFiles){    

[string]$kbArticle = $MSU.Name -split '-' | Select-String -Pattern "KB" | select -Unique

    If ($KBArray -contains $kbArticle){
        $PrevInstallPatches += $kbArticle
        $PrevInstallDate = (Get-Hotfix -ComputerName $Computer | where {$_.hotfixid -eq $kbArticle} | select -ExpandProperty installedon).toshortdatestring()
        
        write-Host "$computer - $kbArticle previously installed on $PrevInstallDate" -ForegroundColor Green
            if($kbArticlearray -notcontains $kbarticle){
                    $kbArticlearray += $kbarticle
                    $remotecomputer = [ordered]@{ "KB Article"           = $kbarticle
                                                  "Install Date"         = $PrevInstallDate }
                    $remoteobj = New-Object psobject -Property $remotecomputer
                    if (([bool](($remotearray | select -ExpandProperty "KB Article") -match $remoteobj.'KB Article')) -eq $false){
                    $remotearray += $remoteobj
                    $remotearray | Export-Csv -Path "$LocalRepositoryPath\$ReportDate - LocalPatchReport.csv" -NoTypeInformation -Append}}}

    Else{
    Check-Mutex
    Copy-Item -LiteralPath $MSU.FullName -Destination "\\$computer\c$\Local_Repository"
    
    #expand msu file to .cab
    $SB = { Start-Process -filepath 'powershell.exe' -ArgumentList "expand -f:* c:\Local_Repository\*.msu c:\Local_Repository" -PassThru | Wait-Process -Timeout 2000 }
    invoke-command -Session $session -ScriptBlock $SB 

    #install patch
    $SB={ $patch = Get-Item -Path "C:\Local_Repository\*" | where {($_.name -like "*kb*") -and ($_.Name -like "*.cab")}
    $patch = $patch.fullname
    Start-Process -FilePath 'dism.exe' -ArgumentList "/online /add-package /PackagePath:$patch /quiet /norestart" -PassThru | Wait-Process -Timeout 2000 }
    invoke-command -Session $session -ScriptBlock $SB 


    #delete non-csv folder items
    Get-Item "$LocalRepositoryPath\*" | where {$_.name -notmatch ".csv"} | Remove-Item
    Close-Mutex

            #------Send installed KB# to log file and counts number of installed patches
            if ((Get-HotFix -ComputerName $computer | select -expandProperty hotfixid) -contains $kbArticle){$InstalledPatches += $kbArticle
                 write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
                 elseif(CheckWMI -like $kbarticle){$InstalledPatches += $kbArticle
                        write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
                 elseif(CheckRegistry -like $kbarticle){$InstalledPatches += $kbArticle
                        write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
            else{Write-Host "$computer - $kbArticle skipped, possibly superseeded" -ForegroundColor Yellow; $SkippedArray+=$kbArticle}
            $ReportDate = Get-Date -Format ("yyyy-MM-dd")
            try{$InstallDate = (Get-Hotfix -ComputerName $Computer | where {$_.hotfixid -eq $kbArticle} | select -ExpandProperty installedon).toshortdatestring()}
            catch{$InstallDate = $null}
            if($kbArticlearray -notcontains $kbarticle){
                    $kbArticlearray += $kbarticle
                    $remotecomputer = [ordered]@{ "KB Article"           = $kbarticle
                                                  "Install Date"         = $InstallDate }
                    $remoteobj = New-Object psobject -Property $remotecomputer
                    $remotearray += $remoteobj
                    $remotearray | Export-Csv -Path "$LocalRepositoryPath\$ReportDate - LocalPatchReport.csv" -NoTypeInformation -Append}}}
                    #endregion-MSU
                    

#region###################### CAB ########################

#------Collets all patch viable .cab files that match computer's architecture
$CABPatchFiles = Get-Childitem -Path "$using:ServerRepo" -Recurse | Where{($_.Name -like "*$sysArch*") -and ($_.Name -like "*$CabVer*") -and ($_.Name -match ".cab")}


Foreach ($CAB in $CABPatchFiles){
[string]$kbArticle = $CAB.Name -split '-' | Select-String -Pattern "KB" | select -Unique

    If ($KBArray -contains $kbArticle){
        $PrevInstallPatches += $kbArticle
        $PrevInstallDate = (Get-Hotfix -ComputerName $Computer | where {$_.hotfixid -eq $kbArticle} | select -ExpandProperty installedon).toshortdatestring()
        
        write-Host "$computer - $kbArticle previously installed on $PrevInstallDate" -ForegroundColor Green
            if($kbArticlearray -notcontains $kbarticle){
                    $kbArticlearray += $kbarticle
                    $remotecomputer = [ordered]@{ "KB Article"           = $kbarticle
                                                  "Install Date"         = $PrevInstallDate }
                    $remoteobj = New-Object psobject -Property $remotecomputer
                    if (([bool](($remotearray | select -ExpandProperty "KB Article") -match $remoteobj.'KB Article')) -eq $false){
                    $remotearray += $remoteobj
                    $remotearray | Export-Csv -Path "$LocalRepositoryPath\$ReportDate - LocalPatchReport.csv" -NoTypeInformation -Append}}}

    Else{
    Check-Mutex
    Copy-Item -LiteralPath $CAB.FullName -Destination "\\$computer\c$\Local_Repository"
    
    #install patch
    $SB={ $patch = Get-Item -Path "C:\Local_Repository\*" | where {($_.name -like "*kb*") -and ($_.Name -like "*.cab")}
    $patch = $patch.fullname
    Start-Process -FilePath 'dism.exe' -ArgumentList "/online /add-package /PackagePath:$patch /quiet /norestart" -PassThru | Wait-Process -Timeout 2000 }
    invoke-command -Session $session -ScriptBlock $SB 


    #delete non-csv folder items
    Get-Item "$LocalRepositoryPath\*" | where {$_.name -notmatch ".csv"} | Remove-Item
    Close-Mutex

            #------Send installed KB# to log file and counts number of installed patches
            if ((Get-HotFix -ComputerName $computer | select -expandProperty hotfixid) -contains $kbArticle){$InstalledPatches += $kbArticle
                 write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
                 elseif(CheckWMI -like $kbarticle){$InstalledPatches += $kbArticle
                        write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
                 elseif(CheckRegistry -like $kbarticle){$InstalledPatches += $kbArticle
                        write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
            else{Write-Host "$computer - $kbArticle skipped, possibly superseeded" -ForegroundColor Yellow; $SkippedArray+=$kbArticle}
            $ReportDate = Get-Date -Format ("yyyy-MM-dd")
            try{$InstallDate = (Get-Hotfix -ComputerName $Computer | where {$_.hotfixid -eq $kbArticle} | select -ExpandProperty installedon).toshortdatestring()}
            catch{$InstallDate = $null}
            if($kbArticlearray -notcontains $kbarticle){
                    $kbArticlearray += $kbarticle
                    $remotecomputer = [ordered]@{ "KB Article"           = $kbarticle
                                                  "Install Date"         = $PrevInstallDate }
                    $remoteobj = New-Object psobject -Property $remotecomputer
                    $remotearray += $remoteobj
                    $remotearray | Export-Csv -Path "$LocalRepositoryPath\$ReportDate - LocalPatchReport.csv" -NoTypeInformation -Append}}}
                    #endregion-CAB
        

#region##################### .NET ########################


#------Collets all patch viable .NET Framework files that match computer's architecture
$NDPPatchFiles = Get-Childitem -Path "$using:ServerRepo" -Recurse | Where{($_.Name -like "*$sysArch*") -and ($_.Name -like "*$CabVer*") -and ($_.Name -like "*NDP*")}


Foreach ($NDP in $NDPPatchFiles){
[string]$kbArticle = $NDP.Name -split '-' | Select-String -Pattern "KB" | select -Unique
[string]$Name = $NDP.Name

    If ($KBArray -contains $kbArticle){
        $PrevInstallPatches += $kbArticle
        $PrevInstallDate = (Get-Hotfix -ComputerName $Computer | where {$_.hotfixid -eq $kbArticle} | select -ExpandProperty installedon).toshortdatestring()
        
        write-Host "$computer - $kbArticle previously installed on $PrevInstallDate" -ForegroundColor Green
            if($kbArticlearray -notcontains $kbarticle){
                    $kbArticlearray += $kbarticle
                    $remotecomputer = [ordered]@{ "KB Article"           = $kbarticle
                                                  "Install Date"         = $PrevInstallDate }
                    $remoteobj = New-Object psobject -Property $remotecomputer
                    if (([bool](($remotearray | select -ExpandProperty "KB Article") -match $remoteobj.'KB Article')) -eq $false){
                    $remotearray += $remoteobj
                    $remotearray | Export-Csv -Path "$LocalRepositoryPath\$ReportDate - LocalPatchReport.csv" -NoTypeInformation -Append}}}

    Else{
    Check-Mutex
    Copy-Item -LiteralPath $NDP.FullName -Destination "\\$computer\c$\Local_Repository"

    #install patch
        #------Installation Command
        $EXEline = "$localrepo\$name /quiet /norestart"

        #------Creates cmd for currently loaded patch to install on target computer
        mAdSwitch -Switch "Install" -InstallLine $EXEline -InstallPath $LocalRepositoryPath
        
        #------Launches created cmd
        $install = (([WMICLASS]"\\$Computer\ROOT\CIMV2:win32_process").Create('c:\Local_Repository\mAd.cmd')).processid
        $wait1 = get-process -cn $Computer -pid $install -ea SilentlyContinue                       
        
        #------Script waits for the launched cmd process to complete
        While($wait1 -ne $null){
            start-sleep -seconds 5
            $wait1 = get-process -cn $Computer -pid $install -ea SilentlyContinue
            }

        #------Deletes the cmd file
        mAdSwitch -Switch "Cleanup" -File $name  -InstallPath $LocalRepositoryPath


    #delete non-csv folder items
    Get-Item "$LocalRepositoryPath\*" | where {$_.name -notmatch ".csv"} | Remove-Item
    Close-Mutex

            #------Send installed KB# to log file and counts number of installed patches
            if ((Get-HotFix -ComputerName $computer | select -expandProperty hotfixid) -contains $kbArticle){$InstalledPatches += $kbArticle
                 write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
                 elseif(CheckWMI -like $kbarticle){$InstalledPatches += $kbArticle
                        write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
                 elseif(CheckRegistry -like $kbarticle){$InstalledPatches += $kbArticle
                        write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
            else{Write-Host "$computer - $kbArticle skipped, possibly superseeded" -ForegroundColor Yellow; $SkippedArray+=$kbArticle}
            $ReportDate = Get-Date -Format ("yyyy-MM-dd")
            try{$InstallDate = (Get-Hotfix -ComputerName $Computer | where {$_.hotfixid -eq $kbArticle} | select -ExpandProperty installedon).toshortdatestring()}
            catch{$InstallDate = $null}
            if($kbArticlearray -notcontains $kbarticle){
                    $kbArticlearray += $kbarticle
                    $remotecomputer = [ordered]@{ "KB Article"           = $kbarticle
                                                  "Install Date"         = $PrevInstallDate }
                    $remoteobj = New-Object psobject -Property $remotecomputer
                    $remotearray += $remoteobj
                    $remotearray | Export-Csv -Path "$LocalRepositoryPath\$ReportDate - LocalPatchReport.csv" -NoTypeInformation -Append}}}
                    #endregion-.NET


#region#################### Office #######################

#------Registry location of Office version
$OfficeRegPath = "hklm:\SOFTWARE\Microsoft\Office"
$OfficeRegArray = @()

#------Collects all installed office version via registry key subnames
Get-ChildItem -path $OfficeRegPath | Select -Property PSChildName | Select-String -Pattern "\d+" | foreach{$OfficeRegArray += [string]$_.matches}

#------Determines computer's viable office patches via registry keys
if($OfficeRegArray -contains "*14*"){    $OfficeVer = '2010'    }
if($OfficeRegArray -contains "*15*"){    $OfficeVer = '2013'    }

#------Collets all patch viable office files that match computer's architecture
$OfficePatchFiles = Get-Childitem -Path "$using:ServerRepo" -Recurse | Where{($_.Name -like "*$sysArch*") -and ($_.Name -match $Officever)}


Foreach ($Office in $OfficePatchFiles){
[string]$kbArticle = $Office.Name -split '-' | Select-String -Pattern "KB" | select -Unique
[string]$Name = $Office.Name

    If ($KBArray -contains $kbArticle){
        $PrevInstallPatches += $kbArticle
        $PrevInstallDate = (Get-Hotfix -ComputerName $Computer | where {$_.hotfixid -eq $kbArticle} | select -ExpandProperty installedon).toshortdatestring()
        
        write-Host "$computer - $kbArticle previously installed on $PrevInstallDate" -ForegroundColor Green
            if($kbArticlearray -notcontains $kbarticle){
                    $kbArticlearray += $kbarticle
                    $remotecomputer = [ordered]@{ "KB Article"           = $kbarticle
                                                  "Install Date"         = $PrevInstallDate }
                    $remoteobj = New-Object psobject -Property $remotecomputer
                    if (([bool](($remotearray | select -ExpandProperty "KB Article") -match $remoteobj.'KB Article')) -eq $false){
                    $remotearray += $remoteobj
                    $remotearray | Export-Csv -Path "$LocalRepositoryPath\$ReportDate - LocalPatchReport.csv" -NoTypeInformation -Append}}}

    Else{
    Check-Mutex
    Copy-Item -LiteralPath $Office.FullName -Destination "\\$computer\c$\Local_Repository"

    #install patch
        #------Installation Command
        $EXEline = "$localrepo\$name /quiet /norestart"

        #------Creates cmd for currently loaded patch to install on target computer
        mAdSwitch -Switch "Install" -InstallLine $EXEline -InstallPath $LocalRepositoryPath
        
        #------Launches created cmd
        $install = (([WMICLASS]"\\$Computer\ROOT\CIMV2:win32_process").Create('c:\Local_Repository\mAd.cmd')).processid
        $wait1 = get-process -cn $Computer -pid $install -ea SilentlyContinue                       
        
        #------Script waits for the launched cmd process to complete
        While($wait1 -ne $null){
            start-sleep -seconds 5
            $wait1 = get-process -cn $Computer -pid $install -ea SilentlyContinue
            }

        #------Deletes the cmd file
        mAdSwitch -Switch "Cleanup" -File $name  -InstallPath $LocalRepositoryPath


    #delete non-csv folder items
    Get-Item "$LocalRepositoryPath\*" | where {$_.name -notmatch ".csv"} | Remove-Item
    Close-Mutex

            #------Send installed KB# to log file and counts number of installed patches
            if ((Get-HotFix -ComputerName $computer | select -expandProperty hotfixid) -contains $kbArticle){$InstalledPatches += $kbArticle
                 write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
                 elseif(CheckWMI -like $kbarticle){$InstalledPatches += $kbArticle
                        write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
                 elseif(CheckRegistry -like $kbarticle){$InstalledPatches += $kbArticle
                        write-Host "$computer - $kbArticle successfully installed!" -ForegroundColor Green}
            else{Write-Host "$computer - $kbArticle skipped, possibly superseeded" -ForegroundColor Yellow; $SkippedArray+=$kbArticle}
            $ReportDate = Get-Date -Format ("yyyy-MM-dd")
            try{$InstallDate = (Get-Hotfix -ComputerName $Computer | where {$_.hotfixid -eq $kbArticle} | select -ExpandProperty installedon).toshortdatestring()}
            catch{$InstallDate = $null}
            if($kbArticlearray -notcontains $kbarticle){
                    $kbArticlearray += $kbarticle
                    $remotecomputer = [ordered]@{ "KB Article"           = $kbarticle
                                                  "Install Date"         = $PrevInstallDate }
                    $remoteobj = New-Object psobject -Property $remotecomputer
                    $remotearray += $remoteobj
                    $remotearray | Export-Csv -Path "$LocalRepositoryPath\$ReportDate - LocalPatchReport.csv" -NoTypeInformation -Append}}}
                    #endregion-Office



Remove-PSSession -computerName $computer



#           Ending Tasks
#######################################

if($InstalledPatches -eq "offline"){$InstalledPatches = "offline"}
else{$InstalledPatches = ($InstalledPatches | sort -Unique).count}

if($PrevInstallPatches -eq "offline"){$PrevInstallPatches = "offline"}
else{$PrevInstallPatches = ($PrevInstallPatches | sort -Unique).count}

$stoptimer = Get-Date   #------Collects end time
$ReportDate = Get-Date -Format ("yyyy-MM-dd")
$resultsarray = @()

$eachcomputer = [ordered]@{ "Computer"               = $computer
                            "SysArch"                = $sysArch
                            "OS Version"             = $OSversion
                            "OS Build"               = $sysversion
                            "Start Time"             = $starttimer
                            "Stop Time"              = $stoptimer
                            "Elapsed Time in Hours"  = [math]::round(($stoptimer - $starttimer).TotalHours , 2)
                            "New Patches Installed"  = $InstalledPatches 
                            "Previously Installed"   = $PrevInstallPatches
                            "Skipped/Doesn't Apply"  = ($SkippedArray | sort -Unique).count }

$newobj = New-Object psobject -Property $eachcomputer
$resultsarray += $newobj
$resultsarray | Export-Csv -Path "$LocalRepositoryPath\Logs\$ReportDate - PatchReport.csv" -NoTypeInformation -Force

Write-Verbose "Attempting to grab mutex" -Verbose
    $mtx = New-Object System.Threading.Mutex($false, "Global\TestMutex")
    If ($mtx.WaitOne(1000)) 
        { 
        Write-Verbose "Recieved mutex!" -Verbose
        $log = "$using:psscriptroot\Logs\$ReportDate -PatchReport.csv"
        Write-Verbose "Writing data to $log" -Verbose
        $resultsarray | Export-Csv -Path $log -NoTypeInformation -Append 
        Write-Verbose "Releasing mutex" -Verbose
        [void]$mtx.ReleaseMutex() } 
    Else { Write-Warning "Timed out acquiring mutex!" }

}}
}
function Install-HBSS {
    #Collect Variables
    #region
    $Framepkg = "$PSScriptRoot\2. Patches\Framepkg.exe"
    $FramepkgEXE = "C:\FramePkg.exe"
    $OutputFile = "$PSScriptRoot\Logs\McAfee_Results_$($timestamp).csv"
    $Throttle = $env:NUMBER_OF_PROCESSORS
    #endregion

    #Start RSJobs
    $Computers | Start-RSJob -Name {"$($_)"} -Throttle $Throttle -ScriptBlock {
        Param($Computername)
        $DebugPreference = 'Continue'
        $PSBoundParameters.GetEnumerator() | ForEach {
            Write-Debug $_
        }
    
        #Check if computer is online    
        $ping = Test-Connection -ComputerName $Computername -Count 1 -Quiet -ErrorAction Stop
            
        if ($ping -eq $false){
            Write-Host "$Computername is offline" -ErrorAction Stop
            $resultsarray = @()

            $eachcomputer = [ordered]@{ "PSComputername"  = $Computername
                                        "DisplayName"     = "offline"
                                        "Version"         = "offline"
                                        "InstallDate"     = "offline" }

            $newobj = New-Object psobject -Property $eachcomputer
            $resultsarray += $newobj

            Do {
                try {
                    [IO.File]::OpenWrite($using:OutputFile ).close();$success = $true
                        $resultsarray | Export-Csv -Path $using:OutputFile  -Append -NoTypeInformation -Force
                }
                catch {$success = $false;sleep 1}
            }

            Until ($success -eq $true)
                }
        
        else {       
      
        
            Copy-Item "$using:Framepkg" -Destination "\\$Computername\c$\" -Force
            
            #Enable PSRemoting if not already turned on 
         
            if (!(Test-WSMan -ComputerName $Computername)){ 

                Write-Verbose "Enabling WinRM" -Verbose
                psexec 2> $null \\$Computername -s -d powershell "Enable-PSRemoting -force"
                Start-Service winrm
                Start-Sleep -Seconds 30
            }

            #Verify if access is authorized

            if(!(Test-Path \\$Computername\c$\ -ErrorAction SilentlyContinue)){

                Write-Host "Access is denied on $Computername"

                $eachcomputer = [ordered]@{ "PSComputername"  = $Computername
                                        "DisplayName"     = "Error"
                                        "Version"         = "Error"
                                        "InstallDate"     = "Error" }

                $newobj = New-Object psobject -Property $eachcomputer
                $resultsarray += $newobj


                Do {
                    try {
                        [IO.File]::OpenWrite($using:OutputFile ).close();$success = $true
                            $resultsarray | Export-Csv -Path $using:OutputFile  -Append -NoTypeInformation -Force
                    }
                    catch {$success = $false;sleep 1}
                }

                Until ($success -eq $true)  

                 
            }

            
            #Establish connection

            $sess = New-PSSession -ComputerName $Computername

            
            #Begin Uninstall/Reinstall Process

            Invoke-Command -Session $sess -ScriptBlock {
                Start-Process "C:\framepkg.exe" -ArgumentList /install=agent' '/forceinstall' '/silent'' -Wait
                Remove-Item "C:\framepkg.exe"
            }


            #CollectSendProps
        
            psexec 2> $null \\$computername -s 'C:\Program Files\McAfee\Agent\cmdagent.exe' /p
            psexec 2> $null \\$computername -s 'C:\Program Files\McAfee\Agent\cmdagent.exe' /c
            psexec 2> $null \\$computername -s 'C:\Program Files\McAfee\Agent\cmdagent.exe' /e
        
     

    
    
    
        #Verify Installation    
    
        $CheckAgent = Get-WmiObject -ComputerName $Computername -Class win32reg_addremoveprograms | select -Property PSComputername,DisplayName,Version,InstallDate | where {$_.displayname -eq "mcafee agent"}

            if (!($CheckAgent)) {
                write-host -ForegroundColor Yellow "$Computername : McAfee agent not installed"
            }
            else {
                #$CheckAgent | Export-Csv -Path $using:OutputFile -NoTypeInformation -Append
                Do {
                    try {
                        [IO.File]::OpenWrite($using:OutputFile ).close();$success = $true
                            $CheckAgent | Export-Csv -Path $using:OutputFile  -Append -NoTypeInformation -Force
                    }
                    catch {$success = $false;sleep 1}
                }

                Until ($success -eq $true)  
            }
    
        }

    }


}
function Get-IAVA {
    ""
    $TCNO =  Read-Host "Please enter TCNO number (e.x. 2018-347-017)"
    $url = "https://act.af.smil.mil/Orders/Details/$TCNO"
    $regex = '\w{4}-\w{1}-\w{4}'
    $content = wget $url
    $rawcontent = ($content.RawContent.ToString()).split("")
    $IAVAs = ($rawcontent | Select-String -Pattern $regex | Out-String).Split("")
    $IAVAs = ($IAVAs -replace ",","" | where {$_ -like "20*"} | sort -Unique ).Trim()
    Write-Host ""
    Write-Host "Related IAVAs:"
    Write-Host ""
    $IAVAs 
}
function Get-Patch {
    Write-Host ""
    $IAVA = Read-Host "Please enter IAVA number (e.x. 2018-A-0371)"
    $year = $IAVA -split "-" | select -First 1
    $url = wget https://www.cybercom.smil.mil/J3/IAVM/Vulnerability%20Alerts/$year/$IAVA.htm
    $KB = (($url.Content.ToString()).split("")).split(">") | Select-String kb | sort -Unique | Out-String
    Write-Host ""
    Write-Host "The following patches are available for IAVA $IAVA"
    Write-Host ""
    ($KB.Split("") -like "KB*" -replace "<br").Trim()

}
Function Invoke-Ping {
<#
.SYNOPSIS
    Ping or test connectivity to systems in parallel
    
.DESCRIPTION
    Ping or test connectivity to systems in parallel
    Default action will run a ping against systems
        If Quiet parameter is specified, we return an array of systems that responded
        If Detail parameter is specified, we test WSMan, RemoteReg, RPC, RDP and/or SMB
.PARAMETER ComputerName
    One or more computers to test
.PARAMETER Quiet
    If specified, only return addresses that responded to Test-Connection
.PARAMETER Detail
    Include one or more additional tests as specified:
        WSMan      via Test-WSMan
        RemoteReg  via Microsoft.Win32.RegistryKey
        RPC        via WMI
        RDP        via port 3389
        SMB        via \\ComputerName\C$
        *          All tests
.PARAMETER Timeout
    Time in seconds before we attempt to dispose an individual query.  Default is 20
.PARAMETER Throttle
    Throttle query to this many parallel runspaces.  Default is 100.
.PARAMETER NoCloseOnTimeout
    Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out
    This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.
.EXAMPLE
    Invoke-Ping Server1, Server2, Server3 -Detail *
    # Check for WSMan, Remote Registry, Remote RPC, RDP, and SMB (via C$) connectivity against 3 machines
.EXAMPLE
    $Computers | Invoke-Ping
    # Ping computers in $Computers in parallel
.EXAMPLE
    $Responding = $Computers | Invoke-Ping -Quiet
    
    # Create a list of computers that successfully responded to Test-Connection
.LINK
    https://gallery.technet.microsoft.com/scriptcenter/Invoke-Ping-Test-in-b553242a
.FUNCTIONALITY
    Computers
#>
    [cmdletbinding(DefaultParameterSetName='Ping')]
    param(
        [Parameter( ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true, 
                    Position=0)]
        [string[]]$Computers,
        
        [Parameter( ParameterSetName='Detail')]
        [validateset("*","WSMan","RemoteReg","RPC","RDP","SMB")]
        [string[]]$Detail,
        
        [Parameter(ParameterSetName='Ping')]
        [switch]$Quiet,
        
        [int]$Timeout = 20,
        
        [int]$Throttle = 100,

        [switch]$NoCloseOnTimeout
    )
    Begin
    {

        #http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430
        function Invoke-Parallel {
            [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
            Param (   
                [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
                    [System.Management.Automation.ScriptBlock]$ScriptBlock,

                [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
                [ValidateScript({test-path $_ -pathtype leaf})]
                    $ScriptFile,

                [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
                [Alias('CN','__Server','IPAddress','Server','ComputerName')]    
                    [PSObject]$InputObject,

                    [PSObject]$Parameter,

                    [switch]$ImportVariables,

                    [switch]$ImportModules,

                    [int]$Throttle = 20,

                    [int]$SleepTimer = 200,

                    [int]$RunspaceTimeout = 0,

			        [switch]$NoCloseOnTimeout = $false,

                    [int]$MaxQueue,

                [validatescript({Test-Path (Split-Path $_ -parent)})]
                    [string]$LogFile = "C:\temp\log.log",

			        [switch] $Quiet = $false
            )
    
            Begin {
                
                #No max queue specified?  Estimate one.
                #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
                if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
                {
                    if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
                    else{ $script:MaxQueue = $Throttle * 3 }
                }
                else
                {
                    $script:MaxQueue = $MaxQueue
                }

                Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

                #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
                if ($ImportVariables -or $ImportModules)
                {
                    $StandardUserEnv = [powershell]::Create().addscript({

                        #Get modules and snapins in this clean runspace
                        $Modules = Get-Module | Select -ExpandProperty Name
                        $Snapins = Get-PSSnapin | Select -ExpandProperty Name

                        #Get variables in this clean runspace
                        #Called last to get vars like $? into session
                        $Variables = Get-Variable | Select -ExpandProperty Name
                
                        #Return a hashtable where we can access each.
                        @{
                            Variables = $Variables
                            Modules = $Modules
                            Snapins = $Snapins
                        }
                    }).invoke()[0]
            
                    if ($ImportVariables) {
                        #Exclude common parameters, bound parameters, and automatic variables
                        Function _temp {[cmdletbinding()] param() }
                        $VariablesToExclude = @( (Get-Command _temp | Select -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                        Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                        # we don't use 'Get-Variable -Exclude', because it uses regexps. 
                        # One of the veriables that we pass is '$?'. 
                        # There could be other variables with such problems.
                        # Scope 2 required if we move to a real module
                        $UserVariables = @( Get-Variable | Where { -not ($VariablesToExclude -contains $_.Name) } ) 
                        Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"

                    }

                    if ($ImportModules) 
                    {
                        $UserModules = @( Get-Module | Where {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select -ExpandProperty Path )
                        $UserSnapins = @( Get-PSSnapin | Select -ExpandProperty Name | Where {$StandardUserEnv.Snapins -notcontains $_ } ) 
                    }
                }

                #region functions
            
                    Function Get-RunspaceData {
                        [cmdletbinding()]
                        param( [switch]$Wait )

                        #loop through runspaces
                        #if $wait is specified, keep looping until all complete
                        Do {

                            #set more to false for tracking completion
                            $more = $false

                            #Progress bar if we have inputobject count (bound parameter)
                            if (-not $Quiet) {
						        Write-Progress  -Activity "Running Query" -Status "Starting threads"`
							        -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
							        -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
					        }

                            #run through each runspace.           
                            Foreach($runspace in $runspaces) {
                    
                                #get the duration - inaccurate
                                $currentdate = Get-Date
                                $runtime = $currentdate - $runspace.startTime
                                $runMin = [math]::Round( $runtime.totalminutes ,2 )

                                #set up log object
                                $log = "" | select Date, Action, Runtime, Status, Details
                                $log.Action = "Removing:'$($runspace.object)'"
                                $log.Date = $currentdate
                                $log.Runtime = "$runMin minutes"

                                #If runspace completed, end invoke, dispose, recycle, counter++
                                If ($runspace.Runspace.isCompleted) {
                            
                                    $script:completedCount++
                        
                                    #check if there were errors
                                    if($runspace.powershell.Streams.Error.Count -gt 0) {
                                
                                        #set the logging info and move the file to completed
                                        $log.status = "CompletedWithErrors"
                                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                        foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                            Write-Error -ErrorRecord $ErrorRecord
                                        }
                                    }
                                    else {
                                
                                        #add logging details and cleanup
                                        $log.status = "Completed"
                                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    }

                                    #everything is logged, clean up the runspace
                                    $runspace.powershell.EndInvoke($runspace.Runspace)
                                    $runspace.powershell.dispose()
                                    $runspace.Runspace = $null
                                    $runspace.powershell = $null

                                }

                                #If runtime exceeds max, dispose the runspace
                                ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            
                                    $script:completedCount++
                                    $timedOutTasks = $true
                            
							        #add logging details and cleanup
                                    $log.status = "TimedOut"
                                    Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                                    #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                                    if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                                    $runspace.Runspace = $null
                                    $runspace.powershell = $null
                                    $completedCount++

                                }
                   
                                #If runspace isn't null set more to true  
                                ElseIf ($runspace.Runspace -ne $null ) {
                                    $log = $null
                                    $more = $true
                                }

                                #log the results if a log file was indicated
                                if($logFile -and $log){
                                    ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                                }
                            }

                            #Clean out unused runspace jobs
                            $temphash = $runspaces.clone()
                            $temphash | Where { $_.runspace -eq $Null } | ForEach {
                                $Runspaces.remove($_)
                            }

                            #sleep for a bit if we will loop again
                            if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                        #Loop again only if -wait parameter and there are more runspaces to process
                        } while ($more -and $PSBoundParameters['Wait'])
                
                    #End of runspace function
                    }

                #endregion functions
        
                #region Init

                    if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
                    {
                        $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
                    }
                    elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
                    {
                        #Start building parameter names for the param block
                        [string[]]$ParamsToAdd = '$_'
                        if( $PSBoundParameters.ContainsKey('Parameter') )
                        {
                            $ParamsToAdd += '$Parameter'
                        }

                        $UsingVariableData = $Null
                

                        # This code enables $Using support through the AST.
                        # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!
                
                        if($PSVersionTable.PSVersion.Major -gt 2)
                        {
                            #Extract using references
                            $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)    

                            If ($UsingVariables)
                            {
                                $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                                ForEach ($Ast in $UsingVariables)
                                {
                                    [void]$list.Add($Ast.SubExpression)
                                }

                                $UsingVar = $UsingVariables | Group Parent | ForEach {$_.Group | Select -First 1}
        
                                #Extract the name, value, and create replacements for each
                                $UsingVariableData = ForEach ($Var in $UsingVar) {
                                    Try
                                    {
                                        $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                        $NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        [pscustomobject]@{
                                            Name = $Var.SubExpression.Extent.Text
                                            Value = $Value.Value
                                            NewName = $NewName
                                            NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        }
                                        $ParamsToAdd += $NewName
                                    }
                                    Catch
                                    {
                                        Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                                    }
                                }
    
                                $NewParams = $UsingVariableData.NewName -join ', '
                                $Tuple = [Tuple]::Create($list, $NewParams)
                                $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                                $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))
        
                                $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                                $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                                Write-Verbose $StringScriptBlock
                            }
                        }
                
                        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
                    }
                    else
                    {
                        Throw "Must provide ScriptBlock or ScriptFile"; Break
                    }

                    Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
                    Write-Verbose "Creating runspace pool and session states"

                    #If specified, add variables and modules/snapins to session state
                    $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                    if ($ImportVariables)
                    {
                        if($UserVariables.count -gt 0)
                        {
                            foreach($Variable in $UserVariables)
                            {
                                $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                            }
                        }
                    }
                    if ($ImportModules)
                    {
                        if($UserModules.count -gt 0)
                        {
                            foreach($ModulePath in $UserModules)
                            {
                                $sessionstate.ImportPSModule($ModulePath)
                            }
                        }
                        if($UserSnapins.count -gt 0)
                        {
                            foreach($PSSnapin in $UserSnapins)
                            {
                                [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                            }
                        }
                    }

                    #Create runspace pool
                    $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
                    $runspacepool.Open() 

                    Write-Verbose "Creating empty collection to hold runspace jobs"
                    $Script:runspaces = New-Object System.Collections.ArrayList        
        
                    #If inputObject is bound get a total count and set bound to true
                    $global:__bound = $false
                    $allObjects = @()
                    if( $PSBoundParameters.ContainsKey("inputObject") ){
                        $global:__bound = $true
                    }

                    #Set up log file if specified
                    if( $LogFile ){
                        New-Item -ItemType file -path $logFile -force | Out-Null
                        ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                    }

                    #write initial log entry
                    $log = "" | Select Date, Action, Runtime, Status, Details
                        $log.Date = Get-Date
                        $log.Action = "Batch processing started"
                        $log.Runtime = $null
                        $log.Status = "Started"
                        $log.Details = $null
                        if($logFile) {
                            ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                        }

			        $timedOutTasks = $false

                #endregion INIT
            }

            Process {

                #add piped objects to all objects or set all objects to bound input object parameter
                if( -not $global:__bound ){
                    $allObjects += $inputObject
                }
                else{
                    $allObjects = $InputObject
                }
            }

            End {
        
                #Use Try/Finally to catch Ctrl+C and clean up.
                Try
                {
                    #counts for progress
                    $totalCount = $allObjects.count
                    $script:completedCount = 0
                    $startedCount = 0

                    foreach($object in $allObjects){
        
                        #region add scripts to runspace pool
                    
                            #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                            $powershell = [powershell]::Create()
                    
                            if ($VerbosePreference -eq 'Continue')
                            {
                                [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                            }

                            [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                            if ($parameter)
                            {
                                [void]$PowerShell.AddArgument($parameter)
                            }

                            # $Using support from Boe Prox
                            if ($UsingVariableData)
                            {
                                Foreach($UsingVariable in $UsingVariableData) {
                                    Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                                    [void]$PowerShell.AddArgument($UsingVariable.Value)
                                }
                            }

                            #Add the runspace into the powershell instance
                            $powershell.RunspacePool = $runspacepool
    
                            #Create a temporary collection for each runspace
                            $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                            $temp.PowerShell = $powershell
                            $temp.StartTime = Get-Date
                            $temp.object = $object
    
                            #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                            $temp.Runspace = $powershell.BeginInvoke()
                            $startedCount++

                            #Add the temp tracking info to $runspaces collection
                            Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                            $runspaces.Add($temp) | Out-Null
            
                            #loop through existing runspaces one time
                            Get-RunspaceData

                            #If we have more running than max queue (used to control timeout accuracy)
                            #Script scope resolves odd PowerShell 2 issue
                            $firstRun = $true
                            while ($runspaces.count -ge $Script:MaxQueue) {

                                #give verbose output
                                if($firstRun){
                                    Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                                }
                                $firstRun = $false
                    
                                #run get-runspace data and sleep for a short while
                                Get-RunspaceData
                                Start-Sleep -Milliseconds $sleepTimer
                    
                            }

                        #endregion add scripts to runspace pool
                    }
                     
                    Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
                    Get-RunspaceData -wait

                    if (-not $quiet) {
			            Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
		            }

                }
                Finally
                {
                    #Close the runspace pool, unless we specified no close on timeout and something timed out
                    if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
	                    Write-Verbose "Closing the runspace pool"
			            $runspacepool.close()
                    }

                    #collect garbage
                    [gc]::Collect()
                }       
            }
        }

        Write-Verbose "PSBoundParameters = $($PSBoundParameters | Out-String)"
        
        $bound = $PSBoundParameters.keys -contains "ComputerName"
        if(-not $bound)
        {
            [System.Collections.ArrayList]$AllComputers = @()
        }
    }
    Process
    {

        #Handle both pipeline and bound parameter.  We don't want to stream objects, defeats purpose of parallelizing work
        if($bound)
        {
            $AllComputers = $Computers
        }
        Else
        {
            foreach($Computer in $Computers)
            {
                $AllComputers.add($Computer) | Out-Null
            }
        }

    }
    End
    {

        #Built up the parameters and run everything in parallel
        $params = @($Detail, $Quiet)
        $splat = @{
            Throttle = $Throttle
            RunspaceTimeout = $Timeout
            InputObject = $AllComputers
            parameter = $params
        }
        if($NoCloseOnTimeout)
        {
            $splat.add('NoCloseOnTimeout',$True)
        }

        Invoke-Parallel @splat -ScriptBlock {
        
            $computer = $_.trim()
            $detail = $parameter[0]
            $quiet = $parameter[1]

            #They want detail, define and run test-server
            if($detail)
            {
                Try
                {
                    #Modification of jrich's Test-Server function: https://gallery.technet.microsoft.com/scriptcenter/Powershell-Test-Server-e0cdea9a
                    Function Test-Server{
                        [cmdletBinding()]
                        param(
	                        [parameter(
                                Mandatory=$true,
                                ValueFromPipeline=$true)]
	                        [string[]]$Computers,
                            [switch]$All,
                            [parameter(Mandatory=$false)]
	                        [switch]$CredSSP,
                            [switch]$RemoteReg,
                            [switch]$RDP,
                            [switch]$RPC,
                            [switch]$SMB,
                            [switch]$WSMAN,
                            [switch]$IPV6,
	                        [Management.Automation.PSCredential]$Credential
                        )
                            begin
                            {
	                            $total = Get-Date
	                            $results = @()
	                            if($credssp -and -not $Credential)
                                {
                                    Throw "Must supply Credentials with CredSSP test"
                                }

                                [string[]]$props = write-output Name, IP, Domain, Ping, WSMAN, CredSSP, RemoteReg, RPC, RDP, SMB

                                #Hash table to create PSObjects later, compatible with ps2...
                                $Hash = @{}
                                foreach($prop in $props)
                                {
                                    $Hash.Add($prop,$null)
                                }

                                function Test-Port{
                                    [cmdletbinding()]
                                    Param(
                                        [string]$srv,
                                        $port=135,
                                        $timeout=3000
                                    )
                                    $ErrorActionPreference = "SilentlyContinue"
                                    $tcpclient = new-Object system.Net.Sockets.TcpClient
                                    $iar = $tcpclient.BeginConnect($srv,$port,$null,$null)
                                    $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
                                    if(-not $wait)
                                    {
                                        $tcpclient.Close()
                                        Write-Verbose "Connection Timeout to $srv`:$port"
                                        $false
                                    }
                                    else
                                    {
                                        Try
                                        {
                                            $tcpclient.EndConnect($iar) | out-Null
                                            $true
                                        }
                                        Catch
                                        {
                                            write-verbose "Error for $srv`:$port`: $_"
                                            $false
                                        }
                                        $tcpclient.Close()
                                    }
                                }
                            }

                            process
                            {
                                foreach($name in $Computers)
                                {
	                                $dt = $cdt= Get-Date
	                                Write-verbose "Testing: $Name"
	                                $failed = 0
	                                try{
	                                    $DNSEntity = [Net.Dns]::GetHostEntry($name)
	                                    $domain = ($DNSEntity.hostname).replace("$name.","")
	                                    $ips = $DNSEntity.AddressList | %{
                                            if(-not ( -not $IPV6 -and $_.AddressFamily -like "InterNetworkV6" ))
                                            {
                                                $_.IPAddressToString
                                            }
                                        }
	                                }
	                                catch
	                                {
		                                $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
		                                $rst.name = $name
		                                $results += $rst
		                                $failed = 1
	                                }
	                                Write-verbose "DNS:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
	                                if($failed -eq 0){
	                                    foreach($ip in $ips)
	                                    {
	    
		                                    $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
	                                        $rst.name = $name
		                                    $rst.ip = $ip
		                                    $rst.domain = $domain
		            
                                            if($RDP -or $All)
                                            {
                                                ####RDP Check (firewall may block rest so do before ping
		                                        try{
                                                    $socket = New-Object Net.Sockets.TcpClient($name, 3389) -ErrorAction stop
		                                            if($socket -eq $null)
		                                            {
			                                            $rst.RDP = $false
		                                            }
		                                            else
		                                            {
			                                            $rst.RDP = $true
			                                            $socket.close()
		                                            }
                                                }
                                                catch
                                                {
                                                    $rst.RDP = $false
                                                    Write-Verbose "Error testing RDP: $_"
                                                }
                                            }
		                                Write-verbose "RDP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                        #########ping
	                                    if(test-connection $ip -count 2 -Quiet)
	                                    {
	                                        Write-verbose "PING:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                $rst.ping = $true
			    
                                            if($WSMAN -or $All)
                                            {
                                                try{############wsman
				                                    Test-WSMan $ip -ErrorAction stop | Out-Null
				                                    $rst.WSMAN = $true
				                                }
			                                    catch
				                                {
                                                    $rst.WSMAN = $false
                                                    Write-Verbose "Error testing WSMAN: $_"
                                                }
				                                Write-verbose "WSMAN:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                    if($rst.WSMAN -and $credssp) ########### credssp
			                                    {
				                                    try{
					                                    Test-WSMan $ip -Authentication Credssp -Credential $cred -ErrorAction stop
					                                    $rst.CredSSP = $true
					                                }
				                                    catch
					                                {
                                                        $rst.CredSSP = $false
                                                        Write-Verbose "Error testing CredSSP: $_"
                                                    }
				                                    Write-verbose "CredSSP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                    }
                                            }
                                            if($RemoteReg -or $All)
                                            {
			                                    try ########remote reg
			                                    {
				                                    [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ip) | Out-Null
				                                    $rst.remotereg = $true
			                                    }
			                                    catch
				                                {
                                                    $rst.remotereg = $false
                                                    Write-Verbose "Error testing RemoteRegistry: $_"
                                                }
			                                    Write-verbose "remote reg:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            }
                                            if($RPC -or $All)
                                            {
			                                    try ######### wmi
			                                    {	
				                                    $w = [wmi] ''
				                                    $w.psbase.options.timeout = 15000000
				                                    $w.path = "\\$Name\root\cimv2:Win32_ComputerSystem.Name='$Name'"
				                                    $w | select none | Out-Null
				                                    $rst.RPC = $true
			                                    }
			                                    catch
				                                {
                                                    $rst.rpc = $false
                                                    Write-Verbose "Error testing WMI/RPC: $_"
                                                }
			                                    Write-verbose "WMI/RPC:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            }
                                            if($SMB -or $All)
                                            {

                                                #Use set location and resulting errors.  push and pop current location
                    	                        try ######### C$
			                                    {	
                                                    $path = "\\$name\c$"
				                                    Push-Location -Path $path -ErrorAction stop
				                                    $rst.SMB = $true
                                                    Pop-Location
			                                    }
			                                    catch
				                                {
                                                    $rst.SMB = $false
                                                    Write-Verbose "Error testing SMB: $_"
                                                }
			                                    Write-verbose "SMB:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"

                                            }
	                                    }
		                                else
		                                {
			                                $rst.ping = $false
			                                $rst.wsman = $false
			                                $rst.credssp = $false
			                                $rst.remotereg = $false
			                                $rst.rpc = $false
                                            $rst.smb = $false
		                                }
		                                $results += $rst	
	                                }
                                }
	                            Write-Verbose "Time for $($Name): $((New-TimeSpan $cdt ($dt)).totalseconds)"
	                            Write-Verbose "----------------------------"
                                }
                            }
                            end
                            {
	                            Write-Verbose "Time for all: $((New-TimeSpan $total ($dt)).totalseconds)"
	                            Write-Verbose "----------------------------"
                                return $results
                            }
                        }
                    
                    #Build up parameters for Test-Server and run it
                        $TestServerParams = @{
                            ComputerName = $Computer
                            ErrorAction = "Stop"
                        }

                        if($detail -eq "*"){
                            $detail = "WSMan","RemoteReg","RPC","RDP","SMB" 
                        }

                        $detail | Select -Unique | Foreach-Object { $TestServerParams.add($_,$True) }
                        Test-Server @TestServerParams | Select -Property $( "Name", "IP", "Domain", "Ping" + $detail )
                }
                Catch
                {
                    Write-Warning "Error with Test-Server: $_"
                }
            }
            #We just want ping output
            else
            {
                Try
                {
                    #Pick out a few properties, add a status label.  If quiet output, just return the address
                    $result = $null
                    if( $result = @( Test-Connection -ComputerName $computer -Count 2 -erroraction Stop ) )
                    {
                        $Output = $result | Select -first 1 -Property Address,
                                                                      IPV4Address,
                                                                      IPV6Address,
                                                                      ResponseTime,
                                                                      @{ label = "STATUS"; expression = {"Responding"} }

                        if( $quiet )
                        {
                            $Output.address
                        }
                        else
                        {
                            $Output
                        }
                    }
                }
                Catch
                {
                    if(-not $quiet)
                    {
                        #Ping failed.  I'm likely making inappropriate assumptions here, let me know if this is the case : )
                        if($_ -match "No such host is known")
                        {
                            $status = "Unknown host"
                        }
                        elseif($_ -match "Error due to lack of resources")
                        {
                            $status = "No Response"
                        }
                        else
                        {
                            $status = "Error: $_"
                        }

                        "" | Select -Property @{ label = "Address"; expression = {$computer} },
                                              IPV4Address,
                                              IPV6Address,
                                              ResponseTime,
                                              @{ label = "STATUS"; expression = {$status} }
                    }
                }
            }
        }
    }
}
#endregion

cls
 

Menu