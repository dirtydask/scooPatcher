# ScooPatcher
Script will only work for MICROSOFT PATCHES!   

    This is a multithreaded script that will attempt to patch every computer listed in the Computers.txt file with any Microsoft patch that exists in the <2.Patches> folder.

        Instructions:

    1. Open Prereqs folder and install PSexec and Powershell 5.0 on your admin computer

    2. Download the patches you intend to push with script from https://patches.csd.disa.mil/Default.aspx , https://catalog.update.microsoft.com or from one of your local patch repositories

    3. Paste patches into local <2.Patches> folder

    4. Optional - Run the CheckforPMOandServers script to purge your list of target computers of any computers that do not belong to your specified OU. An Instructional txt file is included.

    5. Populate the Computers.txt file with your list of target computers if you skipped step 4 and didn't need to purge your target list for computers belonging to any unwanted OU's.

    6. Right-click <SCOO-Patcher> , select Run with PowerShell



    A PatchReport.csv log file will be created and updated in <$($PSScriptRoot)\Logs> folder as each computer finishes. Please do not open the csv file while the script is still running to assure that each computer can update this file as they finish.


    SSgt Daskalakis, Stilianos
    52 CS/SCP
    452-2888
