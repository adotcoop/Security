
<#
    
    .SYNOPSIS
        Extract attack surface reduction events from the event log and optionally export to CSV file
    
     .NOTES
        Author: Andrew Cooper
        Twitter: @adotcoop
        
    .LINK
        https://github.com/adotcoop

    .DESCRIPTION
        Dumps the events that are created when asr rules fire into a powershell object that can be manipulated
        further, or exported to csv. Requires rights to read the local Defender operatonal event log (typically
        Administrator rights). 
        
        To look for events from a specific user you could use something like

        $parsedEvents | Where-Object {$_.User -like "*username*"} | Select-Object ASRIDName, 'Process Name'

        or to look for a specific process (in this example, the psexec service)

        $parsedEvents | Where-Object {$_.'Process Name' -like "*psexesvc*"}

        Uses the event log parse principles from this post at stackoverflow
        https://stackoverflow.com/questions/59154238/powershell-getting-advanced-eventlog-informations-xml
        with additional help from 
        https://evotec.xyz/powershell-everything-you-wanted-to-know-about-event-logs/

        The lookup table was created from the list of GUIDs on the docs.microsoft.com page-
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide
        -if more rules get added, you can add the lookup manually

    .EXAMPLE

        PS> Get-ASREvents.ps1 -Mode Audit

        Computer                      : mycomputer
        EventID                       : 1122
        Mode                          : Audit
        ASRIDName                     : Block process creations originating from PSExec and WMI commands
        Product Name                  : Windows Defender Antivirus
        Product Version               : 4.18.2104.14           : 
        ID                            : D1E49AAC-8F56-4280-B9BA-993A6D77406C
        Detection Time                : 19/05/2021 12:14:17
        User                          : NT AUTHORITY\SYSTEM
        Path                          : C:\Windows\System32\cmd.exe
        Process Name                  : C:\Windows\PSEXESVC.exe
        Security intelligence Version : 1.339.968.0
        Engine Version                : 1.1.18100.6

#>

param (
    
    [ValidateSet("Audit", "Block", "All")]
    # Specifies whether to look for audit events or block events. Audit mode is the default.
    $Mode = "Audit",

    # Specifies the output path for csv export. 
    [System.IO.FileInfo]$CSVExportPath,

    [ValidateSet($true, $false)]
    # Specifies whether to return output or to run silently
    $Quiet = $false

    )

$ASRLookup = @{ 
    "56a863a9-875e-4185-98a7-b882c64b5ce5"="Block abuse of exploited vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"="Block Adobe Reader from creating child processes"
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"="Block all Office applications from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"="Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"="Block executable content from email client and webmail"
    "01443614-cd74-433a-b99e-2ecdc07bfc25"="Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"="Block execution of potentially obfuscated scripts"
    "3B576869-A4EC-4529-8536-B80A7769E899"="Block Office applications from creating executable content"
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"="Block Office applications from injecting code into other processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869"="Block Office communication application from creating child processes"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c"="Block process creations originating from PSExec and WMI commands"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"="Block untrusted and unsigned processes that run from USB"
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"="Block Win32 API calls from Office macros"
    "D3E037E1-3EB8-44C8-A917-57927947596D"="Block JavaScript or VBScript from launching downloaded executable content"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b"="Block persistence through WMI event subscription"
    "c1db55ab-c21a-4637-bb3f-a12568109d35"="Use advanced protection against ransomware"
 }

switch ($Mode)
{
    "Audit" {$modeID = 1122}
    "Block" {$modeID = 1121}
    "All" {$modeID = 1121,1122}
}

$listOfEvents = Get-WinEvent -FilterHashtable @{Logname="*Defender/Operational";Id=$modeID}

$parsedEvents = foreach ($event in $listOfEvents)
{
    
    $eventxml = ([xml]$event.ToXml()).Event

    $evt = [ordered]@{
        Computer  = $eventXml.System.Computer
        EventID = $eventXml.System.EventID
        }
    switch ($evt.EventID)
    {
        1122 { $evt["Mode"] = "Audit"}
        1121 { $evt["Mode"] = "Block"}
    }


    $ASRId = ($eventXml.EventData | Select-Object -ExpandProperty ChildNodes | Where-Object {$_.Name -eq "ID"}).'#text'
    $evt["ASRIDName"] =  $ASRLookup[$ASRId]
   
    # parse the xml, removing unused fields and setting correct type info for timestamp
    foreach ($eventNode in $eventXml.EventData.ChildNodes)
    {
        if ($eventNode.Name -notlike "Unused")
        {
            if ($eventNode.Name -like "Detection Time")
            {
                $evt[$eventNode.Name] = [datetime]($eventNode.'#text')
            }
            else
            {
                $evt[$eventNode.Name] = $eventNode.'#text'
            }
        }  
    } 
   
    [PsCustomObject]$evt

}

if ($Quiet -eq $false){$parsedEvents}

if ($CSVExportPath)
{
    if (Test-Path $CSVExportPath)
    {
        # if file already exists, append and don't write headings
        $parsedEvents | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 |  Out-File $CSVExportPath -Append
    }
    else
    {
        $parsedEvents | ConvertTo-Csv -NoTypeInformation | Out-File $CSVExportPath -Force
    }
}
