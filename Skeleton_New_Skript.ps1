

# C:\Windows\System32\WindowsPowerShell\v1.0

<#______________________________________________________________________________________________________________________

	(c) Vitaly Ruhl 2021-2022
    Homepage: Vitaly-Ruhl.de
    Github:https://github.com/vitalyruhl/
    License: GNU General Public License v3.0
______________________________________________________________________________________________________________________#>
#>

$Funktion = 'Skeleton.ps1'


$Version = 'V2.0.0' #	26.03.2021		Vitaly Ruhl		Clean and versioning as variables
$Version = 'V2.1.0' #	14.02.2023		Vitaly Ruhl		translate in english 
$Version = 'V2.1.1' #	14.02.2023		Vitaly Ruhl		more translate in english 
<#		

________________________________________________________________________________________    
functional description:
    Basic structure with the most important functions
________________________________________________________________________________________#>


#***********************************************************************************************
# Settings
$AdminRightsRequired = $false # set to $true if this script needs admin rights
#***********************************************************************************************

#***********************************************************************************************
# Debug Settings
$global:DebugPrefix = $Funktion + ' ' + $Version + ' -> '
$global:Modul = 'Main' #Section name for Debug-log
$global:debug = $false # $true $false
$ErrorActionPreference = "Continue" #Ignore,SilentlyContinue,Continue,Stop,Inquire 
#***********************************************************************************************


#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
#region begin Misk Functions
function whr ()	{ Write-Host "`r`n`r`n" }
	
	
function separate ($text) {
	Write-Host "`r`n  ----------------------------------------------------------------------------"
	Write-Host "   [$text]"
	Write-Host "`r`n  ----------------------------------------------------------------------------`r`n"
}
	
	
function separateY ($text) {
	Write-Host "`r`n-----------------------------------------------------------------------------------------------" -ForegroundColor Yellow
	Write-Host " $text" -ForegroundColor Yellow
	Write-Host "`r`n"
}
	
function log ($text) {
	if ($global:debug) {
		Write-Host "$global:DebugPrefix $global:Modul -> $text" -ForegroundColor DarkGray
	}		
}
	
function Get-ScriptDirectory() {
	$tempModul = $global:Modul 
	$global:Modul = 'Get-ScriptDirectory'
	try {
		$Invocation = (Get-Variable MyInvocation -Scope 1).Value
		Split-Path $Invocation.MyCommand.Path
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
	}	
	$global:Modul = $tempModul 	
}

function  Achive($Was, $Wohin) {
	<#
	#Example...
		$ScriptPath = Get-ScriptDirectory
		$BackupBasicPath = (get-item $ScriptPath ).parent.FullName
		$Projekt = (get-item $ScriptPath ).Name
		$zd = $BackupBasicPath + '\' + $Projekt + '_' + $Datum + '.zip'
		Achive "$ScriptPath" "$zd"
	#>

	$tempModul = $global:Modul 
	$global:Modul = 'Achive'
	separateY 'Archiving ... (depending on the size it may take some time)'
	try {
		#Add-Type -AssemblyName System.IO.Compression.FileSystem
		#$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
		#[System.IO.Compression.ZipFile]::CreateFromDirectory($Was, $Wohin, $compressionLevel, $True)    

		if (-not (test-path "$env:ProgramFiles\7-Zip\7z.exe")) { throw "$env:ProgramFiles\7-Zip\7z.exe needed" } 
		set-alias sz "$env:ProgramFiles\7-Zip\7z.exe"  
		sz a -mx=9 "$Wohin" "$Was"
		Write-Host 'finished without error...'
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
	}	
	$global:Modul = $tempModul 	
}

function Add-Path($MyPath) {
 #Checks if the path exists, otherwise create a new one.....
	<#
			Example: 
			$Pfad="$env:TEMP\PS_Skript"
			Add-Path($Pfad)
	#>
	$tempModul = $global:Modul 
	$global:Modul = 'Add-Path'

	try {
		
		if (!(Test-Path -path $MyPath -ErrorAction SilentlyContinue )) {
			if (!(Test-Path -Path $MyPath)) {
				New-Item -Path $MyPath -ItemType Directory -ErrorAction SilentlyContinue # | Out-Null
			}      
		}

	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
	}	
	$global:Modul = $tempModul 	
}

function start-countdown ($sleepintervalsec) {
	<#
			#Example...
			start-countdown 60
		#>
	$ec = 0
	foreach ($step in (1..$sleepintervalsec)) {
		try {
			if ([console]::KeyAvailable) {
				$key = [system.console]::readkey($true)
				if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
					Write-Warning "CTRL-C gedrückt" 
					return
				}
				else {
					Write-Host "Key pressed [$($key.keychar)]"
					pause
					return
				}
			}
		}
		catch {
			if ($ec -eq 0) {
				Write-Warning "Start in the ISE - no console query possible..."
				$ec++
			}
		}
		finally {
			$rest = $sleepintervalsec - $step
			write-progress -Activity "Waiting" -Status "The window will close in $rest sec...." -SecondsRemaining ($rest) -PercentComplete  ($step / $sleepintervalsec * 100)
			start-sleep -seconds 1
		}
	}
}
	
function MsgBox($Title, $msg, $Typ, $look) {
		
	<# Example:
            $test = MsgBox  "test title"  "Test text" 0 5 
        #>

	<#
		Types of Messageboxes:	
		0:	OK
		1:	OK Cancel
		2:	Abort Retry Ignore
		3:	Yes No Cancel
		4:	Yes No
		5:	Retry Cancel
		
		#Looks...
			Symbol			Icon	                Name
			0				None					None
			1				(i)				        Information
			2				(?)					    Question
			3				Error (X)			    Error
			4				Exclamation /!\		    Exclamation
			5				(i)		                Asterisk
			6				Hand (X)			    Hand
			7				Stop (X)			    Stop
			8				Warning /!\		        Warning
		#>
	$tempModul = $global:Modul 
	$global:Modul = 'MsgBox'
	try {
		log "passed params ([$Title], [$msg], [$Typ],[$look])"
		[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
		switch ($look) {
			0 { $result = [System.Windows.MessageBox]::show($msg, $Title, $Typ) }
			1 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Information) }
			2 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Question) }
			3 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Error) }
			4 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Exclamation) }
			5 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Asterisk) }
			6 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Hand) }
			7 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Stop) }
			8 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Warning) }
			9 { $result = [System.Windows.Forms.MessageBox]::show($msg, $Title, $Typ, [System.Windows.Forms.MessageBoxIcon]::Exclamation -band [System.Windows.Forms.MessageBoxIcon]::SystemModal) }
		}		
		log "Function MsgBox executed" 
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
	}	
	$global:Modul = $tempModul 	
	return $result
}

function Get-UserInput($title, $msg, $Default) {
	<# Example:
		$test = get-UserInput  "test"  "192.168.2.250" 0
	#>

	$tempModul = $global:Modul 
	$global:Modul = 'Get-UserInput'
	try {
		log "Passed parameter ([$Title], [$msg], [$Default])"
		[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
		$inp = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title, $Default, 5)
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
	}	
	$global:Modul = $tempModul 	
	return $inp
}

function Get-FileDialog($InitialDirectory, [switch]$AllowMultiSelect) {
	$tempModul = $global:Modul 
	$global:Modul = 'Get-FileDialog'
	try {
		Add-Type -AssemblyName System.Windows.Forms
		$openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
		$openFileDialog.initialDirectory = $InitialDirectory
		$openFileDialog.filter = "All files (*.*)| *.*"
		if ($AllowMultiSelect) { 
			$openFileDialog.MultiSelect = $true 
		}
		$openFileDialog.ShowDialog() > $null
		if ($allowMultiSelect) { 
			$global:Modul = $tempModul 	
			return $openFileDialog.Filenames 
		} 
		else { 
			$global:Modul = $tempModul 	
			return $openFileDialog.Filename 
		}
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
	}	
	$global:Modul = $tempModul 	
}

function  Get-FolderDialog([string]$InitialDirectory) {
	$tempModul = $global:Modul 
	$global:Modul = 'Get-FolderDialog'
	try {
		Add-Type -AssemblyName System.Windows.Forms
		$openFolderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
		$openFolderDialog.ShowNewFolderButton = $true
		$openFolderDialog.RootFolder = $InitialDirectory
		$openFolderDialog.ShowDialog()
	
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
	}	
	$global:Modul = $tempModul 	
	return $openFolderDialog.SelectedPath
}

Function Send-ToRecycleBin
#https://social.technet.microsoft.com/Forums/en-US/ff39d018-9c38-4276-a4c9-3234f088c630/how-can-i-delete-quotto-recycle-binquot-in-powershell-instead-of-remove-item-?forum=winserverpowershell
{
    Param(
    [Parameter(Mandatory = $true,
    ValueFromPipeline = $true)]
    [alias('FullName')]
    [string]$FilePath
    )
    Begin{$shell = New-Object -ComObject 'Shell.Application'}
    Process{
        $Item = Get-Item $FilePath
        $shell.namespace(0).ParseName($item.FullName).InvokeVerb('delete')
    }
}


function ftimer(){
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $window = New-Object System.Windows.Forms.Form
    $window.Width = 1000
    $window.Height = 800
    $Label = New-Object System.Windows.Forms.Label
    $Label.Location = New-Object System.Drawing.Size(10,10)
    $Label.Text = "Text im Fenster"
    $Label.AutoSize = $True
    $window.Controls.Add($Label)

    $i=0
    $timer_Tick={
        $script:i++
        $Label.Text= "$i new text"
    }
    $timer = New-Object 'System.Windows.Forms.Timer'
    $timer.Enabled = $True 
    $timer.Interval = 1000
    $timer.add_Tick($timer_Tick)
    
    [void]$window.ShowDialog()

}



#endregion Misk Functions


#****************************************************************************************************
#region begin SQL


function Get-DBList ($mserver) {
	#Return of the databases on the server
	<#
			   #Example...
			   $PC          = $env:computername
			   $Instance    = "SQL"
			   Get-DBList "$PC\$Instance" 
		   #>
	$tempModul = $global:Modul 
	$global:Modul = 'Get-DBList'
	try {
		$srv = New-Object 'Microsoft.SqlServer.Management.Smo.Server' $mserver
		$tt = $srv.Databases | Select-Object -ExpandProperty name #, RecoveryModel, 
		log $tt
		$global:Modul = $tempModul 
		return $tt
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 

	}	
	$global:Modul = $tempModul 	
	return ''
}

function Backup-SQLDB($serverName, $backupDirectory, $daysToStoreBackups) {
	<#
			#Example...
			$PC          = $env:computername
			$ScriptPath = Get-ScriptDirectory 
			$Instance    = "SQL"
			$RemoveAfterDays=10
			Backup-SQLDB "$PC\$Instance"  $ScriptPath $RemoveAfterDays
	#>

	$tempModul = $global:Modul 
	$global:Modul = 'Backup-SQLDB'
	try {
		
		Write-Host "...................................................................................................................."
		Write-Host "Server: [$serverName]"
		Write-Host "Backup Dir: [$backupDirectory]"
		#Write-Host "remove after: [$daysToStoreBackups] day(s)"
		Write-Host "...................................................................................................................."
	
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtThe End...d") | Out-Null
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null

		$server = New-Object 'Microsoft.SqlServer.Management.Smo.Server' $serverName
		$dbs = $server.Databases	
				
		$timestamp = Get-Date -format yyyy.MM.dd-HHmm
		foreach ($database in $dbs | Write-Hostere-Object { $_.IsSystemObject -eq $False }) {
			$dbName = $database.Name
				
			$targetPath = $backupDirectory + "\" + $dbName + "_" + $timestamp + ".bak"
			$targetPath = $backupDirectory + "\" + $dbName + ".bak"
			Write-Host "DB:[$dbName] --> to file:[$targetPath]"
				
			$smoBackup = New-Object ("Microsoft.SqlServer.Management.Smo.Backup")
			$smoBackup.Action = "Database"
			$smoBackup.BackupSetDescription = "Full Backup of " + $dbName
			$smoBackup.BackupSetName = $dbName + " Backup"
			$smoBackup.Database = $dbName
			$smoBackup.MediaDescription = "Disk"
			$smoBackup.Devices.AddDevice($targetPath, "File")
			#$smoBackup.CompressionOption = 1
			$smoBackup.SqlBackup($server)

			Write-Host ".............................................................................................................................................................................."
			#Write-Host "removing backups older than $daysToStoreBackups days..." 
			#Get-ChildItem "$backupDirectory\*.bak" |? { $_.lastwritetime -le (Get-Date).AddDays(-$daysToStoreBackups)} |% {Remove-Item $_ -force }     

		}
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
		$global:Modul = $tempModul 	
		return $false
	}	
	$global:Modul = $tempModul 	
	return $true
}

function Remove-SqlDataFromCSV ($Table, $CSV_File, $ServerInstance, $delimiter) {
	##Also as an example for loading a CSV file
	<#
			   #Example...
			   $ScriptPath = Get-ScriptDirectory 
			   $Instance   = "SQL"
			   $Table 	= "t_ObjMAParameter"
			   $Import_File = "MAParameter.txt"
			   Remove-SqlDataFromCSV "$Table" "$ScriptPath\$Import_File" "$PC\$Instance"
		   #>
   
	$tempModul = $global:Modul 
	$global:Modul = 'Sceleton'
	try {
		
		Write-Host "...................................................................................................................."
		Write-Host "Server-Instance : [$ServerInstance]"
		Write-Host "CSV-File        : [$CSV_File]"
		Write-Host "...................................................................................................................."

		Write-Host "Load the CSV into memory..."
		$CcvData = Import-CSV $CSV_File -Delimiter "$delimiter"

		Write-Host ""
		Write-Host "delete existing entries...."

		ForEach ($Line in $CcvData) {
			$MID = $Line.MAID  
			$Q = "DELETE FROM $Datenbank.dbo.$Table Write-HostERE MAID = $MID"
			Invoke-Sqlcmd -Query $Q -ServerInstance $ServerInstance
			log $Q
		}
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
		$global:Modul = $tempModul 	
		return $false
	}	
	$global:Modul = $tempModul 	
	return $true
}

#endregion SQL
#****************************************************************************************************


function EmptyFunction() {
	<#
		Information about the module::

	#>
	$tempModul = $global:Modul 
	$global:Modul = 'EmptyFunction'
	try {
		log "Function EmptyFunction execute" 
		$global:Modul = $tempModul 	
		return $true
	}
	catch { 
		Write-Warning "$global:Modul -  Something went wrong" 
		$global:Modul = $tempModul 	
		return $false
	}	
	$global:Modul = $tempModul 	
	return $true
}



#****************************************************************************************************
#****************************************************************************************************


$global:Modul = 'Main'
if ($global:debug) {
	Clear-Host
	whr
	log "entry debug ist an..."
}

#region begin Request admin rights
if ($AdminRightsRequired) {
	#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	##https://www.heise.de/ct/hotline/PowerShell-Skript-mit-Admin-Rechten-1045393.html
	$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$princ = New-Object System.Security.Principal.WindowsPrincipal($identity)
	if (!$princ.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
		$powershell = [System.Diagnostics.Process]::GetCurrentProcess()
		$psi = New-Object System.Diagnostics.ProcessStartInfo $powerShell.Path
		$script = $MyInvocation.MyCommand.Path
		$prm = $script
		foreach ($a in $args) {
			$prm += ' ' + $a
		}
		$psi.Arguments = $prm
		$psi.Verb = "runas"
		[System.Diagnostics.Process]::Start($psi) | Out-Null
		return;
	}
	#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
}
#endregion




$global:Modul = 'Input-Test:'
separatey " Input - Test "
$test = get-UserInput  "test title"  "Example 192.168.2.250" "192.168.2.250"
Write-Host "Returned value: $test"

$global:Modul = 'ENV'
separatey "ENV-Test"
$PC = $env:computername #Find out the current PC name

$datum = Get-Date -Format yyyy.MM.dd_HHmm
$DTminusEinMonat = (get-date).AddDays(-30).ToString("yyy.MM.dd") #Calculate 30 days back
$ScriptPath = Get-ScriptDirectory 
$BackupBasicPath = (get-item $ScriptPath ).parent.FullName #one level back
$Projekt = (get-item $ScriptPath ).Name #Path only

$username = "$env:USERDOMAIN\$env:USERNAME" #current user
$ausgabe = @(	
	@{Name = "PC:"; Value = "[$PC]" }
	@{Name = "User:"; Value = "[$username]" }
	, @{Name = "Date/Time:"; Value = "[$datum]" }
	, @{Name = "Date -30 Days:";	Value = "[$DTminusEinMonat]" }
	, @{Name = "Project folder:"; Value = "[$Projekt]" }
)
$ausgabe | ForEach-Object { [PSCustomObject]$_ } | Format-Table -Property Name, Value -AutoSize

write-host "`r`nNext the script path and one level back:`r`n`r`script path:[$ScriptPath]`r`nParent:[$BackupBasicPath]"

$global:Modul = 'The End...'
if ($global:debug) {
	
}

separate 'Script executed!'
Write-Warning 'If nothing is red, then everything is ok ;-)'#-ForegroundColor Green

#start-countdown 30
#pause


<##****************************************************************************************************
	
	C:\Windows\System32\WindowsPowerShell\v1.0
	
	approved-verbs:
	https://docs.microsoft.com/de-de/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.1
	
	psexec.exe \\192.168.1.10 -u "domain\administrator" -p "password" cmd
	set-executionpolicy remotesigned
	Get-ExecutionPolicy -list |% {Set-ExecutionPolicy -scope $_.scope remotesigned -force -ErrorAction SilentlyContinue} #in allen scopes durchlaufen
	-ErrorAction SilentlyContinue
	-ForegroundColor Yellow
	powershell.exe -NoLogo -NoProfile -Command 'Install-Module -Name PackageManagement -Force -MinimumVersion 1.4.6 -Scope CurrentUser -AllowClobber'
#>

<## execute command from string
	$Command = 'Get-Process | where {$_.cpu -gt 1000}'
	Invoke-Expression $Command
#>


#https://www.windowspro.de/script/json-powershell-erzeugen-bearbeiten
# $h = [ordered]@{M = 1; N = [ordered]@{}; A = @("Schwarz", "Weiß"); O = 2 }
# 
# $h.N.N1 = 1.1
# $h.N.N2 = 1.2
# 
# $h | ConvertTo-Json


<#
[-BackgroundColor {Black | DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta | DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red | Magenta | Yellow | Write-Hostite}]
[-ForegroundColor {Black | DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta | DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red | Magenta | Yellow | Write-Hostite}]
#>

<#
	$DaysBack = 30*2;#2 Monate
	$DateForXDays = (Get-Date).AddDays($DaysBack * -1)
	get-childitem "$Source" | Write-Hostere {$_.mode -match "d" -and $_.LastWriteTime -lt $DateForXDays}| remove-item -Recurse -force -verbose # folders only
	#get-childitem "$Source" | Write-Hostere {$_.lastwritetime -lt $DateForXDays -and -not $_.psiscontainer} |% {remove-item $_.fullname -force -verbose} #without folders
	$_.LastWriteTime
	$_.Length
#>

<#
	$TransScriptPrefix = "ClearOldFiles_Data_" + $DaysBack + "_Days_"
	start-transcript "$Source\$TransScriptPrefix$(get-date -format yyyy.MM).txt"
	... code
	
	Stop-Transcript
#>


<# Eventlog:
	#Create a user-defined event log (check beforehand whether it already exists, otherwise an error will occur - unpleasant)
		if ($s=Get-WinEvent -ListLog Vivil -ErrorAction SilentlyContinue) { if ($debug) {Write-Host "eventlog existiert bereits"}} else {New-EventLog -Source "Vivil" -LogName "Vivil"} 
	
	# Event-Entry: 
		Write-EventLog -LogName 'Vivil' -Source 'Vivil' -EventID 1111 -EntryType Information -Message "Registryeinträge für einen Fake -WSUS angelegt"
		Write-EventLog -LogName 'Vivil' -Source 'Vivil' -EventID 1111 -EntryType Error -Message $errText		
#>

<# Reristry:
	New-ItemProperty "hklm:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1 -PropertyType "DWord" 
	New-ItemProperty "hklm:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"    -Name "WUServer"    -Value "https://fakename.fake:8531" -PropertyType "String"
#>

<# error handling:	
	try 
	{
		
	} 
	catch 
	{
		$errText = "Windowsaufgabe '$NewTaskName' --> Anlegen der Aufgabe Fehlgeschlagen! `r`n Fehler: $Error `r`n"
        if ($debug) {Write-Host $errText}
	} 
	finally 
	{
	
	}
	
	#$error | %{$_ | select CategoryInfo, Exception | fl}
	#$error.Count
#>


<# task scheduler:	
	#Settings...
		$NewTaskName = "No-Win10-Updates"
		$username = "$env:USERDOMAIN\$env:USERNAME" #read current user
		$cred = Get-Credential $username #ask for the password via the Windows Net Security function
		$Password = $cred.GetNetworkCredential().Password #Cache the password in clear text
	
	#Configure task...
		$trig    = New-ScheduledTaskTrigger -Once -At (date) -RepetitionDuration  (New-TimeSpan -Days 1)  -RepetitionInterval  (New-TimeSpan -Minutes 1) #Trigger: run every minute every day
		$action  = New-ScheduledTaskAction -WorkingDirectory $env:TEMP -Execute $env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe -Argument "-Command '$ScriptPath\Deactivate_Windows_Updates.ps1'"
		$conf    = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -WakeToRun 
		$STPrincipal = New-ScheduledTaskPrincipal -RunLevel Highest -User $username #-Password $Password #Unfortunately, only a clear text password can be passed here. Network principals are not supported
		$MyTask =  New-ScheduledTask -Action $action -Settings $conf -Trigger $trig -Principal $STPrincipal 
		Register-ScheduledTask $NewTaskName -TaskPath "\Vivil" -InputObject $MyTask -User $username -Password $Password -Force #Task Create
	
	#show again
	if ($debug) {Get-ScheduledTask | ? TaskName -eq $NewTaskName }	

	#further....
		$trig = New-ScheduledTaskTrigger -weekly -At 21:00 -DaysOfWeek @("Monday","Friday")
		#if required, the command can also be applied to a remote PC with the CimSession parameter
#>


<#----------------------------
	for ($i=1; $i -le 10; $i++) {$i,"`n"}
#>


<#----------------------------
	Write-Hostile(($inp = Read-Host -Prompt "Choose an order") -ne "Q")
	{
		switch($inp)
		{
			L {Write-Host "order 1"}
			A {Write-Host "order 2"}
			R {Write-Host "order 3"}
			Q {Write-Host "The End..."}
			default {Write-Host "Invalid Input"}
		}
	}
#>


<#----------------------------
	$user = Get-ADUser -Filter *
	foreach($u in $user) 
	{
		$u.surname
	}

	(Get-ADUser -Filter *).Surname #does the same - output because of ()
#>



<#----------------------------
	Function MsgBoxGlbl ($Title, $Text)
	{
		[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
		$responseA=[System.Windows.Forms.MessageBox]::Show($Text, $Title, 4)
		Set-Variable -Name _ResponseA ($responseA) -Scope "Global"
	}
#>
















