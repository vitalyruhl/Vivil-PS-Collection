
# C:\Program Files\PowerShell\7\pwsh.exe
# C:\Program Files\WindowsApps\
# C:\Windows\System32\WindowsPowerShell\v1.0

<#
________________________________________________________________________________________

	(c) HERMES Systeme GmbH                             Telefon: +49 (0) 4431 9360-0
        MSR & Automatisierungstechnik                   Telefax: +49 (0) 4431 9360-60
        Visbeker Str. 55                                E-Mail: info@hermes-systeme.de
        27793 Wildeshausen                              Home: www.hermes-systeme.de
________________________________________________________________________________________
#>
<#______________________________________________________________________________________________________________________

	(c) Vitaly Ruhl 2024-2025
	Homepage: https://Vitaly-Ruhl.de
	GitHub:   https://github.com/vitalyruhl/
	License:  GNU General Public License v3.0
______________________________________________________________________________________________________________________#>

[CmdletBinding()] # Enables -Verbose/-Debug at script scope
param(
	[Parameter(HelpMessage = "Target directory used by the script where needed.")]
	[AllowNull()]
	[string]$TargetDirectory
)

$script:ScriptName = 'Skeleton.ps1'

# Version history (newest last)
# 2021-03-26  V2.0.0   Cleanup and versioning as variables
# 2023-02-14  V2.1.0   Translated to English
# 2024-10-16  V2.2.0   Update and bugfixing
# 2024-10-24  V2.3.0   Add parameters
# 2024-11-21  V2.3.1   Bugfix admin rights check for PS >= 7.x
# 2025-08-15  V2.3.2   Export exit-info to a function
$script:Version = 'V2.3.3' # 2025-09-18  Refactor to best practices and English naming

<#

________________________________________________________________________________________
Functional description:
	Basic skeleton with commonly useful helper functions.
________________________________________________________________________________________#>


<#______________________________________________________________________________________________________________________
	To-Do / Errors:
______________________________________________________________________________________________________________________#>


<#______________________________________________________________________________________________________________________
    Pre-Settings:#>
	$script:AdminRightsRequired = $false # set to $true if this script needs admin rights
<#______________________________________________________________________________________________________________________#>


#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#region Debugging Settings

#**********************************************************************************************************************
# Debug Settings
Set-StrictMode -Version Latest
[bool]$script:DebugEnabled = $true   # $true $false
[int] $script:LogLevel     = 10      # 0=Errors/Warn, 1=+Info, 2=+Debug
[bool]$script:TranscriptEnabled = $false
$script:DebugPrefix = "$($script:ScriptName) $($script:Version) -> "
$script:TranscriptPrefix = "Log_" + $script:ScriptName + '_' + $script:Version
$script:ModuleName = 'Main'
$ErrorActionPreference = 'Stop' # So try/catch works consistently
$script:DebugPreference = if ($script:DebugEnabled) { 'Continue' } else { 'SilentlyContinue' } # PowerShell Debug preference
#**********************************************************************************************************************
function Write-Log {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$Message,
		[int]$Level = 1,
		[ConsoleColor]$Color = [ConsoleColor]::DarkGray
	)
	if ($script:DebugEnabled -and ($script:LogLevel -ge $Level)) {
		Write-Host "$($script:DebugPrefix)$($script:ModuleName) -> $Message" -ForegroundColor $Color
	} else {
		Write-Verbose "$($script:ModuleName): $Message"
	}
}

function Stop-ActiveTranscript {
	[CmdletBinding()] param()
	try {
		$transcriptInfo = Get-Transcript -ErrorAction Stop
		Stop-Transcript | Out-Null
 
	}
	catch {
		return $null
	}
}
function Pause {
    Write-Host "Press any key to continue . . ."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Get-ScriptDirectory ($exitOnFail = $true) {
	$tmp = $script:ModuleName
	$script:ModuleName = 'Get-ScriptDirectory'

    if ($PSScriptRoot) { #new version
		Write-Log "PSScriptRoot:[$PSScriptRoot]" 1
		$script:ModuleName = $tmp
		return $PSScriptRoot
	}

    #fallback to old version
	$Invocation = (Get-Variable MyInvocation -Scope 1).Value

	if ($Invocation) {
		Write-Log "Invocation:[$Invocation]" 1
		$script:ModuleName = $tmp
		return Split-Path $Invocation.MyCommand.Path
	}

    # an error occured
	Write-Warning "Can't get the script directory. Please check the script."
	Write-Warning "The script will be stopped."
	pause
	$script:ModuleName = $tmp
	if ($exitOnFail) {
		Stop-ActiveTranscript
		exit
	}
	return $null

}

if (-not $TargetDirectory) {
    $TargetDirectory = Get-ScriptDirectory
}

if ($script:TranscriptEnabled) {
	$script:ModuleName = 'Transcript'
	Write-Log "Starting transcript..." 1
	if ($PSScriptRoot) {
		$logPath = Join-Path -Path $PSScriptRoot -ChildPath "log"
		if (-not (Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory | Out-Null }
		Start-Transcript (Join-Path $logPath ("$($script:TranscriptPrefix)" + (Get-Date -Format yyyy-MM) + ".txt")) | Out-Null
	}
}

function Stop-ScriptExecution ($WithoutCountdown = $false) {
	Write-Separator 'Script executed!'
	Write-Warning 'If nothing is red, then everything is ok ;-)'

	if ($script:TranscriptEnabled) { Stop-ActiveTranscript }

	if ($script:DebugEnabled) {
		Pause
		exit
	} else {
		if (-not $WithoutCountdown) { Start-Countdown 30 }
		exit
	}
}
function ExitScript { param([bool]$withoutCountdown = $false) Stop-ScriptExecution -WithoutCountdown:$withoutCountdown }
#endregion

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#region begin Miscellaneous Functions



# . .\module\recentlyUsedFunctions.ps1 # Import helper functions if needed

function Write-BlankLines { param([int]$Count = 2) 1..$Count | ForEach-Object { Write-Host "" } }

function Write-Separator ($Text) {
	Write-Host "`r`n  ----------------------------------------------------------------------------"
	Write-Host "   [$Text]"
	Write-Host "`r`n  ----------------------------------------------------------------------------`r`n"
}
function Write-SeparatorWarning ($Text) {
	Write-Host "`r`n-----------------------------------------------------------------------------------------------" -ForegroundColor Yellow
	Write-Host " $Text" -ForegroundColor Yellow
	Write-Host "`r`n"
}

function Write-SeparatorError ($Text) {
	Write-Host "`r`n-----------------------------------------------------------------------------------------------" -ForegroundColor Red
	Write-Host " $Text" -ForegroundColor Red
	Write-Host "`r`n"
}


function Compress-Directory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceFolder,
        [Parameter(Mandatory)][string]$TargetArchive
    )
	<#
	#Example...
		$scriptPath = Get-ScriptDirectory
		$backupBase = (Get-Item $scriptPath).Parent.FullName
		$project    = (Get-Item $scriptPath).Name
		$archive    = Join-Path $backupBase ("${project}_$((Get-Date -Format yyyyMMddHHmm)).zip")
		Compress-Directory -SourceFolder $scriptPath -TargetArchive $archive
	#>

	$tempModul = $script:ModuleName
	$script:ModuleName = 'Compress-Directory'
	Write-SeparatorWarning 'Archiving ... (depending on the size it may take some time)'
	try {
		if (-not (Test-Path "$env:ProgramFiles\7-Zip\7z.exe")) { throw "$env:ProgramFiles\7-Zip\7z.exe needed" }
		Set-Alias sz "$env:ProgramFiles\7-Zip\7z.exe"
		sz a -mx=9 "$TargetArchive" "$SourceFolder" | Out-Null
		Write-Host 'Finished without error.'
	}
	catch {
		Write-Warning "$script:ModuleName - Something went wrong: $($_.Exception.Message)"
	}
	$script:ModuleName = $tempModul
}


function New-DirectoryIfMissing {
 # Checks if the path exists; if not, creates it.
	<#
			Example:
			$path = "$env:TEMP\PS_Script"
			New-DirectoryIfMissing -Path $path
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$Path
	)
	$tempModul = $script:ModuleName
	$script:ModuleName = 'New-DirectoryIfMissing'

	try {
		if (-not (Test-Path -Path $Path -PathType Container -ErrorAction SilentlyContinue)) {
			New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}
	catch {
		Write-Warning "$script:ModuleName - Something went wrong: $($_.Exception.Message)"
	}
	$script:ModuleName = $tempModul
}


function Remove-EmptyDirectory {
    param (
        [string]$folder
    )
    #Checks if there are empty folder, deletes them
    # 2023.11.03 viru - create
       <#
            Example:
            $ScriptPath = Get-ScriptDirectory
            Remove-EmptyFolders $ScriptPath
       #>


	if (Test-Path $folder) {
		$childFolders = Get-ChildItem $folder -Directory

		foreach ($childFolder in $childFolders) {
			Remove-EmptyDirectory $childFolder.FullName
        }

        $items = Get-ChildItem $folder
        if ($items.Count -eq 0) {
			Write-Log "Removing empty folder $folder" 1
            Remove-Item $folder
        }
    }
}

function Start-Countdown ($sleepintervalsec) {
	<#
		#Example...
		Start-Countdown 60
	#>
	$ec = 0
	foreach ($step in (1..$sleepintervalsec)) {
		try {
			if ([console]::KeyAvailable) {
				$key = [system.console]::readkey($true)
				if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
					Write-Warning "CTRL-C pressed"
					return
				}
				else {
					Write-Host "Key pressed [$($key.keychar)]"
					Pause
					return
				}
			}
		}
		catch {
			if ($ec -eq 0) {
				Write-Warning "Started in ISE - no console key query possible..."
				$ec++
			}
		}
		finally {
			$rest = $sleepintervalsec - $step
			Write-Progress -Activity "Waiting" -Status "The window will close in $rest sec...." -SecondsRemaining  ($rest) -PercentComplete  ($step / $sleepintervalsec * 100)
			Start-Sleep -Seconds 1
		}
	}
}


function Show-MessageBox($Title, $Message, $Buttons, $IconStyle) {

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
	$tempModul = $script:ModuleName
	$script:ModuleName = 'Show-MessageBox'
	try {
		Write-Log "passed params ([$Title], [$Message], [$Buttons],[$IconStyle])" 1
		[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
		switch ($IconStyle) {
			0 { $result = [System.Windows.MessageBox]::Show($Message, $Title, $Buttons) }
			1 { $result = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, [System.Windows.Forms.MessageBoxIcon]::Information) }
			2 { $result = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, [System.Windows.Forms.MessageBoxIcon]::Question) }
			3 { $result = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, [System.Windows.Forms.MessageBoxIcon]::Error) }
			4 { $result = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, [System.Windows.Forms.MessageBoxIcon]::Exclamation) }
			5 { $result = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, [System.Windows.Forms.MessageBoxIcon]::Asterisk) }
			6 { $result = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, [System.Windows.Forms.MessageBoxIcon]::Hand) }
			7 { $result = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, [System.Windows.Forms.MessageBoxIcon]::Stop) }
			8 { $result = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, [System.Windows.Forms.MessageBoxIcon]::Warning) }
		}
		Write-Log "Function Show-MessageBox executed" 1
	}
	catch {
		Write-Warning "$script:ModuleName -  Something went wrong: $($_.Exception.Message)"
	}
	$script:ModuleName = $tempModul
	return $result
}


function Get-UserInput($title, $msg, $Default) {
	<# Example:
		$test = get-UserInput  "test"  "192.168.2.250" 0
	#>

	$tempModul = $script:ModuleName
	$script:ModuleName = 'Get-UserInput'
	try {
		Write-Log "Passed parameter ([$Title], [$msg], [$Default])" 1
		[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
		$inp = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title, $Default, 5)
	}
	catch {
		Write-Warning "$script:ModuleName -  Something went wrong: $($_.Exception.Message)"
	}
	$script:ModuleName = $tempModul
	return $inp
}

function Show-FileOpenDialog($InitialDirectory, [switch]$AllowMultiSelect) {
	$tempModul = $script:ModuleName
	$script:ModuleName = 'Show-FileOpenDialog'
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
			$script:ModuleName = $tempModul
			return $openFileDialog.Filenames
		}
		else {
			$script:ModuleName = $tempModul
			return $openFileDialog.Filename
		}
	}
	catch {
		Write-Warning "$script:ModuleName -  Something went wrong: $($_.Exception.Message)"
	}
	$script:ModuleName = $tempModul
}

function  Show-FolderBrowserDialog([string]$InitialDirectory) {
	$tempModul = $script:ModuleName
	$script:ModuleName = 'Show-FolderBrowserDialog'
	try {
		Add-Type -AssemblyName System.Windows.Forms
		$openFolderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
		$openFolderDialog.ShowNewFolderButton = $true
		$openFolderDialog.RootFolder = $InitialDirectory
		$openFolderDialog.ShowDialog()

	}
	catch {
		Write-Warning "$script:ModuleName -  Something went wrong: $($_.Exception.Message)"
	}
	$script:ModuleName = $tempModul
	return $openFolderDialog.SelectedPath
}
function  Get-FolderDialog([string]$InitialDirectory) { Show-FolderBrowserDialog -InitialDirectory $InitialDirectory }

function Test-ScriptCancellation() {
	$tempModul = $script:ModuleName
	$script:ModuleName = 'Test-ScriptCancellation'
	try {
		if ([console]::KeyAvailable) {
			$key = [system.console]::readkey($true)
			if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
				Write-Log "CTRL-C pressed" 1
				$script:ModuleName = $tempModul
				return $($key.keychar)
			}
			else {
				Write-Log "Key pressed [$($key.keychar)]" 1
			}
		}
	}
	catch { Write-Warning "$script:ModuleName - Started in ISE - no console key query possible..." }
	$script:ModuleName = $tempModul
}

function Get-PowerShellVersion {
	# Cross-version safe detection: PS 2.0 doesn't define $PSVersionTable
	try {
		if (Test-Path Variable:PSVersionTable) { return $PSVersionTable.PSVersion }
	} catch { }
	return $host.Version
}

#endregion Miscellaneous Functions
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#region begin SQL Functions

function Get-DatabaseList {
	#Return of the databases on the server
	<#
			   #Example...
			   $PC          = $env:computername
			   $Instance    = "SQLHERMES"
			   Get-DBList "$PC\$Instance"
		   #>
	param([Parameter(Mandatory)][string]$ServerInstance)
	$tempModul = $script:ModuleName
	$script:ModuleName = 'Get-DatabaseList'
	try {
		[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO')
		$srv = New-Object 'Microsoft.SqlServer.Management.Smo.Server' $ServerInstance
		$tt = $srv.Databases | Select-Object -ExpandProperty Name
		Write-Log ("Databases: " + ($tt -join ', ')) 1
		$script:ModuleName = $tempModul
		return $tt
	}
	catch {
		Write-Warning "$script:ModuleName -  Something went wrong: $($_.Exception.Message)"

	}
	$script:ModuleName = $tempModul
	return ''
}

function Backup-Database {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$ServerName,
		[Parameter(Mandatory)][string]$BackupDirectory,
		[int]$DaysToStoreBackups = 0
	)
	<#
			#Example...
			$PC          = $env:computername
			$ScriptPath = Get-ScriptDirectory
			$Instance    = "SQLHERMES"
			$RemoveAfterDays=10
			Backup-SQLDB "$PC\$Instance"  $ScriptPath $RemoveAfterDays
	#>

	$tempModul = $script:ModuleName
	$script:ModuleName = 'Backup-Database'
	try {

		Write-Host "...................................................................................................................."
		Write-Host "Server: [$ServerName]"
		Write-Host "Backup Dir: [$BackupDirectory]"
		if ($DaysToStoreBackups -gt 0) { Write-Host "Remove after: [$DaysToStoreBackups] day(s)" }
		Write-Host "...................................................................................................................."

		[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO')
		[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SmoExtended')
		[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.ConnectionInfo')
		[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SmoEnum')

		$server = New-Object 'Microsoft.SqlServer.Management.Smo.Server' $ServerName
		$dbs = $server.Databases

		#$timestamp = Get-Date -format yyyy.MM.dd-HHmm
		foreach ($database in $dbs | Where-Object { $_.IsSystemObject -eq $False }) {
			$dbName = $database.Name

			$targetPath = Join-Path $BackupDirectory ("$dbName.bak")
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
			if ($DaysToStoreBackups -gt 0) {
				Write-Host "Removing backups older than $DaysToStoreBackups day(s)..."
				Get-ChildItem (Join-Path $BackupDirectory '*.bak') |
					Where-Object { $_.LastWriteTime -le (Get-Date).AddDays(-$DaysToStoreBackups)} |
					ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
			}

		}
	}
	catch {
		Write-Warning "$script:ModuleName -  Something went wrong: $($_.Exception.Message)"
		$script:ModuleName = $tempModul
		return $false
	}
	$script:ModuleName = $tempModul
	return $true
}

function Remove-SqlDataFromCsv {
	##Also as an example for loading a CSV file
	<#
			   #Example...
			   $ScriptPath = Get-ScriptDirectory
			   $Instance   = "SQLHERMES"
			   $Tabelle 	= "HerObjMAParameter"
			   $Import_File = "HerMAParameter.txt"
			   Remove-SqlDataFromCSV "$ScriptPath\$Import_File" "$PC\$Instance"
		   #>

	param(
		[Parameter(Mandatory)][string]$CsvFile,
		[Parameter(Mandatory)][string]$ServerInstance,
		[Parameter(Mandatory)][string]$Database,
		[Parameter(Mandatory)][string]$Table,
		[Parameter()][char]$Delimiter = ';'
	)
	$tempModul = $script:ModuleName
	$script:ModuleName = 'Remove-SqlDataFromCsv'
	try {

		Write-Host "...................................................................................................................."
		Write-Host "Server-Instance : [$ServerInstance]"
		Write-Host "CSV-File        : [$CsvFile]"
		Write-Host "Database        : [$Database]"
		Write-Host "Table           : [$Table]"
		Write-Host "...................................................................................................................."

		Write-Host "Load the CSV completely into memory..."
		$CsvData = Import-Csv -Path $CsvFile -Delimiter $Delimiter

		Write-Host ""
		Write-Host "delete existing entries...."

		ForEach ($Line in $CsvData) {
			$MID = $Line.MAID
			$Q = "DELETE FROM [$Database].dbo.[$Table] WHERE [MAID] = @MID"
			Invoke-Sqlcmd -ServerInstance $ServerInstance -Query $Q -Variable MID=$MID
			Write-Log $Q 2
		}
	}
	catch {
		Write-Warning "$script:ModuleName -  Something went wrong: $($_.Exception.Message)"
		$script:ModuleName = $tempModul
		return $false
	}
	$script:ModuleName = $tempModul
	return $true
}


function Get-SqlConnection ($Server,$Database,$Username,$Password){
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.ConnectionString = "Server=$Server;Database=$Database;User ID=$Username;Password=$Password;"
    $SqlConnection.Open()
    return $SqlConnection
}

function Invoke-SqlQuery {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$ServerInstance,
		[Parameter()][string]$Username,
		[Parameter()][string]$Password,
		[Parameter(Mandatory)][string]$Query,
		[switch]$TrustServerCertificate
	)
	$params = @{ ServerInstance = $ServerInstance; Query = $Query }
	if ($Username) { $params.Username = $Username }
	if ($Password) { $params.Password = $Password }
	if ($TrustServerCertificate) { $params.TrustServerCertificate = $true }
	Invoke-Sqlcmd @params
}


#endregion SQL
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



function Invoke-Empty() {
	<#
		Information about the module::

	#>
	$tempModul = $script:ModuleName
	$script:ModuleName = 'Invoke-Empty'
	try {
		Write-Log "Function Invoke-Empty execute" 1
		$script:ModuleName = $tempModul
		return $true
	}
	catch {
		Write-Warning "$script:ModuleName -  Something went wrong: $($_.Exception.Message)"
		$script:ModuleName = $tempModul
		return $false
	}
	$script:ModuleName = $tempModul
	return $true
}

#****************************************************************************************************
#****************************************************************************************************
# 									MAIN PART

$script:ModuleName = 'Start-Sequence'
Write-Log "Start" 1

if ($script:DebugEnabled) {
	$script:ModuleName = 'ENV'
	Write-Log "Environment test" 1
    $psv = Get-PowerShellVersion
	Write-Log "PS-Version:$psv" 1

    $PC = $env:computername
	Write-Log $PC 1
	Write-Log "logLevel:$script:LogLevel" 1
	Write-Log "Project in Path:$PSScriptRoot" 1
}

#region Begin Request Admin Rights
if ($script:AdminRightsRequired) {
    Write-Output "check for Admin rights"

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $princ = New-Object System.Security.Principal.WindowsPrincipal($identity)

    if (!$princ.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Output "No Admin rights detected. Restarting script with Admin rights."

        # Check for Version of PowerShell (7 / 5.1)
        $pwshPath = if ($PSVersionTable.PSEdition -eq 'Core') {
            # PowerShell 7 or higher
            (Get-Command pwsh).Source
        } else {
            # classic PowerShell 5.1
            [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        }

	Write-Output "Use PowerShell path: $pwshPath"

        # create new ProcessStartInfo object
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $pwshPath
        $psi.Verb = "runas"  # "runas" = start as admin
        $psi.UseShellExecute = $true

        # get script path and arguments
        $script = $MyInvocation.MyCommand.Path
        if (-not $script) {
            Write-Error "ERROR: Script path not found. Exiting."
            exit 1
        }

        $arguments = "-File `"$script`" " + ($args -join ' ')
        $psi.Arguments = $arguments

        Write-Output "Start PS with arguments: $arguments"

		try {
			# Restart script with admin rights
            [System.Diagnostics.Process]::Start($psi) | Out-Null
			Start-Sleep -Seconds 1 # give process a moment; PS7.x may need a bit
        } catch {
			Write-Error "ERROR: Can't start with Admin-Rights: $_"
        }

	# End script to avoid infinite loops
        exit
    } else {
        Write-Output "Script is running with Admin rights."
    }
}
#endregion

$script:ModuleName = 'Input-Test'
Write-SeparatorWarning " Input - Test "
$test = Get-UserInput  "test title"  "Example 192.168.2.250" "192.168.2.250"
Write-Host "return: $test"

$script:ModuleName = 'ENV'
Write-SeparatorWarning "ENV-Test"
$PC = $env:computername # Find out the current PC name

$datum = Get-Date -Format yyyy.MM.dd_HHmm
$DateMinusThirtyDays = (Get-Date).AddDays(-30).ToString("yyyy.MM.dd") # Calculate 30 days back
$ScriptPath = Get-ScriptDirectory
$BackupBasicPath = (Get-Item $ScriptPath ).Parent.FullName # one level back
$ProjectName = (Get-Item $ScriptPath ).Name # Path only

$username = "$env:USERDOMAIN\$env:USERNAME" # current user
$anArray = @(
	@{Name = "PC:"; Value = "[$PC]" }
	@{Name = "User:"; Value = "[$username]" }
	, @{Name = "Date/Time:"; Value = "[$datum]" }
	, @{Name = "Date -30 Days:"; Value = "[$DateMinusThirtyDays]" }
	, @{Name = "Project folder:"; Value = "[$ProjectName]" }
	, @{Name = "TargetDirectory (from parameter):"; Value = "[$TargetDirectory]" }
)
$anArray | ForEach-Object { [PSCustomObject]$_ } | Format-Table -Property Name, Value -AutoSize

Write-Host "`r`nNext the script path and one level back:`r`n`r`nScript path:[$ScriptPath]`r`nParent:[$BackupBasicPath]"

$script:ModuleName = 'End'
if ($script:DebugEnabled) { Write-Log "Script [$($script:ScriptName)] executed!" 1 }

Stop-ScriptExecution



<##****************************************************************************************************
	# Miscellaneous info
	C:\Windows\System32\WindowsPowerShell\v1.0

	Approved verbs:
	https://learn.microsoft.com/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands

	psexec.exe \\192.168.1.10 -u "domain\administrator" -p "password" cmd
	set-executionpolicy remotesigned
	Get-ExecutionPolicy -list |% {Set-ExecutionPolicy -scope $_.scope remotesigned -force -ErrorAction SilentlyContinue} #in allen scopes durchlaufen
	-ErrorAction SilentlyContinue
	-ForegroundColor Yellow
	powershell.exe -NoLogo -NoProfile -Command 'Install-Module -Name PackageManagement -Force -MinimumVersion 1.4.6 -Scope CurrentUser -AllowClobber'
#>

<## Command from a variable
	$Command = 'Get-Process | where {$_.cpu -gt 1000}'
	Invoke-Expression $Command
#>

#https://www.windowspro.de/script/json-powershell-erzeugen-bearbeiten
# $h = [ordered]@{M = 1; N = [ordered]@{}; A = @("Black", "White"); O = 2 }
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
	$TageZL = 30*2; # 2 months
	$DatumVorXTagen = (Get-Date).AddDays($TageZL * -1)
	get-childitem "$Source" | Write-Hostere {$_.mode -match "d" -and $_.LastWriteTime -lt $DatumVorXTagen} | remove-item -Recurse -force -verbose # directories only
	#get-childitem "$Source" | Write-Hostere {$_.lastwritetime -lt $DatumVorXTagen -and -not $_.psiscontainer} |% {remove-item $_.fullname -force -verbose} # without directories
	$_.LastWriteTime
	$_.Length
#>

<# Instead of 'ls' or 'dir' you can use 'gci' -> has more capabilities
	gci -r -force -include *.tmp -ErrorAction SilentlyContinue $env:USERPROFILE # list all temporary files recursively under the user's profile; can be piped to Remove-Item
#>

<# Event log
	# Create a custom event log (check first if it already exists to avoid an error)
		if ($s=Get-WinEvent -ListLog HERMES -ErrorAction SilentlyContinue) { if ($debug) {Write-Host "eventlog existiert bereits"}} else {New-EventLog -Source "HERMES" -LogName "HERMES"}

	# Write an event entry
		Write-EventLog -LogName 'HERMES' -Source 'HERMES' -EventID 1111 -EntryType Information -Message "Registryeinträge für einen Fake -WSUS angelegt"
		Write-EventLog -LogName 'HERMES' -Source 'HERMES' -EventID 1111 -EntryType Error -Message $errText
#>

<# Registry entries
	New-ItemProperty "hklm:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1 -PropertyType "DWord"
	New-ItemProperty "hklm:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"    -Name "WUServer"    -Value "https://fakename.fake:8531" -PropertyType "String"
#>

<# Task Scheduler:
	# Settings...
		$NewTaskName = "No-Win10-Updates"
		$username = "$env:USERDOMAIN\$env:USERNAME" # read current user
		$cred = Get-Credential $username # prompt for the password via Windows credential UI
		$Password = $cred.GetNetworkCredential().Password # temporarily store the password in plain text

	# Configure task...
		$trig    = New-ScheduledTaskTrigger -Once -At (date) -RepetitionDuration (New-TimeSpan -Days 1) -RepetitionInterval (New-TimeSpan -Minutes 1) # Trigger: run every minute for one day
		$action  = New-ScheduledTaskAction -WorkingDirectory $env:TEMP -Execute $env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe -Argument "-Command '$ScriptPath\Windows_Updates_Deaktivieren.ps1'"
		$conf    = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -WakeToRun
		$STPrincipal = New-ScheduledTaskPrincipal -RunLevel Highest -User $username #-Password $Password # Unfortunately only a clear-text password can be supplied here. Network principals are not supported
		$MyTask =  New-ScheduledTask -Action $action -Settings $conf -Trigger $trig -Principal $STPrincipal
		Register-ScheduledTask $NewTaskName -TaskPath "\HERMES" -InputObject $MyTask -User $username -Password $Password -Force # Create task

	# show again
	if ($debug) {Get-ScheduledTask | ? TaskName -eq $NewTaskName }

	# more examples...
		$trig = New-ScheduledTaskTrigger -weekly -At 21:00 -DaysOfWeek @("Monday","Friday")
		# If needed, you can run the command against a remote PC using the CimSession parameter.
#>

<#----------------------------
	Write-Hostile(($inp = Read-Host -Prompt "Wählen Sie einen Befehl") -ne "Q")
	{
		switch($inp)
		{
			L {Write-Host "Datei wird gelöscht"}
			A {Write-Host "Datei wird angezeigt"}
			R {Write-Host "Datei erhält Schreibschutz"}
			Q {Write-Host "The End..."}
			default {Write-Host "Ungültige Eingabe"}
		}
	}
#>

#****************************************************************************************************
<## Interesting!!!!

	# ... detect USB devices being plugged in and check for permission ...
		https://social.technet.microsoft.com/Forums/de-DE/4689e5e5-b445-4f95-8ac3-896ea9886045/skript-lsst-sich-in-ise-aber-nicht-ber-powershell-oder-batch-ausfhren?forum=powershell_de

	# Troubleshooting - if a script refuses to run
		https://disziplean.de/powershell-leerzeichen-startet-nicht-verknuepfung-parameter/
#>



















