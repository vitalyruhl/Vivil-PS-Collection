
# C:\Windows\System32\WindowsPowerShell\v1.0

<#______________________________________________________________________________________________________________________

	(c) Vitaly Ruhl 2021-2022
    Homepage: Vitaly-Ruhl.de
    Github:https://github.com/vitalyruhl/
    License: GNU General Public License v3.0
______________________________________________________________________________________________________________________#>
#>

$Funktion = 'iBMS-Stop-All-Service-GetAdmin.ps1'


$Version = 'V1.0.0' #	11.05.2023		Vitaly Ruhl		creata
<#		

________________________________________________________________________________________    
functional description:
    get all running INGA-Service and stop it
________________________________________________________________________________________#>


#***********************************************************************************************
# Settings
$AdminRightsRequired = $true # set to $true if this script needs admin rights
$LogTranscript = $true # set to $true if this script needs a log file
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

#endregion Misk Functions


$global:Modul = 'Main'
if ($global:debug) {

	log "entry debug ist an..."
}

#region begin Request admin rights
if ($AdminRightsRequired) {
	#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	#https://www.heise.de/ct/hotline/PowerShell-Skript-mit-Admin-Rechten-1045393.html
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

$InstallPath = Get-ScriptDirectory 

if ($LogTranscript) {
	log "Transcript-Log is on..."
    Start-Transcript -Path "$InstallPath\Transkriptdatei.txt"
}

separateY "Show all running iBMS-Service..."
Get-Service iBMS* | Where-Object {$_.status -eq 'running'} 


separateY "Stop all running iBMS-Service..."
Get-Service iBMS* | Where-Object {$_.status -eq 'running'} | Stop-Service -Force

separateY "Show all iBMS-Service... If There are some runing, please stop them manualy"
Get-Service iBMS*



if ($LogTranscript) {
	log "terminate Transcript..."
    Stop-Transcript
}


$global:Modul = 'The End...'
if ($global:debug) {
	
}

separate 'Script executed!'
Write-Warning 'If nothing is red, then everything is ok ;-)'#-ForegroundColor Green

pause


