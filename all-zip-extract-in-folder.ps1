
<#______________________________________________________________________________________________________________________

	(c) Vitaly Ruhl 2021-2022
______________________________________________________________________________________________________________________#>

$Funktion = 'all-zip-extract-in-folder.ps1'

  
<#______________________________________________________________________________________________________________________    
    		Version  	Datum           Author        Beschreibung
    		-------  	----------      -----------   -----------                                                       #>

$Version = 100 #	03.04.2023		Vitaly Ruhl		create


<#______________________________________________________________________________________________________________________
    Function:
   Extract all zips in a folder
______________________________________________________________________________________________________________________#>



#C:\Windows\System32\WindowsPowerShell\v1.0
#Get-ExecutionPolicy -list |% {Set-ExecutionPolicy -scope $_.scope remotesigned -force -ErrorAction SilentlyContinue}

<## execute a command from variable
	$Command = 'Get-Process | where {$_.cpu -gt 1000}'
	Invoke-Expression $Command
#>

#**********************************************************************************************************************
# Settings
[bool]$AdminRightsRequired = $false 
#**********************************************************************************************************************

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#region Debugging and User-Interface Functions


#**********************************************************************************************************************
# Debug Settings
[bool]$global:debug = $false # $true $false
[bool]$global:debugTransScript = $false # $true $false
$global:DebugPrefix = $Funktion + ' ' + $Version + ' -> ' #Variable für Debug-log vorbelegen
$global:TransScriptPrefix = "Log_" + $Funktion + '_' + $Version
$global:Modul = 'Main' #Variable für Debug-log vorbelegen
$ErrorActionPreference = "Continue" #(Ignore,SilentlyContinue,Continue,Stop,Inquire) 
$global:DebugPreference = if ($global:debug) { "Continue" } else { "SilentlyContinue" } #Powershell-Own Debug settings
#**********************************************************************************************************************

function SetDebugState ($b){
    $global:DebugPreference = if ($b) {"Continue"} else {"SilentlyContinue"} #Powershell-Own Debug settings
}


function whr ()	{ Write-Host "`r`n`r`n" }
	
function section ($text) {
    Write-Host "`r`n-----------------------------------------------------------------------------------------------"
    Write-Host " $text"
    Write-Host "`r`n"
}
	
function sectionY ($text) {
    Write-Host "`r`n-----------------------------------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " $text" -ForegroundColor Yellow
    Write-Host "`r`n"
}
	
function log ($text) {
    if ($global:debug) {
        Write-Host "$global:DebugPrefix $global:Modul -> $text" -ForegroundColor DarkGray	
    }
}

function debug ($text){
    if ($global:debug) {
        Write-debug "$global:DebugPrefix $global:Modul -> $text"# -ForegroundColor DarkGray
    }	
}

#endregion



function compress($Source, $Target) {
    Write-Host 'Compressing...'
    #Add-Type -AssemblyName System.IO.Compression.FileSystem
    #$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    #[System.IO.Compression.ZipFile]::CreateFromDirectory($Source, $Target, $compressionLevel, $True)    

    if (-not (test-path "$env:ProgramFiles\7-Zip\7z.exe")) { throw "$env:ProgramFiles\7-Zip\7z.exe needed" } 
    set-alias sz "$env:ProgramFiles\7-Zip\7z.exe"  
    sz a -mx=9 "$Target" "$Source"
}

function Get-ScriptDirectory() {
    $tempModul = $global:Modul # Save pre-text temporarily 
    $global:Modul = 'Get-ScriptDirectory'
    try {
        $Invocation = (Get-Variable MyInvocation -Scope 1).Value
        Split-Path $Invocation.MyCommand.Path
    }
    catch { 
        Write-Warning "$global:Modul -  Something went wrong" 
    }	
    $global:Modul = $tempModul #restore old module text	
}


#region begin AdminRights

#You need to import this Function in your Root-Project, otherwise it dont work!
function AdminRightsRequired {
    log "get Adminrights - Allow? $AdminRightsRequired"
        #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
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
            $psi.Verb = 'runas'
            [System.Diagnostics.Process]::Start($psi) | Out-Null
            return;
        }
        #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  
}
#endregion


function EmptyFunction() {
    <#
		Info/Example:

	#>
    $tempModul = $global:Modul # save Modul-Prefix
    $global:Modul = 'EmptyFunction'
    try {
        log "Function EmptyFunction execute" 	
        return $true
    }
    catch { 
        Write-Warning "$global:Modul -  Something went wrong" 
        return $false
    }
    finally{
        $global:Modul = $tempModul #set saved Modul-Prefix
    }	
	
    return $true
}

$global:Modul = 'ENV'
log "entry"


$pfad = Get-ScriptDirectory #path where the script stored

$7z = "C:\Program Files\7-Zip\7z.exe"

Get-ChildItem -Path $pfad -Filter *.zip | ForEach-Object {

    $zielordner = Join-Path $pfad $_.BaseName
    New-Item -ItemType Directory -Force -Path $zielordner

    & $7z x $_.FullName "-o$zielordner"
}

