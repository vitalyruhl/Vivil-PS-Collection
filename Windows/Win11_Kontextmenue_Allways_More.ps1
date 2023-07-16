

# C:\Windows\System32\WindowsPowerShell\v1.0

<#
______________________________________________________________________________________________________________________

	(c) Vitaly Ruhl, 2023
______________________________________________________________________________________________________________________
#>
#$Funktion = 'Win11_Kontextmenue_Allways_More.ps1'
#$Version = 'V1.0.0' #	11.07.2023		Vitaly Ruhl		create
<#		

______________________________________________________________________________________________________________________
    Description:
    Add a registry entry to Enabling ‘Show More Options’ by Default in Context Menu
    https://allthings.how/how-to-show-more-options-by-default-in-windows-11-file-explorer/
    https://learn.microsoft.com/de-de/powershell/module/microsoft.powershell.core/about/about_registry_provider?view=powershell-7.3
    
    PS: If you wish to enable the ‘Show more options’ by default in the context menu, remove the registry entry you created above.
______________________________________________________________________________________________________________________
#>


#**********************************************************************************************************************
# Settings

$ErrorActionPreference = "Continue" #Ignore,SilentlyContinue,Continue,Stop,Inquire
#**********************************************************************************************************************


$path = 'Registry::HKEY_CURRENT_USER\SOFTWARE\CLASSES\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
$pathW = 'Registry::HKEY_CURRENT_USER\SOFTWARE\CLASSES\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
$tp = Test-Path $path

if ($tp) {
    write-host "Path found -> updating/creating Property..."
    $tpW = Test-Path $pathW
    if (!$tpW) {
        New-Item $pathW
    }
    Set-ItemProperty -Path $pathW -Name "(default)" -Value ""
    # New-ItemProperty -Path $path -name ShortcutNameTemplate  -Value '%s.lnk' -Force
}
else {
    write-host "Path not found -> creating path and property..."
    New-Item $path
    New-Item $pathW
    Set-ItemProperty -Path $pathW -Name "(default)" -Value ""
}

write-host "Done!"
pause