
#***********************************************************************************************
# Settings
$AdminRightsRequired = $true # set to $true if this script needs admin rights
#***********************************************************************************************

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
#******************************************************************************************************************

$PSVersionTable.PSVersion
#https://www.microsoft.com/en-us/download/details.aspx?id=54616
#https://github.com/PowerShell/PowerShell/releases

#https://aka.ms/WMF5Download

winget search Microsoft.PowerShell
winget install --id Microsoft.Powershell --source winget

#https://apps.microsoft.com/store/detail/powershell/9MZ1SNWT0N5D?hl=de-de&gl=de&rtc=1

Get-Module -Name PowerShellGet -ListAvailable | Select-Object Name,Version
Install-Module -Name PowerShellGet -Force -AllowClobber

Get-PackageProvider -Name NuGet -ListAvailable | Select-Object Name,Version
Install-PackageProvider -Name NuGet -Force
pause
