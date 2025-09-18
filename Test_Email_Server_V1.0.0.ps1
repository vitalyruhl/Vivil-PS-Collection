
# C:\Program Files\PowerShell\7\pwsh.exe
# C:\Program Files\WindowsApps\
# C:\Windows\System32\WindowsPowerShell\v1.0
# powershell.exe -Version 2 -NoProfile -Sta -File "D:\____Tools\999_Programmierung_Allgemein\100_PowerShell\Test_Email_Server_V1.0.0.ps1"


<#______________________________________________________________________________________________________________________

	(c) Vitaly Ruhl 2024-2025
	Homepage: https://Vitaly-Ruhl.de
	GitHub:   https://github.com/vitalyruhl/
	License:  GNU General Public License v3.0
______________________________________________________________________________________________________________________#>

# [CmdletBinding()] # Enables -Verbose/-Debug at script scope
# param(
# 	[Parameter(HelpMessage = "Target directory used by the script where needed.")]
# 	[AllowNull()]
# 	[string]$TargetDirectory
# )

$script:ScriptName = 'Test_Email_Server.ps1'

# Version history (newest last)
# 'V1.0.0' # 2025-09-18  created
$script:Version = 'V1.0.0' # 2025-09-18  created

<#

________________________________________________________________________________________
Functional description:
	test a email server.
________________________________________________________________________________________#>


<#______________________________________________________________________________________________________________________
	To-Do / Errors:
	- test clean without ssl
	- test complete on a native Windows powershell 2.0 (with old smtp client)! its not tested yet!!!
______________________________________________________________________________________________________________________#>


<#______________________________________________________________________________________________________________________
    Pre-Settings:#>
	$sueGUI = $true
	$mandatoryUseOldSmtpClient = $false # for powershell 2.x, but can be used on any version - on false = automatically selected if PS version < 3.0
	$SmtpServer = "domain, or ip"  # SMTP-Server
	$SmtpPort = 25 # Port, clear:25, SMTPS=465, STARTTLS:587
	$From = "viru@domain.com"
	$To = "viru@domain.com"
	$Subject = "Test Email"
	$Body = "Testmail from PowerShell"
	$UseSsl = $true
	$userName = "user"
	$password = "password"

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
	function log { param($text, $level = 1) Write-Log -Message $text -Level $level }# Backward-compatible alias

	function Stop-ActiveTranscript {
		[CmdletBinding()] param()
		# Cross-version safe: there's no Get-Transcript, so simply attempt stop
		try { Stop-Transcript -ErrorAction Stop | Out-Null } catch { return $null }
	}
	function Pause {
		Write-Host "Press any key to continue . . ."
		try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { [void](Read-Host "Press Enter to continue") }
	}

	function Get-ScriptDirectory ($exitOnFail = $true) {
		$tmp = $script:ModuleName
		$script:ModuleName = 'Get-ScriptDirectory'

		# Use Test-Path to avoid strict-mode errors on PS2
		if (Test-Path Variable:PSScriptRoot) { # PS 3+
			$root = (Get-Variable -Name PSScriptRoot -ValueOnly -ErrorAction SilentlyContinue)
			if ($root) {
				Write-Log "PSScriptRoot:[$root]" 1
				$script:ModuleName = $tmp
				return $root
			}
		}

		# fallback to old version
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

	$TargetDirectory = $null
	if (-not $TargetDirectory) {
		$TargetDirectory = Get-ScriptDirectory
	}

	if ($script:TranscriptEnabled) {
		$script:ModuleName = 'Transcript'
		Write-Log "Starting transcript..." 1
		$basePath = if ($TargetDirectory) { $TargetDirectory } else { (Get-Location).Path }
		$logPath = Join-Path -Path $basePath -ChildPath "log"
		if (-not (Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory | Out-Null }
		Start-Transcript (Join-Path $logPath ("$($script:TranscriptPrefix)" + (Get-Date -Format yyyy-MM) + ".txt")) | Out-Null
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

#endregion

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#region begin Several Functions

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
function Get-PowerShellVersion {
	# Cross-version safe detection: PS 2.0 doesn't define $PSVersionTable
	try {
		if (Test-Path Variable:PSVersionTable) { return $PSVersionTable.PSVersion }
	} catch { }
	return $host.Version
}
#endregion Several Functions
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



#****************************************************************************************************
	# 									MAIN PART

	$script:ModuleName = 'Start-Sequence'
	Write-Log "Start" 1

	if ($script:DebugEnabled) {
		$script:ModuleName = 'ENV'
		Write-Log "Environment test" 1

		$PC = $env:computername
		Write-Log $PC 1
		Write-Log "logLevel:$($script:LogLevel)" 1
		Write-Log "Project in Path:$PSScriptRoot" 1
	}


	$script:ModuleName = 'Check PS Version'

	$psvObj = Get-PowerShellVersion
	Write-Log "PS-Version:$psvObj" 1

	$script:ModuleName = 'Ask for server'
	if ($sueGUI) {
		# Show a simple Windows Forms GUI to collect SMTP settings (PS2-compatible)
		try {
			[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
			[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')

			$form = New-Object System.Windows.Forms.Form
			$form.Text = "Test Email Server"
			$form.Size = New-Object System.Drawing.Size(560, 560)
			$form.StartPosition = 'CenterScreen'
			$form.TopMost = $false

			$labelWidth = 120
			$inputLeft = 140
			$top = 15
			$space = 30

			# Helper to create label
			function New-Label([string]$text, [int]$top) {
				$lbl = New-Object System.Windows.Forms.Label
				$lbl.Text = $text
				$lbl.AutoSize = $true
				$lbl.Location = New-Object System.Drawing.Point([int]15, [int]$top)
				return $lbl
			}

			# Server
			$lblServer = New-Label 'SMTP Server:' $top
			$txtServer = New-Object System.Windows.Forms.TextBox
			$txtServer.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]($top - 3))
			$txtServer.Size = New-Object System.Drawing.Size(380, 20)
			$txtServer.Text = $SmtpServer
			$top += $space

			# Port (ComboBox with common values)
			$lblPort = New-Label 'Port:' $top
			$cmbPort = New-Object System.Windows.Forms.ComboBox
			$cmbPort.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]($top - 3))
			$cmbPort.Size = New-Object System.Drawing.Size(100, 20)
			$cmbPort.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown  # allow custom typing
			[void]$cmbPort.Items.AddRange(@('25','465','587'))
			$cmbPort.Text = if ($SmtpPort) { [string]$SmtpPort } else { '25' }
			$top += $space

			# From
			$lblFrom = New-Label 'From:' $top
			$txtFrom = New-Object System.Windows.Forms.TextBox
			$txtFrom.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]($top - 3))
			$txtFrom.Size = New-Object System.Drawing.Size(380, 20)
			$txtFrom.Text = $From
			$top += $space

			# To
			$lblTo = New-Label 'To:' $top
			$txtTo = New-Object System.Windows.Forms.TextBox
			$txtTo.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]($top - 3))
			$txtTo.Size = New-Object System.Drawing.Size(380, 20)
			$txtTo.Text = $To
			$top += $space

			# Subject
			$lblSubject = New-Label 'Subject:' $top
			$txtSubject = New-Object System.Windows.Forms.TextBox
			$txtSubject.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]($top - 3))
			$txtSubject.Size = New-Object System.Drawing.Size(380, 20)
			$txtSubject.Text = $Subject
			$top += $space

			# Body (multiline)
			$lblBody = New-Label 'Body:' $top
			$txtBody = New-Object System.Windows.Forms.TextBox
			$txtBody.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]($top - 3))
			$txtBody.Size = New-Object System.Drawing.Size(380, 120)
			$txtBody.Multiline = $true
			$txtBody.ScrollBars = 'Vertical'
			$txtBody.Text = $Body
			$top += 130

			# SSL
			$chkSsl = New-Object System.Windows.Forms.CheckBox
			$chkSsl.Text = 'Use SSL'
			$chkSsl.AutoSize = $true
			$chkSsl.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]$top)
			$chkSsl.Checked = [bool]$UseSsl
			$top += $space

			# Username
			$lblUser = New-Label 'Username:' $top
			$txtUser = New-Object System.Windows.Forms.TextBox
			$txtUser.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]($top - 3))
			$txtUser.Size = New-Object System.Drawing.Size(380, 20)
			$txtUser.Text = $userName
			$top += $space

			# Password
			$lblPwd = New-Label 'Password:' $top
			$txtPwd = New-Object System.Windows.Forms.TextBox
			$txtPwd.Location = New-Object System.Drawing.Point([int]$inputLeft, [int]($top - 3))
			$txtPwd.Size = New-Object System.Drawing.Size(380, 20)
			$txtPwd.UseSystemPasswordChar = $true
			$txtPwd.Text = $password
			$top += ($space + 10)

			# Buttons
			$btnOk = New-Object System.Windows.Forms.Button
			$btnOk.Text = 'Send'
			$btnOk.Size = New-Object System.Drawing.Size(90, 28)
			$btnOk.Location = New-Object System.Drawing.Point([int]330, [int]$top)
			$btnOk.Anchor = 'Bottom,Right'

			$btnCancel = New-Object System.Windows.Forms.Button
			$btnCancel.Text = 'Cancel'
			$btnCancel.Size = New-Object System.Drawing.Size(90, 28)
			$btnCancel.Location = New-Object System.Drawing.Point([int]430, [int]$top)
			$btnCancel.Anchor = 'Bottom,Right'

			# Add controls
			$form.Controls.AddRange(@(
				$lblServer,$txtServer,
				$lblPort,$cmbPort,
				$lblFrom,$txtFrom,
				$lblTo,$txtTo,
				$lblSubject,$txtSubject,
				$lblBody,$txtBody,
				$chkSsl,
				$lblUser,$txtUser,
				$lblPwd,$txtPwd,
				$btnOk,$btnCancel
			))

			$form.AcceptButton = $btnOk
			$form.CancelButton = $btnCancel

			# Button events
			$btnOk.Add_Click({
				# Basic validation
				if (-not $txtServer.Text.Trim()) { [void][System.Windows.Forms.MessageBox]::Show('Please enter SMTP Server.'); return }
				if (-not $txtFrom.Text.Trim())   { [void][System.Windows.Forms.MessageBox]::Show('Please enter From address.'); return }
				if (-not $txtTo.Text.Trim())     { [void][System.Windows.Forms.MessageBox]::Show('Please enter To address.'); return }

				[int]$portParsed = $SmtpPort
				try { $portParsed = [int]$cmbPort.Text } catch { $portParsed = $SmtpPort }

				# Assign to script variables
				$script:SmtpServer = $txtServer.Text.Trim()
				$script:SmtpPort   = $portParsed
				$script:From       = $txtFrom.Text.Trim()
				$script:To         = $txtTo.Text.Trim()
				$script:Subject    = $txtSubject.Text
				$script:Body       = $txtBody.Text
				$script:UseSsl     = [bool]$chkSsl.Checked
				$script:userName   = $txtUser.Text
				$script:password   = $txtPwd.Text

				$form.DialogResult = [System.Windows.Forms.DialogResult]::OK
				$form.Close()
			})

			$btnCancel.Add_Click({
				$form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
				$form.Close()
			})

			$result = $form.ShowDialog()
			if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
				Write-Warning 'Operation canceled by user.'
				Stop-ScriptExecution $true
			}
		}
		catch {
			Write-SeparatorError "GUI error: $_"
		}
	}

	# Fallback: ensure valid port when no GUI or invalid input; default to 25
	$__tmp = 0
	if (-not [int]::TryParse([string]$SmtpPort, [ref]$__tmp)) { $SmtpPort = 25 } else { $SmtpPort = $__tmp }

	Write-Log "SMTP-Server:$SmtpServer" 1
	Write-Log "SMTP-Port:$SmtpPort" 1

	#powershell 2.x does not have Send-MailMessage cmdlet, it is introduced in 3.0
	if ($mandatoryUseOldSmtpClient -or ([Version]$psvObj -lt [Version]'3.0')) {
		try {
			Write-Log "Using manual SMTP client" 1
			$SMTP = New-Object Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
			if ($UseSsl) {
				$SMTP.EnableSsl = $true
				$SMTP.Credentials = New-Object System.Net.NetworkCredential("$userName","$password")
			} else {
				$SMTP.EnableSsl = $false
			}

			$MailMessage = New-Object System.Net.Mail.MailMessage($From, $To, $Subject, $Body)

			$SMTP.Send($MailMessage)
		}
		Catch {
			Write-SeparatorError "Error: $_"
		}
	}
		else {
			try {
				Write-Log "Using Send-MailMessage cmdlet 'powershell 3.0+'" 1

				# Convert password to secure string
				$SecurePassword = ConvertTo-SecureString $password -AsPlainText -Force
				$Credential = New-Object System.Management.Automation.PSCredential($userName, $SecurePassword)

				# Send email
				Send-MailMessage -To $To `
								-From $From `
								-SmtpServer $SmtpServer `
								-Port $SmtpPort `
								-Credential $Credential `
								-Subject $Subject `
								-Body $Body `
								-UseSsl:$UseSsl `
								-ErrorAction Stop
			}
			catch {
				Write-SeparatorError "Error: $_"
			}
		}

	$script:ModuleName = 'End'
	if ($script:DebugEnabled) { Write-Log "Script [$($script:ScriptName)] executed!" 1 }
	# Pause
	Stop-ScriptExecution

#****************************************************************************************************