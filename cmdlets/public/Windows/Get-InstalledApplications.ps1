<#
  .DESCRIPTION 
  This is designed to get the get the list of applications on the system. Originally from https://azuretothemax.net/log-analytics-index/
#>
function Get-InstalledApplications {
  [CmdletBinding()]
  param(
    [Parameter()][ValidateNotNullOrEmpty()][string]$UserSid
  )
  New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
  $regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
  $regpath += "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  if (-not ([IntPtr]::Size -eq 4)) {
    $regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  }
  $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString', 'InstallDate'
  $Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, InstallDate, PSPath | Sort-Object DisplayName
  Remove-PSDrive -Name "HKU" | Out-Null
  Return $Apps
}