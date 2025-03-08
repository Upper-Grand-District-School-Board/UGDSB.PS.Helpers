<#
  .DESCRIPTION 
  This is designed to add autorun keys for the machine. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Set-AutorunRegKeys {
  [cmdletbinding()]
  param(
    [parameter(Mandatory = $true)][string]$Name,
    [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$CommandLine,
    [parameter()][string]$UserName = $null,
    [parameter()][switch]$runOnce
  )
  $forceload = $false
  # Get a list of all the user profiles on the machine
  $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20") }
  $UserList = foreach ($UserKey in $ProfileList) {
    @{
      ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
      UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
      SID         = $UserKey.PSChildName
      ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
    }
  } 
  if($null -ne $Username -and $UserName -ne ""){
    $SID = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).SID
    $baseprofile = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).ProfilePath
    if($runOnce.IsPresent){
      $registryPath = "REGISTRY::HKEY_USERS\$($SID)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    else{
      $registryPath = "REGISTRY::HKEY_USERS\$($SID)\Software\Microsoft\Windows\CurrentVersion\Run"
    }
    if(-not (Test-Path -Path $registryPath)){
      $hivepath = Join-Path -Path $baseprofile -ChildPath "NTUSER.DAT"
      reg Load "HKU\$($SID)" "$($hivepath)" | Out-Null
      $forceload = $true
      if(-not (Test-Path -Path  $registryPath)){
        throw "Unable to load hive for user: $($UserName)"
      }
    }
  }
  else{
    if($runOnce.IsPresent){
      $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    else{
      $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
    }    
  } 
  New-ItemProperty -Path $registryPath -Name $Name -Value $CommandLine
  if($forceload){
    [gc]::Collect()
    reg unload "HKU\$($SID)" | Out-Null    
  }
}