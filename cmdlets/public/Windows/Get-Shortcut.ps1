function Get-Shortcut{
  [CmdletBinding()]
  param(
    [parameter()][ValidateNotNullOrEmpty()][string]$Name,
    [parameter()][string]$UserName = $null,
    [parameter()][string]$OneDriveOrgName = $null,
    [parameter()][switch]$StartMenu,
    [parameter()][string]$folder    
  )
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
  # Determine if we should be using paths from the user's profile or the public profile
  if($null -ne $Username -and $UserName -ne ""){
    $baseprofile = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).ProfilePath
    if(-not $baseprofile){
      throw "Unable to find profile for username: $($UserName)"
    }
    $desktopPath = Join-Path -Path $baseprofile -ChildPath "Desktop\$($folder)"
    $onedrivePath = Join-Path -Path $baseprofile -ChildPath "OneDrive - $($OneDriveOrgName)\Desktop\$($folder)"
    if($null -ne $OneDriveOrgName -and (Test-Path $onedrivePath)){
      $desktopPath = $onedrivePath
    }
    $startMenuPath = Join-Path -Path $baseprofile -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($folder)"
  }
  else{
    $desktopPath = Join-Path -Path $ENV:PUBLIC -ChildPath "Desktop\$($folder)"
    $startMenuPath = Join-Path -path $ENV:ALLUSERSPROFILE -ChildPath "Microsoft\Windows\Start Menu\Programs\$($folder)"
  }
  # Set the path based on if we are doing start menu or desktop
  if($startMenu.IsPresent){
    $path = $startMenuPath
  }
  else{
    $path = $desktopPath
  }
  $shortcut = Join-Path -Path $path -ChildPath "$($Name).lnk"
  if(Test-Path $shortcut){
    $obj = New-Object -ComObject WScript.Shell
    $link = $obj.CreateShortcut($shortcut)
    return $link
  }
  else{
    throw "Shortcut not found: $($shortcut)"
  }
}