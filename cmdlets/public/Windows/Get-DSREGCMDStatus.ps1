<#
  .DESCRIPTION 
  This is designed to parse the dsregcmd command to usable data. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Get-DSREGCMDStatus {
  [cmdletbinding()]
  param(
    [parameter(HelpMessage = "Use to add /DEBUG to DSREGCMD")][switch]$bDebug
  )
  try {
    Write-Output "Calling DSREGCMDSTATUS"
    $cmdArgs = if ($bDebug) { "/STATUS", "/DEBUG" } else { "/STATUS" }
    $DSREGCMDStatus = & DSREGCMD $cmdArgs
    $DSREGCMDEntries = [PSCustomObject]@{}
    if ($DSREGCMDStatus) {
      for ($i = 0; $i -le $DSREGCMDStatus.Count ; $i++) {
        if ($DSREGCMDStatus[$i] -like "| *") {
          $GroupName = $DSREGCMDStatus[$i].Replace("|", "").Trim().Replace(" ", "")
          $Member = @{
            MemberType = "NoteProperty"
            Name       = $GroupName
            Value      = $null
          }
          $DSREGCMDEntries | Add-Member @Member
          $i++ #Increment to skip next line with +----
          $GroupEntries = [PSCustomObject]@{}
          do {
            $i++
            if ($DSREGCMDStatus[$i] -like "*::*") {
              $DiagnosticEntries = $DSREGCMDStatus[$i] -split "(^DsrCmd.+(?=DsrCmd)|DsrCmd.+(?=\n))" | Where-Object { $_ -ne '' }
              foreach ($Entry in $DiagnosticEntries) {
                $EntryParts = $Entry -split "(^.+?::.+?: )" | Where-Object { $_ -ne '' }
                $EntryParts[0] = $EntryParts[0].Replace("::", "").Replace(": ", "")
                if ($EntryParts) {
                  $Member = @{
                    MemberType = "NoteProperty"
                    Name       = $EntryParts[0].Trim().Replace(" ", "")
                    Value      = $EntryParts[1].Trim()
                  }
                  $GroupEntries | Add-Member @Member
                  $Member = $null
                }
              }
            }
            elseif ($DSREGCMDStatus[$i] -like "* : *") {
              $EntryParts = $DSREGCMDStatus[$i] -split ':'
              if ($EntryParts) {
                $Member = @{
                  MemberType = "NoteProperty"
                  Name       = $EntryParts[0].Trim().Replace(" ", "")
                  Value      = if ($EntryParts.Count -gt 2) {
                                                  ( $EntryParts[1..(($EntryParts.Count) - 1)] -join ":").Split("--").Replace("[ ", "").Replace(" ]", "").Trim()
                  }
                  else {
                    $EntryParts[1].Trim()
                  }
                }
                $GroupEntries | Add-Member @Member
                $Member = $null
              }
            }
                  
          } until($DSREGCMDStatus[$i] -like "+-*" -or $i -eq $DSREGCMDStatus.Count)
          $DSREGCMDEntries.$GroupName = $GroupEntries
        }
      }
      return $DSREGCMDEntries
    }
    else {
      return "No Status Found"
    }
  }
  catch {
    throw $_
  }
}