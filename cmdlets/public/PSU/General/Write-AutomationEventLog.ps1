function Write-AutomationEventLog{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter()][string]$LogName = "PowerShellScripts",
    [Parameter()][string]$EventType = "Information",
    [Parameter()][int]$EventId = 1000,
    [Parameter()][int]$threadID,
    [Parameter(Mandatory = $true)][string]$user,
    [Parameter(Mandatory = $true)][string]$action,
    [Parameter()][string]$result = "Success",
    [Parameter()][string]$errormsg = $null
  )
  # Thread ID
  if (-not $PSBoundParameters.ContainsKey("threadID")){
    $threadID = Get-Random
  }
  $EventEntry = @{
    Source    = $Source
    LogName   = $LogName
    EventType = $EventType
    EventId   = $EventId  
    EventData = [Ordered]@{
      thread    = $threadID
      user      = $user     
      action    = $action
      result    = $result
      error     = $errormsg
    }
  }
  Write-WinEvent @EventEntry
}