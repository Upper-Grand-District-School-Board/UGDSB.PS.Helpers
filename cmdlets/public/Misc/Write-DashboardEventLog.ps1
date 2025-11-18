function Write-DashboardEventLog {
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
    [Parameter()][string]$errormsg = $null,
    [Parameter()][bool]$showToasts = $true,
    [Parameter()][bool]$eventLog = $true
  )
  $error_toast_params = @{
    Duration        = 5000
    MessageColor    = "white"
    BackgroundColor = "red"
    Position        = "center"
    CloseOnClick    = $true
  }
  $success_toast_params = @{
    Duration        = 2000
    MessageColor    = "white"
    BackgroundColor = "green"
    Position        = "center"
    CloseOnClick    = $true
  }
  $warning_toast_params = @{
    Duration        = 2000
    MessageColor    = "white"
    BackgroundColor = "darkorange"
    Position        = "center"
    CloseOnClick    = $true
  }  
  # Thread ID
  if (-not $PSBoundParameters.ContainsKey("threadID")) {
    $threadID = Get-Random
  }
  $EventEntry = @{
    Source    = ($Source -replace "-", "_")
    LogName   = $LogName
    EventType = $EventType
    EventId   = $EventId  
    EventData = [Ordered]@{
      thread = $threadID
      user   = $user     
      action = $action
      result = $result
      error  = $errormsg
    }
  }
  if( $eventLog) {
    Write-WinEvent @EventEntry
  }
  if ($showToasts) {
    if ($result -eq "Success") {
      Show-UDToast @success_toast_params -Message $action
    }
    elseif ($result -eq "Warning"){
      Show-UDToast @warning_toast_params -Message $action
    }
    else {
      Show-UDToast @error_toast_params -Message $action
    }
  }
}