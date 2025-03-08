function New-EventSource {
  [CmdLetBinding()]
  param(
    [Parameter()][string]$EventLog = "Application",
    [Parameter()][string]$Source
  )
  # Get Current List of Event Logs and their sources
  $logsources = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_NTEventLOgFile" | Select-Object FileName, Sources | ForEach-Object -Begin { $hash = @{}} -Process { $hash[$_.FileName] = $_.Sources } -end { $Hash }
  # Create Event Log if does not exist.
  if(-not $logsources.ContainsKey($EventLog)){
    try{
      New-EventLog -source $EventLog -LogName $EventLog -ErrorAction Stop
      $logsources = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_NTEventLOgFile" | Select-Object FileName, Sources | ForEach-Object -Begin { $hash = @{}} -Process { $hash[$_.FileName] = $_.Sources } -end { $Hash }
    }
    catch{
      throw 'Event log {0} does not exists, error creating.' -f $EventLog
    }    
  }
  # Check to see if source exists in the specific event log
  if(-not $logsources.$($EventLog).contains($source)){
    $sourceexists = $logsources.values.contains($Source).contains($true)
    if($sourceexists){
      throw "Source already exists in another event log, please choose a different source name"
    }
    else{
      try{
        New-EventLog -source $Source -LogName $EventLog -ErrorAction Stop
      }
      catch{
        'Source {0} for event log {1} can not be created' -f $Source, $EventLog | Write-Warning
        return $EventLog
      }
    }
  }
  else{
    'Source {0} for event log {1} already exists' -f $Source, $EventLog | Write-Verbose
  }
  return $Source
}