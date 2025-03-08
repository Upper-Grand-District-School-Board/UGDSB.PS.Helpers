function Write-WinEvent {
  [CmdLetBinding()]
  param(
    [Parameter()][string]$LogName = 'Application',
    [Parameter()][string]$Source = "Application",
    [Parameter()][int64]$EventId = 1000,
    [Parameter()][System.Diagnostics.EventLogEntryType]$EventType = "Information",
    [Parameter()][System.Collections.Specialized.OrderedDictionary]$EventData,
    [Parameter()][ValidateSet('JSON', 'CSV', 'XML')][string]$MessageFormat = 'JSON'
  )
  $Source = New-EventSource -EventLog $LogName -Source $Source
  $EventMessage = @()
  switch ($MessageFormat) {
    'JSON' { $EventMessage += $EventData | ConvertTo-Json }
    'CSV' { $EventMessage += ($EventData.GetEnumerator() | Select-Object -Property Key, Value | ConvertTo-Csv -NoTypeInformation) -join "`n" }
    'XML' { $EventMessage += ($EventData | ConvertTo-Xml).OuterXml }
  }
  $EventMessage += foreach ($Key in $EventData.Keys) {
    '{0}:{1}' -f $Key, $EventData.$Key
  }
  try {
    $Event = [System.Diagnostics.EventInstance]::New($EventId, $null, $EventType)
    $EventLog = [System.Diagnostics.EventLog]::New()
    $EventLog.Log = $LogName
    $EventLog.Source = $Source
    $EventLog.WriteEvent($Event, $EventMessage)
  }
  catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}