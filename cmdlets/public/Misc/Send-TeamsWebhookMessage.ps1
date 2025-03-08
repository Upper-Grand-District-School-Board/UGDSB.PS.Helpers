function Send-TeamsWebhookMessage{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$webhook,
    [Parameter()][ValidateNotNullOrEmpty()][string]$text,
    [Parameter()][ValidateNotNullOrEmpty()][string]$summary,
    [Parameter()][ValidateNotNullOrEmpty()][string]$themeColor,
    [Parameter()][ValidateNotNullOrEmpty()][string]$title,
    [Parameter()][ValidateNotNullOrEmpty()][string]$activitytitle,
    [Parameter()][ValidateNotNullOrEmpty()][string]$activitysubtitle,
    [Parameter()][ValidateNotNullOrEmpty()][string]$activityimageuri,
    [Parameter()][ValidateNotNullOrEmpty()][string]$activitytext,
    [Parameter()][ValidateNotNullOrEmpty()][hashtable]$facts
  )
  $card = @{
    "@type" = "MessageCard"
    "@context" = "https://schema.org/extensions"
  }
  if($summary){
    $card.Add("summary",$summary) | Out-Null
  }
  else{
    $card.Add("text",$text) | Out-Null
  }
  if($themeColor){$card.Add("themeColor",$themeColor) | Out-Null}
  if($title){$card.Add("title",$title) | Out-Null}

  if($activitytitle -or $activitysubtitle -or $activityimageuri -or $activitytext -or $facts){
    $section = @{}
    if($activitytitle){
      $section.Add("activitytitle",$activitytitle) | Out-Null
    }
    if($activitysubtitle){
      $section.Add("activitysubtitle",$activitysubtitle) | Out-Null
    }    
    if($activityimageuri){
      $section.Add("activityImage",$activityimageuri) | Out-Null
    }   
    if($activitytext){
      $section.Add("text",$activitytext) | Out-Null
    }       
    if($facts){
      $messageFacts = [System.Collections.Generic.List[Hashtable]]@()
      foreach($item in $facts.GetEnumerator()){
        $obj = @{
          "name" = $item.key
          "value" = $item.value
        }
        $messageFacts.Add($obj) | Out-Null
      }
      $section.Add("facts",$messageFacts) | Out-Null
    }
    $card.Add("sections",@($section)) | Out-Null
  }
  Invoke-RestMethod -uri $webhook -Method Post -body ($card | ConvertTo-Json -depth 5) -ContentType 'application/json' | Out-Null
}