function Show-ManageMailboxModal {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$mailbox,
    [Parameter(Mandatory = $true)][string]$permissionType,
    [Parameter(Mandatory = $true)][string]$action
  )
  Show-UDModal -Content {
    New-UDTypography -Text "Email Address" -Variant "h5" -ClassName "card-title rounded x-card-title"
    New-UDTextbox -id "add_email" -Label "Email Address" -Placeholder "Enter Email Address" -Value "" -FullWidth
  } -Footer {
    New-UDButton -Text $action -OnClick {   
      try{
        Import-Module -Name $UGDSBPSPath -Force
        Set-UDElement -Id $permissionType -Content {
          New-UDImage -Url "/assets/LoadingCircle.gif" -Width 250 -Height 250
        }
        $email = (Get-UDElement -id "add_email").Value
        $EventEntry = @{
          Source    = "Manage Mailbox Permissions"
          LogName   = "PowerShellScripts"
          EventType = "Information"
          EventId   = 1000  
          EventData = [Ordered]@{
            thread = Get-Random
            user   = $User 
            action = ""
            result = "Success"
            error  = $null
          }
        }                        
        switch($permissionType){
          "fullaccess" {
            if($action -eq "add"){
              $EventEntry.EventData.Action = "Add Full Access Permission for $($email) on $($mailbox)"
              Add-MailboxPermission -Identity $mailbox -User $email -AccessRights FullAccess  
              Start-Sleep -Seconds 20
            }
            else{
              $EventEntry.EventData.Action = "Remove Full Access Permission for $($email) on $($mailbox)"
              Remove-MailboxPermission -Identity $mailbox -User $email -AccessRights FullAccess -Confirm:$false
              Start-Sleep -Seconds 60
            }
            Get-PermissionList -mailbox $mailbox -permissionType "fullaccess"
          }
          "sendas" {
            if($action -eq "add"){
              $EventEntry.EventData.Action = "Add Send As Permission for $($email) on $($mailbox)"
              Add-RecipientPermission -Identity $mailbox -AccessRights SendAs -Trustee $email -Confirm:$false  
            }
            else{
              $EventEntry.EventData.Action = "Remove Send As Permission for $($email) on $($mailbox)"
              Remove-RecipientPermission -Identity $mailbox -AccessRights SendAs -Trustee $email -Confirm:$false
            }
            Start-Sleep -Seconds 20
            Get-PermissionList -mailbox $mailbox -permissionType "sendas"            
          }
          "sendonbehalf" {
            # Entra ID App Registration Secret
            $clientSecret = Get-Secret -Vault $KVName -Name $AzClientSecret
            # Get Graph Access Token
            Get-GraphAccessToken -clientID $AzAppRegistration -clientSecret $clientSecret.GetNetworkCredential().Password -tenantID $AzTenant | Out-Null                
            if($action -eq "add"){
              $EventEntry.EventData.Action = "Add Send On Behalf Permission for $($email) on $($mailbox)"
              Set-Mailbox $mailbox -GrantSendOnBehalfTo @{add=$email}  
            }
            else{
              $EventEntry.EventData.Action = "Remove Send On Behalf Permission for $($email) on $($mailbox)"
              Set-Mailbox $mailbox -GrantSendOnBehalfTo @{remove=$email}   -Confirm:$false              
            }
            Start-Sleep -Seconds 20
            Get-PermissionList -mailbox $mailbox -permissionType "sendonbehalf"             
          }
          "calendaraccess" {
            if($action -eq "add"){
              $EventEntry.EventData.Action = "Add Calendar Permission for $($email) on $($mailbox)"
              Add-MailboxFolderPermission -Identity "$($mailbox):\Calendar" -User $email -AccessRights Editor -SharingPermissionFlags Delegate  
            }
            else{
              $EventEntry.EventData.Action = "Remove Calendar Permission for $($email) on $($mailbox)"
              Remove-MailboxFolderPermission -Identity "$($mailbox):\Calendar" -User $email    -Confirm:$false          
            }
            Start-Sleep -Seconds 20
            Get-PermissionList -mailbox $mailbox -permissionType "calendaraccess"     
          }
        }  
      }
      catch{
        $EventEntry.EventType = "Error"
        $EventEntry.EventData.Result = "Failed"
        $EventEntry.EventData.error = $_.Exception.Message
        Show-UDToast -Message $_.Exception.Message -Duration 10000 -Position "topRight" -BackgroundColor "#FF0000"
      }
      finally{
        Write-WinEvent @EventEntry    
        Hide-UDModal
      }
    }                                 
    New-UDButton -Text "Close" -OnClick { Hide-UDModal }
  }
}