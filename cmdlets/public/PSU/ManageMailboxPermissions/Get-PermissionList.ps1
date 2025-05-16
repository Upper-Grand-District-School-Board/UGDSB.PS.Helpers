function Get-PermissionList {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$mailbox,
    [Parameter(Mandatory = $true)][string]$permissionType
  )
  switch ($permissionType) {
    "fullaccess" {
      $list = Get-MailboxPermission -Identity $mailbox | Where-Object { $_.User -ne "NT AUTHORITY\SELF" } | Select-Object -Property User
    }
    "sendas" {
      $list = Get-RecipientPermission -Identity $mailbox | Where-Object { $_.Trustee -ne "NT AUTHORITY\SELF" } | Select-Object -Property Trustee
    }
    "sendonbehalf" {
      $list = [System.Collections.Generic.List[PSCustomObject]]::new()
      $sendOnBehalfPermissions = Get-Mailbox -Identity $mailbox | Select-Object GrantSendonBehalfTo
      foreach ($obj in $sendOnBehalfPermissions.GrantSendonBehalfTo) {
        $graphUser = Get-GraphUser -userid $obj
        $list.Add([PSCustomObject]@{ User = $graphUser.DisplayName; Email = $graphUser.UserPrincipalName })
      }   
    }
    "calendaraccess" {
      $list = [System.Collections.Generic.List[PSCustomObject]]::new()
      $calendarPermissions = Get-MailboxFolderPermission -Identity "$($mailbox):\Calendar" | Select-Object -Property User, AccessRights
      foreach ($obj in $calendarPermissions) {
        $list.Add([PSCustomObject]@{ User = $obj.User.DisplayName; AccessRights = ($obj.AccessRights -join ",") })
      }         
    }
  }
  Set-UDElement -Id $permissionType -Content {
    if($list){
      New-UDTable -Data $list
    }
  }
}