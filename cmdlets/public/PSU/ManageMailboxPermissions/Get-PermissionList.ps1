function Get-PermissionList {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$mailbox,
    [Parameter(Mandatory = $true)][string]$permissionType
  )
  switch ($permissionType) {
    "fullaccess" {
      $list = Get-MailboxPermission -Identity $mailbox | Where-Object { $_.User -ne "NT AUTHORITY\SELF" } | Select-Object -Property User, AccessRights, Action
      $columdata = @(    
        @{ field = "user"; flex = 1.0;}
      )
    }
    "sendas" {
      $list = Get-RecipientPermission -Identity $mailbox | Where-Object { $_.Trustee -ne "NT AUTHORITY\SELF" } | Select-Object -Property Trustee, AccessRights, IsInherited
      $columdata = @(    @{ field = "Trustee"; flex = 1.0 }) 
    }
    "sendonbehalf" {
      $list = [System.Collections.Generic.List[PSCustomObject]]::new()
      $sendOnBehalfPermissions = Get-Mailbox -Identity $mailbox | Select-Object GrantSendonBehalfTo
      foreach ($obj in $sendOnBehalfPermissions.GrantSendonBehalfTo) {
        $graphUser = Get-GraphUser -userid $obj
        $list.Add([PSCustomObject]@{ User = $graphUser.DisplayName; Email = $graphUser.UserPrincipalName })
      }   
      $columdata = @(
        @{ field = "User"; flex = 1.0 }
        @{ field = "Email"; flex = 1.0 }
      )   
    }
    "calendaraccess" {
      $list = [System.Collections.Generic.List[PSCustomObject]]::new()
      $calendarPermissions = Get-MailboxFolderPermission -Identity "$($mailbox):\Calendar" | Select-Object -Property User, AccessRights
      foreach ($obj in $calendarPermissions) {
        $list.Add([PSCustomObject]@{ User = $obj.User.DisplayName; AccessRights = ($obj.AccessRights -join ",") })
      }  
      $columdata = @(
        @{ field = "User"; flex = 1.0 }
        @{ field = "AccessRights"; flex = 1.0 }	
      )           
    }
  }
  Set-UDElement -Id $permissionType -Content {
    if($list){
    New-UDDataGrid -id "$($permissionType)_grid" -LoadRows {
      $list | Out-UDDataGridData -Context $EventData -TotalRows $list.Count
    } -Columns $columdata -AutoHeight $true -PageSize 500         }
  }
}