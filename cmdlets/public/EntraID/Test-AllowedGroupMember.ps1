# TEST (maybe split)
<#
  .DESCRIPTION
  This cmdlet is used to check to see if a specific user belongs to a group that is passed
  .PARAMETER groupList
  Array of the groups to check
  .PARAMETER domain
  If active directory, what domain to check. If you use this, it ignores any of the Az parameters
  .PARAMETER AzAppRegistration
  The client id of the azure app registration working under
  .PARAMETER AzTenant
  The directory id for the Azure AD tenant
  .PARAMETER AzSecret
  The client secret used to connect to MS Graph
  .EXAMPLE
  Check for a specific user in active directory
    Test-AllowedGroupMember -userPrincipalName <UPN> -groupList @("GROUPNAME") -domain <DOMAIN>
  Check for a specific user in Azure AD group
    Test-AllowedGroupMember -userPrincipalName <UPN> -groupList @("GROUPNAME") -AzTenant $AzTenant -AzAppRegistration $AzAppRegistration -AzSecret $Secret
#>
function Test-AllowedGroupMember{
  [CmdletBinding()]
  [OutputType([System.Boolean])]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$userPrincipalName,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][Object[]]$groupList,
    [Parameter()][string]$domain,
    [Parameter()][string]$AzAppRegistration,
    [Parameter()][string]$AzTenant,
    [Parameter()][pscredential]$AzSecret
    
  )
  # Nested function to be able to recurse through groups in Azure AD since Get-MGGroupMembers does not have this function currently
  function getNestedMembers{
    param(
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$groupId,
      [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$userPrincipalName
    )
    # Set found to false
    $results = $false
    # Get memberes of the group that was passed
    $members = Get-MgGroupMember -All -GroupId $groupId
    # If the username is found return true
    if($userPrincipalName -in $members.AdditionalProperties.userPrincipalName){
      return $true
    }
    # If not found, check the list for other nested groups
    else{
      $groups = $members | where-object {$_.AdditionalProperties.'@odata.type' -eq "#microsoft.graph.group"}
      # Loop through those groups those nested function
      foreach($group in $groups){
        $results = getNestedMembers -groupId $groupId -userPrincipalName $userPrincipalName
        if($results -eq $true){
          # if the results returned are true, return true.
          return $true
        }
      }
    }
  }
  # If set to query Azure AD Groups connect to MS Graph
  if($AzAppRegistration){
    # Connect to MS Graph
    $msalToken = Get-MsalToken -clientID $AzAppRegistration -clientSecret $AzSecret.Password -tenantID $AzTenant
    Connect-MgGraph -AccessToken $msalToken.AccessToken | Out-Null
  }
  foreach($group in $groupList){
    try{
      if($domain){
        # Get all the members and nested members of the group in Active Directory
        $members = Get-ADGroupMember -Recursive -Server $domain -Identity $group -ErrorAction SilentlyContinue  | where-object {$_.objectClass -eq 'User'} | Get-ADUser | select-object UserPrincipalName
        # Check to see if the list contains the expected UPN and if return true
        if($members.UserPrincipalName -contains $userPrincipalName){
          return $true
        }        
      }
      else{
        # Get the group from Azure AD
        $groups = Get-MGgroup -Filter "DisplayName eq '$($group)'"
        # Loop through if there are multiple groups with the same name
        foreach($group in $groups){
          # Get the results of the function to recurse through the groups
          $results = getNestedMembers -groupId $group.id -userPrincipalName $userPrincipalName
          # Return true if correct
          if($results -eq $true){
            return $true
          }
        }
      }
    }
    catch{
      throw "An error occured while processing group $($group) : $($Error[0])"
    }
  }
  return $false
}