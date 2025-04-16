<#
  .DESCRIPTION
  This cmdlet is designed to check Active Directory for a valid samAccountName when creating/changing user.
  .PARAMETER samAccountName
  The account name we want to test for
  .PARAMETER server
  The server that we want to test against
  .EXAMPLE
  Check for a specific samAccountName
    Test-SamAccountName -samAccountName <NAME> -server <SERVER>
#>
function Test-SamAccountName{
  [CmdletBinding()]
  [OutputType([System.String],[System.Boolean])]
  param(
    [Parameter(Mandatory = $true)]$samAccountName,
    [Parameter(Mandatory = $true)]$server    
  )
  # Default Addition at the end of the name if it exists.
  $postFix = 2
  # Loop through to try to find a valid samAccountName or fail if loops too many times
  do{
    try{
      # Check to see if the user already exists.
      Get-ADUser -Identity $samAccountName -Server $server | Out-Null
      # If it does exist, then add the postfix
      if($postFix -eq 2){
        $samAccountName = "$($samAccountName)$($postFix)"
      }
      # If postfix is greater than default, then remove it (as we max at 9) to add the new postfix
      else{
        $samAccountName = "$($samAccountName.substring(0,$samAccountName.length -1))$($postFix)"
      } 
    }
    # If the account doesn't exist, return the samAccountName as good
    catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
      return $samAccountName
    }
    catch {
      throw $Error[0]
    }
    $postFix++
  }while($postFix -lt 10)  
  # Return false if we couldn't find a valid samAccountName we could use
  return $false  
}
