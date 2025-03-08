<#
  .DESCRIPTION
  This cmdlet will convert a Azure AD Object ID TO Sid
  .PARAMETER ObjectId
  Azure AD Object ID
  .EXAMPLE
  Convert AzADObject to Sid
    Convert-EntraObjIDtoSid -objectId <ID>
#>
function Convert-EntraObjIDtoSid{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$ObjectId
  )  
  $bytes = [Guid]::Parse($ObjectId).ToByteArray()
  $array = New-Object 'UInt32[]' 4
  [Buffer]::BlockCopy($bytes, 0, $array, 0, 16)
  $sid = "S-1-12-1-$array".Replace(' ', '-')
  return $sid  
}