<#
  .DESCRIPTION
  This cmdlet will convert a SID to an Azure AD Object ID
  .PARAMETER sid
  SID of object
  .EXAMPLE
  Convert Sid to Object ID
    Convert-SidtoEntraObjID -sid <SID>
#>
function Convert-SidtoEntraObjID{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$sid
  )
  $text = $sid.Replace('S-1-12-1-', '')
  $array = [UInt32[]]$text.Split('-')
  $bytes = New-Object 'Byte[]' 16
  [Buffer]::BlockCopy($array, 0, $bytes, 0, 16)
  [Guid]$guid = $bytes
  return $guid        
}