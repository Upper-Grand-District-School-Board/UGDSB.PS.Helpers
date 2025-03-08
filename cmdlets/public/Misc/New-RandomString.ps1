<#
  .DESCRIPTION
  This cmdet will generate a random character string based on inputs passed to it.
  .PARAMETER length
  The number of characters you want the random string to contain.
  .PARAMETER characters
  The list of characters that you want it to use to generate the random string
  .EXAMPLE
  New-RandomString -length 10 -characters 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!@#$%^&*'
    Will Generate a random string of 10 characters in length with the characters in abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!@#$%^&*
#>
function New-RandomString{
  [CmdletBinding()]
  [OutputType([System.String])]
  param(
    [Parameter()][ValidateNotNullOrEmpty()][int]$length = 15,
    [Parameter()][ValidateNotNullOrEmpty()][string]$characters = 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!@#$%^&*'
  )
  # Generate a random string based on the length and characters passed
  $randomString = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length}
  $private:ofs = ""
  return [string]$characters[$randomString]
}