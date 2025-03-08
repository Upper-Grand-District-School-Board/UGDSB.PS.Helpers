function Test-LocalAdmin{
  [CmdletBinding()]
  param ()
  try{
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
  }
  catch {
    throw $_
  }  
}