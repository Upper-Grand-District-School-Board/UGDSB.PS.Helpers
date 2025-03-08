<#
    .SYNOPSIS
        Construct the body with the elements for a sucessful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.

    .DESCRIPTION
        Construct the body with the elements for a sucessful device trust validation required by a Function App that's leveraging the AADDeviceTrust.FunctionApp module.

    .EXAMPLE
        .\New-AADDeviceTrustBody.ps1

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2022-03-14
        Updated:     2023-05-14

        Version history:
        1.0.0 - (2022-03-14) Script created
        1.0.1 - (2023-05-10) Max - Updated to no longer use Thumbprint field, no redundant.
        1.0.2 - (2023-05-14) Max - Updating to pull the Azure AD Device ID from the certificate itself.
    #>
function New-EntraIDDeviceTrustBody {
  [CmdletBinding()]
  param()
  # Retrieve required data for building the request body
  $EntraIDDeviceID = Get-EntraIDDeviceID # Still needed to form the signature.
  $CertificateThumbprint = Get-EntraIDRegistrationCertificateThumbprint
  $Signature = New-RSACertificateSignature -Content $EntraIDDeviceID -Thumbprint $CertificateThumbprint
  $PublicKeyBytesEncoded = Get-PublicKeyBytesEncodedString -Thumbprint $CertificateThumbprint

  # Construct client-side request header
  $BodyTable = [ordered]@{
    DeviceName = $env:COMPUTERNAME
    #DeviceID = $EntraIDDeviceID - Will be pulled from the key.
    Signature  = $Signature
    #Thumbprint = $CertificateThumbprint - Will be pulled from the key.
    PublicKey  = $PublicKeyBytesEncoded
  }

  # Handle return value
  return $BodyTable
}