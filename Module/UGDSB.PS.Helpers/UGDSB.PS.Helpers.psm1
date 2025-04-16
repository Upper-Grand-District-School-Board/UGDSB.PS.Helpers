#Region '.\Public\Add-PInvokeType.ps1' 0
function Add-PInvokeType {
  [cmdletbinding()]
  param()
  #region LSAUtil
  # C# Code to P-invoke LSA functions.
  # This code is copied from PInvoke.net
  # http://www.pinvoke.net/default.aspx/advapi32.lsaretrieveprivatedata

  Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PInvoke.LSAUtil {
    public class LSAutil {
        [StructLayout (LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout (LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        private enum LSA_AccessPolicy : long {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaRetrievePrivateData (
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaStorePrivateData (
            IntPtr policyHandle,
            ref LSA_UNICODE_STRING KeyName,
            ref LSA_UNICODE_STRING PrivateData
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaOpenPolicy (
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaNtStatusToWinError (
            uint status
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaClose (
            IntPtr policyHandle
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaFreeMemory (
            IntPtr buffer
        );

        private LSA_OBJECT_ATTRIBUTES objectAttributes;
        private LSA_UNICODE_STRING localsystem;
        private LSA_UNICODE_STRING secretName;

        public LSAutil (string key) {
            if (key.Length == 0) {
                throw new Exception ("Key lenght zero");
            }

            objectAttributes = new LSA_OBJECT_ATTRIBUTES ();
            objectAttributes.Length = 0;
            objectAttributes.RootDirectory = IntPtr.Zero;
            objectAttributes.Attributes = 0;
            objectAttributes.SecurityDescriptor = IntPtr.Zero;
            objectAttributes.SecurityQualityOfService = IntPtr.Zero;

            localsystem = new LSA_UNICODE_STRING ();
            localsystem.Buffer = IntPtr.Zero;
            localsystem.Length = 0;
            localsystem.MaximumLength = 0;

            secretName = new LSA_UNICODE_STRING ();
            secretName.Buffer = Marshal.StringToHGlobalUni (key);
            secretName.Length = (UInt16) (key.Length * UnicodeEncoding.CharSize);
            secretName.MaximumLength = (UInt16) ((key.Length + 1) * UnicodeEncoding.CharSize);
        }

        private IntPtr GetLsaPolicy (LSA_AccessPolicy access) {
            IntPtr LsaPolicyHandle;
            uint ntsResult = LsaOpenPolicy (ref this.localsystem, ref this.objectAttributes, (uint) access, out LsaPolicyHandle);
            uint winErrorCode = LsaNtStatusToWinError (ntsResult);
            if (winErrorCode != 0) {
                throw new Exception ("LsaOpenPolicy failed: " + winErrorCode);
            }
            return LsaPolicyHandle;
        }

        private static void ReleaseLsaPolicy (IntPtr LsaPolicyHandle) {
            uint ntsResult = LsaClose (LsaPolicyHandle);
            uint winErrorCode = LsaNtStatusToWinError (ntsResult);
            if (winErrorCode != 0) {
                throw new Exception ("LsaClose failed: " + winErrorCode);
            }
        }

        private static void FreeMemory (IntPtr Buffer) {
            uint ntsResult = LsaFreeMemory (Buffer);
            uint winErrorCode = LsaNtStatusToWinError (ntsResult);
            if (winErrorCode != 0) {
                throw new Exception ("LsaFreeMemory failed: " + winErrorCode);
            }
        }

        public void SetSecret (string value) {
            LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING ();

            if (value.Length > 0) {
                //Create data and key
                lusSecretData.Buffer = Marshal.StringToHGlobalUni (value);
                lusSecretData.Length = (UInt16) (value.Length * UnicodeEncoding.CharSize);
                lusSecretData.MaximumLength = (UInt16) ((value.Length + 1) * UnicodeEncoding.CharSize);
            } else {
                //Delete data and key
                lusSecretData.Buffer = IntPtr.Zero;
                lusSecretData.Length = 0;
                lusSecretData.MaximumLength = 0;
            }

            IntPtr LsaPolicyHandle = GetLsaPolicy (LSA_AccessPolicy.POLICY_CREATE_SECRET);
            uint result = LsaStorePrivateData (LsaPolicyHandle, ref secretName, ref lusSecretData);
            ReleaseLsaPolicy (LsaPolicyHandle);

            uint winErrorCode = LsaNtStatusToWinError (result);
            if (winErrorCode != 0) {
                throw new Exception ("StorePrivateData failed: " + winErrorCode);
            }
        }

        public string GetSecret () {
            IntPtr PrivateData = IntPtr.Zero;

            IntPtr LsaPolicyHandle = GetLsaPolicy (LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION);
            uint ntsResult = LsaRetrievePrivateData (LsaPolicyHandle, ref secretName, out PrivateData);
            ReleaseLsaPolicy (LsaPolicyHandle);

            uint winErrorCode = LsaNtStatusToWinError (ntsResult);
            if (winErrorCode != 0) {
                throw new Exception ("RetreivePrivateData failed: " + winErrorCode);
            }

            LSA_UNICODE_STRING lusSecretData =
                (LSA_UNICODE_STRING) Marshal.PtrToStructure (PrivateData, typeof (LSA_UNICODE_STRING));
            string value = Marshal.PtrToStringAuto (lusSecretData.Buffer).Substring (0, lusSecretData.Length / 2);

            FreeMemory (PrivateData);

            return value;
        }
    }
}
"@
  #endregion  
}
#EndRegion '.\Public\Add-PInvokeType.ps1' 190
#Region '.\Public\Convert-EntraObjIDtoSid.ps1' 0
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
#EndRegion '.\Public\Convert-EntraObjIDtoSid.ps1' 21
#Region '.\Public\Convert-SidtoEntraObjID.ps1' 0
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
#EndRegion '.\Public\Convert-SidtoEntraObjID.ps1' 22
#Region '.\Public\Get-AutorunRegKeys.ps1' 0
function Get-AutorunRegKeys {
  [cmdletbinding()]
  param(
    [parameter(Mandatory = $true)][string]$Name,
    [parameter()][string]$UserName = $null,
    [parameter()][switch]$runOnce
  )
  $forceload = $false
  # Get a list of all the user profiles on the machine
  $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20") }
  $UserList = foreach ($UserKey in $ProfileList) {
    @{
      ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
      UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
      SID         = $UserKey.PSChildName
      ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
    }
  } 
  if($null -ne $Username -and $UserName -ne ""){
    $SID = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).SID
    $baseprofile = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).ProfilePath
    if($runOnce.IsPresent){
      $registryPath = "REGISTRY::HKEY_USERS\$($SID)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    else{
      $registryPath = "REGISTRY::HKEY_USERS\$($SID)\Software\Microsoft\Windows\CurrentVersion\Run"
    }
    if(-not (Test-Path -Path $registryPath)){
      $hivepath = Join-Path -Path $baseprofile -ChildPath "NTUSER.DAT"
      reg Load "HKU\$($SID)" "$($hivepath)" | Out-Null
      $forceload = $true
      if(-not (Test-Path -Path  $registryPath)){
        throw "Unable to load hive for user: $($UserName)"
      }
    }
  }
  else{
    if($runOnce.IsPresent){
      $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    else{
      $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
    }    
  } 
  $Keys = (Get-ItemProperty -Path $registryPath).psobject.properties | Where-Object { $_.Name -eq $Name }
  if($forceload){
    [gc]::Collect()
    reg unload "HKU\$($SID)" | Out-Null    
  }
  return $Keys
}
#EndRegion '.\Public\Get-AutorunRegKeys.ps1' 52
#Region '.\Public\Get-DSREGCMDStatus.ps1' 0
<#
  .DESCRIPTION 
  This is designed to parse the dsregcmd command to usable data. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Get-DSREGCMDStatus {
  [cmdletbinding()]
  param(
    [parameter(HelpMessage = "Use to add /DEBUG to DSREGCMD")][switch]$bDebug
  )
  try {
    Write-Output "Calling DSREGCMDSTATUS"
    $cmdArgs = if ($bDebug) { "/STATUS", "/DEBUG" } else { "/STATUS" }
    $DSREGCMDStatus = & DSREGCMD $cmdArgs
    $DSREGCMDEntries = [PSCustomObject]@{}
    if ($DSREGCMDStatus) {
      for ($i = 0; $i -le $DSREGCMDStatus.Count ; $i++) {
        if ($DSREGCMDStatus[$i] -like "| *") {
          $GroupName = $DSREGCMDStatus[$i].Replace("|", "").Trim().Replace(" ", "")
          $Member = @{
            MemberType = "NoteProperty"
            Name       = $GroupName
            Value      = $null
          }
          $DSREGCMDEntries | Add-Member @Member
          $i++ #Increment to skip next line with +----
          $GroupEntries = [PSCustomObject]@{}
          do {
            $i++
            if ($DSREGCMDStatus[$i] -like "*::*") {
              $DiagnosticEntries = $DSREGCMDStatus[$i] -split "(^DsrCmd.+(?=DsrCmd)|DsrCmd.+(?=\n))" | Where-Object { $_ -ne '' }
              foreach ($Entry in $DiagnosticEntries) {
                $EntryParts = $Entry -split "(^.+?::.+?: )" | Where-Object { $_ -ne '' }
                $EntryParts[0] = $EntryParts[0].Replace("::", "").Replace(": ", "")
                if ($EntryParts) {
                  $Member = @{
                    MemberType = "NoteProperty"
                    Name       = $EntryParts[0].Trim().Replace(" ", "")
                    Value      = $EntryParts[1].Trim()
                  }
                  $GroupEntries | Add-Member @Member
                  $Member = $null
                }
              }
            }
            elseif ($DSREGCMDStatus[$i] -like "* : *") {
              $EntryParts = $DSREGCMDStatus[$i] -split ':'
              if ($EntryParts) {
                $Member = @{
                  MemberType = "NoteProperty"
                  Name       = $EntryParts[0].Trim().Replace(" ", "")
                  Value      = if ($EntryParts.Count -gt 2) {
                                                  ( $EntryParts[1..(($EntryParts.Count) - 1)] -join ":").Split("--").Replace("[ ", "").Replace(" ]", "").Trim()
                  }
                  else {
                    $EntryParts[1].Trim()
                  }
                }
                $GroupEntries | Add-Member @Member
                $Member = $null
              }
            }
                  
          } until($DSREGCMDStatus[$i] -like "+-*" -or $i -eq $DSREGCMDStatus.Count)
          $DSREGCMDEntries.$GroupName = $GroupEntries
        }
      }
      return $DSREGCMDEntries
    }
    else {
      return "No Status Found"
    }
  }
  catch {
    throw $_
  }
}
#EndRegion '.\Public\Get-DSREGCMDStatus.ps1' 77
#Region '.\Public\Get-EntraDeviceCertificate.ps1' 0
<#
  .DESCRIPTION 
  This is designed to get the device certificate for Entra that is enrolled. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Get-EntraDeviceCertificate {
  [CmdletBinding()]
  [OutputType([X509Certificate])]
  param (
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][Object]$dsregcmdStatus
  )
  try {
    Write-Host "Getting Azure AD Device Certificate"
    #Get best cert from DSRegCmd
    $Thumbprint = $dsregcmdstatus.DeviceDetails.Thumbprint
    #Get the local cert that matches the DSRegCMD Cert
    $Certs = Get-ChildItem -Path Cert:\LocalMachine\My 
    $Cert = $Certs | Where-Object { $_.Thumbprint -eq $dsregcmdstatus.DeviceDetails.Thumbprint }
    if ($Cert.Thumbprint -eq $Thumbprint) {
      return $Cert
    }
    else {
      Write-Output "No valid Entra Device Cert Found."
    }
  }
  catch {
    throw $_
  }
}
#EndRegion '.\Public\Get-EntraDeviceCertificate.ps1' 29
#Region '.\Public\Get-EntraIDDeviceID.ps1' 0
<#
  .DESCRIPTION 
  This is designed to get the entra id device id. Originally from https://azuretothemax.net/log-analytics-index/
#>
function Get-EntraIDDeviceID {
  [CmdletBinding()]
  param()  
  # Define Cloud Domain Join information registry path
  $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

  # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
  $EntraIDJoinInfoThumbprint = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
  if ($EntraIDJoinInfoThumbprint -ne $null) {
    # Retrieve the machine certificate based on thumbprint from registry key
    $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $EntraIDJoinInfoThumbprint }
    if ($EntraIDJoinCertificate -ne $null) {
      # Determine the device identifier from the subject name
      $EntraIDDeviceID = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
      # Convert upper to lowercase.
      $EntraIDDeviceID = "$($EntraIDDeviceID)".ToLower()
      # Handle return value
      return $EntraIDDeviceID
    }
    else {
      #If no certificate was found, locate it by Common Name instead of Thumbprint. This is likely a CPC or similar.
      $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=($EntraIDJoinInfoThumbprint)" }
      if ($EntraIDJoinCertificate -ne $null) {
        # Cert is now found, extract Device ID from Common Name
        $EntraIDDeviceID = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
        # Convert upper to lowercase.
        $EntraIDDeviceID = "$($EntraIDDeviceID)".ToLower()
        # Handle return value
        return $EntraIDDeviceID
      }
      else {
        # Last ditch effort, try and use the ThumbPrint (reg key) itself.
        $EntraIDDeviceID = $EntraIDJoinInfoThumbprint
        # Convert upper to lowercase.
        $EntraIDDeviceID = "$($EntraIDDeviceID)".ToLower()
        return $EntraIDDeviceID
      }
    }
  }
}
#EndRegion '.\Public\Get-EntraIDDeviceID.ps1' 45
#Region '.\Public\Get-EntraIDJoinDate.ps1' 0
<#
  .DESCRIPTION 
  This is designed to get the entra id join date. Originally from https://azuretothemax.net/log-analytics-index/
#>
function Get-EntraIDJoinDate {
  [CmdletBinding()]
  param()
  # Define Cloud Domain Join information registry path
  $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
  # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
  $EntraIDJoinInfoThumbprint = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
  if ($EntraIDJoinInfoThumbprint -ne $null) {
    # Retrieve the machine certificate based on thumbprint from registry key
    $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $EntraIDJoinInfoThumbprint }
    if ($EntraIDJoinCertificate -ne $null) {
      # Determine the device identifier from the subject name
      $EntraIDJoinDate = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
      # Handle return value
      return $EntraIDJoinDate
    }
    if ($EntraIDJoinCertificate -eq $null) {
      $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -eq "CN=$($EntraIDJoinInfoThumbprint)" }
      $EntraIDJoinDate = ($EntraIDJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
      return $EntraIDJoinDate
    }
  }
}
#EndRegion '.\Public\Get-EntraIDJoinDate.ps1' 28
#Region '.\Public\Get-EntraIDRegistrationCertificateThumbprint.ps1' 0
<#
  .SYNOPSIS
      Get the thumbprint of the certificate used for Azure AD device registration.
  
  .DESCRIPTION
      Get the thumbprint of the certificate used for Azure AD device registration.
  
  .NOTES
      Author:      Nickolaj Andersen
      Contact:     @NickolajA
      Created:     2021-06-03
      Updated:     2021-06-03
  
      Version history:
      1.0.0 - (2021-06-03) Function created
      1.0.1 - (2023-05-10) Max Updated for Cloud PCs which don't have their thumbprint as their JoinInfo key name.
  #>
function Get-EntraIDRegistrationCertificateThumbprint {
  [CmdletBinding()]
  param()  
  # Define Cloud Domain Join information registry path
  $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
  # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
  $EntraIDJoinInfoThumbprint = Get-ChildItem -Path $EntraIDJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
  # Check for a cert matching that thumbprint
  $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $EntraIDJoinInfoThumbprint }
  if ($EntraIDJoinCertificate -ne $null) {
    # if a matching cert was found tied to that reg key (thumbprint) value, then that is the thumbprint and it can be returned.
    $EntraIDThumbprint = $EntraIDJoinInfoThumbprint
    # Handle return value
    return $EntraIDThumbprint
  }
  else {
    # If a cert was not found, that reg key was not the thumbprint but can be used to locate the cert as it is likely the Azure ID which is in the certs common name.
    $EntraIDJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($EntraIDJoinInfoThumbprint)" }
    #Pull thumbprint from cert
    $EntraIDThumbprint = $EntraIDJoinCertificate.Thumbprint
    # Handle return value
    return $EntraIDThumbprint
  }
}
#EndRegion '.\Public\Get-EntraIDRegistrationCertificateThumbprint.ps1' 42
#Region '.\Public\Get-EntraIDTenantID.ps1' 0
<#
  .DESCRIPTION 
  This is designed to get the entra tenant id that device belogs too. Originally from https://azuretothemax.net/log-analytics-index/
#>
function Get-EntraIDTenantID{
  [CmdletBinding()]
  param()  
  # Cloud Join information registry path
  $EntraIDTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
  # Retrieve the child key name that is the tenant id for EntraID
  $EntraIDTenantID = Get-ChildItem -Path $EntraIDTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
  return $EntraIDTenantID  
}
#EndRegion '.\Public\Get-EntraIDTenantID.ps1' 14
#Region '.\Public\Get-InstalledApplications.ps1' 0
<#
  .DESCRIPTION 
  This is designed to get the get the list of applications on the system. Originally from https://azuretothemax.net/log-analytics-index/
#>
function Get-InstalledApplications {
  [CmdletBinding()]
  param(
    [Parameter()][ValidateNotNullOrEmpty()][string]$UserSid
  )
  New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
  $regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
  $regpath += "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  if (-not ([IntPtr]::Size -eq 4)) {
    $regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  }
  $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString', 'InstallDate'
  $Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, InstallDate, PSPath | Sort-Object DisplayName
  Remove-PSDrive -Name "HKU" | Out-Null
  Return $Apps
}
#EndRegion '.\Public\Get-InstalledApplications.ps1' 22
#Region '.\Public\Get-IntuneDeviceCertificate.ps1' 0
<#
  .DESCRIPTION 
  This is designed to get the device certificate for Intune that is enrolled. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Get-IntuneDeviceCertificate {
  [CmdletBinding()]
  [OutputType([X509Certificate])]
  param (
  )
  try {
    $CertIssuer = "CN=Microsoft Intune MDM Device CA"
    $ProviderRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments"
    $ProviderPropertyName = "ProviderID"
    $ProviderPropertyValue = "MS DM Server"
    $ProviderGUID = (Get-ChildItem -Path Registry::$ProviderRegistryPath -Recurse | ForEach-Object { if ((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath -ErrorAction SilentlyContinue | Get-ItemPropertyValue -Name $ProviderPropertyName -ErrorAction SilentlyContinue) -match $ProviderPropertyValue) { $_ } }).PSChildName
    $DMClientPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\$($ProviderGUID)\DMClient\MS DM Server"
    $IntuneDeviceId = (Get-ItemPropertyValue -Path Registry::$DMClientPath -Name "EntDMID")

    $Cert = (Get-ChildItem cert:\LocalMachine\my | where-object { $_.Issuer -in $CertIssuer -and $_.Subject -like "*$IntuneDeviceId*" })
    if ($cert) {
      return $Cert
    }
  }
  catch {
    throw $_
  }  
}
#EndRegion '.\Public\Get-IntuneDeviceCertificate.ps1' 28
#Region '.\Public\Get-KeyVaultSecret.ps1' 0
<#
  .DESCRIPTION
  This cmdlet is used to connect to a keyvault as the machine identity of the Azure Machine it is running under.
  .PARAMETER vaultName
  The name of the vault that we want to check
  .PARAMETER secretName
  The name of the secret we want to recover
  .EXAMPLE
  Check a secret out of a specific vault
    Get-KeyVaultSecret -vaultName <VAULT> -secretName <SECRET>
#>
function Get-KeyVaultSecret{
  [CmdletBinding()]
  [OutputType([System.String])]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$vaultName,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$secretName
  )
  # The URI for the vault that we want to access
  $keyVaultURI = "https://$($vaultName).vault.azure.net/secrets/$($secretName)?api-version=2016-10-01"
  # Using the identity of the virtual machine account running the script
  $response = Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -Method GET -Headers @{Metadata="true"}
  # What the vault token is
  $keyVaultToken = $response.access_token
  try{
    # Get the relevant secret and return it
    $secret = Invoke-RestMethod -Uri $keyVaultURI -Method GET -Headers @{Authorization="Bearer $KeyVaultToken"}
    return $secret.Value | ConvertFrom-Json
  }
  # Error handling possible expected errors
  catch{
    if(($Error[0] -match "The remote name could not be resolved")){
      $message = "Error: Attempting to connect to Azure Key vault URI $($keyVaultURI)`n$($_)"
    }
    elseif(($Error[0] -match "Unauthorized")){
      $message = "Error: No authorization to Azure Key Vault  URI $($keyVaultURI)`n$($_)"
    }
    elseif(($Error[0] -match "SecretNotFound")){
      $message = "Error: The secret $($secretName) is not found in Azure Key Vault  URI $($keyVaultURI)`n$($_)"
    }
    else{
      $message = "Error: Unknown error connection to Azure Key vault URI $($keyVaultURI)`n$($_)"
    }
    Write-EventLog -LogName "Application" -Source "PowerShell Universal Scripts" -EntryType "Warning" -EventId 1001 -Message $message
    return $message
  }
}
#EndRegion '.\Public\Get-KeyVaultSecret.ps1' 48
#Region '.\Public\Get-PublicKeyBytesEncodedString.ps1' 0
<#
  .SYNOPSIS
      Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
  
  .DESCRIPTION
      Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
      The certificate used must be available in the LocalMachine\My certificate store.

  .PARAMETER Thumbprint
      Specify the thumbprint of the certificate.
  
  .NOTES
      Author:      Nickolaj Andersen / Thomas Kurth
      Contact:     @NickolajA
      Created:     2021-06-07
      Updated:     2023-05-10
  
      Version history:
      1.0.0 - (2021-06-07) Function created
      1.0.1 - (2023-05-10) Max - Updated to use X509 for the full public key with extended properties in the PEM format

      Credits to Thomas Kurth for sharing his original C# code.
  #>
function Get-PublicKeyBytesEncodedString {
  [CmdletBinding()]
  param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
    [ValidateNotNullOrEmpty()]
    [string]$Thumbprint
  )
  Process {
    # Determine the certificate based on thumbprint input
    $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $Thumbprint }
    if ($Certificate -ne $null) {
      # Bring the cert into a X509 object
      $X509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($Certificate)
      #Set the type of export to perform
      $type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
      #Export the public cert
      $PublicKeyBytes = $X509.Export($type, "")

      # Handle return value - convert to Base64
      return [System.Convert]::ToBase64String($PublicKeyBytes)
    }
  }
}
#EndRegion '.\Public\Get-PublicKeyBytesEncodedString.ps1' 47
#Region '.\Public\Get-ScriptVariables.ps1' 0
function Get-ScriptVariables{
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true,ParameterSetName = 'JSON')][ValidateNotNullOrEmpty()][String]$JSON,
    [Parameter(Mandatory = $true,ParameterSetName = 'URI')][ValidateNotNullOrEmpty()][String]$URI,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$Environment,
    [Parameter()][ValidateNotNullOrEmpty()][String]$Script
  )
  # If path to JSON file is selected
  if($JSON){
    $vars = Get-Content -Path $JSON | ConvertFrom-JSON -Depth 10
  }
  # If a URI to a JSON is provided
  else{
    $vars = (Invoke-WebRequest -Uri $URI -Method "GET" -UseBasicParsing).Content | ConvertFrom-JSON -Depth 10
  }
  foreach ($var in $vars.PSObject.Properties) {
    if($var.Name -eq "Environment"){
      foreach($item in $var.Value.PSObject.Properties){
        if($item.Name -eq $Environment){
          foreach($obj in $item.Value.PSObject.Properties){
            Set-Variable -Name $obj.Name -Value $obj.Value -Scope Global
          }
          break
        }
      }
    }
    elseif($var.Name -eq "ScriptSpecific"){
      foreach($item in $var.Value.PSObject.Properties){
        if($item.Name -eq $Script){
          foreach($obj in $item.Value.PSObject.Properties){
            Set-Variable -Name $obj.Name -Value $obj.Value -Scope Global
          }
          break
        }
      }
    }
    else{
      Set-Variable -Name $var.Name -Value $var.Value -Scope Global
    }
  }
}
#EndRegion '.\Public\Get-ScriptVariables.ps1' 43
#Region '.\Public\Get-Shortcut.ps1' 0
function Get-Shortcut{
  [CmdletBinding()]
  param(
    [parameter()][ValidateNotNullOrEmpty()][string]$Name,
    [parameter()][string]$UserName = $null,
    [parameter()][string]$OneDriveOrgName = $null,
    [parameter()][switch]$StartMenu,
    [parameter()][string]$folder    
  )
  # Get a list of all the user profiles on the machine
  $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20") }
  $UserList = foreach ($UserKey in $ProfileList) {
    @{
      ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
      UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
      SID         = $UserKey.PSChildName
      ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
    }
  }
  # Determine if we should be using paths from the user's profile or the public profile
  if($null -ne $Username -and $UserName -ne ""){
    $baseprofile = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).ProfilePath
    if(-not $baseprofile){
      throw "Unable to find profile for username: $($UserName)"
    }
    $desktopPath = Join-Path -Path $baseprofile -ChildPath "Desktop\$($folder)"
    $onedrivePath = Join-Path -Path $baseprofile -ChildPath "OneDrive - $($OneDriveOrgName)\Desktop\$($folder)"
    if($null -ne $OneDriveOrgName -and (Test-Path $onedrivePath)){
      $desktopPath = $onedrivePath
    }
    $startMenuPath = Join-Path -Path $baseprofile -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($folder)"
  }
  else{
    $desktopPath = Join-Path -Path $ENV:PUBLIC -ChildPath "Desktop\$($folder)"
    $startMenuPath = Join-Path -path $ENV:ALLUSERSPROFILE -ChildPath "Microsoft\Windows\Start Menu\Programs\$($folder)"
  }
  # Set the path based on if we are doing start menu or desktop
  if($startMenu.IsPresent){
    $path = $startMenuPath
  }
  else{
    $path = $desktopPath
  }
  $shortcut = Join-Path -Path $path -ChildPath "$($Name).lnk"
  if(Test-Path $shortcut){
    $obj = New-Object -ComObject WScript.Shell
    $link = $obj.CreateShortcut($shortcut)
    return $link
  }
  else{
    throw "Shortcut not found: $($shortcut)"
  }
}
#EndRegion '.\Public\Get-Shortcut.ps1' 54
#Region '.\Public\Get-Values.ps1' 0
<#
  .DESCRIPTION
  This cmdlet is designed to help PSU scripts for display of values
  .PARAMETER fields
  What fields to display
#>
function Get-Values(){
  param(
    [Parameter(Mandatory)][string[]]$fields,
    [Parameter(Mandatory)][PSCustomObject]$item
  )  
  $value = ""
  # Loop through the array to take not of what values were selected, and then return that value.
  foreach($i in $fields){
    if($item.$i){
      if($i.Contains('-1')){$value += $i.Substring(0,$i.Length-2) + ","}
      else{$value += $i + ","}
    }
  }
  return $value.Replace("-"," ")
}
#EndRegion '.\Public\Get-Values.ps1' 22
#Region '.\Public\Get-YesNo.ps1' 0
<#
  .DESCRIPTION
  This cmdlet is designed to help PSU scripts for display of yes/no
  .PARAMETER fields
  What fields to display
#>
function Get-YesNo(){
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory = $true)][string[]]$fields,
    [Parameter(Mandatory)][PSCustomObject]$item
  )
  # Loop through values that are passed, and if exist, return yes, otherwise return No
  foreach($i in $fields){
    if($item.$i){return "Yes"}
  }
  return "No"
}  
#EndRegion '.\Public\Get-YesNo.ps1' 20
#Region '.\Public\New-EntraIDDeviceTrustBody.ps1' 0
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
#EndRegion '.\Public\New-EntraIDDeviceTrustBody.ps1' 43
#Region '.\Public\New-EventSource.ps1' 0
function New-EventSource {
  [CmdLetBinding()]
  param(
    [Parameter()][string]$EventLog = "Application",
    [Parameter()][string]$Source
  )
  # Get Current List of Event Logs and their sources
  $logsources = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_NTEventLOgFile" | Select-Object FileName, Sources | ForEach-Object -Begin { $hash = @{}} -Process { $hash[$_.FileName] = $_.Sources } -end { $Hash }
  # Create Event Log if does not exist.
  if(-not $logsources.ContainsKey($EventLog)){
    try{
      New-EventLog -source $EventLog -LogName $EventLog -ErrorAction Stop
      $logsources = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_NTEventLOgFile" | Select-Object FileName, Sources | ForEach-Object -Begin { $hash = @{}} -Process { $hash[$_.FileName] = $_.Sources } -end { $Hash }
    }
    catch{
      throw 'Event log {0} does not exists, error creating.' -f $EventLog
    }    
  }
  # Check to see if source exists in the specific event log
  if(-not $logsources.$($EventLog).contains($source)){
    $sourceexists = $logsources.values.contains($Source).contains($true)
    if($sourceexists){
      throw "Source already exists in another event log, please choose a different source name"
    }
    else{
      try{
        New-EventLog -source $Source -LogName $EventLog -ErrorAction Stop
      }
      catch{
        'Source {0} for event log {1} can not be created' -f $Source, $EventLog | Write-Warning
        return $EventLog
      }
    }
  }
  else{
    'Source {0} for event log {1} already exists' -f $Source, $EventLog | Write-Verbose
  }
  return $Source
}
#EndRegion '.\Public\New-EventSource.ps1' 40
#Region '.\Public\New-RandomString.ps1' 0
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
#EndRegion '.\Public\New-RandomString.ps1' 24
#Region '.\Public\New-RSACertificateSignature.ps1' 0
<#
  .SYNOPSIS
      Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
  
  .DESCRIPTION
      Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
      The certificate used must be available in the LocalMachine\My certificate store, and must also contain a private key.

  .PARAMETER Content
      Specify the content string to be signed.

  .PARAMETER Thumbprint
      Specify the thumbprint of the certificate.
  
  .NOTES
      Author:      Nickolaj Andersen / Thomas Kurth
      Contact:     @NickolajA
      Created:     2021-06-03
      Updated:     2021-06-03
  
      Version history:
      1.0.0 - (2021-06-03) Function created

      Credits to Thomas Kurth for sharing his original C# code.
  #>
function New-RSACertificateSignature {
  param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the content string to be signed.")]
    [ValidateNotNullOrEmpty()]
    [string]$Content,

    [parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
    [ValidateNotNullOrEmpty()]
    [string]$Thumbprint
  )
  Process {
    # Determine the certificate based on thumbprint input
    $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $CertificateThumbprint }
    if ($Certificate -ne $null) {
      if ($Certificate.HasPrivateKey -eq $true) {
        # Read the RSA private key
        $RSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if ($RSAPrivateKey -ne $null) {
          if ($RSAPrivateKey -is [System.Security.Cryptography.RSACng]) {
            # Construct a new SHA256Managed object to be used when computing the hash
            $SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"
            # Construct new UTF8 unicode encoding object
            $UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8
            # Convert content to byte array
            [byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)
            # Compute the hash
            [byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)
            # Create signed signature with computed hash
            [byte[]]$SignatureSigned = $RSAPrivateKey.SignHash($ComputedHash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            # Convert signature to Base64 string
            $SignatureString = [System.Convert]::ToBase64String($SignatureSigned)
            # Handle return value
            return $SignatureString
          }
        }
      }
    }
  }
}
#EndRegion '.\Public\New-RSACertificateSignature.ps1' 65
#Region '.\Public\New-Shortcut.ps1' 0
<#
  .DESCRIPTION 
  This is designed to create a shortcut on the desktop. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function New-Shortcut {
  [CmdletBinding()]
  param(
    [parameter()][ValidateNotNullOrEmpty()][string]$Name,
    [parameter()][ValidateNotNullOrEmpty()][string]$CommandLine,
    [parameter()][ValidateNotNullOrEmpty()][string]$Arguments,
    [parameter()][string]$UserName = $null,
    [parameter()][string]$OneDriveOrgName = $null,
    [parameter()][switch]$StartMenu,
    [parameter()][string]$folder
  )
  # Get a list of all the user profiles on the machine
  $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20") }
  $UserList = foreach ($UserKey in $ProfileList) {
    @{
      ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
      UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
      SID         = $UserKey.PSChildName
      ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
    }
  }
  # Determine if we should be using paths from the user's profile or the public profile
  if($null -ne $Username -and $UserName -ne ""){
    $baseprofile = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).ProfilePath
    if(-not $baseprofile){
      throw "Unable to find profile for username: $($UserName)"
    }
    $desktopPath = Join-Path -Path $baseprofile -ChildPath "Desktop\$($folder)"
    $onedrivePath = Join-Path -Path $baseprofile -ChildPath "OneDrive - $($OneDriveOrgName)\Desktop\$($folder)"
    if($null -ne $OneDriveOrgName -and (Test-Path $onedrivePath)){
      $desktopPath = $onedrivePath
    }
    $startMenuPath = Join-Path -Path $baseprofile -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($folder)"
  }
  else{
    $desktopPath = Join-Path -Path $ENV:PUBLIC -ChildPath "Desktop\$($folder)"
    $startMenuPath = Join-Path -path $ENV:ALLUSERSPROFILE -ChildPath "Microsoft\Windows\Start Menu\Programs\$($folder)"
  }
  # Set the path based on if we are doing start menu or desktop
  if($startMenu.IsPresent){
    $path = $startMenuPath
  }
  else{
    $path = $desktopPath
  }  
  try{
    # Create folder if it does not exist, and is set to need one
    if($folder -and -not (Test-Path -Path $path)){
      New-Item -Path $path -ItemType Directory | Out-Null
    }
    $path = Join-Path -Path $path -ChildPath "$($Name).lnk"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($Path)
    $Shortcut.TargetPath = $CommandLine
    $Shortcut.Arguments = $Arguments
    Write-host "Shortcut-Path = $Path"
    $Shortcut.Save()
  }
  catch {
    throw $_
  }  
}
#EndRegion '.\Public\New-Shortcut.ps1' 67
#Region '.\Public\Remove-AutorunRegKeys.ps1' 0
<#
  .DESCRIPTION 
  This is designed to remove autorun keys for the machine. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Remove-AutorunRegKeys {
  [cmdletbinding()]
  param (
    [parameter(Mandatory = $true)][string]$Name,
    [parameter()][string]$UserName = $null,
    [parameter()][switch]$runOnce,
    [parameter()][switch]$wildcard
  )
  $forceload = $false
  # Get a list of all the user profiles on the machine
  $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20") }
  $UserList = foreach ($UserKey in $ProfileList) {
    @{
      ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
      UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
      SID         = $UserKey.PSChildName
      ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
    }
  } 
  if($null -ne $Username -and $UserName -ne ""){
    $SID = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).SID
    $baseprofile = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).ProfilePath
    if($runOnce.IsPresent){
      $registryPath = "REGISTRY::HKEY_USERS\$($SID)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    else{
      $registryPath = "REGISTRY::HKEY_USERS\$($SID)\Software\Microsoft\Windows\CurrentVersion\Run"
    }
    if(-not (Test-Path -Path $registryPath)){
      $hivepath = Join-Path -Path $baseprofile -ChildPath "NTUSER.DAT"
      reg Load "HKU\$($SID)" "$($hivepath)" | Out-Null
      $forceload = $true
      if(-not (Test-Path -Path  $registryPath)){
        throw "Unable to load hive for user: $($UserName)"
      }
    }
  }
  else{
    if($runOnce.IsPresent){
      $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    else{
      $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
    }    
  }
  if($wildcard.IsPresent){
    $Keys = (Get-ItemProperty -Path $registryPath).psobject.properties | Where-Object { $_.Name -like "$($Name)*" }
  }
  else{
    $Keys = (Get-ItemProperty -Path $registryPath).psobject.properties | Where-Object { $_.Name -eq $Name }
  }
  try{
    foreach ($entry in $Keys) {
      Write-Host "Removing existing items $($entry.Name)"
      Remove-ItemProperty -Path $registryPath -Name $Entry.Name
    }
    if($forceload){
      [gc]::Collect()
      reg unload "HKU\$($SID)" | Out-Null    
    }    
  }
  catch{
    throw $_
  }
}
#EndRegion '.\Public\Remove-AutorunRegKeys.ps1' 70
#Region '.\Public\Remove-Shortcut.ps1' 0
function Remove-Shortcut {
  [CmdletBinding()]
  param(
    [parameter(Mandatory = $true)][string]$Name,
    [parameter()][string]$UserName = $null,
    [parameter()][string]$OneDriveOrgName = $null,
    [parameter()][switch]$StartMenu,
    [parameter()][string]$folder,
    [parameter()][switch]$wildcard
  )
  # Get a list of all the user profiles on the machine
  $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20") }
  $UserList = foreach ($UserKey in $ProfileList) {
    @{
      ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
      UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
      SID         = $UserKey.PSChildName
      ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
    }
  }
  # Determine if we should be using paths from the user's profile or the public profile
  if($null -ne $Username -and $UserName -ne ""){
    $baseprofile = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).ProfilePath
    if(-not $baseprofile){
      throw "Unable to find profile for username: $($UserName)"
    }
    $desktopPath = Join-Path -Path $baseprofile -ChildPath "Desktop\$($folder)"
    $onedrivePath = Join-Path -Path $baseprofile -ChildPath "OneDrive - $($OneDriveOrgName)\Desktop\$($folder)"
    if(Test-Path $onedrivePath){
      $desktopPath = $onedrivePath
    }
    $startMenuPath = Join-Path -Path $baseprofile -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$($folder)"
  }
  else{
    $desktopPath = Join-Path -Path $ENV:PUBLIC -ChildPath "Desktop\$($folder)"
    $startMenuPath = Join-Path -path $ENV:ALLUSERSPROFILE -ChildPath "Microsoft\Windows\Start Menu\Programs\$($folder)"
  }
  # Set the path based on if we are doing start menu or desktop
  if($startMenu.IsPresent){
    $path = $startMenuPath
  }
  else{
    $path = $desktopPath
  }
  if($wildcard.IsPresent){
    Get-ChildItem -Path $path -Filter "$($Name)*.lnk" | Remove-Item -Force -Confirm:$false
  }
  else{
    Get-ChildItem -Path $path -Filter "$($Name).lnk" | Remove-Item -Force -Confirm:$false
  }
}
#EndRegion '.\Public\Remove-Shortcut.ps1' 52
#Region '.\Public\Remove-WindowsAutoLogon.ps1' 0
<#
  .DESCRIPTION 
  This is designed to disable windows autologon functionality. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross and https://github.com/mkht/DSCR_AutoLogon
#>
function Remove-WindowsAutoLogon {
  [cmdletbinding()]
  param ()
  try {
    if (-not (Test-LocalAdmin)) {
      Write-Error ('Administrator privilege is required to execute this command')
      return
    }
    Add-PInvokeType
    Write-Output "Disabling AutoLogon"
    $WinLogonKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path registry::$WinLogonKey -Name "AutoAdminLogon" -Value 0 -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultUserName" -ErrorAction SilentlyContinue
    $private:LsaUtil = New-Object PInvoke.LSAUtil.LSAutil -ArgumentList "DefaultPassword"
    if ($LsaUtil.GetSecret()) {
      $LsaUtil.SetSecret($null) #Clear existing password
    }
    Write-Verbose ('Auto logon has been disabled')
  }
  catch {
    throw $_
  }
}
#EndRegion '.\Public\Remove-WindowsAutoLogon.ps1' 29
#Region '.\Public\Send-TeamsWebhookMessage.ps1' 0
function Send-TeamsWebhookMessage{
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$webhook,
    [Parameter()][ValidateNotNullOrEmpty()][string]$text,
    [Parameter()][ValidateNotNullOrEmpty()][string]$summary,
    [Parameter()][ValidateNotNullOrEmpty()][string]$themeColor,
    [Parameter()][ValidateNotNullOrEmpty()][string]$title,
    [Parameter()][ValidateNotNullOrEmpty()][string]$activitytitle,
    [Parameter()][ValidateNotNullOrEmpty()][string]$activitysubtitle,
    [Parameter()][ValidateNotNullOrEmpty()][string]$activityimageuri,
    [Parameter()][ValidateNotNullOrEmpty()][string]$activitytext,
    [Parameter()][ValidateNotNullOrEmpty()][hashtable]$facts
  )
  $card = @{
    "@type" = "MessageCard"
    "@context" = "https://schema.org/extensions"
  }
  if($summary){
    $card.Add("summary",$summary) | Out-Null
  }
  else{
    $card.Add("text",$text) | Out-Null
  }
  if($themeColor){$card.Add("themeColor",$themeColor) | Out-Null}
  if($title){$card.Add("title",$title) | Out-Null}

  if($activitytitle -or $activitysubtitle -or $activityimageuri -or $activitytext -or $facts){
    $section = @{}
    if($activitytitle){
      $section.Add("activitytitle",$activitytitle) | Out-Null
    }
    if($activitysubtitle){
      $section.Add("activitysubtitle",$activitysubtitle) | Out-Null
    }    
    if($activityimageuri){
      $section.Add("activityImage",$activityimageuri) | Out-Null
    }   
    if($activitytext){
      $section.Add("text",$activitytext) | Out-Null
    }       
    if($facts){
      $messageFacts = [System.Collections.Generic.List[Hashtable]]@()
      foreach($item in $facts.GetEnumerator()){
        $obj = @{
          "name" = $item.key
          "value" = $item.value
        }
        $messageFacts.Add($obj) | Out-Null
      }
      $section.Add("facts",$messageFacts) | Out-Null
    }
    $card.Add("sections",@($section)) | Out-Null
  }
  Invoke-RestMethod -uri $webhook -Method Post -body ($card | ConvertTo-Json -depth 5) -ContentType 'application/json' | Out-Null
}
#EndRegion '.\Public\Send-TeamsWebhookMessage.ps1' 57
#Region '.\Public\Set-AutorunRegKeys.ps1' 0
<#
  .DESCRIPTION 
  This is designed to add autorun keys for the machine. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross
#>
function Set-AutorunRegKeys {
  [cmdletbinding()]
  param(
    [parameter(Mandatory = $true)][string]$Name,
    [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$CommandLine,
    [parameter()][string]$UserName = $null,
    [parameter()][switch]$runOnce
  )
  $forceload = $false
  # Get a list of all the user profiles on the machine
  $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20") }
  $UserList = foreach ($UserKey in $ProfileList) {
    @{
      ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
      UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
      SID         = $UserKey.PSChildName
      ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
    }
  } 
  if($null -ne $Username -and $UserName -ne ""){
    $SID = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).SID
    $baseprofile = ($UserList | Where-Object {$_.UserName -like "*$($UserName)*"}).ProfilePath
    if($runOnce.IsPresent){
      $registryPath = "REGISTRY::HKEY_USERS\$($SID)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    else{
      $registryPath = "REGISTRY::HKEY_USERS\$($SID)\Software\Microsoft\Windows\CurrentVersion\Run"
    }
    if(-not (Test-Path -Path $registryPath)){
      $hivepath = Join-Path -Path $baseprofile -ChildPath "NTUSER.DAT"
      reg Load "HKU\$($SID)" "$($hivepath)" | Out-Null
      $forceload = $true
      if(-not (Test-Path -Path  $registryPath)){
        throw "Unable to load hive for user: $($UserName)"
      }
    }
  }
  else{
    if($runOnce.IsPresent){
      $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    else{
      $registryPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
    }    
  } 
  New-ItemProperty -Path $registryPath -Name $Name -Value $CommandLine
  if($forceload){
    [gc]::Collect()
    reg unload "HKU\$($SID)" | Out-Null    
  }
}
#EndRegion '.\Public\Set-AutorunRegKeys.ps1' 56
#Region '.\Public\Set-WindowsAutoLogon.ps1' 0
<#
  .DESCRIPTION 
  This is designed to enable windows autologon functionality. Originally from https://github.com/AdamGrossTX/ManagedUserManagement/blob/main/ClientScripts/Set-AutoLogon.ps1 by Adam Gross and https://github.com/mkht/DSCR_AutoLogon
#>
function Set-WindowsAutoLogon {
  [cmdletBinding()]
  param(
    [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][PSCredential]$Credential
  )
  try {
    if (-not (Test-LocalAdmin)) {
      Write-Error ('Administrator privilege is required to execute this command')
      return
    }
    Add-PInvokeType
    Write-Output "Enabling Autologon"
    $WinLogonKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path registry::$WinLogonKey -Name "AutoAdminLogon" -Value 1 -Force
    Set-ItemProperty -Path registry::$WinLogonKey -Name "DefaultUserName" -Value $Credential.UserName -Force
    Remove-ItemProperty -Path registry::$WinLogonKey -Name "AutoLogonCount" -ErrorAction SilentlyContinue
    Write-Verbose ('Password will be encrypted')
    Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue
    $private:LsaUtil = New-Object PInvoke.LSAUtil.LSAutil -ArgumentList "DefaultPassword"
    $LsaUtil.SetSecret($Credential.GetNetworkCredential().Password)
    Write-Verbose ('Auto logon has been enabled')
  }
  catch {
    throw $_
  }
}
#EndRegion '.\Public\Set-WindowsAutoLogon.ps1' 31
#Region '.\Public\Test-AllowedGroupMember.ps1' 0
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
#EndRegion '.\Public\Test-AllowedGroupMember.ps1' 96
#Region '.\Public\Test-EntraIDDeviceRegistration.ps1' 0
<#
  .SYNOPSIS
      Determine if the device conforms to the requirement of being either Azure AD joined or Hybrid Azure AD joined.
  
  .DESCRIPTION
      Determine if the device conforms to the requirement of being either Azure AD joined or Hybrid Azure AD joined.
  
  .NOTES
      Author:      Nickolaj Andersen
      Contact:     @NickolajA
      Created:     2022-01-27
      Updated:     2022-01-27
  
      Version history:
      1.0.0 - (2022-01-27) Function created
  #>
function Test-EntraIDDeviceRegistration {
  [CmdletBinding()]
  param()  
  $EntraIDJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
  if (Test-Path -Path $EntraIDJoinInfoRegistryKeyPath) {
    return $true
  }
  else {
    return $false
  }
}
#EndRegion '.\Public\Test-EntraIDDeviceRegistration.ps1' 28
#Region '.\Public\Test-LocalAdmin.ps1' 0
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
#EndRegion '.\Public\Test-LocalAdmin.ps1' 11
#Region '.\Public\Test-SamAccountName.ps1' 0
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
#EndRegion '.\Public\Test-SamAccountName.ps1' 47
#Region '.\Public\Write-WinEvent.ps1' 0
function Write-WinEvent {
  [CmdLetBinding()]
  param(
    [Parameter()][string]$LogName = 'Application',
    [Parameter()][string]$Source = "Application",
    [Parameter()][int64]$EventId = 1000,
    [Parameter()][System.Diagnostics.EventLogEntryType]$EventType = "Information",
    [Parameter()][System.Collections.Specialized.OrderedDictionary]$EventData,
    [Parameter()][ValidateSet('JSON', 'CSV', 'XML')][string]$MessageFormat = 'JSON'
  )
  $Source = New-EventSource -EventLog $LogName -Source $Source
  $EventMessage = @()
  switch ($MessageFormat) {
    'JSON' { $EventMessage += $EventData | ConvertTo-Json }
    'CSV' { $EventMessage += ($EventData.GetEnumerator() | Select-Object -Property Key, Value | ConvertTo-Csv -NoTypeInformation) -join "`n" }
    'XML' { $EventMessage += ($EventData | ConvertTo-Xml).OuterXml }
  }
  $EventMessage += foreach ($Key in $EventData.Keys) {
    '{0}:{1}' -f $Key, $EventData.$Key
  }
  try {
    $Event = [System.Diagnostics.EventInstance]::New($EventId, $null, $EventType)
    $EventLog = [System.Diagnostics.EventLog]::New()
    $EventLog.Log = $LogName
    $EventLog.Source = $Source
    $EventLog.WriteEvent($Event, $EventMessage)
  }
  catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}
#EndRegion '.\Public\Write-WinEvent.ps1' 32
