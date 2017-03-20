# ***********************************************************************
# Core library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCORE.psm1
# * Description:  Script block to create the PISYSAUDIT module.
# *
# * Copyright 2016 OSIsoft, LLC
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# * 
# *   <http://www.apache.org/licenses/LICENSE-2.0>
# * 
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *
# * Modifications copyright (C) <YYYY> <Name>, <Org>
# * <Description of modification>
# *
# ************************************************************************
# Version History:
# ------------------------------------------------------------------------
# Version 1.0.0.8 Initial release on OSIsoft Users Community.
# Authors:  Jim Davidson, Bryan Owen and Mathieu Hamel from OSIsoft.
#
# ************************************************************************

# ........................................................................
# Global Variables
#
#	PISysAuditShowUI
#	ScriptsPath
#	PasswordPath
#	PISysAuditInitialized
#	PISysAuditCachedSecurePWD
#   PISysAuditIsElevated
# ........................................................................

# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

function SetFolders
{
	# Retrieve the folder from which this script is called ..\Scripts and split the path
	# to remove the Scripts part.	
	$modulePath = $PSScriptRoot
	
	# ..\
	# ..\Scripts
	# ..\Scripts\PISYSAUDIT
	# ..\Scripts\Temp
	# ..\Export
	# ..\pwd	
	$scriptsPath = Split-Path $modulePath
	$rootPath = Split-Path $scriptsPath				
	
	$exportPath = PathConcat -ParentPath $rootPath -ChildPath "Export"
	if (!(Test-Path $exportPath)){
	New-Item $exportPath -type directory
	}
	$scriptsPathTemp = PathConcat -ParentPath $scriptsPath -ChildPath "Temp"
	if (!(Test-Path $scriptsPathTemp)){
	New-Item $scriptsPathTemp -type directory
	}

	$pwdPath = PathConcat -ParentPath $rootPath -ChildPath "pwd"		
	$logFile = PathConcat -ParentPath $exportPath -ChildPath "PISystemAudit.log"		

	# Store them at within the global scope range.	
	New-Variable -Name "ScriptsPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $scriptsPath
	New-Variable -Name "ScriptsPathTemp" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $scriptsPathTemp			
	New-Variable -Name "PasswordPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $pwdPath
	if($null -eq (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
	{
		New-Variable -Name "ExportPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $exportPath
	}
	if($null -eq (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
	{
		New-Variable -Name "PISystemAuditLogFile" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $logFile	
	}
}

function NewObfuscateValue
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("v")]
		[string]
		$Value)
		
	$fn = GetFunctionName
	
	try
	{
		# Create a Rijndael symmetric key encryption object.
		$r = New-Object System.Security.Cryptography.RijndaelManaged  
		# Set the key and initialisation vector to 128-bytes each of (1..16).
		$c = $r.CreateEncryptor((1..16), (1..16))    
		# Create so objectes needed for manipulation.
		$ms = New-Object IO.MemoryStream
		# Target data stream, transformation, and mode.
		$cs = New-Object Security.Cryptography.CryptoStream $ms, $c, "Write"
		$sw = New-Object IO.StreamWriter $cs
		
		# Write the string through the crypto stream into the memory stream
		$sw.Write($Value)
		
		# Clean up	
		$sw.Close()
		$cs.Close()
		$ms.Close()
		$r.Clear()
		
		# Convert to byte array from the encrypted memory stream.
		[byte[]]$result = $ms.ToArray()
		# Convert to base64 for transport.
		$encryptedValue = [Convert]::ToBase64String($result)

		# return the encryptedvalue
		return $encryptedValue
	}
	catch
	{
		# Return the error message.
		$msg = "The obfuscation of the value has failed"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}	
}

function WriteHostPartialResult
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[object]
		$AuditItem)
	
	if($AuditItem.AuditItemValue -eq $false)
	{
		$a = $AuditItem # for brevity
		$msg = "{0,-9} {1,-8} {2,-20} {3,40}"
		Write-Host ($msg -f $a.Severity, $a.ID, $a.ServerName, $a.AuditItemName)
	}
}

function CheckIfRunningElevated
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
		
	$fn = GetFunctionName		
	
	try
	{
		if($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage")
		{
			# sfc utility requires admin to run on all supported OSes
			# when run elevated, it will return the list of arguments
			# if not run elevated, it will return a message stating 
			# the user must be admin.
			return ($(sfc /? | Out-String) -like '*/*')
		}
		else
		{
			$windowsPrinciple = new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
			return $windowsPrinciple.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
		}         
	}
	catch
	{
		# Return the error message.
		$msg = "Error encountered when checking if running elevated."						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $false
	}
}

function ValidateFileContent
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("fc")]		
		$FileContent,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("v")]
		[string]
		$Validation)
					
	$fn = GetFunctionName
	
	try
	{
		Foreach($line in $FileContent)
		{						
			if(($line.ToLower() ).Contains($Validation.ToLower() ))
			{ return $true }
		}
		
		# The content was not found.
		return $false						
	}
	catch
	{
		# Return the error message.
		$msg = "The content validation has failed"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}	
}

function ResolveComputerName
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(									
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[alias("rcn")]
		[string]
		$RemoteComputerName)
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{								
		# Return the right server name to use.
		if($LocalComputer)
		{
			# Obtain the machine name from the environment variable.			
			return (get-content env:computername)
		}
		else
		{ 
			if($RemoteComputerName -eq "")
			{
				$msg = "The remote computer name is empty."
				Write-PISysAudit_LogMessage $msg "Error" $fn
				return $null
			}
			else
			{ return $RemoteComputerName }
		}
	}
	catch
	{ return $null }
}
		
function ReturnSQLServerName
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(									
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[string]
		$ServerName,
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[string]
		$InstanceName)
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{						
		# Build the connection string.
		if(($InstanceName.ToLower() -eq "default") `
			-or ($InstanceName.ToLower() -eq "mssqlserver") `
			-or ($SQLServerInstanceName -eq ""))
		{
			# Use the Server name only as the identity of the server.
			return $ServerName						
		}
		else
		{
			# Use the Server\Named Instance as the identity of the server.
			return ($ServerName + "\" + $InstanceName)
		}								
	}
	catch
	{ return $null }
}

function SetSQLAccountPasswordInCache
{	
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(											
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[string]
		$ServerName,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]				
		[string]
		$InstanceName,
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]		
		[string]
		$UserName)
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{
		# Define the password message template
		$msgPasswordTemplate = "Please enter the password for the user {0} for the SQL Server: {1}"	

		# Get the SQL Server name.
		$sqlServerName = ReturnSQLServerName $ServerName $InstanceName
		
		# Get the password via a protected prompt.
		$msgPassword = [string]::Format($msgPasswordTemplate, $UserName, $sqlServerName)
		$securePWD = Read-Host -assecurestring $msgPassword
		
		# Verbose only if Debug Level is 2+
		$msg = "The user was prompted to enter the password for SQL connection"					
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
		
		# Cache the secure password for next usage.
		if($null -eq (Get-Variable "PISysAuditCachedSecurePWD" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
		{
			New-Variable -Name "PISysAuditCachedSecurePWD" -Scope "Global" -Visibility "Public" -Value $securePWD	
		}
		else
		{
			Set-Variable -Name "PISysAuditCachedSecurePWD" -Scope "Global" -Visibility "Public" -Value $securePWD
		}		
	}
	catch
	{
		# Return the error message.
		$msg = "Set the SQL Account passwor into cache failed"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}				

function SetConnectionString
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(									
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,								
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]	
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)			
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{				
		# Define the requested server name.
		$computerName = ResolveComputerName $LocalComputer $RemoteComputerName		
		
		# Define the complete SQL Server name (Server + instance name).
		$sqlServerName = ReturnSQLServerName $computerName $InstanceName			
										
		# SQL Server uses named instance.
		# If you use the integrated security to connect to your PI AF Storage Server use this connection string template.
		$connectionStringTemplate1="Server={0};Database=master;Integrated Security=SSPI;"				
		# If you use the sa account to connect to your PI AF Storage Server use this connection string template.		
		$connectionStringTemplate2="Server={0};Database=master;User ID={1};Password={2};"
				
		# Define the connection string.
		if($IntegratedSecurity)
		{ $connectionString = [string]::format($connectionStringTemplate1, $sqlServerName) }
		else
		{			
			if($PasswordFile -eq "")
			{								
				# Read from the global constant bag.
				# Read the secure password from the cache								 
				$securePWDFromCache = (Get-Variable "PISysAuditCachedSecurePWD" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
				if(($null -eq $securePWDFromCache) -or ($securePWDFromCache -eq ""))
				{ 
					# Return the error message.
					$msg = "The password is not stored in cache"					
					Write-PISysAudit_LogMessage $msg "Error" $fn
					return $null
				}
				else
				{ 																				
					# Verbose only if Debug Level is 2+
					$msg = "The password stored in cached will be used for SQL connection"					
					Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2										
					
					# The CLU does not understand secure string and needs to get the raw password
					# Use the pointer method to reach the value in memory.
					$pwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePWDFromCache))
				}												
			}
			else
			{ $pwd = GetPasswordOnDisk $PasswordFile }							
			$connectionString = [string]::format($connectionStringTemplate2, $SQLServerName, $UserName, $pwd)
		}						
	
		# Return the connection string.
		return $connectionString
				
	}
	catch
	{ 
		# Return the error message.
		$msg = "Setting the connection string has failed"		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

function ExecuteCommandLineUtility
# Run a command line utility on the local or remote computer,
# directing the output to a file. Read from the file, delete the
# file, then delete the file and return the output.
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(									
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("exec")]
		[string]
		$UtilityExec,		
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("output")]
		[string]
		$OutputFilePath,	
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("args")]
		[string]
		$ArgList,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)			
		
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{	
			$scriptBlock = { 
				param([string]$UtilityExecutable, [string]$ArgumentList, [string]$FilePath) 
					if(Test-Path $FilePath) { Remove-Item $FilePath }
					Start-Process -FilePath $UtilityExecutable -ArgumentList $ArgumentList -RedirectStandardOutput $FilePath -Wait -NoNewWindow
					$FileContent = Get-Content -Path $FilePath
					if(Test-Path $FilePath) { Remove-Item $FilePath }
					return $FileContent
				}
			# Verbose only if Debug Level is 2+
			$msgTemplate = "Command: {0}; Target: {1}"
			$msg = [string]::Format($msgTemplate, $scriptBlock.ToString(), $RemoteComputerName)
			Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2	

			if($LocalComputer)
			{
				$outputFileContent = & $scriptBlock -UtilityExecutable $UtilityExec -ArgumentList $ArgList -FilePath $OutputFilePath
			}
			else
			{
				$outputFileContent = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $UtilityExec, $ArgList, $OutputFilePath
			}
			return $outputFileContent
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred with {0} on local computer"
		$msgTemplate2 = "A problem occurred with {0} on {1} computer"
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $UtilityExec) }
		else
		{ $msg = [string]::Format($msgTemplate2, $UtilityExec, $RemoteComputerName) }		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

function GetPasswordOnDisk
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[string]
		$File)
		
	$fn = GetFunctionName
	
	try
	{
		# Read from the global constant bag.
		$pwdPath = (Get-Variable "PasswordPath" -Scope "Global").Value			
		# Set the path.
		$pwdFile = PathConcat -ParentPath $pwdPath -ChildPath $File
		
		# Decrypt.
		
		# If you want to use Windows Data Protection API (DPAPI) to encrypt the standard string representation
		# leave the key undefined. Visit this URL: http://msdn.microsoft.com/en-us/library/ms995355.aspx to know more.
		# This salt key had been generated with the Set-PISysAudit_SaltKey cmdlet.
		# $mySaltKey = "Fnzg+mrVxXEEmfEMzFwiag=="
		# $keyInBytes = [System.Convert]::FromBase64String($mySaltKey)
		# $securePWD = Get-Content -Path $pwdFile | ConvertTo-SecureString -key $keyInBytes				
		$securePWD = Get-Content -Path $pwdFile | ConvertTo-SecureString -key (1..16)			
		
		# Return the password.
		return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePWD))					
	}
	catch
	{
		# Return the error message.
		$msg = "Decrypting the password has failed"
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

function ValidateIfHasPIDataArchiveRole
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		

	$fn = GetFunctionName
	
	try
	{
		# Get the PISERVER variable.
		if($LocalComputer)
		{ $PIServer_path = Get-PISysAudit_EnvVariable "PISERVER" }
		else
		{ $PIServer_path = Get-PISysAudit_EnvVariable "PISERVER" -lc $false -rcn $RemoteComputerName }
		
		# Validate...
		if($null -eq $PIServer_path) { return $false }
		return $true
	}
	catch
	{ return $false }
}

function ValidateIfHasPIAFServerRole
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		

	$fn = GetFunctionName
	
	try
	{
		$className = "Win32_Service"
		$namespace = "root\CIMV2"
		$filterExpression = [string]::Format("name='{0}'", "AFService")
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel								
		if($null -eq $WMIObject) { return $false}
		return $true
	}
	catch
	{ return $false }
}

function ValidateIfHasSQLServerRole
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		

	$fn = GetFunctionName
	
	try
	{
		$className = "Win32_Service"
		$namespace = "root\CIMV2"
		if(($InstanceName -eq "") -or ($InstanceName.ToLower() -eq "default") -or ($InstanceName.ToLower() -eq "mssqlserver"))
		{ $filterExpression = [string]::Format("name='{0}'", "MSSQLSERVER") }
		else
		{
			# Don't forget the escape character so that the '$' is not interpreted as a variable
			$value = ("MSSQL`$" + $InstanceName).ToUpper()
			$filterExpression = [string]::Format("name='{0}'", $value)			
		}
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel								
		if($null -eq $WMIObject) { return $false}
		return $true
	}
	catch
	{ return $false }
}

function ValidateIfHasPICoresightRole
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		

	$fn = GetFunctionName
	
	try
	{
		$result = $false
		$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
		$result = Get-PISysAudit_TestRegistryKey -lc $LocalComputer -rcn $RemoteComputerName -rkp $RegKeyPath -DBGLevel $DBGLevel						
		return $result
	}
	catch
	{ return $false }
}

function ExecuteWMIQuery
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("wcn")]
		[string]
		$WMIClassName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("n")]
		[string]
		$Namespace = "root\CIMV2",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("f")]
		[string]
		$FilterExpression = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
		
	$fn = GetFunctionName
	
	try
	{
		$scriptBlock = {
				param([string]$Namespace, [string]$WMIClassName, [parameter(Mandatory=$false)][string]$FilterExpression="") 
				if($FilterExpression -eq "")
				{ Get-WMIObject -Namespace $Namespace -Class $WMIClassName }
				else 
				{ Get-WMIObject -Namespace $Namespace -Class $WMIClassName -Filter $FilterExpression }
		}	

		# Verbose only if Debug Level is 2+
		$msgTemplate = "Local command to send is: {0}"
		$msg = [string]::Format($msgTemplate, $scriptBlock.ToString())
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2	
		
		if($LocalComputer)
		{		
			$WMIObject = & $scriptBlock -Namespace $Namespace -WMIClassName $WMIClassName -FilterExpression $FilterExpression															
		}
		else
		{												
			$WMIObject = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock	-ArgumentList $Namespace, $WMIClassName, $FilterExpression						
		}
		return $WMIObject
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "Query the WMI classes from local computer has failed"
		$msgTemplate2 = "Query the WMI classes from {0} has failed"
		if($LocalComputer)
		{ $msg = $msgTemplate1 }
		else
		{ $msg = [string]::Format($msgTemplate2, $RemoteComputerName) }		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

function ValidateWSMan
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
					
	$fn = GetFunctionName
	
	try
	{
		# Only need the 'Computer' role
		$ComputerParams = $ComputerParams.Value | Where-Object AuditRoleType -EQ "Computer"
			
		# Test non-local computer to validate if WSMan is working.
		if($ComputerParams.IsLocal)
		{
			$result = $true
			$msgTemplate = "The server: {0} does not need WinRM communication because it will use a local connection"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1					
		}
		else
		{								
			$result = Test-WSMan -authentication default -ComputerName $ComputerParams.ComputerName -ErrorAction SilentlyContinue
			if($null -eq $result)
			{
				$msgTemplate = "The server: {0} has a problem with WinRM communication"
				$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Error" $fn
				New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
									-at $AuditTable -an 'Computer' -fn $fn -msg $msg
			}
		}
		
		if($result) { return $true }
		else { return $false }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem has occurred during the validation with WSMan"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an 'Computer' -fn $fn -msg $msg
		# Validation has failed.
		return $false
	}	
}

function Test-PISysAudit_PrincipalOrGroupType
{
<#
.SYNOPSIS
(Core functionality) Checks a specified characteristic of a Principal or Group.
.DESCRIPTION
Checks a specified Principal or Group Type based on the SID.  
Return values include LowPrivileged, Administrator, Machine or Custom
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[string]
		$SID,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		

BEGIN {}
PROCESS 
{	

	$fn = GetFunctionName
	$type = 'Custom'

	# Enumerate test arrays https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	$WellKnownSIDs = @{
								'S-1-1-0'='LowPrivileged';       # Everyone
								'S-1-5-7'='LowPrivileged';       # Anonymous
								'S-1-5-11'='LowPrivileged';      # Authenticated Users
								'S-1-5-18'='Machine';            # Local System
								'S-1-5-19'='Machine';            # Local Service
								'S-1-5-20'='Machine';            # Network Service
								'S-1-5-32-544'='Administrator';  # Administrators						
								'S-1-5-32-545'='LowPrivileged';  # Users
								'S-1-5-32-546'='LowPrivileged';  # Guests
								'S-1-5-32-555'='LowPrivileged';  # Remote Desktop Users
								'S-1-5-21*-500'='Administrator'; # Administrator
								'S-1-5-21*-501'='LowPrivileged'; # Guest
								'S-1-5-21*-512'='Administrator'; # Domain Admins
								'S-1-5-21*-513'='LowPrivileged'; # Domain Users
								'S-1-5-21*-514'='LowPrivileged'; # Domain Guests
								'S-1-5-21*-515'='Machine';       # Domain Computers
								'S-1-5-21*-519'='Administrator'; # Enterprise Admins
							}
	try
	{	
		$type = $WellKnownSIDs.GetEnumerator() | Where-Object {$SID -like $_.Name} | Select-Object -ExpandProperty Value
		return $type
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred checking the condition {0} on account {1}. Error:{2}"
		$msg = [string]::Format($msgTemplate, $Condition, $AccountSID, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Test-WebAdministrationModuleAvailable
{
<#
.SYNOPSIS
(Core functionality) Checks for the WebAdministration module.
.DESCRIPTION
Validate that IIS module can be loaded and configuration data can be accessed.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{			
	$fn = GetFunctionName
	$value = $false
	try
	{
		# Sometimes the module is imported and the IIS drive is inaccessible
		$scriptBlock = {
				Import-Module -Name "WebAdministration"	
				$value = Test-Path IIS:\
				return $value
			}

		if($LocalComputer)		
		{ $value = & $scriptBlock }
		else
		{ $value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock }

		return $value		
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred checking for IIS scripting tools: {0} from local machine."
		$msgTemplate2 = "A problem occurred checking for IIS scripting tools: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message, $RemoteComputerName) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Test-PowerShellToolsForPISystemAvailable
{
    # Check for availability of PowerShell Tools for the PI System
    if( -not(Test-Path variable:global:ArePowerShellToolsAvailable) -and $PSVersionTable.PSVersion.Major -ge 3)
	{
		if(Get-Module -ListAvailable -Name OSIsoft.PowerShell)
		{
			Import-Module -Name OSIsoft.PowerShell
			$global:ArePowerShellToolsAvailable = $true
		}
		else
		{
			$global:ArePowerShellToolsAvailable = $false
		}
	}
}

function StartComputerAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]
		$ComputerParams,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[int]
		$AuditLevelInt = 1,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)	
					
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{		
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary1 -lvl $AuditLevelInt
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No machine checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}																						
				
		# Set message templates.
		$activityMsgTemplate1 = "Check computer '{0}'..."
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}: {2}"
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0}, arguments: {1}, {2}, {3}, {4}"
				
		# Process.
		$i = 0	
		
		# Set activity message.			
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)								

		# Proceed with all the compliance checks.
		foreach($function in $listOfFunctions.GetEnumerator())
		{																									
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++
				$auditItem = (Get-Help $function.Name).Synopsis
				$ActivityMsg1 = [string]::Format($activityMsgTemplate1, $computerParams.ComputerName)
				$StatusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString(), $auditItem)
				$pctComplete = ($i-1) / $listOfFunctions.Count * 100
				Write-Progress -activity $ActivityMsg1 -Status $StatusMsg -ParentId 1 -PercentComplete $pctComplete
			}
			
			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................						
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, `
										$computerParams.IsLocal, $computerParams.ComputerName, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $computerParams.IsLocal -rcn $computerParams.ComputerName -dbgl $DBGLevel						
		}			
		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -ParentId 1 -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of computer checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}			
}	

function StartPIDataArchiveAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[int]
		$AuditLevelInt = 1,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)	
					
	# Get and store the function Name.
	$fn = GetFunctionName
	$global:PIDataArchiveConnection = $null

	try
	{
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value						

		# Validate the presence of a PI Data Archive
		if((ValidateIfHasPIDataArchiveRole -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel) -eq $false)
		{
			# Return the error message.
			$msgTemplate = "The computer {0} does not have a PI Data Archive role or the validation failed"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}

		# Check for availability of PowerShell Tools for the PI System
		Test-PowerShellToolsForPISystemAvailable

		if($global:ArePowerShellToolsAvailable)
		{
			try
			{
				$global:PIDataArchiveConnection = Connect-PIDataArchive -PIDataArchiveMachineName $ComputerParams.ComputerName
				if($global:PIDataArchiveConnection.Connected){
					$msgTemplate = "Successfully connected to the PI Data Archive {0} with PowerShell."
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
				}
				else
				{
					$portOpen = $true
					if($PSVersionTable.PSVersion.Major -ge 4){
						$portOpen = $(Test-NetConnection -ComputerName $ComputerParams.ComputerName -Port 5450 -InformationLevel Quiet -WarningAction SilentlyContinue)
					}
					elseif($PSVersionTable.PSVersion.Major -lt 4 -and $ExecutionContext.SessionState.LanguageMode -ne 'ConstrainedLanguage'){
						try
						{
							$testPort = new-object net.sockets.tcpclient
							$testPort.Connect($ComputerParams.ComputerName, 5450)
						}
						catch { $portOpen = $false }
					}
					if($portOpen -eq $false)
					{ $msgTemplate = "The PI Data Archive {0} is not accessible over port 5450" }
					else
					{ $msgTemplate = "Unable to access the PI Data Archive {0} with PowerShell.  Check if there is a valid mapping for your user. Terminating PI Data Archive audit" }
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Error" $fn
					$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI Data Archive Audit" -fn $fn -msg $msg
					return
				}
			}
			catch
			{
				# Return the error message.
				$msgTemplate = "An error occurred connecting to the PI Data Archive {0} with PowerShell. Terminating PI Data Archive audit"
				$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
				$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI Data Archive Audit" -fn $fn -msg $msg
				return
			}
		}
		else
		{
			$msg = "Unable to locate module OSIsoft.Powershell on the computer running this script. Terminating PI Data Archive audit"
			Write-PISysAudit_LogMessage $msg "Error" $fn
			$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI Data Archive Audit" -fn $fn -msg $msg
			return
		}
		
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary2 -lvl $AuditLevelInt
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No PI Data Archive checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}			
									
		# Set message templates.		
		$activityMsgTemplate1 = "Check PI Data Archive component on '{0}' computer"
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}: {2}"
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0}, arguments: {1}, {2}, {3}, {4}"
															
		# Proceed with all the compliance checks.
		$i = 0
		foreach($function in $listOfFunctions.GetEnumerator())
		{		
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++
				$auditItem = (Get-Help $function.Name).Synopsis
				$statusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString(), $auditItem)
				$pctComplete = ($i-1) / $listOfFunctions.Count * 100
				Write-Progress -activity $activityMsg1 -Status $statusMsg -ParentId 1 -PercentComplete $pctComplete
			}
			
			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................				
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, `
										$ComputerParams.IsLocal, $ComputerParams.ComputerName, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel																																							
		}

		# Disconnect if PowerShell Tools are used.
		if($global:PIDataArchiveConnection.Connected){$global:PIDataArchiveConnection.Disconnect()}

		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -ParentId 1 -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of PI Data Archive checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}			
}

function PathConcat {
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("pp")]
		[string]
		$ParentPath,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("cp")]
		[string]
		$ChildPath,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
		
	# Get and store the function Name.
	$fn = GetFunctionName

		try {
		$FullPath = ($ParentPath.TrimEnd('\', '/') + '\' + $ChildPath.TrimStart('\', '/'))
		return $FullPath
		}
		catch {
		# Return the error message.
		$msgTemplate = "An error occurred building file path {0} with PowerShell."
		$msg = [string]::Format($msgTemplate, $FullPath)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return
		}
}

function StartPIAFServerAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[int]
		$AuditLevelInt = 1,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)	
					
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value
		$IsElevated = (Get-Variable "PISysAuditIsElevated" -Scope "Global" -ErrorAction "SilentlyContinue").Value				
		
		# Validate the presence of a PI AF Server
		if((ValidateIfHasPIAFServerRole -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel) -eq $false)
		{
			# Return the error message.
			$msgTemplate = "The computer {0} does not have a PI AF Server role or the validation failed"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI AF Server Audit" -fn $fn -msg $msg
			return
		}
		
		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary3 -lvl $AuditLevelInt
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No PI AF Server checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}						
		
		# Check for availability of PowerShell Tools for the PI System
		Test-PowerShellToolsForPISystemAvailable

		if($global:ArePowerShellToolsAvailable)
		{
			try
			{
				$global:AFServerConnection = Connect-AFServer -AFServer $(Get-AFServer -Name $ComputerParams.ComputerName)
				if($global:AFServerConnection.ConnectionInfo.IsConnected)
				{
					$msgTemplate = "Successfully connected to the PI AF Server {0} with PowerShell."
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
				}
				else
				{
					$msgTemplate = "Unable to access the PI AF Server {0} with PowerShell.  Check if there is a valid mapping for your user."
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Warning" $fn
					$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI AF Server Audit" -fn $fn -msg $msg
					return
				}
			}
			catch
			{
				# Return the error message.
				$msgTemplate = "An error occurred connecting to the PI AF Server {0} with PowerShell."
				$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
				$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI AF Server Audit" -fn $fn -msg $msg
				return
			}
		}

		# Set message templates.		
		$activityMsgTemplate1 = "Check PI AF Server component on '{0}' computer"
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}: {2}"
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0}, arguments: {1}, {2}, {3}, {4}"
				
		# Prepare data required for multiple compliance checks

		$global:AFDiagOutput = Invoke-PISysAudit_AFDiagCommand -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel
										
		# Proceed with all the compliance checks.
		$i = 0
		foreach($function in $listOfFunctions.GetEnumerator())
		{									
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++
				$auditItem = (Get-Help $function.Name).Synopsis
				$statusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString(), $auditItem)
				$pctComplete = ($i-1) / $listOfFunctions.Count * 100
				Write-Progress -activity $activityMsg1 -Status $statusMsg -ParentId 1 -PercentComplete $pctComplete	
			}
			
			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................				
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, `
										$ComputerParams.IsLocal, $ComputerParams.ComputerName, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel
		}

		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -ParentId 1 -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of PI AF Server checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}
}

function StartSQLServerAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(										
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[int]
		$AuditLevelInt = 1,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
					
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value					

		# If no password has been given and SQL Server security is in use,
		# prompt for a password and store in the cache.
		# This will avoid to ask many times to the user when a
		# SQL query is performed.
		if(($ComputerParams.IntegratedSecurity -eq $false) -and ($ComputerParams.PasswordFile -eq ""))
		{ SetSQLAccountPasswordInCache $ComputerParams.ComputerName $ComputerParams.InstanceName $ComputerParams.SQLServerUserID}		
			
		# Validate the presence of a SQL Server
			try
			{
				if((ValidateIfHasSQLServerRole -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
											-InstanceName $ComputerParams.InstanceName -dbgl $DBGLevel) -eq $false)						
				{
					# Return the error message.
					$msgTemplate = "The computer {0} does not have a SQL Server role or the validation failed"
					$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
					Write-PISysAudit_LogMessage $msg "Warning" $fn
					$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "SQL Server Audit" -fn $fn -msg $msg
					return
				}
				
				if (-not (Get-Module -ListAvailable -Name SQLPS))
				{
					# Return if SQLPS not available on machine
					$msg = "Unable to locate module SQLPS on the computer running this script. Terminating SQL Server audit"
					Write-PISysAudit_LogMessage $msg "Error" $fn
					$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "SQL Server Audit" -fn $fn -msg $msg
					return
				}

				# Push and Pop are to prevent a context switch to the SQL shell from persisting after invocation of SQL commands.
				Push-Location
				Import-Module SQLPS -DisableNameChecking
				Pop-Location
				# Simplest query to return a response to ensure we can query the SQL server
				Invoke-PISysAudit_Sqlcmd_ScalarValue -Query 'SELECT 1 as TEST' -LocalComputer $ComputerParams.IsLocal -RemoteComputerName $ComputerParams.ComputerName `
											-InstanceName $ComputerParams.InstanceName -IntegratedSecurity $ComputerParams.IntegratedSecurity `
											-UserName $ComputerParams.SQLServerUserID -PasswordFile $ComputerParams.PasswordFile `
											-ScalarValue 'TEST' | Out-Null
			}
			catch
			{
				# Return the error message.
				$msgTemplate = "Could not execute test query against SQL Server on computer {0}"
				$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
				Write-PISysAudit_LogMessage $msg "Warning" $fn
				$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
						-at $AuditTable -an "SQL Server Audit" -fn $fn -msg $msg
				return
			}

		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary4 -lvl $AuditLevelInt
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No SQL Server checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}			
		
		# Set message templates.
		$activityMsgTemplate1 = "Check SQL Server component on '{0}' computer"
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}: {2}"
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0} and arguments are:" `
												+ " Audit Table = {1}, Server Name = {2}, SQL Server Instance Name = {3}," `
												+ " Use Integrated Security  = {4}, User name = {5}, Password file = {6}, Debug Level = {7}"								
	
		# Proceed with all the compliance checks.
		$i = 0
		foreach($function in $listOfFunctions.GetEnumerator())
		{									
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++
				$auditItem = (Get-Help $function.Name).Synopsis
				$statusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString(), $auditItem)
				$pctComplete = ($i-1) / $listOfFunctions.Count * 100
				Write-Progress -activity $activityMsg1 -Status $statusMsg -ParentId 1 -PercentComplete $pctComplete
			}

			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................							
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, $ComputerParams.ComputerName, `
									$ComputerParams.InstanceName, $ComputerParams.IntegratedSecurity, `
									$ComputerParams.SQLServerUserID, $ComputerParams.PasswordFile, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
												-InstanceName $ComputerParams.InstanceName `
												-IntegratedSecurity $ComputerParams.IntegratedSecurity `
												-user $ComputerParams.SQLServerUserID `
												-pf $ComputerParams.PasswordFile `
												-dbgl $DBGLevel														
		}
		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -ParentId 1 -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of SQL Server checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}		
}

function StartPICoresightServerAudit
{
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(										
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,		
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[int]
		$AuditLevelInt = 1,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
					
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		$IsElevated = (Get-Variable "PISysAuditIsElevated" -Scope "Global" -ErrorAction "SilentlyContinue").Value	
			
		# Validate the presence of IIS
		if((ValidateIfHasPICoresightRole -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel) -eq $false)
		{
			# Return the error message.
			$msgTemplate = "The computer {0} does not have the PI Coresight role or the validation failed"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI Coresight Server Audit" -fn $fn -msg $msg
			return
		}

		if($ComputerParams.IsLocal -and -not($IsElevated))
		{
			$msg = "Elevation required to run Audit checks using IIS Cmdlet.  Run PowerShell as Administrator to complete these checks."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI Coresight Server Audit" -fn $fn -msg $msg
			return
		}

		if((Get-PISysAudit_InstalledWin32Feature -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -wfn "IIS-ManagementScriptingTools" -DBGLevel $DBGLevel) -ne 1)
		{
			# Return the error message.
			$msgTemplate = "The computer {0} does not have the IIS Management Scripting Tools Feature (IIS cmdlets) or the validation failed; some audit checks may not be available."
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI Coresight Server Audit" -fn $fn -msg $msg
			return
		}

		try
		{
			Get-PISysAudit_GlobalPICoresightConfiguration -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -DBGLevel $DBGLevel 
		}
		catch
		{
			# Return the error message.
			$msgTemplate = "An error occurred while accessing the global configuration of PI Coresight on {0}"
			$msg = [string]::Format($msgTemplate, $ComputerParams.ComputerName)
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$AuditTable = New-PISysAuditError -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName `
							-at $AuditTable -an "PI Coresight Server Audit" -fn $fn -msg $msg
			return
		}

		# Get the list of functions to execute.
		$listOfFunctions = Get-PISysAudit_FunctionsFromLibrary5 -lvl $AuditLevelInt
		# There is nothing to execute.
		if($listOfFunctions.Count -eq 0)		
		{
			# Return the error message.
			$msg = "No PI Coresight checks have been found."
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}			
		
		# Set message templates.
		$activityMsgTemplate1 = "Check PI Coresight component on '{0}' computer"
		$activityMsg1 = [string]::Format($activityMsgTemplate1, $ComputerParams.ComputerName)
		$statusMsgProgressTemplate1 = "Perform check {0}/{1}: {2}"
		$statusMsgCompleted = "Completed"
		$complianceCheckFunctionTemplate = "Compliance Check function: {0} and arguments are:" `
												+ " Audit Table = {1}, Server Name = {2}," `
												+ " Debug Level = {3}"									
				
		# Proceed with all the compliance checks.
		$i = 0
		foreach($function in $listOfFunctions.GetEnumerator())
		{									
			# Set the progress.
			if($ShowUI)
			{
				# Increment the counter.
				$i++
				$auditItem = (Get-Help $function.Name).Synopsis
				$statusMsg = [string]::Format($statusMsgProgressTemplate1, $i, $listOfFunctions.Count.ToString(), $auditItem)
				$pctComplete = ($i-1) / $listOfFunctions.Count * 100
				Write-Progress -activity $activityMsg1 -Status $statusMsg -ParentId 1 -PercentComplete $pctComplete
			}

			# ............................................................................................................
			# Verbose at Debug Level 2+
			# Show some extra messages.
			# ............................................................................................................							
			$msg = [string]::Format($complianceCheckFunctionTemplate, $function.Name, $AuditTable, $ComputerParams.ComputerName, $DBGLevel)
			Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			# Call the function.
			& $function.Name $AuditTable -lc $ComputerParams.IsLocal -rcn $ComputerParams.ComputerName -dbgl $DBGLevel														
		}
		# Set the progress.
		if($ShowUI)
		{ Write-Progress -activity $activityMsg1 -Status $statusMsgCompleted -ParentId 1 -completed }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of PI Coresight checks"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return
	}		
}

# ........................................................................
# Public Functions
# ........................................................................
function Initialize-PISysAudit
{
<#  
.SYNOPSIS
(Core functionality) Initialize the module.
.DESCRIPTION
Initialize the module.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$ShowUI = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{		
	# Read from the global constant bag.
	$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value		
			
	# Set folders.
	# Set the initialization flag..
	if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
	{			
		# Set folder names required by the script.
		SetFolders
		
		# Set global variable checking for elevated status.
		$IsElevated = CheckIfRunningElevated
		New-Variable -Name "PISysAuditIsElevated" -Scope "Global" -Visibility "Public" -Value $IsElevated

		# Validate if used with PowerShell version 3.x and more	
		$majorVersionPS = $PSVersionTable.PSVersion.Major	
		if($majorVersionPS -lt 3)
		{						
			$msg = "This script won't execute under less than version 3.0 of PowerShell"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}
			
		# Set the ShowUI flag
		if($null -eq (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
		{ New-Variable -Name "PISysAuditShowUI" -Scope "Global" -Visibility "Public" -Value $true }		
									
		# Set an PISysAuditInitialized flag
		New-Variable -Name "PISysAuditInitialized" -Scope "Global" -Visibility "Public" -Value $true				
	}			
}

END {}

#***************************
#End of exported function
#***************************
}
				
function Set-PISysAudit_SaltKey
{
<#  
.SYNOPSIS
(Core functionality) Create a crypto salt key (16 digits).
.DESCRIPTION
Create a crypto salt key (16 digits).
#>
BEGIN {}
PROCESS
{
	$fn = GetFunctionName
	
	try
	{
		# Initialize the module if needed	
		Initialize-PISysAudit
			
		# Read from the global constant bag.
		$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		# If initialization failed, leave the function.
		if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
		{
			$msg = "This script won't execute because initialization has not completed"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}
		
		$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()		
		$myKey = New-Object System.Byte[] 16
		$rng.GetBytes($myKey)
		return [System.Convert]::ToBase64String($myKey)		
	}
	catch
	{
		# Return the error message.
		$msg = "The creation of a cryptokey has failed."								
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
	}
}

END {}

#***************************
#End of exported function
#***************************
}
  
function New-PISysAudit_PasswordOnDisk
{
<#  
.SYNOPSIS
(Core functionality) Encrypt password on disk.
.DESCRIPTION
Encrypt password on disk.
#>
BEGIN {}
PROCESS
{			
	$fn = GetFunctionName
	
	try
	{				
		# Initialize the module if needed	
		Initialize-PISysAudit
		
		# Read from the global constant bag.
		$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		# If initialization failed, leave the function.
		if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
		{
			$msg = "This script won't execute because initialization has not completed"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			return
		}
	
		# Read from the global constant bag.
		$pwdPath = (Get-Variable "PasswordPath" -Scope "Global").Value			
			
		# Get the password.	
		$pwd = Read-Host -assecurestring "Please enter the password to save on disk for further usage"
		
		# Define the file to save it.	
		$file = Read-Host "Please enter the file name to store it"
		# Validate.
		if([string]::IsNullOrEmpty($file))
		{
			Write-PISysAudit_LogMessage "No file name has been entered. Please retry!" "Error" $fn -sc $true
			return
		}
			
		# Set the path.
		$pwdFile = PathConcat -ParentPath $pwdPath -ChildPath $file
		
		# Encrypt.	
		
		# If you want to use Windows Data Protection API (DPAPI) to encrypt the standard string representation
		# leave the key undefined. Visit this URL: http://msdn.microsoft.com/en-us/library/ms995355.aspx to know more.
		# This salt key had been generated with the Set-PISysAudit_SaltKey cmdlet.
		# $mySaltKey = "Fnzg+mrVxXEEmfEMzFwiag=="
		# $keyInBytes = [System.Convert]::FromBase64String($mySaltKey)			
		# $securePWD = ConvertFrom-SecureString $pwd -key $keyInBytes
		$securepwd = ConvertFrom-SecureString $pwd -key (1..16)
				
		# Save.
		Out-File -FilePath $pwdFile -InputObject $securePWD
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "The creation of {0} file containing your password has failed."						
		$msg = [string]::Format($msgTemplate, $pwdFile)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
	}	
}

END {}

#***************************
#End of exported function
#***************************
}

function Write-PISysAudit_LogMessage
{
<#  
.SYNOPSIS
(Core functionality) Write to console and/or log file (PISystemAudit.log) in the same folder where the script is found.
.DESCRIPTION
Write to console and/or log file (PISystemAudit.log) in the same folder where the script is found.
.NOTES
The non-use of Write-Error, Write-Verbose, Write-Warning have been deliberately taken for design purposes.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(	
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("msg,M")]
		[string]
		$Message,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("mt")]
		[ValidateSet("Error", "Warning", "Info", "Debug")]
		[string]
		$MessageType,						
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]
		[alias("fn")]			
		[string]
		$FunctionName,						
		[parameter(ParameterSetName = "Default")]
		[alias("dbgl")]			
		[int]
		$CurrentDBGLevel = 0,
		[parameter(ParameterSetName = "Default")]
		[alias("rdbgl")]			
		[int]
		$RequiredDBGLevel = 0,
		[parameter(ParameterSetName = "Default")]
		[alias("sc")]			
		[boolean]
		$ShowToConsole = $false,		
		[parameter(ParameterSetName = "Default")]
		[alias("eo")]			
		[object]
		$ErrorObject = $null)
BEGIN {}
PROCESS
{		
		# Skip if this the proper level is not reached.
		if($CurrentDBGLevel -lt $RequiredDBGLevel) { return }
		
		# Get the defined PISystemAudit log file.
		$logPath = (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value								
		
		# Read from the global constant bag.
		$ShowUI = (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value							
	
		# Get current date for log message prefix
		$ts = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + ", "
				
		# Templates
		$msgTemplate1 = "Function: {0}, Error: {1}."
		$msgTemplate2 = "Function: {0}, Error: {1}, Details: {2}."
		$msgTemplate3 = "Function: {0}, Line: {1}, Error: {2}, Details: {3}."
		$msgTemplate4 = "Warning, {0}."
		$msgTemplate5 = "Information, {0}."
		$msgTemplate6 = "Function: {0}, Debug: {1}."
		
		# Message.
		$msg = ""
				
		if($MessageType.ToLower() -eq "error")
		{
			# This type of message is always shown whatever the debug level.
			# Form the message.
			if($null -eq $ErrorObject)
			{ $msg = $msgTemplate1 -f $FunctionName, $Message }
			else
			{				
				# Remove the trailing period of the error message, template already contains
				# a period to end the message.
				if($ErrorObject.Exception.Message.EndsWith("."))
				{ $modifiedErrorMessage = $ErrorObject.Exception.Message.SubString(0, $ErrorObject.Exception.Message.Length - 1) }
				else
				{ $modifiedErrorMessage = $ErrorObject.Exception.Message }
				
				$msg = $msgTemplate3 -f $FunctionName, $ErrorObject.InvocationInfo.ScriptLineNumber, `
												$Message, $modifiedErrorMessage
			}
			
			# Write the content.
			Add-Content -Path $logPath -Value ($ts + $msg) -Encoding ASCII
			
			# Force to show on console.
			$ShowToConsole = $true			
			
			# Set color.
			$ForegroundColor = "Red"
			$BackgroundColor = "Black"

			if($ShowToConsole -and $ShowUI) { Write-Host $msg -ForeGroundColor $ForegroundColor -BackgroundColor $BackgroundColor }
			
		}
		elseif($MessageType.ToLower() -eq "warning")
		{						
			# Form the message.
			$msg = $msgTemplate4 -f $Message
			
			# Write the content.
			Add-Content -Path $logPath -Value ($ts + $msg) -Encoding ASCII
			
			# Force to show on console.
			$ShowToConsole = $true			
			
			# Set color.
			$ForegroundColor = "Yellow"
			$BackgroundColor = "Black"

			if($ShowToConsole -and $ShowUI) { Write-Host $msg -ForeGroundColor $ForegroundColor -BackgroundColor $BackgroundColor }
		}
		elseif($MessageType.ToLower() -eq "info")
		{
			if($Message -ne "")			
			{
				# Form the message.
				$msg = $msgTemplate5 -f $Message
				$msgConsole = $Message
			
				# Write the content.
				Add-Content -Path $logPath -Value ($ts + $msg) -Encoding ASCII	
				
				if($ShowToConsole -and $ShowUI) { Write-Host $msgConsole }					
			}
		}
		elseif($MessageType.ToLower() -eq "debug")
		{
			# Do nothing if the debug level is not >= required debug level
			if($CurrentDBGLevel -ge $RequiredDBGLevel)
			{			
				# Form the message.
				$msg = $msgTemplate6 -f $FunctionName, $Message
				
				# Write the content.
				Add-Content -Path $logPath -Value ($ts + $msg) -Encoding ASCII		
				
				if($ShowToConsole -and $ShowUI) { Write-Host $msg }						
			}
		}
		else
		{			
			$msg = $msgTemplate1 -f $FunctionName, "An invalid level of message has been picked."
				
			# Write the content.
			Add-Content -Path $logPath -Value ($ts + $msg) -Encoding ASCII								
			
			# Set color.
			$ForegroundColor = "Red"
			$BackgroundColor = "Black"
			
			if($ShowToConsole -and $ShowUI) { Write-Host $msg -ForeGroundColor $ForegroundColor -BackgroundColor $BackgroundColor }	
		}
	}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_EnvVariable
{
<#
.SYNOPSIS
(Core functionality) Get a machine related environment variable.
.DESCRIPTION
Get a machine related environment variable.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("vn")]
		[string]
		$VariableName,		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("t")]
		[ValidateSet("Machine", "User", "Process")]
		[string]
		$Target = "Machine",				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{		
	$fn = GetFunctionName
	
	try
	{
		$scriptBlock = {
				param([string]$Variable) 
				Get-ChildItem -Path $('Env:' + $Variable) | Select-Object -ExpandProperty Value
			}
		# Execute the GetEnvironmentVariable method locally or remotely via the Invoke-Command cmdlet.
		if($LocalComputer)
		{
			$value = & $scriptBlock -Variable $VariableName
		}
		else
		{			
			$value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock	-ArgumentList $VariableName						
		}
		
		# Verbose if debug level is 2+
		$msgTemplate = "Value returned is {0}"
		$msg = [string]::Format($msgTemplate, $value)
		Write-PISysAudit_LogMessage $msg "Debug" $fn -rdbgl 2 -dbgl $DBGLevel

		# Return the value found.
		return $value
	}	
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred during the reading of the environment variable: {0} from local machine."
		$msgTemplate2 = "A problem occurred during the reading of the environment variable: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message, $RemoteComputerName) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}		
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_RegistryKeyValue
{
<#
.SYNOPSIS
(Core functionality) Read a value from the Windows Registry Hive.
.DESCRIPTION
Read a value from the Windows Registry Hive.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("rkp")]
		[string]
		$RegKeyPath,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("a")]
		[string]
		$Attribute,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{			
	$fn = GetFunctionName
	
	try
	{
		$scriptBlock = { 
				param([string]$Path, [string]$Name) 
				$Value = Get-ItemProperty -Path $Path -Name $Name | Select-Object -ExpandProperty $Name 
				return $Value
			}

		if($LocalComputer)
		{ $value = & $scriptBlock -Path $RegKeyPath -Name $Attribute }
		else
		{ $value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $RegKeyPath, $Attribute }
	
		# Return the value found.
		return $value		
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred during the reading of the registry key: {0} from local machine."
		$msgTemplate2 = "A problem occurred during the reading of the registry key: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message, $RemoteComputerName) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_TestRegistryKey
{
<#
.SYNOPSIS
(Core functionality) Test for the existence of a key in the Windows Registry Hive.
.DESCRIPTION
Test for the existence of a key in the Windows Registry Hive.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("rkp")]
		[string]
		$RegKeyPath,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{			
	$fn = GetFunctionName
	
	try
	{
		$scriptBlock = {
				param([string]$Path)
				return $(Test-Path -Path $Path)
			}

		# Execute the Test-Path cmdlet method locally or remotely via the Invoke-Command cmdlet.
		if($LocalComputer)
		{ $value = & $scriptBlock -Path $RegKeyPath }
		else
		{ $value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $RegKeyPath }
	
		# Return the value found.
		return $value		
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred during the reading of the registry key: {0} from local machine."
		$msgTemplate2 = "A problem occurred during the reading of the registry key: {0} from {1} machine."
		if($LocalComputer)
		{ $msg = [string]::Format($msgTemplate1, $_.Exception.Message) }
		else
		{ $msg = [string]::Format($msgTemplate2, $_.Exception.Message) }
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_				
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_ParseDomainAndUserFromString
{
<#
.SYNOPSIS
(Core functionality) Parse the domain portion out of an account string.
.DESCRIPTION
Parse the domain portion out of an account string.  Supports UPN or Down-Level format
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("us")]
		[string]
		$UserString,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{
	$fn = GetFunctionName
	try
	{
		If ($UserString.ToLower() -in 
				@("localsystem", "networkservice", "localservice",
					"nt authority\localsystem", "nt authority\networkservice", "nt authority\localservice",
					 "applicationpoolidentity", "nt service\afservice", "nt service\piwebapi", "nt service\picrawler" ))
		{ 
			$ServiceAccountDomain = 'MACHINEACCOUNT'
			$parsingPosDL = $UserString.IndexOf('\')
			If($parsingPosDL -ne -1 ) 
			{
				$ServiceAccount = $UserString.Substring($parsingPosDL+1)
			}
			Else 
			{
				$ServiceAccount = $UserString
			}
		}
		Else{
			# Parse as UPN or Down-Level Logon format
			$parsingPosDL = $UserString.IndexOf('\') # DL
			$parsingPosUPN = $UserString.IndexOf('@') # UPN
			If($parsingPosDL -ne -1 ) 
			{
				$ServiceAccountDomain = $UserString.Substring(0,$parsingPosDL)
				$ServiceAccount = $UserString.Substring($parsingPosDL+1)
			}
			ElseIf($parsingPosUPN -ne -1)
			{
				$ServiceAccountDomain = $UserString.Substring($parsingPosUPN+1)
				$ServiceAccount = $UserString.Substring(0,$parsingPosUPN)
			}
			Else
			{
				$ServiceAccountDomain = $null
				$ServiceAccount = $UserString
			}
		}

		$AccountObject = New-Object PSCustomObject					
		Add-Member -InputObject $AccountObject -MemberType NoteProperty -Name "UserName" -Value $ServiceAccount
		Add-Member -InputObject $AccountObject -MemberType NoteProperty -Name "Domain" -Value $ServiceAccountDomain	

		return $AccountObject			
	}
	catch
	{
		# Return the error message.				
		Write-PISysAudit_LogMessage "Unable to determine account domain." "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_ServiceProperty
{
<#
.SYNOPSIS
(Core functionality) Get a property (state, startup type, or logon account) of a service on a given computer.
.DESCRIPTION
Get a property (state, startup type, or logon account) of a service on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("sn")]
		[string]
		$ServiceName,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("sp")]
		[ValidateSet("State", "StartupType", "LogOnAccount")]
		[string]
		$ServiceProperty,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName

	# Map cmdlet parameter to actual property name of WMI object
	# State        -> State
	# StartupType  -> StartMode
	# LogOnAccount -> StartName
	if ($ServiceProperty -eq 'State') { $Property = 'State'}
	elseif ($ServiceProperty -eq 'StartupType') { $Property = 'StartMode' }
	elseif ($ServiceProperty -eq 'LogOnAccount') { $Property = 'StartName'}
	
	try
	{
		$className = "Win32_Service"
		$namespace = "root\CIMV2"
		$filterExpression = [string]::Format("name='{0}'", $ServiceName)
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel								
		return ($WMIObject | Select-Object -ExpandProperty $Property)
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Execution of WMI Query has failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_AccountProperty
{
<#
.SYNOPSIS
(Core functionality) Get a property of a user on a given computer.
.DESCRIPTION
Get a property of a user on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("an")]
		[string]
		$AccountName,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("ap")]
		[ValidateSet("Caption", "SID", "Domain", "Name", "All")]
		[string]
		$AccountProperty,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName

	$className = "Win32_UserAccount"
	$namespace = "root\CIMV2"
	
	try
	{
		$Account = Get-PISysAudit_ParseDomainAndUserFromString -UserString $AccountName

		$filterExpression = [string]::Format("Name='{0}'", $Account.UserName)
		if($Account.Domain -eq 'MACHINEACCOUNT')
		{
			$className = "Win32_SystemAccount"
			switch ($Account.UserName)
			{
				"LocalSystem" { $Account.UserName = "SYSTEM" }
				"LocalService" { $Account.UserName = "Local Service" }
				"NetworkService" { $Account.UserName = "Network Service" }
			}
			$filterExpression = [string]::Format("Name='{0}'", $Account.UserName)
		}
		elseif($Account.Domain -eq '.' -or $Account.Domain -eq '')
		{
			$filterExpression = [string]::Format("Name='{0}' AND LocalAccount='TRUE'", $Account.UserName)
		}
		else
		{
			$filterExpression = [string]::Format("Name='{0}' AND LocalAccount='FALSE' AND Domain='{1}'", $Account.UserName, $Account.Domain)
		}

		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel
		
		if ($UserAccountProperty -eq 'All') # Return the whole object
		{ 
			return $WMIObject 
		}
		else # Return the explicitly requested property
		{ 
			$Property = $AccountProperty 
			return ($WMIObject | Select-Object -ExpandProperty $Property)
		}	
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Execution of WMI Query has failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CertificateProperty
{
<#
.SYNOPSIS
(Core functionality) Get a property of a certificate on a given computer.
.DESCRIPTION
Get a property of a certificate on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("ct")]
		[string]
		$CertificateThumbprint,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]
		[ValidateSet("Issuer")]
		[string]
		$CertificateProperty,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{
		$scriptBlock = { 
			param([string]$Thumbprint, [string]$Property)
			Get-ChildItem -Path $('Cert:\LocalMachine\My\' + $Thumbprint) | Format-List -Property $Property | Out-String 
		}
		
		if($LocalComputer)
		{ $value = & $scriptBlock -Thumbprint $CertificateThumbprint -Property $CertificateProperty }
		else
		{ $value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $CertificateThumbprint, $CertificateProperty }
		
		# Only return the value, otherwise every check will have to massage it
		$value = $value.Split('=')[1].Trim()
		
		return $value
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Accessing certificate properties failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_BoundCertificate
{
<#
.SYNOPSIS
(Core functionality) Determine what certificate is bould to a particular IP and Port.
.DESCRIPTION
Determine what certificate is bould to a particular IP and Port.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pt")]
		[string]
		$Port,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("ip")]
		[string]
		$IPAddress="0.0.0.0",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{
		$scriptBlock = { 
			param([string]$IPPort)
			netsh http show sslcert ipport=$($IPPort)
		}

		$IPPort = $IPAddress + ':' + $Port
		
		if($LocalComputer)
		{ $value = & $scriptBlock -IPPort $IPPort }
		else
		{ $value = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $IPPort }
		
		return $value
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Accessing certificate properties failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_ResolveDnsName
{
<#
.SYNOPSIS
(Core functionality) Retrieves attributes of a DNS record 
.DESCRIPTION
Wraps nslookup or Resolve-DnsName depending on PS version used.  Currently
only supports returning the Type of record.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("ln")]
		[string]
		$LookupName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("at")]
		[ValidateSet('Type')]
		[string]
		$Attribute='Type',
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{
		if($PSVersionTable.PSVersion.Major -ge 4)
		{
			$record = Resolve-DnsName -Name $LookupName 
			$recordObjectType = $record.GetType().Name
			if($recordObjectType -eq 'Object[]') # Either CNAME and corresponding A records or collection of A and AAAA records
			{
				if($record[0].GetType().Name -eq 'DnsRecord_PTR')
				{ $type = $record[0].Type }
				else 
				{ $type = 'A' } 
			}
			elseif($recordObjectType -in @('DnsRecord_A','DnsRecord_AAAA'))
			{ $type = 'A' }
			else
			{ $type = $record.Type }
		}
		else
		{
			# non-authoritative answer returns an error with nslookup, but not with the more modern Resolve-DnsName
			# for consistent implementation, sending error output to null for nslookup and noting error if not results
			# are returned.
			$record = nslookup $LookupName 2> $null 
			if($null -eq $record){
				$msgTemplate = "No results returned by nslookup for {0}"	
				$msg = [string]::Format($msgTemplate, $LookupName)
				Write-PISysAudit_LogMessage $msg "Warning" $fn
				return $null
			}
			else
			{
				if($null -eq $($record -match 'Aliases:')) # A or AAAA
				{ $type = 'A'	}
				else # CNAME
				{ $type = 'CNAME' }
			}
		}

		return $type
	}
	catch
	{
		Write-PISysAudit_LogMessage "Accessing DNS record failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_GroupMembers
{
<#
.SYNOPSIS
(Core functionality) Return the members of a group.
.DESCRIPTION
Return the members of a group.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("gn")]
		[string]
		$GroupName,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("gd")]
		[string]
		$GroupDomain,
		[parameter(Mandatory=$false, Position=1, ParameterSetName = "Default")]
		[alias("cu")]
		[string]
		$CheckUser = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	$blnCheckUser = $CheckUser -ne ""
	$className = "win32_GroupUser"
	$namespace = "root\CIMV2"
	try
	{
		if($blnCheckUser)
		{ 
			$CheckUserObject = Get-PISysAudit_ParseDomainAndUserFromString -UserString $CheckUser 
			if($CheckUserObject.Domain -eq '.' -or $CheckUserObject.Domain -eq 'MACHINEACCOUNT')
			{ $CheckUserObject.Domain = $RemoteComputerName.Split(".")[0] } # use the hostname
		}
		
		if($GroupDomain.ToLower() -eq 'local')
		{ $GroupDomain = $RemoteComputerName.Split(".")[0] } 
		
		$filterExpression = "GroupComponent=`"Win32_Group.Domain='$GroupDomain',Name='$GroupName'`""
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel	
		
		$GroupMembers = @()
		Foreach($entry in $WMIObject)
		{
			# PartComponent always has the form below.
			# \\<Machine>\root\cimv2:Win32_UserAccount.Domain="<Domain>",Name="<Name>"
			$entry = $entry.PartComponent.Split(',').Split('=').Trim('"')
			$Domain = $entry[1]
			$Name = $entry[3]
			if($blnCheckUser)
			{
				if($CheckUserObject.Domain -eq $Domain -and $CheckUserObject.UserName -eq $Name)
				{ return $true }
			}
			else
			{
				$GroupMember = New-Object pscustomobject
				$GroupMember | Add-Member -MemberType NoteProperty -Name 'Domain' -Value $Domain
				$GroupMember | Add-Member -MemberType NoteProperty -Name 'Name' -Value $Name
				$GroupMembers += $GroupMember
			}
		} 

		if($blnCheckUser)
		{ return $false }
		else 
		{ return $GroupMembers }
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Execution of WMI Query has failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_InstalledComponents
{
<#
.SYNOPSIS
(Core functionality) Get installed software on a given computer.
.DESCRIPTION
Get installed software on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{				
		# Retrieve installed 64-bit programs (or all programs on 32-bit machines)
		$mainNodeKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
		# If it exists, also get 32-bit programs from the corresponding Wow6432Node keys
		$wow6432NodeKey = 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
		$scriptBlock = { 
			param([string]$RegKey) 
			if($RegKey -like 'Wow6432') { $Action = 'SilentlyContinue' }
			else { $Action = 'Continue' }
			Get-ChildItem $RegKey -ErrorAction $Action | ForEach-Object { Get-ItemProperty $_.PsPath } | Where-Object { $_.Displayname -and ($_.Displayname -match ".*") } 
		}
		
		if($LocalComputer)
		{
			$unsortedAndUnfilteredResult = & $scriptBlock -RegKey $mainNodeKey
			$wow6432NodeResult = & $scriptBlock -RegKey $wow6432NodeKey
		}
		else
		{	
			$unsortedAndUnfilteredResult = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $mainNodeKey
			$wow6432NodeResult = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $wow6432NodeKey
		}	
		$result = $unsortedAndUnfilteredResult + $wow6432NodeResult | Sort-Object Displayname | Select-Object DisplayName, Publisher, DisplayVersion, InstallDate
		return $result
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Reading the registry for installed components failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_InstalledKBs
{
<#
.SYNOPSIS
(Core functionality) Get installed Microsoft KBs (patches) on a given computer.
.DESCRIPTION
Get installed Microsoft KBs (patches) on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("tp")]
		[ValidateSet('HotFix','Reliability','All')]
		[string]
		$Type = 'All',
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{									
		$namespace = "root\CIMV2"
		$WMIObject = @()
		if($Type -eq 'HotFix' -or $Type -eq 'All')
		{
			$className = "Win32_quickfixengineering"
			$filterExpression = ""
			$WMIObject += ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel `
											| Select-Object @{LABEL = "Name";EXPRESSION={$_.HotFixID}}, InstalledOn
		}
		if($Type -eq 'Reliability' -or $Type -eq 'All')
		{
			$className = 'win32_reliabilityRecords'
			$filterExpression = "sourcename='Microsoft-Windows-WindowsUpdateClient'"
			$WMIObject += ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel `
											| Select-Object @{LABEL = "Name";EXPRESSION={$_.ProductName}}, @{LABEL="InstalledOn";EXPRESSION={$_.ConvertToDateTime($_.TimeGenerated)}}
		}
			
		return $WMIObject | Sort-Object Name					
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Execution of WMI Query has failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_InstalledWin32Feature
{
<#
.SYNOPSIS
(Core functionality) Get install status of Windows Feature on a given computer.
.DESCRIPTION
Get install status of Windows Feature on a given computer.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("wfn")]
		[string]
		$WindowsFeatureName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{									
		$className = "Win32_OptionalFeature"
		$namespace = "root\CIMV2"		
		$filterExpressionTemplate = "Name='{0}'"
		$filterExpression = [string]::Format($filterExpressionTemplate, $WindowsFeatureName)
		$WMIObject = ExecuteWMIQuery $className -n $namespace -lc $LocalComputer -rcn $RemoteComputerName -FilterExpression $filterExpression -DBGLevel $DBGLevel										
		return $WMIObject.InstallState
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "Reading the registry for installed components failed!" "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_FirewallState
{
<#
.SYNOPSIS
(Core functionality) Validate the state of a firewall.
.DESCRIPTION
Validate the state of a firewall.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{									
		if($LocalComputer)
		{			                    			
			$firewallState = Get-NetFirewallProfile 
		}
		else
		{                            				
			$firewallState = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock { Get-NetFirewallProfile } 
		}
		# Return the content.
		return $firewallState
	}
	catch
	{
		# Return the error message.
		Write-PISysAudit_LogMessage "A problem occurred when calling the Get-NetFirewallProfile cmdlet." "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_AppLockerState
{
<#
.SYNOPSIS
(Core functionality) Get the state of AppLocker.
.DESCRIPTION
Get the state of AppLocker.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{									
		$scriptBlock = { if($PSVersionTable.PSVersion.Major -ge 3) { Get-AppLockerPolicy -Effective -XML } else { $null } }
		if($LocalComputer)
		{			                    			
			$appLockerPolicy = & $scriptBlock
		}
		else
		{                            				
			$appLockerPolicy = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock
		}
		
		# Return the content.
		return $appLockerPolicy
	}
	catch
	{
		
		# Return the error message.
		Write-PISysAudit_LogMessage "A problem occurred while retrieving the AppLocker configuration." "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

Function Get-PISysAudit_KnownServers
{
<#
.SYNOPSIS
(Core functionality) Get the servers in the PI Data Archive or PI AF Server KST.
.DESCRIPTION
Get the servers in the PI Data Archive or PI AF Server KST.
#>
	param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("st")]
		[ValidateSet('PIServer','AFServer')]
		[string] 
		$ServerType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	$fn = GetFunctionName

	If($ServerType -eq 'PIServer')
	{
		# Get PI Servers
		$regpathKST = 'HKLM:\SOFTWARE\PISystem\PI-SDK\1.0\ServerHandles'
		$scriptBlock = {param([string]$RegPath) Get-ChildItem $RegPath | ForEach-Object {Get-ItemProperty $_.pspath} | where-object {$_.path} | Foreach-Object {$_.path}}
		if($LocalComputer)
		{ $KnownServers = & $scriptBlock -RegPath $regpathKST }
		Else
		{ $KnownServers = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $regpathKST }
	}
	Else
	{
		# Get AF Servers
		$programDataWebServer = Get-PISysAudit_EnvVariable "ProgramData" -lc $LocalComputer -rcn $RemoteComputerName  -Target Process
		$afsdkConfigPathWebServer = "$programDataWebServer\OSIsoft\AF\AFSDK.config"
		
		$scriptBlock = { param([string]$ConfigPath) Get-Content -Path $ConfigPath | Out-String }

		# Verbose only if Debug Level is 2+
		$msgTemplate = "Remote command to send to {0} is: {1}"
		$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlock.ToString())
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

		if($LocalComputer)
		{ $AFSDK = & $scriptBlock -ConfigPath $afsdkConfigPathWebServer }
		Else
		{ $AFSDK = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $afsdkConfigPathWebServer }
		$KnownServers = [regex]::Matches($AFSDK, 'host=\"([^\"]*)')
	}

	$msgTemplate = "Known servers found: {0}"
	$msg = [string]::Format($msgTemplate, $KnownServers)
	Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

	return $KnownServers
}

function Get-PISysAudit_CheckPrivilege
{
<#
.SYNOPSIS
(Core functionality) Return the access token (security) of a process or service.
.DESCRIPTION
Return the access token (security) of a process or service.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("an")]
		[string]
		$AccountName,	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]		
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS		
{						
	$fn = GetFunctionName
	
	try
	{			
		$AccountSID = Get-PISysAudit_AccountProperty -AccountName $AccountName -AccountProperty SID -lc $LocalComputer -rc $RemoteComputerName -DBGLevel $DBGLevel
		if($null -eq $AccountSID)
		{
			# Return the error message.
			$msg = "Could not resolve the SID for $AccountName to evaluate the Privilege."
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
			return $null
		}
		$scriptBlock = {
					param([string]$SID) 
					if(Test-Path $($env:ProgramData + "\OSIsoft")) 
					{ 
						$FilePathRoot = $($env:ProgramData + "\OSIsoft")
					}
					elseif(Test-Path $($env:pihome64 + "\dat"))
					{
						$FilePathRoot = $($env:pihome64 + "\dat")
					}
					else
					{
						return $null
					}
					$FilePath = $FilePathRoot + '\PISysAudit_CheckPrivilege.CFG'
					$UtilityExecutable = $env:Windir + '\system32\secedit.exe'
					$ArgumentList = @('/export', '/areas USER_RIGHTS', $('/cfg "' + $FilePath + '"'))
					Start-Process -FilePath $UtilityExecutable -ArgumentList $ArgumentList -Wait -NoNewWindow
					$FileContent = Get-Content -Path $FilePath
					if(Test-Path $FilePath) { Remove-Item $FilePath }
					$Privs = @()
					Foreach($Priv in $FileContent)
					{
						if($Priv -like "Se*=*" -and $Priv -like $('*' + $SID + '*'))
						{
							$Privs += $Priv.Split('=').Trim()[0]
						}
					}
					return $Privs
		}

		if($LocalComputer)
		{ $AccountPrivileges = & $scriptBlock -UserSID $AccountSID }
		else
		{ 
			$AccountPrivileges = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $AccountSID
		}
		return $AccountPrivileges
	}
	catch
	{
		# Return the error message.
		$msg = "Reading privileges from the process failed"
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
	
	# Return the result.
	return $result
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_ProcessedPIConnectionStatistics 
{
<#
.SYNOPSIS
(Core functionality) Transpose and filter PI Connection Statistics.
.DESCRIPTION
Transpose and filter PI Connection Statistics.  Options to filter returned results by
protocol and whether the connection is local or remote.  
#>
    [CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
    param(							
        [parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("pic")]
		[object]
		$PIDataArchiveConnection,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("pics")]
		[object]
		$PIConnectionStats,
        [parameter(Mandatory=$false, ParameterSetName = "Default")]
        [ValidateSet('Windows','Trust','ExplicitLogin','SubSystem','Any')]
        [alias("ap")]
        [string]
        $ProtocolFilter="Any",
        [parameter(Mandatory=$false, ParameterSetName = "Default")]
        [alias("ro")]
        [boolean]
        $RemoteOnly=$false,	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
        [alias("so")]
        [boolean]
        $SuccessOnly=$true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
        [alias("cts")]
        [boolean]
        $CheckTransportSecurity=$false,	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0) 
BEGIN {}
PROCESS 
{     
	$fn = GetFunctionName

	try
	{
		$transposedStats = @()
		Foreach($stat in $PIConnectionStats) 
		{
			# Determine properties included in the connection statistic 
			$hasProperty = @()
			foreach($property in $stat.StatisticType)
			{
				if($stat.StatisticType -contains $property -and "" -ne $stat.Item($property).Value.ToString())
				{ $hasProperty += $property }
			}
        
			# Identify the Authentication Protocol
			$statAuthProtocol = "Unknown"
			if(($hasProperty -contains 'ConnectionType') -and ($hasProperty -contains 'ConnectionStatus'))
			{
				# Only include active connections
				if($Stat.Item('ConnectionStatus').Value -eq '[0] Success' -or ($SuccessOnly -eq $false))
				{
					if($hasProperty -contains 'Trust') 
					{ $statAuthProtocol = 'Trust' }
					elseif($hasProperty -contains 'OSUser')
					{ $statAuthProtocol = 'Windows' }
					elseif($hasProperty -contains 'User')
					{ $statAuthProtocol = 'ExplicitLogin' }
					elseif($Stat.Item('ConnectionType').Value -eq 'Local Connection')
					{ $statAuthProtocol = 'SubSystem' }
				}   
			}
			elseif($hasProperty -contains 'ServerID') # PINetMgr is a special case
			{ $statAuthProtocol = 'SubSystem' }

			# Determine whether or not the connection is remote.
			[boolean]$IsRemote = $false
			if($hasProperty -contains 'ConnectionType')
			{
				if($Stat.Item('ConnectionType').Value -eq 'Remote resolver' -or `
				($Stat.Item('ConnectionType').Value -eq 'PI-API Connection' -and $Stat.Item('PeerAddress').Value -notin ('127.0.0.1','')))
				{ $IsRemote = $true }
			}
        
			# Apply protocol and RemoteOnly filters if applicable
			if(($statAuthProtocol -eq $ProtocolFilter -or $ProtocolFilter -eq 'Any') -and ($IsRemote -or $RemoteOnly -eq $false))
			{ 
				$transposedStat = New-Object PSObject
				# Add an authentication protocol attribute for easy filtering
				$transposedStat | Add-Member -MemberType NoteProperty -Name 'AuthenticationProtocol' -Value $statAuthProtocol
				$transposedStat | Add-Member -MemberType NoteProperty -Name 'Remote' -Value $IsRemote.ToString()
				# Transpose the object into PSObject with NoteProperties
				Foreach($property in $stat.StatisticType){ $transposedStat | Add-Member -MemberType NoteProperty -Name $property -Value $stat.Item($property).Value }
				$transposedStats += $transposedStat 
			}
		}

		if($CheckTransportSecurity)
		{ $transposedStats = Test-PISysAudit_SecurePIConnections -PIDataArchiveConnection $PIDataArchiveConnection -PIConnections $transposedStats -DBGLevel $DBGLevel }

		return $transposedStats
	}
	catch
	{
		$msg = "A problem occurred while processing PI Connection Statistics."		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}
END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_AFDiagCommand
{
<#
.SYNOPSIS
(Core functionality) Perform a diagnostic check with the AFDiag.exe command.
.DESCRIPTION
Perform a diagnostic check with the AFDiag.exe command.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{						
	$fn = GetFunctionName
	
	try
	{
		#......................................................................................
		# Set Paths
		#......................................................................................
		# Set the PIPC folder (64 bit).		
		$PIHome64_path = Get-PISysAudit_EnvVariable "PIHOME64" -lc $LocalComputer -rcn $RemoteComputerName
		# Set the PIPC\AF folder (64 bit).		
		$PIHome_AF_path = PathConcat -ParentPath $PIHome64_path -ChildPath "AF"
		# Set the path to reach out the afdiag.exe CLU.
		$AFDiagExec = PathConcat -ParentPath $PIHome_AF_path -ChildPath "afdiag.exe"
		# Set the path to reach out the AFService executable.
		$pathToService = PathConcat -ParentPath $PIHome_AF_path -ChildPath "AFService.exe"

		if($LocalComputer)
		{						
			$IsElevated = (Get-Variable "PISysAuditIsElevated" -Scope "Global" -ErrorAction "SilentlyContinue").Value
			
			if(-not($IsElevated))
			{
				$msg = "Elevation required to run Audit checks using AFDiag.  Run PowerShell as Administrator to complete these checks."
				Write-PISysAudit_LogMessage $msg "Warning" $fn
				return $null
			}

			# Set the output folder.
			$scriptTempFilesPath = (Get-Variable "scriptsPathTemp" -Scope "Global").Value                           			                                
		}
		else
		{																		
			$PIHome_path = Get-PISysAudit_EnvVariable "PIHOME" -lc $false -rcn $RemoteComputerName
			# Set the PIPC\dat folder (64 bit).
			$scriptTempFilesPath = PathConcat -ParentPath $PIHome_path -ChildPath "dat"	
		}
		# Define the arguments required by the afdiag.exe command
		$argListTemplate = "/ExeFile:`"{0}`""
		$argList = [string]::Format($ArgListTemplate, $pathToService)
		
		# Set the output for the CLU.
        $outputFilePath = PathConcat -ParentPath $scriptTempFilesPath -ChildPath "afdiag_output.txt"
		$outputFileContent = ExecuteCommandLineUtility -lc $LocalComputer -rcn $RemoteComputerName -UtilityExec $AFDiagExec `
														-ArgList $argList -OutputFilePath $outputFilePath -DBGLevel $DBGLevel	
		
		return $outputFileContent		
	}
	catch
	{
		# Return the error message.
		$msgTemplate1 = "A problem occurred with afdiag.exe on local computer"
		$msgTemplate2 = "A problem occurred with afdiag.exe on {0} computer"
		if($LocalComputer)
		{ $msg = $msgTemplate1 }
		else
		{ $msg = [string]::Format($msgTemplate2, $RemoteComputerName) }		
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_SPN
{
<#
.SYNOPSIS
(Core functionality) Perform an SPN check with the setspn.exe command.
.DESCRIPTION
Perform an SPN check with the setspn.exe command.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("svcname")]
		[string]
		$ServiceName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("svctype")]
		[string]
		$ServiceType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("appPool")]
		[string]
		$csappPool,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("CustomHeader")]
		[string]
		$CoresightHeader,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{
	$fn = GetFunctionName
	
	try
	{
		# Get Domain info.
		$MachineDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

		# Get Hostname.
		$hostname = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" "ComputerName" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

		# Build FQDN using hostname and domain strings.
		$fqdn = $hostname + "." + $MachineDomain

		# SPN check is done for PI Coresight using a custom host header.
		If ( $ServiceName -eq "coresight_custom" ) 
		{ 
			# Pass the Coresight AppPool identity as the service account.
			$svcacc = $csappPool
			$svcaccParsed = Get-PISysAudit_ParseDomainAndUserFromString -UserString $svcacc -DBGLevel $DBGLevel
				
			# Take Custom header information and create its short and long version.
			If ($CoresightHeader -match "\.") 
			{
				$csCustomHeaderLong = $CoresightHeader
				$pos = $CoresightHeader.IndexOf(".")
				$csCustomHeaderShort = $CoresightHeader.Substring(0, $pos)
			} 
			Else 
			{ 
				$csCustomHeaderShort = $CoresightHeader
				$csCustomHeaderLong = $CoresightHeader + "." + $MachineDomain
			}

			# Deal with the custom header - run nslookup and capture the result.
			$AliasTypeCheck = Get-PISysAudit_ResolveDnsName -LookupName $CoresightHeader -Attribute Type -DBGLevel $DBGLevel

			# Check if the custom header is a Alias (CNAME) or Host (A) entry.
			If ($AliasTypeCheck -eq 'CNAME') 
			{ 
				# Verify hostnane AND FQDN SPNs are assigned to the service account.
				#
				# In case of Alias (CNAME), SPNs should exist for both short and fully qualified name of oth the Alias (CNAME)
				# ..and for the machine the Alias (CNAME) is pointing to. Overall, there should be 4 SPNs.
				#
				# With Host (A) entries, SPNs are needed only for the short and fully qualified names.
			
				$hostnameSPN = $($serviceType.ToLower() + "/" + $hostname.ToLower())
				$fqdnSPN = $($serviceType.ToLower() + "/" + $fqdn.ToLower())
				$csCustomHeaderSPN = $($serviceType.ToLower() + "/" + $csCustomHeaderShort.ToLower())
				$csCustomHeaderLongSPN = $($serviceType.ToLower() + "/" + $csCustomHeaderLong.ToLower())
			
				$result = Test-PISysAudit_ServicePrincipalName -HostName $hostname -MachineDomain $MachineDomain `
																-SPNShort $hostnameSPN -SPNLong $fqdnSPN `
																-SPNShortAlias $csCustomHeaderSPN -SPNLongAlias $csCustomHeaderLongSPN `
																-TargetAccountName $svcaccParsed.UserName -ServiceAccountDomain $svcaccParsed.Domain -DBGLevel $DBGLevel
						
				return $result			
			} 			
			ElseIf($AliasTypeCheck -eq 'A')
			{ 
				$csCustomHeaderSPN = $($serviceType.ToLower() + "/" + $csCustomHeaderShort.ToLower())
				$csCustomHeaderLongSPN = $($serviceType.ToLower() + "/" + $csCustomHeaderLong.ToLower())

				$result = Test-PISysAudit_ServicePrincipalName -HostName $hostname -MachineDomain $MachineDomain `
																-SPNShort $csCustomHeaderSPN -SPNLong $csCustomHeaderLongSPN `
																-TargetAccountName $svcaccParsed.UserName -TargetDomain $svcaccParsed.Domain -DBGLevel $DBGLevel

				return $result
			}
			Else
			{
				$msgTemplate = "Unexpected DNS record type: {0}"	
				$msg = [string]::Format($msgTemplate, $AliasTypeCheck)
				Write-PISysAudit_LogMessage $msg "Error" $fn
				return $null
			}
		}	
		# SPN Check is done for PI Coresight or other service
		Else
		{
			# SPN check is done for PI Coresight without custom headers.
			If ( $ServiceName -eq "coresight" )
			{
				# In case of PI Coresight, the AppPool account is used in the SPN check.
				$svcacc = $csappPool
			}
			# SPN check is not done for PI Coresight.
			Else
			{
				# Get the Service account
				$svcacc = Get-PISysAudit_ServiceProperty -sn $ServiceName -sp LogOnAccount -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
			}
			$svcaccParsed = Get-PISysAudit_ParseDomainAndUserFromString -UserString $svcacc -DBGLevel $DBGLevel

			# Proceed with checking SPN for Coresight or non-IIS app (PI/AF).
			# Distinguish between Domain/Virtual account and Machine Accounts.
			$hostnameSPN = $($serviceType.ToLower() + "/" + $hostname.ToLower())
			$fqdnSPN = $($serviceType.ToLower() + "/" + $fqdn.ToLower())

			$result = Test-PISysAudit_ServicePrincipalName -HostName $hostname -MachineDomain $MachineDomain `
															-SPNShort $hostnameSPN -SPNLong $fqdnSPN `
															-TargetAccountName $svcaccParsed.UserName -TargetDomain $svcaccParsed.Domain -DBGLevel $DBGLevel

			return $result
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred using setspn.exe"	
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $null
	}
}

END {}

#***************************
#End of exported function
#***************************
}

function Test-PISysAudit_SecurePIConnections
{
<#
.SYNOPSIS
(Core functionality) Check if connections are protected by transport security
.DESCRIPTION
Check if connections are protected by transport security.  Adds SecureStatus and 
SecureStatusDetail note properties to the connection objects checked
.PARAMETER PIDataArchiveConnection
Pass the PI Data Archive connection object for the connections you want to verify.
.PARAMETER PIConnections
You can use the output of the command Get-PISysAudit_ProcessedPIConnectionStatistics 
directly.  Otherwise, requires the connecttime, ID and AuthenticationProtocol for each
connection.
#>
	[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)] 
    param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("pic")]
		[object]
		$PIDataArchiveConnection,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("con")]
		[Object[]]
		$PIConnections,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN{}
PROCESS
{
    $fn = GetFunctionName

	try
	{
		$logCutoffExceeded = 0
		$timeBuffer = 3 # Second buffer checking connection messages

		# Check Message Log Cutoff tuning parameter
		$messageLog_DayLimitParameter = Get-PITuningParameter -Connection $PIDataArchiveConnection -Name 'MessageLog_DayLimit'
		$Now = Get-Date
		if($null -eq $messageLog_DayLimitParameter.Value)
		{ $MessageLog_CutoffDate = $Now.AddDays(-1*$messageLog_DayLimitParameter.Default) }
		else
		{ $MessageLog_CutoffDate = $Now.AddDays(-1*$messageLog_DayLimitParameter.Value) }
		
		Foreach($PIConnection in $PIConnections)
		{
			$SecureStatus = "Unknown"
			$SecureStatusDetail = "Connection not found."
			if($PIConnection.AuthenticationProtocol -ne 'Windows') # Only Windows Connections can use transport security
			{ 
				$SecureStatus = "Not Secure"
				$SecureStatusDetail = "Insecure protocol ({0})" -f $PIConnection.AuthenticationProtocol
			} 
			elseif($MessageLog_CutoffDate -gt $PIConnection.ConnectedTime) # Remove connections too old to exist in the logs
			{
				$logCutoffExceeded++
				$SecureStatus = "Unknown"
				$SecureStatusDetail = "Connection before log cutoff date."
			}
			else # Verify remaining connections with successful connection message
			{
				$connectedTime = $(Get-Date $PIConnection.ConnectedTime)
				# Message ID 7082 corresponds to a successful connection with Windows
				$connectionMessages = Get-PIMessage -Connection $PIDataArchiveConnection -StartTime $connectedTime.AddSeconds(-1*$timeBuffer) -EndTime $connectedTime.AddSeconds($timeBuffer) -Id 7082 -Program pinetmgr
				foreach($message in $connectionMessages)
				{
					# Extract the connection ID
					$startID = $message.Message.IndexOf('ID:') + 3
					$endID = $message.Message.IndexOf('. Address:')
					[int]$connectionId = $message.Message.Substring($startID, $endID - $startID).Trim()
					
					# Check ID against the set of connections
					if($connectionId -eq $PIConnection.ID)
					{
						# Parse the Method attribute out of the message text
						$startMethod = $message.Message.IndexOf('. Method:') + 9
						$connectionMethod = $message.Message.Substring($startMethod).Trim()
						
						# Parse the cipher info
						$startCipher = $connectionMethod.IndexOf('(') + 1
						$endCipher = $connectionMethod.IndexOf(')')
						$cipherInfo =  $connectionMethod.Substring($startCipher, $endCipher - $startCipher)
						
						if($connectionMethod -match 'HMAC')
						{ $SecureStatus = "Secure" }
						else
						{ $SecureStatus = "Not Secure" }
						$SecureStatusDetail = $cipherInfo
					}
				}
			}
			# Set the Security attributes on the connection
			Add-Member -InputObject $PIConnection -MemberType NoteProperty -Name SecureStatus -Value $SecureStatus
			Add-Member -InputObject $PIConnection -MemberType NoteProperty -Name SecureStatusDetail -Value $SecureStatusDetail
		}

		if($logCutoffExceeded -gt 0)
		{
			$msg = "The message log cutoff date {0} is later than some connect times. {1} connections were be skipped." -f $MessageLog_CutoffDate, $logCutoffExceeded
			Write-PISysAudit_LogMessage $msg "Warning" $fn
		}
		
		return $PIConnections
	}
	catch
	{
		$msg = "A problem occurred while verifying transport security on connections: {0}" -f $_.Exception.Message
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		return $null
	}			
}
END{}

#***************************
#End of exported function
#***************************
}

function Test-PISysAudit_ServicePrincipalName
{
<#
.SYNOPSIS
(Core functionality) Check for an SPN
.DESCRIPTION
Check for the existence of an SPN
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("host")]
		[string]
		$HostName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[string]
		$MachineDomain,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("SPNS")]
		[string]
		$SPNShort,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("SPNL")]
		[string]
		$SPNLong,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("SPNSA")]
		[string]
		$SPNShortAlias="",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("SPNLA")]
		[string]
		$SPNLongAlias="",
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("TargetAccountName")]
		[string]
		$strSPNtargetAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("TargetDomain")]
		[string]
		$strSPNtargetDomain=".",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	$blnAlias = $false
	try
	{
		$blnAlias = $SPNShortAlias -ne "" -and $SPNLongAlias -ne ""
		
		# Define user syntax for SPN command
		If($strSPNtargetDomain -eq 'MACHINEACCOUNT') # Use the hostname when a machine account is identified
		{
			$accountNane = $MachineDomain + '\' + $HostName + '$'
		}
		ElseIf($strSPNtargetDomain -eq '.') # Local account detected means SPN call will fail
		{ return $false }
		Else # Use parsed name
		{
			$accountNane = $strSPNtargetDomain + '\' + $strSPNtargetAccount
		}
		
		# Run setspn
		$spnCheck = $(setspn -l $accountNane)
		
		# Loop through SPNs, trimming and ensure all lower for comparison
		$spnCounter = 0
		foreach($line in $spnCheck)
		{		
			If($blnAlias){
				switch($line.ToLower().Trim())
				{
					$SPNShort {$spnCounter++; break}
					$SPNLong {$spnCounter++; break}
					$SPNShortAlias {$spnCounter++; break}
					$SPNLongAlias {$spnCounter++; break}
					default {break}
				}
			}
			Else
			{
				switch($line.ToLower().Trim())
				{
					$SPNShort {$spnCounter++; break}
					$SPNLong {$spnCounter++; break}
					default {break}
				}
			}	
		}

		# Return details to improve messaging in case of failure.
		If ($blnAlias -and $spnCounter -eq 4) { $result = $true } 
		ElseIf ($spnCounter -eq 2) { $result = $true }
		Else 
		{ 
			$result =  $false 
		}
		return $result
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred using setspn.exe"	
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		return $false
	}
}
END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_ADONET_ScalarValueFromSQLServerQuery
{
<#
.SYNOPSIS
(Core functionality) Perform a SQL query against a local/remote computer using an ADO.NET connection.
.DESCRIPTION
Perform a SQL query against a local/remote computer using an ADO.NET connection.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,				
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]
		[alias("rspc")]
		[boolean]
		$Require_sp_configure,			
		[parameter(Mandatory=$true, Position=3, ParameterSetName = "Default")]
		[alias("q")]
		[string]
		$Query,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[string]
		$InstanceName = "",								
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName
	
	try
	{							
		# Define the connection string.
		$connectionString = SetConnectionString $LocalComputer $RemoteComputerName -InstanceName $InstanceName `
													-IntegratedSecurity $IntegratedSecurity -user $UserName -pf $PasswordFile -dbgl $DBGLevel
											
		# Create a connection object.
		$conn = New-Object System.Data.SQLClient.SQLConnection 
		$conn.ConnectionString = $connectionString
		
		# Open the connection
		$conn.Open() 			
		
		# Does it require to execute the sp_configure stored procedure?
		if($Require_sp_configure)
		{
			$sp_configure_query = "EXEC sp_configure 'show advanced options', 1;Reconfigure;"
			
			# Create a sql command
			$sp_configure_cmd = new-object System.Data.SqlClient.SqlCommand 
			$sp_configure_cmd.Connection = $conn	
		
			# Execute first command.
			$sp_configure_cmd.CommandText = $sp_configure_query
			$sp_configure_cmd.CommandTimeout = 600
			# The query returns the result but we are not interested, so send it
			# to null.
			$sp_configure_cmd.ExecuteNonQuery() | Out-Null			
		}
						
		# Get the value.
		$query_cmd = new-object System.Data.SqlClient.SqlCommand 
		$query_cmd.Connection = $conn	
		$query_cmd.CommandText = $Query
		$query_cmd.CommandTimeout = 600
		
		# Execute a scalar function.
		$value = $query_cmd.ExecuteScalar()				
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred during the SQL Query: {0}"
		$msg = [string]::Format($msgTemplate, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		$value = $null
	}				
	
	# Close the connection.
	if(!($null -eq $conn)) { $conn.Close() }
	return $value
}

END {}

#***************************
#End of exported function
#***************************
}

function Invoke-PISysAudit_Sqlcmd_ScalarValue
{
<#
.SYNOPSIS
(Core functionality) Perform a SQL query against a local/remote computer using the Invoke-Sqlcmd Cmdlet.
.DESCRIPTION
Perform a SQL query against a local/remote computer using the Invoke-Sqlcmd Cmdlet.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[alias("rcn")]
		[string]
		$RemoteComputerName,		
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("q")]
		[string]
		$Query,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]				
		[string]
		$ScalarValue,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[string]
		$InstanceName = "",									
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",							
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS		
{		
	$fn = GetFunctionName		
															
	try
	{	
		# Define the requested server name.	
		$computerName = ResolveComputerName $LocalComputer $RemoteComputerName						
		
		# Define the complete SQL Server name (Server + instance name)
		$SQLServerName = ReturnSQLServerName $computerName $InstanceName											
		
		# Integrated Security or SQL Security?
		if($IntegratedSecurity -eq $false)
		{
			if($PasswordFile -eq "")
			{												
				# Read from the global constant bag.
				# Read the secure password from the cache								 
				$securePWDFromCache = (Get-Variable "PISysAuditCachedSecurePWD" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
				if(($null -eq $securePWDFromCache) -or ($securePWDFromCache -eq ""))
				{ 
					# Return the error message.
					$msg = "The password is not stored in cache"					
					Write-PISysAudit_LogMessage $msg "Error" $fn
					return $null
				}
				else
				{ 																				
					# Verbose only if Debug Level is 2+
					$msg = "The password stored in cached will be used for SQL connection"					
					Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2										
					
					# The CLU does not understand secure string and needs to get the raw password
					# Use the pointer method to reach the value in memory.
					$pwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePWDFromCache))
				}
			}
			else
			{				
				$pwd = GetPasswordOnDisk $PasswordFile				
			}

			$value = Invoke-Sqlcmd -Query $query -ServerInstance $SQLServerName -Username $UserName -Password $pwd | Select-Object -ExpandProperty $ScalarValue
		}
		else
		{
			$value = Invoke-Sqlcmd -Query $query -ServerInstance $SQLServerName | Select-Object -ExpandProperty $ScalarValue
		}
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred during the SQL Query: {0}"
		$msg = [string]::Format($msgTemplate, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		$value = $null
	}
	return $value
}

END {}

#***************************
#End of exported function
#***************************
}

function Import-PISysAuditComputerParamsFromCsv
{
<#
.SYNOPSIS
(Core functionality) Parse CSV file with components to audit.
.DESCRIPTION
Parse a CSV file with computer parameters and put them in the appropriate format 
to run an audit.  The CSV file must have the following headings: ComputerName, 
PISystemComponentType, InstanceName, IntegratedSecurity, SQLServerUserID, 
PasswordFile.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(															
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cpf")]
		[string]
		$ComputerParametersFile
		)
BEGIN {}
PROCESS		
{	
	$fn = GetFunctionName
	$ComputerParamsTable = $null
	If(Test-Path -Path $ComputerParametersFile)
	{
		$ComputerParameters = Import-Csv -Path $ComputerParametersFile
	}
	Else
	{
		$msg = "Computer parameters file not found."
		Write-PISysAudit_LogMessage $msg "Error" $fn -sc $true
		return $null
	}
	$sqlServerLabels = @('sql','sqlserver')
	Foreach($ComputerParameter in $ComputerParameters)
	{
		If($ComputerParameter.PISystemComponentType.ToLower() -in $sqlServerLabels)
		{
			If($ComputerParameter.IntegratedSecurity.ToLower() -eq 'false'){$ComputerParameter.IntegratedSecurity = $false}
			Else {$ComputerParameter.IntegratedSecurity = $true}
			$ComputerParamsTable = New-PISysAuditComputerParams -ComputerParamsTable $ComputerParamsTable `
																-ComputerName $ComputerParameter.ComputerName `
																-PISystemComponent $ComputerParameter.PISystemComponentType `
																-InstanceName $ComputerParameter.InstanceName `
																-IntegratedSecurity $ComputerParameter.IntegratedSecurity `
																-SQLServerUserID $ComputerParameter.SQLServerUserID `
																-PasswordFile $ComputerParameter.PasswordFile
		}
		Else
		{
			$ComputerParamsTable = New-PISysAuditComputerParams -ComputerParamsTable $ComputerParamsTable `
																-ComputerName $ComputerParameter.ComputerName `
																-PISystemComponent $ComputerParameter.PISystemComponentType
		}
					
	}
	return $ComputerParamsTable
}
END {}
}

function New-PISysAuditObject
{
<#
.SYNOPSIS
(Core functionality) Create an audit object and place it inside a hash table object.
.DESCRIPTION
Create an audit object and place it inside a hash table object.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(			
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]		
		[AllowEmptyString()]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[AllowEmptyString()]
		[alias("rcn")]
		[string]
		$RemoteComputerName,			
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditHashTable,		
		[parameter(Mandatory=$true, Position=3, ParameterSetName = "Default")]
		[alias("id")]
		[String]
		$AuditItemID,				
		[parameter(Mandatory=$true, Position=4, ParameterSetName = "Default")]
		[alias("ain")]
		[String]
		$AuditItemName,
		[parameter(Mandatory=$true, Position=5, ParameterSetName = "Default")]
		[alias("aiv")]
		[object]
		$AuditItemValue,
		[parameter(Mandatory=$true, Position=5, ParameterSetName = "Default")]
		[alias("aif")]
		[String]
		$AuditItemFunction,		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("msg")]
		[String]
		$MessageList = "",		
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("g1")]
		[String]
		$Group1 = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("g2")]
		[String]
		$Group2 = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("g3")]
		[String]
		$Group3 = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("g4")]
		[String]
		$Group4 = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("s")]
		[ValidateSet("Unknown", "N/A", "Low", "Moderate", "Severe")]
		[String]
		$Severity = "Low")
BEGIN {}
PROCESS		
{	
	$fn = GetFunctionName	

	# Define the server name to use for reporting.				
	$computerName = ResolveComputerName $LocalComputer $RemoteComputerName									
	
	# Create a custom object.
	$tempObj = New-Object PSCustomObject
	
	# Create an unique ID with the item ID and computer name.
	$myKey = $AuditItemID + "-" + $computerName
	
	# If the validation succeeds, there is no issue; if the validation fails, we can't accurately assess severity.
	if($AuditItemValue){$Severity = "N/A"}
	elseif($AuditItemValue -eq "N/A"){$Severity = "Unknown"}

	# Set the properties.
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ID" -Value $AuditItemID
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ServerName" -Value $computerName
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditItemName" -Value $AuditItemName
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditItemValue" -Value $AuditItemValue	
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditItemFunction" -Value $AuditItemFunction
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "MessageList" -Value $MessageList
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Group1" -Value $Group1
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Group2" -Value $Group2
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Group3" -Value $Group3
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Group4" -Value $Group4
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Severity" -Value $Severity
	
	# Add this custom object to the hash table.
	$AuditHashTable.Add($myKey, $tempObj)
		
	# Show partial results on screen.
	WriteHostPartialResult $tempObj
	
	# return the table
	return $AuditHashTable
}

END {}

#***************************
#End of exported function
#***************************
}

function New-PISysAuditError
{
<#
.SYNOPSIS
(Core functionality) Create an audit error object and place it inside a hash table object.
.DESCRIPTION
Create an audit error object and place it inside a hash table object.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[AllowEmptyString()]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[AllowEmptyString()]
		[alias("rcn")]
		[string]
		$RemoteComputerName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditHashTable,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("an")]
		[String]
		$AuditName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("fn")]
		[String]
		$FunctionName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("msg")]
		[String]
		$MessageList = "")

BEGIN {}
PROCESS		
{
	$fn = GetFunctionName

	# Define the server name to use for reporting.
	$computerName = ResolveComputerName $LocalComputer $RemoteComputerName

	# Create a custom object.
	$tempObj = New-Object PSCustomObject
	
	# Create an unique ID with format "ERROR_<function>-<computerName>
	$myKey = "ERROR_" + $FunctionName + "-" + $computerName
	
	# If the validation succeeds, there is no issue; if the validation fails, we can't accurately assess severity.

	# Set the properties.
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "Severity" -Value "Error"
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ServerName" -Value $computerName
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditName" -Value $AuditName
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "FunctionName" -Value $FunctionName
	Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "MessageList" -Value $MessageList
	
	# Add this custom object to the hash table.
	$AuditHashTable.Add($myKey, $tempObj)
	
	# return the table
	return $AuditHashTable
}

END {}

#***************************
#End of exported function
#***************************
}

function New-PISysAuditComputerParams
{
<#
.SYNOPSIS
Generate parameters that define the servers to audit with the New-PISysAuditReport cmdlet.
.DESCRIPTION
Generate parameters that define the servers to audit with the New-PISysAuditReport cmdlet.
The syntax is...
New-PISysAuditComputerParams [[-ComputerParamsTable | -cpt] <hashtable>]
								[[-ComputerName | -cn] <string>]
								[[-PISystemComponentType | -type] <string>]
								[-InstanceName <string>]
								[-IntegratedSecurity <boolean>]
								[[-SQLServerUserID | -user] <string>]
								[[-PasswordFile | -pf] <string>]
								[-ShowUI <boolean>]								
.INPUTS
.OUTPUTS
<hashtable> containing the PISysAuditComputerParams objects.
.PARAMETER cpt
Parameter table defining which computers/servers
to audit and for which PI System components. If a $null
value is passed or the parameter is skipped, the cmdlet
will assume to audit the local machine.
.PARAMETER type
PI System Component to audit.
PI, PIDataArchive, PIServer refer to a PI Data Archive component.
PIAF, PIAFServer, AF refer to a PI AF Server component.
SQL, SQLServer refer to a SQL Server component.
.PARAMETER InstanceName
Parameter to specify the instance name of your SQL Server. If a blank string
or "default" or "mssqlserver" is passed, this will refer to the default
instance.
.PARAMETER IntegratedSecurity
Use or not the Windows integrated security. Default is true.
.PARAMETER user
Specify a SQL user account to use if you are not using the
Windows integrated security.
.PARAMETER pf
Specifiy a file that will contained a ciphered password obtained with the
New-PISysAudit_PasswordOnDisk cmdlet. If not specify and the -user parameter
is configured, the end-user will be prompted to enter the password once. This
password will be kept securely in memory until the end of the execution.
.PARAMETER showui
Output messages on the command prompt or not.
.EXAMPLE
$cpt = New-PISysAuditComputerParams -cpt $cpt -cn "MyPIServer" -type "pi"
The -cpt will use the hashtable of parameters to know how to audit
The -dbgl switch sets the debug level to 2 (full debugging)
.LINK
https://pisquare.osisoft.com
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(											
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[AllowNull()]
		[alias("cpt")]
		[System.Collections.HashTable]
		$ComputerParamsTable,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]				
		[AllowEmptyString()]
		[alias("cn")]
		[string]		
		$ComputerName,
		[parameter(Mandatory=$true, Position=2, ParameterSetName = "Default")]						
		[ValidateSet(
					"PIServer", "PIDataArchive", "PIDA",
					"PIAFServer", "AFServer", "PIAF", "AF",
					"SQLServer", "SQL", "PICoresightServer", 
					"CoresightServer", "PICoresight", 
					"Coresight", "PICS", "CS")]
		[alias("type")]
		[string]		
		$PISystemComponentType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[string]
		$InstanceName = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]			
		[boolean]
		$IntegratedSecurity = $true,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("user")]
		[string]
		$SQLServerUserID = "",					
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("pf")]
		[string]
		$PasswordFile = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[boolean]
		$ShowUI = $true)
BEGIN {}
PROCESS		
{	
	$fn = GetFunctionName	
			
	# Initialize objects.
	$localComputer = $false		
	$resolvedComputerName = ""	
	if($null -eq $ComputerParamsTable) { $ComputerParamsTable = @{} }
	$skipParam = $false
		
	# ............................................................................................................
	# Initialize the module if needed
	# ............................................................................................................
	Initialize-PISysAudit -ShowUI $ShowUI

	# Read from the global constant bag.
	$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		
	# If initialization failed, leave!
	if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
	{
		$msg = "PI System Audit Module initialization failed"
		Write-PISysAudit_LogMessage $msg "Error" $fn
		return
	}		
	
	# ............................................................................................................
	# Validate if computer name refers to a local or remote entity and perform substitution if required.
	# ............................................................................................................
	
	# Obtain the machine name from the environment variable.
	$localComputerName = get-content env:computername
	
	# Validate if the server name refers to the local one	
	if(($ComputerName -eq "") -or ($ComputerName.ToLower() -eq "localhost"))
	{												
		$resolvedComputerName = $localComputerName.ToLower()
		$localComputer = $true
	}
	elseif($localComputerName.ToLower() -eq $ComputerName.ToLower())
	{									
		$resolvedComputerName = $localComputerName.ToLower()
		$localComputer = $true
	}
	else
	{			
		$localComputer = $false			
		$resolvedComputerName = $ComputerName.ToLower()
	}		
	
	# ............................................................................................................
	# Create an object to manipulate that contains the directives on what to audit.
	# ............................................................................................................	
	# Create a custom object (PISysAuditComputerParams).
	$tempObj = New-Object PSCustomObject
	
	if(($PISystemComponentType.ToLower() -eq "piserver") -or `
		($PISystemComponentType.ToLower() -eq "pidataarchive") -or `
		($PISystemComponentType.ToLower() -eq "pida") -or `
		($PISystemComponentType.ToLower() -eq "dataarchive"))
	{
		# Set the properties.
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer		
		# Use normalized type description as 'PIDataArchive'
		$AuditRoleType = "PIDataArchive"
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditRoleType" -Value $AuditRoleType
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "InstanceName" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IntegratedSecurity" -Value $null	
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "SQLServerUserID" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PasswordFile" -Value $null		
	}
	elseif(($PISystemComponentType.ToLower() -eq "piafserver") -or `
		($PISystemComponentType.ToLower() -eq "afserver") -or `
		($PISystemComponentType.ToLower() -eq "piaf") -or `
		($PISystemComponentType.ToLower() -eq "af"))
	{
		# Set the properties.
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer		
		# Use normalized type description as 'PIAFServer'
		$AuditRoleType = "PIAFServer"
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditRoleType" -Value $AuditRoleType
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "InstanceName" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IntegratedSecurity" -Value $null	
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "SQLServerUserID" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PasswordFile" -Value $null		
	}
	elseif(($PISystemComponentType.ToLower() -eq "sqlserver") -or `
		($PISystemComponentType.ToLower() -eq "sql"))
	{		
		# Set the properties.
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer		
		# Use normalized type description as 'SQLServer'
		$AuditRoleType = "SQLServer"
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditRoleType" -Value $AuditRoleType
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "InstanceName" -Value $InstanceName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IntegratedSecurity" -Value $IntegratedSecurity	
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "SQLServerUserID" -Value $SQLServerUserID
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PasswordFile" -Value $PasswordFile				
		
		# Test if a user name has been passed if Window integrated security is not used
		if($IntegratedSecurity -eq $false)
		{
			if($SQLServerUserID -eq "")
			{
				$msg = "No user name has been given. This parameter will be skipped"
				Write-PISysAudit_LogMessage $msg "Error" $fn -sc $true
				$skipParam = $true			
			}						
			else
			{
				if($PasswordFile -eq "") 
				{
					# Warning message to the end-user that a password will be asked
					# before the first query is executed.
					$msg = "You will be prompted for the SQL user account password before the first query!"
					Write-PISysAudit_LogMessage $msg "Warning" $fn -sc $true
					$skipParam = $false
				}
				else 
				{
					# Read from the global constant bag.		
					$pwdPath = (Get-Variable "PasswordPath" -Scope "Global").Value			
					# Set the path.
					$pwdFile = PathConcat -ParentPath $pwdPath -ChildPath $PasswordFile
	
					# Test the password file
					if((Test-Path $pwdFile) -eq $false)
					{									
						$msg = "The password file specified cannot be found. If you haven't defined one" `
									+ " yet, use the New-PISysAudit_PasswordOnDisk cmdlet to create one. This parameter will be skipped"
						Write-PISysAudit_LogMessage $msg "Error" $fn -sc $true
						$skipParam = $true
					}
				}
			}
		}	
	}
	elseif (($PISystemComponentType.ToLower() -eq "picoresightserver") -or `
		($PISystemComponentType.ToLower() -eq "picoresight") -or `
		($PISystemComponentType.ToLower() -eq "coresightserver") -or `
		($PISystemComponentType.ToLower() -eq "coresight") -or `
		($PISystemComponentType.ToLower() -eq "cs") -or `
		($PISystemComponentType.ToLower() -eq "pics"))
	{
		# Set the properties.
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer		
		# Use normalized type description as 'PICoresightServer'
		$AuditRoleType = "PICoresightServer"
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "AuditRoleType" -Value $AuditRoleType
		# Nullify all of the MS SQL specific values
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "InstanceName" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "IntegratedSecurity" -Value $null	
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "SQLServerUserID" -Value $null
		Add-Member -InputObject $tempObj -MemberType NoteProperty -Name "PasswordFile" -Value $null		
	}

	# Add hashtable item and computer audit if not already in params table
	if(-not $ComputerParamsTable.Contains($resolvedComputerName))
	{
		# Build object for Computer audit
		$computerObj = New-Object PSCustomObject
		Add-Member -InputObject $computerObj -MemberType NoteProperty -Name "ComputerName" -Value $resolvedComputerName
		Add-Member -InputObject $computerObj -MemberType NoteProperty -Name "IsLocal" -Value $localComputer
		Add-Member -InputObject $computerObj -MemberType NoteProperty -Name "AuditRoleType" -Value "Computer"

		# Add computer audit as part of an array
		$ComputerParamsTable[$resolvedComputerName] = @($computerObj)
	}

	# Skip the addition of the new parameter or not.
	if($skipParam -eq $false)
	{
		# Check for an existing check of this role on this machine
		$existingCheck = $ComputerParamsTable[$resolvedComputerName] | Where-Object AuditRoleType -EQ $tempObj.AuditRoleType
		
		if($null -eq $existingCheck)
		{
			$ComputerParamsTable[$resolvedComputerName] += $tempObj
		}
	}
		
	# Return the computer parameters table.
	return $ComputerParamsTable	
}

END {}

#***************************
#End of exported function
#***************************
}

function Write-PISysAuditReport
{
<#
.SYNOPSIS
(Core functionality) Writes a report of all checks performed.
.DESCRIPTION
Writes a concise CSV report of all checks performed and optionally a detailed HTML report.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditHashTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("obf")]
		[boolean]
		$ObfuscateSensitiveData = $false,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dtl")]
		[boolean]
		$DetailReport = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("cpt")]
		[System.Collections.HashTable]
		$ComputerParamsTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{		
	$fn = GetFunctionName

	try
	{
		# Get the current timestamp for naming the file uniquely.
		$now = Get-Date
		$reportTimestamp = $now.ToString("dd-MMM-yyyy HH:mm:ss")
		$reportFileTimestamp = $now.ToString("yyyy-MM-dd_HH-mm-ss")		
		
		# Generate Bow Tie diagrams and get file paths
		$bowTieReports = Write-PISysAudit_BowTieDiagrams -at $AuditHashTable -cpt $ComputerParamsTable -ts $now -dbgl $DBGLevel

		# Get the Scripts path.
		$exportPath = (Get-Variable "ExportPath" -Scope "Global").Value												
						
		# Create the log file in the same folder as the script. 
		$fileName = "PISecurityAudit_$reportFileTimestamp.csv"
		$fileToExport = PathConcat -ParentPath $exportPath -ChildPath $fileName

		# Build a collection for errors
		$errs = @()
		foreach($item in $AuditHashTable.GetEnumerator() | Where-Object Name -Like "ERROR*")
		{
			$errs += $item.Value
		}

		# Build a collection for output.
		$results = @()
		foreach($item in $AuditHashTable.GetEnumerator() | Where-Object Name -NotLike "ERROR*")
		{
			# Protect sensitive data if necessary.
			if($ObfuscateSensitiveData)
			{		
				# Obfuscate the server name.
				$newServerName = NewObfuscateValue $item.Value.ServerName
				$item.Value.ServerName = $newServerName							
			}
			
			# Transform the true/false answer into Pass/Fail one.
			if($item.Value.AuditItemValue -eq $true)
			{ $item.Value.AuditItemValue = "Pass" }
			elseif($item.Value.AuditItemValue -eq $false)
			{ $item.Value.AuditItemValue = "Fail" }
			
			# Add to collection.
			$results += $item.Value	
		}
		
		# Export to .csv but sort the results table first to have Failed items on the top sorted by Severity 
		$results = $results | Sort-Object   @{Expression="AuditItemValue";Descending=$false}, `
											@{Expression="Severity";Descending=$true}, `
											@{Expression="ServerName";Descending=$false}, `
											@{Expression="ID";Descending=$false}
		$results | Export-Csv -Path $fileToExport -Encoding ASCII -NoType
	
		
		if($DetailReport){
			
			$fileName = "PISecurityAudit_DetailReport_$reportFileTimestamp.html" 

			$fileToExport = PathConcat -ParentPath $exportPath -ChildPath $fileName

			# Construct HTML table for errors
			$errorRows = ""
			if($errs){ 
				foreach($err in $errs)
				{
					$style = "`"error`""
					$errorRow = @"
					<tr class=$style>
						<td>$($err.Severity)</td>
						<td>$($err.ServerName)</td>
						<td>$($err.AuditName)</td>
						<td>$($err.MessageList)</td>
					</tr>
"@
					$errorRows += $errorRow
				}
				$errorTable = @"
					<table class="errortable table">
						<thead>
							<tr>
								<th colspan="4">Errors</th>
							</tr>
						</thead>
						<thead>
							<tr>
								<th>Severity</th>
								<th>Server</th>
								<th>Audit Name</th>
								<th>Message</th>
							</tr>
						</thead>
						$errorRows
					</table>
					<br/>
"@
			}

			# Construct HTML table and color code the rows by result and severity.
			$tableRows=""
			foreach($result in $results) 
			{
				$highlight = "`"`""
				switch ($result.Severity.ToLower())
				{
					"severe" {$highlight="`"severe`""; break}
					"moderate" {$highlight="`"moderate`""; break}
					"low" {$highlight="`"low`""; break}
				}
				if ($result.AuditItemValue -eq "N/A") {$highlight="`"error`""}
	
				$anchorTag=""
				if($result.AuditItemValue -ieq "fail"){
					$anchorTag = @"
					<a href="#$($result.ID)">
"@
				}
				$tableRow = @"
				<tr class=$highlight>
					<td>$anchorTag$($result.ID)</a></td>
					<td>$($result.ServerName)</td>
					<td>$($result.AuditItemName)</td>
					<td>$($result.AuditItemValue)</td>
					<td>$($result.Severity)</td>
					<td>$($result.MessageList)</td>
					<td>$($result.Group1)</td>
					<td>$($result.Group2)</td>
				</tr>
"@ 
				$tableRows+= $tableRow
			}



			# Get failed results and construct the recommendation section
			$fails=@()
			$fails = $results | Where-Object {$_.AuditItemValue -ieq "fail"}

			$recommendations=""
			if($null -ne $fails){
				$recommendations = "<div>
										<h2>Recommendations for failed validations:</h2>"
		
				$fails | ForEach-Object{
					$AuditFunctionName = $_.AuditItemFunction
					$recommendationInfo = Get-Help $AuditFunctionName
					if($PSVersionTable.PSVersion.Major -eq 2){$recommendationInfoDescription = $recommendationInfo.Description[0].Text} 
					else {$recommendationInfoDescription = $recommendationInfo.Description.Text}
					$recommendations +=@"
					<b id="$($_.ID)">$($recommendationInfo.Synopsis)</b>
					<br/>
					<p>$recommendationInfoDescription</p>
					<br/>
"@
				}
				$recommendations+="</div>"
			}
			

			# HTML report. 
			$reportHTML = @"
			<html>
				<head><meta name="viewport" content="width=device-width" />
					<style type="text/css">
						body {
							font-size: 100%;
							font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;
						}
						h2{
							font-size: 1.875em;
						}
						p{
							font-size: 0.875em;
							}
						a{
							color: black;
						}
	
						.summarytable {
							width: 100%;
							border-collapse: collapse;
							}

						.summarytable td, .summarytable th {
							border: 1px solid #ddd;
							font-size: 0.875em;
						}
						.summarytable th{
							background-color: #f2f2f2;
						}

						.errortable {
							width: 100%;
							border-collapse: collapse;
							}

						.errortable td, .errortable th {
							border: 1px solid #ddd;
							font-size: 0.875em;
						}
						.errortable th{
							background-color: #f2f2f2;
						}

			
						.low{
							background-color: #FFF59D;
						}
			
						.moderate{
							background-color: #FFCC80;
						}
						.severe{
							background-color: #FFAB91;
						}
						.error{
							color: #FF0000;
						}
					</style>

			
				</head>
				<body>
					<div style="padding-bottom:1em">
						<h2>AUDIT SUMMARY </h2>
						<h4>$reportTimestamp</h4> 
					</div>

					$errorTable

					<table class="summarytable table">
						<thead>
							<tr>
								<th colspan="8">Audit Results</th>
							</tr>
						</thead>
						<thead>	
							<tr>
								<th>ID</th>
								<th>Server</th>
								<th>Validation</th>
								<th>Result</th> 
								<th>Severity</th>
								<th>Message</th>
								<th>Category</th> 
								<th>Area</th>
							</tr>
						</thead>
						$tableRows
					</table>
			
					<br/>

					$Recommendations
					
				</body>
			</html>
"@		
			# Print report to file.
			$reportHTML | Out-File $fileToExport
		}
		# Return the report name.
		return $fileName
		
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred during generation of the report"
		$msg = [string]::Format($msgTemplate, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		return $null
	}	
}	

END {}

#***************************
#End of exported function
#***************************
}

function Write-PISysAudit_BowTieDiagrams
{
<#
.SYNOPSIS
Generate Bow Tie Diagrams for a table of Audit Results.
(Core functionality) 
.DESCRIPTION
Uses the SVG templates in Scripts\Utilities to generate SVG documents
that map audit results to the corresponding section of the role's 
bow tie diagram.

Generated files placed in the Exports folder.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditHashTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("cpt")]
		[System.Collections.HashTable]
		$ComputerParamsTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("ts")]
		[datetime]
		$ReportTimestamp,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{		
	$fn = GetFunctionName

	try
	{
		# Get the current timestamp for naming the file uniquely.
		if($ReportTimestamp) { $now = $ReportTimestamp }
		else { $now = Get-Date }
		$reportTimestamp = $now.ToString("dd-MMM-yyyy HH:mm:ss")
		$reportFileTimestamp = $now.ToString("yyyy-MM-dd_HH-mm-ss")

		# Get the Export and Scripts path.
		$exportPath = (Get-Variable "ExportPath" -Scope "Global").Value
		$scriptsPath = (Get-Variable "ScriptsPath" -Scope "Global").Value

		# Initialize hashtable to hold generated report info
		# Key: machine name (UPPERCASE)
		# Value: array of report filepaths for this machine
		$generatedReports = @{}

		# PI Data Archive: load template
		$daTemplatePath = PathConcat -ParentPath $scriptsPath -ChildPath "Utilities\BowTie_PIDataArchive.svg"
		$daTemplate = Get-Content -Path $daTemplatePath

		# PI AF Server: load template
		# .......
		# TO DO
		# .......

		# PI Coresight: load template
		# .......
		# TO DO
		# .......

		foreach($machine in $ComputerParamsTable.GetEnumerator())
		{
			# Filter audit results to return only this machine. Skip if no results
			$allMachineResults = $AuditHashTable.GetEnumerator() | Where-Object { $_.Value.ServerName -ieq $machine.Name }
			if($null -eq $allMachineResults) { continue }
			
			if($machine.Value.AuditRoleType -contains 'PIDataArchive')
			{
				# Filter machine results for PI Data Archive results, skip PI Data Archive bowtie if empty
				$dataArchiveResults = $allMachineResults.GetEnumerator() | Where-Object { $_.Value.ID -ilike 'AU2*' }
				if($null -eq $dataArchiveResults) { continue }

				# Filter results for Computer + PI Data Archive results
				$relevantResults = $allMachineResults.GetEnumerator() | Where-Object { $_.Value.ID -ilike 'AU1*' -or $_.Value.ID -ilike 'AU2*' }
				
				# Get template, set export path
				$svgDoc = $daTemplate
				$fileName = "BowTie_$($machine.Name)_PIDataArchive_$reportFileTimestamp.svg"
				$fileToExport = PathConcat -ParentPath $exportPath -ChildPath $fileName

				# Set Title on SVG
				$titleString = "PI Data Archive Bow Tie Diagram"
				$svgDoc = $svgDoc -replace '%Title%', $titleString

				# Set timestamp
				$svgDoc = $svgDoc -replace '%Timestamp%', $reportTimestamp

				# Set machine name
				$svgDoc = $svgDoc -replace '%MachineName%', $machine.Name.ToUpper()

				# Iterate through results, apply colors for results
				foreach($item in $relevantResults.GetEnumerator())
				{
					$auditItem = $item.Value

					# Set item color
					if($auditItem.AuditItemValue -eq $true)
					{
						$class = 'pass'
					}
					elseif($auditItem.AuditItemValue -eq $false)
					{
						switch($auditItem.Severity.ToLower())
						{
							'low'      { $class = 'low' } 
							'moderate' { $class = 'moderate' } 
							'severe'   { $class = 'severe' } 
							default    { $class = 'na' } 
						}
					}
					else
					{
						$class = 'na'
					}

					# Replace each occurrance of %AUxxxxx% with the class
					# Colors defined in CSS style of SVG template
					$svgDoc = $svgDoc -replace "%$($auditItem.ID)%", $class
					
				}

				# Save SVG BowTie report, add path to list of reports
				$svgDoc | Out-File -FilePath $fileToExport
				if($generatedReports.Contains($machine.Name.ToUpper())) 
				{
					$generatedReports[$machine.Name.ToUpper()] += $fileToExport
				}
				else 
				{
					$generatedReports += @{$machine.Name.ToUpper()=@($fileToExport)} 
				}
			} 

			if($machine.Value.AuditRoleType -contains 'PIAFServer')
			{
				# .......
				# TO DO
				# .......
			}

			if($machine.Value.AuditRoleType -contains 'PICoresightServer')
			{
				# .......
				# TO DO
				# .......
			}
		}

		return $generatedReports
	}
	catch
	{
		# Return the error message.
		$msgTemplate = "A problem occurred during generation of the report"
		$msg = [string]::Format($msgTemplate, $_.Exception.Message)
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_		
		return $null
	}	
}	

END {}

#***************************
#End of exported function
#***************************
}



function New-PISysAuditReport
{
<#  
.SYNOPSIS
Generate a PI System audit report.
.DESCRIPTION
Generate a PI System audit report. The syntax is...				 
New-PISysAuditReport [[-ComputerParamsTable | -cpt] <hashtable>]
 					 [[-ObfuscateSensitiveData | -obf] <boolean>]
					 [-ShowUI <boolean>]
					 [[-DBGLevel | -dbgl] <int>]
.INPUTS
.OUTPUTS
.PARAMETER ComputerParamsTable
Alias: -cpt
Parameter table defining which computers/servers
to audit and for which PI System components. If a $null
value is passed or the parameter is skipped, the cmdlet
will assume to audit the local machine, unless cpf 
specifies a CSV file.
.PARAMETER ComputerParametersFile
Alias: -cpf
CSV file defining which computers/servers to audit and 
for which PI System components. Headings must be included 
in the CSV file.  See example 7 in the conceptual help.
.PARAMETER ObfuscateSensitiveData
Alias: -obf
Obfuscate or not the name of computers/servers
exposed in the audit report.
.PARAMETER ShowUI
Enable or disable message output and progress bar on the command prompt.
.PARAMETER DetailReport
Alias: -dtl
Enable or disable creation of detailed HTML report at end of audit.
.PARAMETER AuditLevel
Alias: -lvl
Choose level of audit to be performed. Higher levels may result
in slow runtimes.
.PARAMETER DBGLevel
Alias: -dbgl
DebugLevel: 0 for no verbose, 1 for intermediary message
to help debugging, 2 for full level of details
.EXAMPLE
New-PISysAuditReport -cpt $cpt -obf $false
The -cpt switch will use the hashtable of parameters to know how to audit
The -cpf switch can be used to load parameters from a CSV file
The -obf switch deactivate the obfuscation of the server name.
The -dbgl switch sets the debug level to 2 (full debugging)
.EXAMPLE
New-PISysAuditReport -cpt $cpt -dbgl 2 -lvl Verbose
-- See Example 1 for explanations of switch -cpt
-- The -dbgl switch sets the debug level to 2 (full debugging)
-- The -lvl switch sets the audit level to 'Verbose'
.LINK
https://pisquare.osisoft.com
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(											
		[parameter(Mandatory=$false, ParameterSetName = "Default")]										
		[alias("cpt")]
		[System.Collections.HashTable]				
		$ComputerParamsTable = $null,	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]										
		[alias("cpf")]
		[string]
		$ComputerParametersFile,	
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("obf")]
		[boolean]
		$ObfuscateSensitiveData = $false,				
		[parameter(Mandatory=$false, ParameterSetName = "Default")]				
		[boolean]
		$ShowUI = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dtl")]
		[boolean]
		$DetailReport = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[ValidateSet("Basic", "Verbose")]
		[string]
		$AuditLevel = "Basic",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		

BEGIN {}
PROCESS
{							
	# Get and store the function Name.
	$fn = GetFunctionName
	
	# ............................................................................................................
	# Initialize the module if needed
	# ............................................................................................................
	Initialize-PISysAudit -ShowUI $ShowUI -dbgl $DBGLevel
	
	# Read from the global constant bag.
	$isPISysAuditInitialized = (Get-Variable "PISysAuditInitialized" -Scope "Global" -ErrorAction "SilentlyContinue").Value					
		
	# If initialization failed, leave!
	if(($null -eq $isPISysAuditInitialized) -or ($isPISysAuditInitialized -eq $false))
	{
		$msg = "PI System Audit Module initialization failed"
		Write-PISysAudit_LogMessage $msg "Error" $fn
		return
	}		
	
	# Initialize some objects.
	$ActivityMsg = "Launch analysis on PI System"
	$statusMsgCompleted = "Completed"

	# Map AuditLevel to the internal AuditLevelInt integer
	switch($AuditLevel)
	{
		"Basic"   { $AuditLevelInt = 1 }
		"Verbose" { $AuditLevelInt = 8 }
		default   { $AuditLevelInt = 1 }
	}
	
	# Write the first message in the log file.
	$msg = "----- Start the audit -----"
	Write-PISysAudit_LogMessage $msg "Info" $fn		
			
	# Add 1 line of padding before showing audit failure list
	if($ShowUI)
	{ Write-Host "`r`n"	}

	# Write headers for issues that are found
	$msg = "{0,-9} {1,-8} {2,-20} {3,40}"
	Write-Host ($msg -f 'Severity','ID','Server','Audit Item Name')
	Write-Host ('-' * 80)
	
	# ............................................................................................................
	# Initialize the table of results
	# ............................................................................................................
	$auditHashTable = @{}	
	
	# ............................................................................................................
	# Validate if a ComputerParams table has been passed, if not create one that use localhost as the default
	# ............................................................................................................
	if($null -eq $ComputerParamsTable)
	{
		# Initialize.
		$ComputerParamsTable = @{}
		
		if($null -eq $ComputerParametersFile -or $ComputerParametersFile -eq "")
		{
			# This means an audit on the local computer is required only PI Data Archive and PI AF Server are checked by default.
			# SQL Server checks ommitted by default as SQL Server will often require an instancename
			$ComputerParamsTable = New-PISysAuditComputerParams $ComputerParamsTable "localhost" "PIServer"
			$ComputerParamsTable = New-PISysAuditComputerParams $ComputerParamsTable "localhost" "PIAFServer"
		}
		Else
		{
			$ComputerParamsTable = Import-PISysAuditComputerParamsFromCsv -cpf $ComputerParametersFile
		}	
	}

	# ............................................................................................................
	# Get total count of audit role checks to be performed, prep messages for progress bar
	# ............................................................................................................						
	$totalCheckCount = 0
	foreach($cpt in $ComputerParamsTable.GetEnumerator())
	{
		$totalCheckCount += $cpt.Value.Count
	}
	$currCheck = 1
	$ActivityMsg = "Performing $AuditLevel PI System Security Audit"
	$statusMsgTemplate = "Checking Role {0}/{1}..."
	$statusMsgCompleted = "Completed"	

	# ....................................................................................
	# For each computer, perform checks for all roles
	# ....................................................................................						
	foreach($item in $ComputerParamsTable.GetEnumerator())
	{
		# Run no checks if WSMan is not available
		if((ValidateWSMan -cp $item -at $auditHashTable -dbgl $DBGLevel) -EQ $true)
		{
			foreach($role in $item.Value)
			{
				# Write status to progress bar
				$statusMsg = [string]::Format($statusMsgTemplate, $currCheck, $totalCheckCount)
				$pctComplete = ($currCheck - 1) / $totalCheckCount * 100
				Write-Progress -Activity $ActivityMsg -Status $statusMsg -Id 1 -PercentComplete $pctComplete
		
				# Proceed based on component type.
				if($role.AuditRoleType -eq "Computer")
				{ StartComputerAudit $auditHashTable $role -lvl $AuditLevelInt -dbgl $DBGLevel }
				elseif($role.AuditRoleType -eq "PIDataArchive")
				{ StartPIDataArchiveAudit $auditHashTable $role -lvl $AuditLevelInt -dbgl $DBGLevel }		
				elseif($role.AuditRoleType -eq "PIAFServer")
				{ StartPIAFServerAudit $auditHashTable $role -lvl $AuditLevelInt -dbgl $DBGLevel }
				elseif($role.AuditRoleType -eq "SQLServer")
				{ StartSQLServerAudit $auditHashTable $role -lvl $AuditLevelInt -dbgl $DBGLevel }
				elseif($role.AuditRoleType -eq "PICoresightServer")
				{ StartPICoresightServerAudit $auditHashTable $role -lvl $AuditLevelInt -dbgl $DBGLevel}

				$currCheck++
			}
		}
		else
		{
			# Skip progress bar ahead for these ckecks since WSman failed
			$currCheck += $item.Value.Count
		}
	}
	Write-Progress -Activity $ActivityMsg -Status $statusMsgCompleted -Id 1 -Completed

	# Pad console ouput with one line
	Write-Host "`r`n"

	# ....................................................................................
	# Show results.
	# ....................................................................................		
	$ActivityMsg = "Generate report"
	if($ShowUI) { Write-Progress -activity $ActivityMsg -Status "in progress..." -Id 1 }
	$reportName = Write-PISysAuditReport $auditHashTable -obf $ObfuscateSensitiveData -dtl $DetailReport -cpt $ComputerParamsTable -dbgl $DBGLevel
	if($ShowUI) { Write-Progress -activity $ActivityMsg -Status $statusMsgCompleted -Id 1 -completed }
	
	# ............................................................................................................
	# Display that the analysis is completed and where the report can be found.
	# ............................................................................................................				
	# Read from the global constant bag.
	$exportPath = (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value										

	$msg = "Report file:     $reportName"
	Write-PISysAudit_LogMessage $msg "Info" $fn -sc $true
	$msg = "Report location: $exportPath"
	Write-PISysAudit_LogMessage $msg "Info" $fn -sc $true
	$msg = "----- Audit Completed -----"
	Write-PISysAudit_LogMessage $msg "Info" $fn 
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Add your core function by replacing the Verb-PISysAudit_TemplateCore one.
# Implement the functionality you want. Don't forget to modify the parameters
# if necessary.
# ........................................................................
function Verb-PISysAudit_TemplateCore
{
<#
.SYNOPSIS
Add a synopsis.
.DESCRIPTION
Add a description.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]
		[alias("cp")]		
		$ComputerParams,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{		
	$fn = GetFunctionName
	
	# ........................................................................
	# Add your code here...
	# ........................................................................
}	

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Create an alias on the cmdlet
# ........................................................................
# <Do not remove>
Set-Alias piaudit New-PISysAuditReport
Set-Alias piauditparams New-PISysAuditComputerParams
Set-Alias pisysauditparams New-PISysAuditComputerParams
Set-Alias pwdondisk New-PISysAudit_PasswordOnDisk
# </Do not remove>
 
# ........................................................................
# Export Module Member
# ........................................................................
# <Do not remove>
Export-ModuleMember PathConcat
Export-ModuleMember Initialize-PISysAudit
Export-ModuleMember Set-PISysAudit_SaltKey
Export-ModuleMember Get-PISysAudit_EnvVariable
Export-ModuleMember Get-PISysAudit_RegistryKeyValue
Export-ModuleMember Get-PISysAudit_TestRegistryKey
Export-ModuleMember Get-PISysAudit_ParseDomainAndUserFromString
Export-ModuleMember Get-PISysAudit_ServiceProperty
Export-ModuleMember Get-PISysAudit_AccountProperty
Export-ModuleMember Get-PISysAudit_CertificateProperty
Export-ModuleMember Get-PISysAudit_BoundCertificate
Export-ModuleMember Get-PISysAudit_ResolveDnsName
Export-ModuleMember Get-PISysAudit_GroupMembers
Export-ModuleMember Get-PISysAudit_CheckPrivilege
Export-ModuleMember Get-PISysAudit_InstalledComponents
Export-ModuleMember Get-PISysAudit_InstalledKBs
Export-ModuleMember Get-PISysAudit_InstalledWin32Feature
Export-ModuleMember Get-PISysAudit_FirewallState
Export-ModuleMember Get-PISysAudit_AppLockerState
Export-ModuleMember Get-PISysAudit_KnownServers
Export-ModuleMember Get-PISysAudit_ProcessedPIConnectionStatistics
Export-ModuleMember Test-PISysAudit_SecurePIConnections
Export-ModuleMember Test-PISysAudit_ServicePrincipalName
Export-ModuleMember Test-PISysAudit_PrincipalOrGroupType
Export-ModuleMember Invoke-PISysAudit_AFDiagCommand
Export-ModuleMember Invoke-PISysAudit_ADONET_ScalarValueFromSQLServerQuery
Export-ModuleMember Invoke-PISysAudit_Sqlcmd_ScalarValue
Export-ModuleMember Invoke-PISysAudit_SPN
Export-ModuleMember New-PISysAuditObject
Export-ModuleMember New-PISysAuditError
Export-ModuleMember New-PISysAudit_PasswordOnDisk
Export-ModuleMember New-PISysAuditComputerParams
Export-ModuleMember New-PISysAuditReport
Export-ModuleMember Write-PISysAuditReport
Export-ModuleMember Write-PISysAudit_BowTieDiagrams
Export-ModuleMember Write-PISysAudit_LogMessage
Export-ModuleMember -Alias piauditparams
Export-ModuleMember -Alias pisysauditparams
Export-ModuleMember -Alias piaudit
Export-ModuleMember -Alias pwdondisk
Export-ModuleMember Test-PowerShellToolsForPISystemAvailable
Export-ModuleMember Test-WebAdministrationModuleAvailable
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Verb-PISysAudit_TemplateCore with the name of your
# function.
# ........................................................................
# Export-ModuleMember Verb-PISysAudit_TemplateCore
