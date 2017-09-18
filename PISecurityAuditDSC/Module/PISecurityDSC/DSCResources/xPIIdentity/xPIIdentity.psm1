function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."


    <#
    $returnValue = @{
    CanDelete = [System.Boolean]
    Enabled = [System.Boolean]
    PIDataArchive = [System.String]
    Ensure = [System.String]
    AllowUseInTrusts = [System.Boolean]
    Name = [System.String]
    AllowExplicitLogin = [System.Boolean]
    AllowUseInMappings = [System.Boolean]
    }

    $returnValue
    #>
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.Boolean]
        $CanDelete,

        [System.Boolean]
        $Enabled,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Boolean]
        $AllowUseInTrusts,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.Boolean]
        $AllowExplicitLogin,

        [System.Boolean]
        $AllowUseInMappings
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."

    #Include this line if the resource requires a system reboot.
    #$global:DSCMachineStatus = 1


}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.Boolean]
        $CanDelete,

        [System.Boolean]
        $Enabled,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Boolean]
        $AllowUseInTrusts,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.Boolean]
        $AllowExplicitLogin,

        [System.Boolean]
        $AllowUseInMappings
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."


    <#
    $result = [System.Boolean]
    
    $result
    #>
}


Export-ModuleMember -Function *-TargetResource

