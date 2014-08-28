##
#
# vElemental
# @clintonskitson
#
# 08/15/2013
# avamar_vcops.psm1 - Avamar and VMware vSphere (PowerCLI)/vCOps cmdlets for reporting on Virtual Machine image backups and posting them to vCenter Operations
#
# Avamar 6.1/7, vSphere 5.0/5.1, vCOps 5.6/5.7
#
##

$global:sPath = (Split-Path -parent $MyInvocation.MyCommand.Definition)

#Connect-AvamarLoginProfile -name profile1
Function Connect-AvamarLoginProfile {
    [CmdletBinding()]
    param($name,[array]$only)
    Begin {
        function Decrypt-SecureString {
        param(
            [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)]
            [System.Security.SecureString]
            $sstr
        )
            $marshal = [System.Runtime.InteropServices.Marshal]
            $ptr = $marshal::SecureStringToBSTR( $sstr )
            $str = $marshal::PtrToStringBSTR( $ptr )
            $marshal::ZeroFreeBSTR( $ptr )
            $str
        }
    }
    Process {
        $loginProfile = Get-AvamarLoginProfile -name $name
        $loginProfile.keys | %{ $loginProfile.$_.password = $loginProfile.$_.password | Decrypt-SecureString }
        [array]$arrNames = @(@{name="avamar";pName="Avamar";cmdlet="Connect-Avamar"},
                             @{name="viserver";pName="vCenter Server";cmdlet="Connect-VIServer -wa 0"},
                             @{name="avamardb";pName="Avamar Postgres DB";cmdlet="Connect-AvamarPostgres"},
                             @{name="vcops";pName="vCenter Operations";cmdlet="Connect-vCOpsServer"})
        try {
            $loginProfile.keys | %{
                $loginProfileName = $_
                $tServer = $arrNames | where {$_.name -eq $loginProfileName}
                if(!$only -or $only -eq ($tServer.name)) {
                    Write-Host "$(Get-Date): Connecting to $($tServer.pName)" 
                    Invoke-Expression "$($tServer.cmdlet) -server `$loginProfile.$($tServer.name).server -username `$loginProfile.$($tServer.name).username -password `$loginProfile.$($tServer.name).password"
                }
            }
        } catch {
            Write-Error "Problem connecting to $($tServer.name) instance at $($loginProfile.($tServer.name).server)"
            Throw $_
        }
    }
}

Function Disconnect-AvamarLoginProfile {
    [CmdletBinding()]
    Param($name,[array]$only)
    Process {
        $loginProfile = Get-AvamarLoginProfile -name $name
        [array]$arrNames = @(@{name="avamar";pName="Avamar";cmdlet="Disconnect-Avamar -server"},
                             @{name="viserver";pName="vCenter Server";cmdlet="Disconnect-VIServer -confirm:`$False -server"},
                             @{name="avamardb";pName="Avamar Postgres DB";cmdlet="Disconnect-vPostgres -server "})
        $arrNames | %{
            $tServer = $_
            if($loginProfile.($tServer.name)) {
                Write-Host "$(Get-Date): Disconnecting from $($tServer.pName)"
                Invoke-Expression "$($tServer.cmdlet) `$loginProfile.$($tServer.name).server"
            }
        }
    }
}


#Connect-AvamarLoginProfile -name brslab -only avamar
#Connect-AvamarLoginProfile -name brslab -only AvamarDB
#Connect-AvamarLoginProfile -name brslab -only VIServer
#Connect-AvamarLoginProfile -name brslab -only vCOps
#Connect-AvamarLoginProfile -name brslab
Function Get-AvamarLoginProfile {
    [CmdletBinding()]
    Param($name)
    Process {
    	if ($name) {
            if (Get-Item "$($global:sPath)\loginprofile_$($name).clixml" -ea 0 ) {
	            Import-CliXml "$($global:sPath)\loginprofile_$($name).clixml"
            }
	    }
        else {
            (Get-Item "$($global:sPath)\loginprofile_*clixml").Name -replace "loginprofile_","" -replace ".clixml",""
        }
    }
}


#New-AvamarLoginProfile -shortcut -name "profile1" -LoginProfile  @{
#            Avamar=@{server="ip/dns";username="MCUser";password='MCpass'}
#            AvamarDB=@{server="ip/dns";username="viewuser";password='viewpass'}
#            VIServer=@{server="ip/dns";username="administrator";password='password'}
#            vCOps=@{server="ip/dns";username="admin";password='password'}
#        }  
Function New-AvamarLoginProfile {
    [CmdletBinding()]
    Param($name=$(throw "must specify -name for profile"),
          $LoginProfile,
          [Switch]$shortcut
          )
    Begin {
        function Decrypt-SecureString {
        param(
            [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)]
            [System.Security.SecureString]
            $sstr
        )
            $marshal = [System.Runtime.InteropServices.Marshal]
            $ptr = $marshal::SecureStringToBSTR( $sstr )
            $str = $marshal::PtrToStringBSTR( $ptr )
            $marshal::ZeroFreeBSTR( $ptr )
            $str
        }
     }
     Process {
        $LoginProfile.keys | %{ if($LoginProfile.$_.password.gettype().name -ne "SecureString") { $LoginProfile.$_.password = $LoginProfile.$_.password | ConvertTo-SecureString -AsPlainText -force } }
        $LoginProfile | Export-Clixml "$($global:spath)\loginprofile_$($name).clixml"
     

        if ($shortcut) {
            $linkPath = Join-Path ($global:sPath) "Avamar vCOps - VM Events ($name).lnk"
            $targetPath = "$env:SystemRoot\system32\WindowsPowerShell\v1.0\powershell.exe"
            $link = (New-Object -ComObject WScript.Shell).CreateShortcut($linkPath)
            $link.TargetPath = $targetPath
            $link.WorkingDirectory = $global:sPath
            $link.Arguments = " -command `" &.\StartAvamarvCOps.ps1 $name`""
            $link.Save()
            Write-Host "`nShortcut has been created.`n"
            $linkPath = Join-Path ($global:sPath) "Avamar vCOps - VM Stats ($name).lnk"
            $targetPath = "$env:SystemRoot\system32\WindowsPowerShell\v1.0\powershell.exe"
            $link = (New-Object -ComObject WScript.Shell).CreateShortcut($linkPath)
            $link.TargetPath = $targetPath
            $link.WorkingDirectory = $global:sPath
            $link.Arguments = " -command `" &.\StartAvamarvCOps2.ps1 $name`""
            $link.Save()
            Write-Host "`nShortcut has been created.`n"
	    $linkPath = Join-Path ($global:sPath) "Avamar vCOps - VM Activities Averages ($name).lnk"
            $targetPath = "$env:SystemRoot\system32\WindowsPowerShell\v1.0\powershell.exe"
            $link = (New-Object -ComObject WScript.Shell).CreateShortcut($linkPath)
            $link.TargetPath = $targetPath
            $link.WorkingDirectory = $global:sPath
            $link.Arguments = " -command `" &.\StartAvamarvCOps3.ps1 $name`""
            $link.Save()
            Write-Host "`nShortcut has been created.`n"
        }
     }
}


#http://msmvps.com/blogs/richardsiddaway/archive/2009/11/20/wmicookbook-read-routing-table.aspx
Function Get-RouteTable { 
param ( 
    [parameter(ValueFromPipeline=$true)] 
    [string]$computer="." 
) 

## create class for object 
$source=@" 
public class WmiIPRoute 
{ 
    private string _destination; 
    private string _mask; 
    private string _nexthop; 
    private string _interface; 
    private int _metric; 
    
     public string Destination { 
        get {return _destination;} 
        set {_destination = value;} 
    } 
    
    public string Mask { 
        get {return _mask;} 
        set {_mask = value;} 
    } 
    
    public string NextHop { 
        get {return _nexthop;} 
        set {_nexthop = value;} 
    } 
    
    public string Interface { 
        get {return _interface;} 
        set {_interface = value;} 
    } 
    
    public int Metric { 
        get {return _metric;} 
        set {_metric = value;} 
    } 
} 
"@ 
$errorActionPreference = "SilentlyContinue"
Add-Type -TypeDefinition $source
$errorActionPreference = "Continue"

    $data = @() 
    Get-WmiObject -Class Win32_IP4RouteTable -ComputerName $computer| foreach { 
        $route = New-Object -TypeName WmiIPRoute 
        $route.Destination = $_.Destination 
        $route.Mask        = $_.Mask 
        $route.NextHop     = $_.NextHop 
        $route.Metric      = $_.Metric1 
        
        $filt = "InterfaceIndex='" + $_.InterfaceIndex + "'"  
        $ip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter $filt -ComputerName $computer).IPAddress 

        if ($_.InterfaceIndex -eq 1) {$route.Interface = "127.0.0.1"} 
        elseif ($ip.length -eq 2){$route.Interface = $ip[0]} 
        else {$route.Interface = $ip} 
        
        $data += $route 
    } 
    $data 
} 



#Connect-Avamar -Server dns/ip -Username root -Password 'Password1' -verbose
Function Connect-Avamar {
    [CmdletBinding()]
     Param (
           $Server=$(throw "Missing -Server"),
           $Username=$(throw "Missing -Username"),
           $Password=$(throw "Missing -Password"),
           $Domain="/",
           $Locale="en_us",
           $Client=(Get-RouteTable | sort metric | select -first 1 | %{ $_.Interface }),
           [boolean]$UnsafeHeaderParsing=$True
     )
     Begin {

        Function New-AvamarWatchDog {
            [CmdletBinding()]
            Param (
                $Server=$defaultAvamarServer.server
            )
            Process {

                $scriptBlock = {
                    function Get-WD_AvamarCurrentTime {
                        param($Href,$xmlSoapRequest)
                        $webClient = New-Object system.net.webclient
                        [xml]$xmlSoapReply = $webClient.UploadString($Href,"POST",$xmlSoapRequest)
                        Remove-Variable webclient | out-null
                        #$xmlSoapReply.Envelope.Body.currentTimeResponse.return
                    }
                    $xmlSoapRequest = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Header>
<ServiceGroupId xmlns="http://ws.apache.org/namespaces/axis2"><serviceId></ServiceGroupId>
</soap:Header>
<soap:Body>
<currentTime xmlns="http://sdk.mc.avamar.com">
<args0>
<description xmlns="http://sdk.mc.avamar.com/xsd">Service Id: <serviceId></description>
<name xmlns="http://sdk.mc.avamar.com/xsd"><serviceId></name>
<value xmlns="http://sdk.mc.avamar.com/xsd">SERVICE</value></args0>
</currentTime>
</soap:Body>
</soap:Envelope>
"@
                    $xmlSoapRequest = $xmlSoapRequest -replace "<serviceId>",$serviceId
            
                    $Href = "https://$($server):9443/services/mcService.McServiceHttpSoap11Endpoint/"
                    #for () { Write-Host "Avamar WatchDog Running";Write-Host (Get-WD_AvamarCurrentTime -Href $Href -xmlSoapRequest $xmlSoapRequest);Write-Host "Avamar WatchDog Sleeping";sleep 120 }
                    for () { Get-WD_AvamarCurrentTime -Href $Href -xmlSoapRequest $xmlSoapRequest;sleep 120 }
            
                }

                $global:Runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($Host)
		        $global:Runspace.Open()
                $global:Runspace.SessionStateProxy.SetVariable("serviceId", $DefaultAvamarServer.Proxy.ServiceGroupId.Value)
                $global:Runspace.SessionStateProxy.SetVariable("server", $defaultAvamarServer.server)
		        if (!$?) { throw "Could not open runspace!" }

                $Pipeline = $global:Runspace.CreatePipeline($Scriptblock)
                $Pipeline.InvokeAsync()
		
            }

        }

     }
     Process {

        #http://poshcode.org/753
        function New-ObjectFromProxy {
	        param($proxy, $proxyAttributeName, $typeName)

	        # Locate the assembly for $proxy
	        $attribute = $proxy | gm * | where { $_.Name -eq $proxyAttributeName }
	        $str = "`$assembly = [" + $attribute.TypeName + "].assembly"
	        invoke-expression $str

	        # Instantiate an AuthenticationHeaderValue object.
	        $type = $assembly.getTypes() | where { $_.Name -eq $typeName }
	        return $assembly.CreateInstance($type)
        }

        if($UnsafeHeaderParsing) {
            $netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])
            IF($netAssembly) {
                $bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
                $settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")
                $instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())
                if($instance) {
                    $bindingFlags = "NonPublic","Instance"
                    $useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)
                    if($useUnsafeHeaderParsingField) {
                        $useUnsafeHeaderParsingField.SetValue($instance, $true) | out-null
                    }
                }
            }
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
            [System.Net.ServicePointManager]::Expect100Continue = $false
        }
        try {
            if(!@(try {$global:DefaultAvamarServers.gettype()} catch {$false}) -and !$global:DefaultAvamarProxy)
            {
                Write-Verbose "DefaultAvamarServers does not exist, executing New-WebServiceProxy"
                $proxy = New-WebServiceProxy -uri "file://$($global:sPath)\mcServer-61-mini-v1.wsdl" -name "mcServer"
                $global:DefaultAvamarProxy = $proxy
                $tmpUrl = [System.Uri]$proxy.url
                $proxy.url = $tmpUrl.AbsoluteUri -replace $tmpUrl.host,$server
                Write-Verbose ($Proxy | fl * | Out-String)
                $global:DefaultAvamarServers = ,@()
            } else {
                Write-Verbose "DefaultAvamarServers exists"
                #if([psobject]$global:DefaultAvamarServer = $global:DefaultAvamarServers | where {$_.server -eq $server}) {
                    Write-Verbose "Setting current Avamar server (DefaultAvamarServer) from DefaultAvamarServers"
                    #only one proxy can exist in ps session due to same namespace for types
                    $proxy = $global:DefaultAvamarProxy
                    $tmpUrl = [System.Uri]$proxy.url
                    $proxy.url = $tmpUrl.AbsoluteUri -replace $tmpUrl.host,$server
                    $proxy.psobject.Members | where {$_.name -eq "ServiceGroupId"} | %{ $_.value = $null }
                #} else {
                    #Throw "Problem with global:defaultAvamarServers variable, reopen powershell"
                #}
            }

            [psobject]$Connection = New-AvamarLogin -Server $Server -Username $Username -Password $Password -Domain $Domain -Locale $Locale -Proxy $Proxy -Client $Client
            [array]$global:DefaultAvamarServers = $global:DefaultAvamarServers | where {$_.Server -ne $Server}
            [array]$global:DefaultAvamarServers += $Connection
            [psobject]$global:DefaultAvamarServer = $Connection
            New-AvamarWatchDog
        } catch {
            [array]$global:DefaultAvamarServers = $global:DefaultAvamarServers | where {$_.Server -ne $Server}
            Write-Host -fore "red" -back "black" "Problem connecting to Avamar $($Server)." 
            Throw ($_ | fl * | out-string)
        }
    }
}

Function New-AvamarLogin {
    [CmdletBinding()] 
     Param (
           $Server=$(throw "Missing -Server"),
           $Username=$(throw "Missing -Username"),
           $Password=$(throw "Missing -Password"),
           $Domain="/",
           $Locale="en_us",
           $Proxy=$(throw "Missing -proxy"),
           $Client=$(throw "Missing -Client which is either hostname or IP of client")
     )
     Begin {
        #Get-AvamarServiceContent
        Function Get-AvamarServiceContent {
            [CmdletBinding()] 
             Param (
                $Server=$defaultAvamarServer.server
             )
             Process {
                $global:DefaultAvamarServer = $global:DefaultAvamarServers | where {$_.Server -eq $Server}
                $global:DefaultAvamarServer.proxy.getServiceContent($global:DefaultAvamarServer.siMoref)
             }
        }
     }
     Process {
            $LoginInfo = New-Object mcServer.logininfo
            $LoginInfo.user = $Username
            $LoginInfo.password = $Password
            $LoginInfo.client = $Client
            $LoginInfo.domain = $Domain
            $LoginInfo.locale = $Locale

            $siMoref=$Proxy.Login($LoginInfo)
            if($siMoref) { Write-Host "Successful Avamar Login to $($Server)." }

            $Connection = New-Object PSObject -Property @{            
                Server = $Server
                Username = $Username
                Password = $Password | ConvertTo-SecureString -asplainText -force
                Domain = $Domain
                Proxy = $Proxy
                siMoref = $siMoref
            }
             Write-Verbose ($Connection | fl * | Out-String)

            [array]$global:DefaultAvamarServers = $global:DefaultAvamarServers | where {$_.Server -ne $Server}
            [array]$global:DefaultAvamarServers += $Connection
            [psobject]$global:DefaultAvamarServer = $Connection

            $authHeader = New-ObjectFromProxy -proxy $Proxy -proxyAttributeName "ServiceGroupId" -typeName "derivedType"
            $authHeader.value = $SiMoref.name
            $Proxy.ServiceGroupId = $authHeader

            $tmpServiceContent = Get-AvamarServiceContent -server $server

            Write-Verbose ($Proxy | fl * | Out-String)

            $Connection = New-Object PSObject -Property @{            
                Server = $Server
                Username = $Username
                Password = $Password | ConvertTo-SecureString -asplainText -force
                Domain = $Domain
                Proxy = $Proxy
                siMoref = $siMoref
                ServiceContent = $tmpServiceContent
                productLineId = $tmpServiceContent.About.productLineId
                version = $tmpServiceContent.About.version
                apiType = $tmpServiceContent.About.apiType
            }

            Write-Verbose ($Connection | fl * | Out-String)

            return $Connection
     }   
}

#Disconnect-Avamar
Function Disconnect-Avamar {
    [CmdletBinding()] 
    Param (
        $Server
    )
    Process {
        if(!$server) {
            Write-Host "Missing -server, specify one of the following."
            $DefaultAvamarServers
        } else {
            $global:Runspace.Close()
            $global:DefaultAvamarProxy.Logout($global:DefaultAvamarServer.siMoref)
            [array]$global:DefaultAvamarServers = $global:DefaultAvamarServers | where {$_.Server -ne $Server}    
        }
    }
}



#Get-VM | Get-VMAvamarClient
Function Get-VMAvamarClient {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
	[switch]$outMoref
    )
    Process {
        $moref = Search-AvamarVMClient -lookupType instanceUuid -lookupValue $VM.ExtensionData.Config.InstanceUuid -ea 0 
	if($outMoref) { $moref } else { $moref | Select *,@{n="VM";e={$VM}} } 
    }
}

#Get-VMAvamarActivities -getAllVms -useBulkAvamarVMLookup -Start_Recorded_Date_Time ((Get-Date).addDays(-3)) -vCOpsPost -showPost 
#Get-VMAvamarActivities -getAllVms -useBulkAvamarVMLookup -useBookmark -vCOpsPost
#Get-VM name | Get-VMAvamarActivities -Start_Recorded_Date_Time ((Get-Date).addDays(-3)) -Finish_Recorded_Date_Time ((Get-Date).addDays(-2))
#Get-VMAvamarActivities -getAllVms -useBulkAvamarVMLookup -avgMetric -useBookmark -vCOpsPost -verbose
#backups or restores
function Get-VMAvamarActivities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl[]]$VM,
        [scriptblock]$filterScript={},
        [Switch]$useBookmark,
        [Switch]$vCOpsPost,
	[Switch]$avgMetric,
	[int]$avgMetricIntervalSeconds=20,
        [Switch]$showPost,
        [Switch]$getAllVms,
        [Switch]$useBulkAvamarVMLookup,
        [Datetime]$Start_Recorded_Date_Time,
        [Datetime]$Finish_Recorded_Date_Time

    )
    Begin {
        $arrVM = @()
        
	function div1MB {
	    param($num)
	    return ([math]::round(($num/1MB),4))
	}
	function div1GB {
	    param($num)
	    return ([math]::round(($num/1GB),4))
	}

	function New-vCOpsAvamarChangeEvent {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
                [psobject]$Result,
                [Boolean]$showPost
            )
            Process {
                $Result | %{
	                $_.VM | New-vCOpsChangeEvent -showPost:$showPost -date $_.started_ts -message "Avamar $($_.plugin_name) $($_.Type) Started ($($_.initiated_by)) (label $($_.snapup_number))"
	                $_.VM | New-vCOpsChangeEvent -showPost:$showPost -date $_.completed_ts -message "Avamar $($_.plugin_name) $($_.Type) Completed in $(($_.completed_ts-$_.started_ts).totalseconds) seconds and $($_.bytes_modified_sent) bytes sent after dedupe - $($_.status_code_summary) (label $($_.snapup_number))"
                }
            }
        }

        Function Get-AvamarVMClient {
            [CmdletBinding()] 
             Param (
                $Server=$defaultAvamarServer.server,
                $Recursive=$true,
                [switch]$Raw,
                $Domain
             )
             Begin {
                if($Domain) { 
                    $domainMoref = New-Object mcServer.DomainMoref
                    $domainMoref.name = ""
                    $domainMoref.description = $Domain
                    $domainMoref.value = ""
                }else {
                    $domainMoref = $Global:DefaultAvamarServer.ServiceContent.rootDomain
                }
             }
             Process {
                $global:DefaultAvamarServer = $global:DefaultAvamarServers | where {$_.Server -eq $Server}
                [array]$tmpOut = $global:DefaultAvamarServer.Proxy.getClientInfoList($domainMoref,$Recursive) | 
                    where {$_.gettype().tostring() -eq "mcServer.VmClientInfo"}
                $tmpOut
             }
        }

        if(!$global:hashVMAvamarClient) { 
            $global:hashVMAvamarClient = @{}
        }

        ##### IS THIS NEEDED IF NOT DOING useBulkAvamarLookup?


        if($useBulkAvamarVMLookup) {
            try {
                [string]$strClientMorefValueNew = ($global:DefaultAvamarServer.Proxy.getClientReferenceList($global:DefaultAvamarServer.ServiceContent.rootDomain,$true) | sort value | %{ $_.value }) -join ""
            } catch {
                Write-Error "Problem getting Avamar Moref list"
                Throw $_
            }

            if(!$global:hashVMAvamarClient.($global:DefaultAvamarServer.Server) -or ($global:hashVMAvamarClient.($global:DefaultAvamarServer.Server) -and !$global:hashVMAvamarClient.($global:DefaultAvamarServer.Server).keys.count) `
                -or $strClientMorefValueNew -ne $global:strClientMorefValue) {
                if(!$global:hashVMAvamarClient.($global:DefaultAvamarServer.Server) -or ($global:hashVMAvamarClient.($global:DefaultAvamarServer.Server) -and !$global:hashVMAvamarClient.($global:DefaultAvamarServer.Server).keys.count)) {
                    Write-Host "$(Get-Date): Avamar server $($global:DefaultAvamarServer.Server) doesn't exist in cache, caching all known VMs from Avamar."
                } elseif($strClientMorefValueNew -ne $global:strClientMorefValue) {
                    Write-Host "$(Get-Date): Avamar server $($global:DefaultAvamarServer.Server) change in Clients detected, updating cache."
                }

                $global:strClientMorefValue = $strClientMorefValueNew
                $global:hashVMAvamarClient.($global:DefaultAvamarServer.Server) = @{}
            
                Get-AvamarVMClient | %{
                    $global:hashVMAvamarClient.($global:DefaultAvamarServer.Server).($_.VmUuid) = New-Object -type mcServer.ManagedObjectReference -Property @{name=$_.nodeName;value=$_.id;description="$($_.directory)/$($_.name)"}
                }
            }
        } else {
            [string]$strClientMorefValueNew = ""
        }

        if($getAllVms) {
            Write-Host "$(Get-Date): Retrieving InstanceUuids from vCenter"
            $hashVMInstanceUuid = @{}
            Get-View -ViewType VirtualMachine -Property "Config.InstanceUuid","Name" | where {$_.Config.InstanceUuid} | %{ $hashVmInstanceUuid.($_.Config.InstanceUuid) = $_ }
        }

    } 
    Process {
        if(!$getAllVms -and !$VM) {
            Throw "Missing either -getAllVms parameter or input of Get-VM"
        }
        if($VM) { 
            if(!$useBulkAvamarVMLookup) {
                $global:strClientMorefValue = ""
                if(!$global:hashVMAvamarClient.($global:DefaultAvamarServer.Server)) {
                    $global:hashVMAvamarClient.($global:DefaultAvamarServer.Server) = @{}
                }
                if(!$global:hashVMAvamarClient.($global:DefaultAvamarServer.Server).($VM.ExtensionData.Config.InstanceUuid)) {
                    $VM | Get-VMAvamarClient | %{
                        $global:hashVMAvamarClient.($global:DefaultAvamarServer.Server).($_.VM.ExtensionData.Config.InstanceUuid) = New-Object -type mcServer.ManagedObjectReference -Property @{name=$_.name;value=$_.value;description=$_.description}
                    }
                }
            }
            [array]$arrVM += $VM 
        }
    } 
    End {
        [array]$arrVMDetails = if(!$arrVM.count) {
            $hashVmInstanceUuid.keys | %{ New-Object -type PsObject -property @{Name=$hashVmInstanceUuid.$_.Name;MoRef=$hashVmInstanceUuid.$_.MoRef;
                                                                                InstanceUuid=$hashVmInstanceUuid.$_.Config.InstanceUuid;
                                                                                ExtensionData=@{Client=$hashVmInstanceUuid.$_.Client;MoRef=$hashVmInstanceUuid.$_.MoRef}} }
        } else {
            $arrVM | %{ New-Object -type PsObject -property @{Name=$_.Name;MoRef=$_.Id;
                                                              InstanceUuid=$_.ExtensionData.Config.InstanceUuid;
                                                              ExtensionData=@{Client=$hashVmInstanceUuid.$_.Client;MoRef=$hashVmInstanceUuid.$_.MoRef}} }
        }

        [array]$arrAvamarVM = $arrVMDetails | %{
            if($global:hashVMAvamarClient.($global:DefaultAvamarServer.Server) -and $global:hashVMAvamarClient.($global:DefaultAvamarServer.Server).($_.InstanceUuid)) {
                New-Object -Type PsObject -Property @{AvamarVMClient=($global:hashVMAvamarClient.($global:DefaultAvamarServer.Server).($_.InstanceUuid));VM=$_}
            }
        }
        
        $hashAvamarVMCID = @{}
        $arrAvamarVM | %{ $hashAvamarVMCID.($_.AvamarVMClient.value) = $_ }


	$bookmarkFile = if($avgMetric) { "$($global:DefaultAvamarDatabase.DataSource)-avgMetric.CliXml" } else { "$($global:DefaultAvamarDatabase.DataSource).CliXml" }
        if($UseBookmark) { 
            $bookmark = Get-Item $bookmarkFile -ea 0 | Import-CliXml
        }

        [array]$arrCid = $arrAvamarVM | %{
            New-Object -type PsObject -Property @{cid=$_.AvamarVMClient.value}
        }
        
        $sqlParam = $bookmark

        if($arrCid.count -gt 0) {
            [string]$strCID = "("+(($arrCid | %{ $_.cid } | %{ "'$_'" }) -join ",")+")"
            if($bookmark.recorded_date_time) { 
                $rdt = "recorded_date_time > '$($bookmark.recorded_date_time.GetDateTimeFOrmats("O"))' and"
            }elseif($start_recorded_date_time) {
                $rdt = "recorded_date_time > '$($Start_recorded_date_time.GetDateTimeFOrmats("O"))' and"
            }

            if($finish_recorded_date_time) {
                $frdt = "recorded_date_time < '$($Finish_recorded_date_time.GetDateTimeFOrmats("O"))' and"
            }

            $query = "Select * from v_activities where $rdt $frdt cid IN $strCID order by started_ts desc"
            Write-Host "$(Get-Date): Executing Avamar Postgres database query for backup jobs"
            write-verbose $query
            [array]$arrResults = Get-vPostgresDataset -connection $global:DefaultAvamarDatabase `
                -query $query | %{ $result=$_;$_ | Select *,@{N="AvamarVMClient";e={$hashAvamarVMCID.$($_.cid).AvamarVMClient}},@{N="VM";e={$hashAvamarVMCID.$($_.cid).VM}} } | sort recorded_date_time
        } else {
            Return
        }

        if(!$vCOpsPost) {
            $arrResults
        } else {
            $arrResults | where {$_} | %{ 
                try {
                    [boolean]$showPost = $showPost
                    
		    if(!$avgMetric) {
			$_ | New-vCOpsAvamarChangeEvent -showPost:$showPost
		    }else {
			$_ | where {$_.status_code -eq 30000} | select VM,started_ts,completed_ts,bytes_modified_sent,bytes_scanned,
				@{n="duration_seconds";e={($_.completed_ts-$_.started_ts).totalseconds}},
				@{n="date";e={$_.started_ts}} -ExcludeProperty started_ts,completed_ts | %{ 
				$metric = $_
				$countDataPoints = [math]::ceiling($metric.duration_seconds / $avgMetricIntervalSeconds)
				if($countDataPoints -gt 0) {
				[array]$arrMetric = %{
					New-Object -type psobject -property @{VM=$metric.VM;Date=$metric.date.addSeconds(-$avgMetricIntervalSeconds);bytes_modified_sent_avg=0;bytes_scanned_avg=0;}
					0..($countDataPoints-1) | %{
						New-Object -type psobject -property @{VM=$metric.VM;Date=$metric.date.addSeconds(($_)*$avgMetricIntervalSeconds);
										      bytes_modified_sent_avg=[math]::round(($metric.bytes_modified_sent/$countDataPoints),2);
										      bytes_scanned_avg=[math]::round(($metric.bytes_scanned/$countDataPoints),2);}
					}
					New-Object -type psobject -property @{VM=$metric.VM;Date=$metric.date.addSeconds($countDataPoints*$avgMetricIntervalSeconds);bytes_modified_sent_avg=0;bytes_scanned_avg=0;}
				}

				$preName = "Avamar:$($DefaultAvamarServer.Server)"

				[array]$arrMetric = $arrMetric | %{
					$tmpHash = @{ 
					  Date=$_.Date;
					  "$($preName)|Backups|Scanned Avg (GB/sec)"=div1GB $_."bytes_scanned_avg";
					  "$($preName)|Backups|New Bytes Avg (MB/sec)"=div1MB $_."bytes_modified_sent_avg"; 
					}
					New-Object -type psobject -property $tmpHash
				}

				$metric.VM | New-vCOpsMetric -expectMinutes 1440 -metric $arrMetric -showPost:([boolean]$showPost)
				
				}
		    	}
			
				
		    }	    
                    if(!$showPost) { 
			New-Object -type PsObject -Property @{recorded_date_time=$_.recorded_date_time} | Export-CliXml $bookmarkFile 
		    }
                } catch {
                    Write-Error "Problem posting, cancelling at this point."
                    Throw $_
                }
            }
        }
    }
}

#Search-AvamarVMClient -lookupType instanceUuid -lookupValue "502d3999-d17d-48cb-4afc-5d8d970bc5e4"
function Search-AvamarVMClient {
       [CmdletBinding()] 
         Param (
            [mcServer.VirtualMachineIdentityType]$lookupType=$(throw "missing -lookupType {dnsName,datastorePath,inventoryPath,ipAddress,instanceUuid,biosUuid}"),
            $lookupValue=$(throw "missing -lookupValue which corresponds to -lookupType"),
            [switch]$OutMoRef,
            $Server=$defaultAvamarServer.server,
            [switch]$ignoreErrors
         )
      #ignoreErrors shouldn't be neeed but is since errors aren't acting normal
      try {
          $DefaultAvamarServer.Proxy.lookupVmClientReference($DefaultAvamarServer.ServiceContent.adminService,$null,$lookupValue,$LookupType)
      } catch { if(!$ignoreErrors) { Throw $_;break } }
      
}


Function Connect-vCOpsServer {
     [CmdletBinding()]
     Param (
        $Server,
        $Username,
        $Password
     )
     Process {
           $URL = "https://$Server/HttpPostAdapter/OpenAPIServlet"
           $http_request = New-Object System.Net.WebClient
           $http_request.Credentials = (New-Object System.Net.NetworkCredential($Username,$Password))
           [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
           $Send = 'action=lookupResource&resourceName=regex:.*'
           try {
           $Data = $http_request.UploadString($URL,$Send)
           }
           catch [Net.WebException] {
           Write-Error "Unable to connect to $Server, please verify connection information and try again"
                Write-Error "$($_.Exception)"
                Return
           }
           $Connection = New-Object PSObject -Property @{            
             Server = $Server
             Username = $Username
                Password = $Password
                Data = ($data -split "`n")
                APIURL = ("https://$Server/HttpPostAdapter/OpenAPIServlet")
         }  
           $Global:DefaultvCOPsServer = $Connection
           Write-Host "Connected to $($DefaultvCOPsServer.Server)"
     }
}


Function New-vCOpsChangeEvent {
	[CmdletBinding()]
    Param (
	   [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
           [PsObject]$PsObject,
	   [String]$Message,
	   [Datetime]$Date,
           [Boolean]$showPost
	)
	Process {
	    if (-not $DefaultvCOPsServer) {
                Throw "No connection to a vCOps Server found, please use Connect-vCOpsServer to connect to a server"
            }
		 
	    if(!$Date) { 
	        $UDateMS = ""
	    } else {
		$UDateMS = [math]::round(([decimal](($Date) | Get-Date -UFormat "%s")*1000),0)
	    }	
		
	    $PsObject | %{
	    	$postBody = "action=addChangeEvent&resourceName=$($_.Name)&adapterKindKey=VMWARE&resourceKindKey=VirtualMachine&identifiers=VMEntityObjectID::$($_.ExtensionData.MoRef.Value)`$`$VMEntityVCID::$($_.ExtensionData.client.ServiceContent.About.InstanceUuid)&time=$($UDateMS)&message=$($Message)"
	    }

        if($showPost) {
            Write-Host $postBody
            return
        }

        Write-Verbose $postBody
        
        $global:http_request = new-object System.Net.WebClient
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

		
		$global:http_request.Credentials = (New-Object System.Net.NetworkCredential($DefaultvCOpsServer.Username,$DefaultvCOpsServer.Password))
		try {
	                Write-Host "Posting message from $($Date.GetDateTimeFOrmats("O")) to VM ($($PsObject.Name)): $($Message)"
			$post = $global:http_request.UploadString($DefaultvCOpsServer.APIURL,$postBody)
			Write-Host "$(Get-Date): Post Completed`n$($post)"
		} catch {
			Write-Error "Problem with post"
			Throw ($_ | Out-String)
		}
	}
}



function Connect-vPostgres {
    [CmdletBinding()]
    param(
        $server = $(Read-Host "SQL Server Name"),
        $username = $(Read-Host "Username"),
        $password = $(Read-Host "Password"),
        $database = $(Read-Host "Default Database"),
        $port = $(Read-Host "Port")
    )
    Process {
        if($PSVersionTable.PSVersion.major -ge 3) { (gi "$($global:sPath)\npgsql.dll") | Unblock-File }
        [void][system.reflection.Assembly]::LoadFrom((gi "$($global:sPath)\npgsql.dll").fullname)
        if(!$global:vPostgresConnection) { $global:vPostgresConnection = @{} }
        $global:vPostgresConnection.$server = New-Object Npgsql.NpgsqlConnection
        $global:vPostgresConnection.$server.ConnectionString = "server=$server;port=$port;user id=$username;password=$password;database=$database;pooling=false"
        $result = Get-vPostgresDataSet -server $server -query "Select 1=2"
        if(!$result) { Throw "Problem connecting to database" }
    }
}

function Get-vPostgresDataSet {
    [CmdletBinding()]
    Param( 
        $server,
        $username,
        $password,
        $database,
        $query,
        $port,
        $sqlparam,
        $connection,
        $timeout 
    )

    if(!$connection -and !$global:vPostgresConnection.$server -and ($server -and $username -and $password)) { 
        Connect-vPostgres $server $username $password $database $port 
    }

    Write-Verbose "Query: $query"
    Write-Verbose "SqlParam: $sqlParam"

    function Get-SqlDataTable {
        [CmdletBinding()]
        Param(
            $server,
            $connection,
            $Query, 
            $sqlparam, 
            [switch]$close,
            [int]$timeout
        )
        Process {
            if($server) { 
                $tmpvPostgres = $global:vPostgresConnection.$server
            }elseif($connection){
                $tmpvPostgres = $connection
            }
    	    if (-not ($tmpvPostgres.State -like "Open")) { $tmpvPostgres.Open() }
    	    $SqlCmd = New-Object npgsql.npgsqlCommand $Query, $tmpvPostgres
            if($timeout) { $SqlCmd.CommandTimeout = $timeout}
            if($sqlparam) { $sqlparam.psobject.properties | %{ [void]$sqlCmd.Parameters.AddWithValue($_.name,$_.value) } }
            $SqlAdapter = New-Object npgsql.npgsqlDataAdapter
    	    $SqlAdapter.SelectCommand = $SqlCmd
    	    $DataSet = New-Object System.Data.DataSet
    	    $SqlAdapter.Fill($DataSet) | Out-Null
    	    if($close) { $tmpvPostgres.Close() }
    	    return $DataSet.Tables[0]
        }
    }
    
    Get-SqlDataTable -connection $connection -server $server -query $Query -sqlparam $sqlparam -timeout $timeout | Select * -ExcludeProperty RowError,RowState,Table,ItemArray,HasErrors
}

#Connect-AvamarPostgres -server 10.241.67.243 -username viewuser -password viewpass
function Connect-AvamarPostgres {
    [CmdletBinding()]
    param (
        $server,
        [parameter(mandatory=$false, position=0, ValueFromRemainingArguments=$true)]$Remaining
    )
    
    [string]$strParams = @("-server",$server)+($remaining | %{ 
            if($_ -notmatch "^-") { '"'+$_+'"' } else { $_ } 
        }) -join " "
    $strParams += " -database mcdb -port 5555"
    Invoke-Expression "Connect-vPostgres $strParams"
    $global:DefaultAvamarDatabase = $vPostgresConnection.$server.Clone()
}

Function Disconnect-vPostgres {
    [CmdletBinding()]
    param($server)
    Process {
        $global:vPostgresConnection.$server.Close()
        $global:vPostgresConnection.$server.Dispose()
        $global:vPostgresConnection.Remove($server)
    }
}



#Get-vm wguest-01 | Get-VmAvamarClient -outMoref | Get-AvamarClientBackup
Function Get-AvamarClientBackup {
    [CmdletBinding()] 
     Param (
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [mcServer.ClientMoref]$clientMoref,
        $backupMoref,
        $Server=$defaultAvamarServer.server,
        $startDate,
        $endDate=$(Get-Date),
        $rowCount
     )
     Begin {
         Function Get-AvamarClientBackupReferenceList_Task {
        [CmdletBinding()] 
         Param (
            $clientMoref=$(throw "missing clientMoref"),
            $backupFilter,
            $Server=$defaultAvamarServer.server
         )
             Process {
                $global:DefaultAvamarServer = $global:DefaultAvamarServers | where {$_.Server -eq $Server}
                $global:DefaultAvamarServer.Proxy.getClientBackupReferenceList_Task($clientMoref,$backupFilter)
             }
         }
         
	Function Get-AvamarTaskInfo {
   	[CmdletBinding()] 
     	Param (
       	 $Server=$defaultAvamarServer.server,
       	 $taskMoref=$(throw "Missing Avamar taskMoref")
     	)
     	
           $TaskInfo = $global:DefaultAvamarServer.Proxy.getTaskInfo($taskMoref)  
        
       	   $TaskInfo
       	   Write-Verbose ($TaskInfo | Out-String)
       	   if($TaskInfo.state -eq "error") {
       	       Write-Error "Error during task"
       	   }
    	 
	}

     }
     Process {
        $global:DefaultAvamarServer = $global:DefaultAvamarServers | where {$_.Server -eq $Server}

        if(!$rowCount -and !$startDate) {
            $startDate = (Get-Date).AddDays(-7)
        }
        if($startDate) { 
            $dateFilter = New-Object mcServer.DateFilter
            $dateFilter.after = $startDate
            $dateFilter.before = $endDate
            $backupFilter = New-Object mcServer.backupFilter -Property @{dateFilter=$dateFilter}
        }elseif($rowCount) {
            $indexFilter = New-Object mcServer.indexFilter
            $indexFilter.rowCount = $rowCount
            $backupFilter = New-Object mcServer.backupFilter -Property @{indexFilter=$indexFilter}
        }

        $taskMoref = Get-AvamarClientBackupReferenceList_Task -clientMoref $clientMoref -backupFilter $backupFilter
        
        Write-Verbose $taskMoref

        [array]$tmpOut = %{ for () {
            try { 
                $taskOut = Get-AvamarTaskInfo -taskMoref $taskMoref -ea 0
                sleep 1 
            } catch { 
                
                if($taskOut.error) {
                    Write-Host -fore red -back black ($taskOut.error.item.data | fl * | out-string)
                    Write-Host -fore red -back black ($taskOut.error.item.event | fl * | out-string)
                }
                              
                $taskOut
                break
            }
        } } 

        
            [array]$tmpOut3 = $tmpOut | %{ $_.result } | where {$_.gettype().Name -eq "XmlElement"} | %{ 
                $tmpXml = $_
                $hashChildren = @{}
                $_.ChildNodes | %{ $hashChildren.($_.LocalName) = if(@("plugin","storage") -contains $_.LocalName) { 
                        Invoke-Expression "New-Object mcServer.$($_.type) -property @{description=`$_.description;name=`$_.name;value=`$_.value}" 
                    } else { 
                        $_."#text" 
                    } 
                } 
                New-Object -type psobject -property $hashChildren
            } 

        $tmpOut3 | select *,@{n="clientMoref";e={$clientMoref}},@{n="backupMoref";e={
                New-Object mcServer.backupMoref -Property @{name=$_.name;description=$_.description;value=$_.id} }}

	$tmpOut3
        
     }
}


#Get-VM wguest-01 | Get-VMAvamarBackup
Function Get-VMAvamarBackup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM
    )
    Process {
	$vmMoref = try { $VM | Get-VMAvamarClient -outmoref } catch {}
	if($vmMoref) {
    		[array]$arrClientBackup = $vmMoref | Get-AvamarClientBackup
		$strName = ($arrClientBackup | %{ "'$($_.name)'" }) -join ","
	        $query = "Select * from v_activities where cid = '$($vmMoref.value)' and snapup_number in ($strName) order by started_ts desc"
	        Write-Verbose $query
		[array]$arrResults = Get-vPostgresDataset -connection $global:DefaultAvamarDatabase `
	          -query $query | sort recorded_date_time  | where {$_.type -match "Snapup"}

		$arrResults | select *,@{n="duration_seconds";e={($_.completed_ts-$_.started_ts).TotalSeconds}},@{n="VM";e={$VM}}
    	}
    }
}

#Get-VM wguest-01 | Get-VMAvamarBackupSummary
Function Get-VMAvamarBackupSummary {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
	[switch]$vCOpsPost,
	[switch]$showPost
    )
    Begin {
	function div1MB {
	    param($num)
	    return ([math]::round(($num/1MB),4))
	}
	function div1GB {
	    param($num)
	    return ([math]::round(($num/1GB),4))
	}

    }
    Process {
	[array]$arrVMAvamarBackup = $VM | Get-VMAvamarBackup

	if($arrVMAvamarBackup.count -gt 0) {
	$summary = 1| select @{n="VM";e={$VM}},
		@{n="bytes_scanned_max";e={$arrVMAvamarBackup | measure -max bytes_scanned | %{ $_.Maximum }}},
		@{n="bytes_scanned_sum";e={$arrVMAvamarBackup | measure -sum bytes_scanned | %{ $_.Sum }}},
		@{n="bytes_scanned_latest";e={$arrVMAvamarBackup[-1].bytes_scanned}},
		@{n="bytes_modified_sent_max";e={$arrVMAvamarBackup | measure -max bytes_modified_sent | %{ $_.Maximum }}},
		@{n="bytes_modified_sent_sum";e={$arrVMAvamarBackup | measure -sum bytes_modified_sent | %{ $_.Sum }}},
		@{n="bytes_modified_sent_latest";e={$arrVMAvamarBackup[-1].bytes_modified_sent}},
		@{n="duration_seconds_average";e={$arrVMAvamarBackup | measure -average duration_seconds | %{ $_.Average }}},
		@{n="duration_seconds_latest";e={($arrVMAvamarBackup | where {$_.completed_ts})[-1].duration_seconds}},
		@{n="started_ts_min";e={$arrVMAvamarBackup | measure -min started_ts | %{ $_.Minimum }}},
		@{n="started_ts_max";e={$arrVMAvamarBackup | measure -max started_ts | %{ $_.Maximum }}},
		@{n="started_ts_latest";e={$arrVMAvamarBackup[-1].started_ts}},
		@{n="backup_count";e={$arrVMAvamarBackup.count}} | select *,
		@{n="dedupe_percent_latest";e={[decimal](100*(1-[math]::round(($_.bytes_modified_sent_latest/($VM.ExtensionData.Summary.Storage.Committed+$VM.ExtensionData.Summary.Storage.Uncommitted)),7)))}},
		@{n="bytes_modified_sent_percent_latest";e={[decimal](100*([math]::round(($_.bytes_modified_sent_latest/$_.bytes_scanned_latest),7)))}},
		@{n="bytes_modified_sent_percent_sum";e={[decimal](100*([math]::round(($_.bytes_modified_sent_sum/$_.bytes_scanned_sum),7)))}}

        if($vCOpsPost) {
	    $newSummary = @{}
	    $summary.psobject.properties | where {$_.name -notmatch "VM|^Started"} | sort name | %{ $newSummary.($_.Name) = $_.Value }
	    $preName = "Avamar:$($DefaultAvamarServer.Server)"
	    $formattedMetrics = @{
		"$preName|Backups|Scanned Max (GB)"=div1GB $newSummary."bytes_scanned_max";
		"$preName|Backups|Scanned Sum (GB)"=div1GB $newSummary."bytes_scanned_sum";
		"$preName|Backups|Scanned Latest (GB)"=div1GB $newSummary."bytes_scanned_latest";
		"$preName|Backups|New Max (MB)"=div1MB $newSummary."bytes_modified_sent_max";
		"$preName|Backups|New Sum (MB)"=div1MB $newSummary."bytes_modified_sent_sum";
		"$preName|Backups|New Latest (MB)"=div1MB $newSummary."bytes_modified_sent_latest";
		"$preName|Backups|Duration Average (seconds)"=$newSummary."duration_seconds_average";
		"$preName|Backups|Duration Latest (seconds)"=$newSummary."duration_seconds_latest";
		"$preName|Backups|Currently Available"=$newSummary."backup_count";
		"$preName|Backups|Deduplication Latest (%25)"=$newSummary."dedupe_percent_latest";
		"$preName|Backups|New Bytes Latest (%25)"=$newSummary."bytes_modified_sent_percent_latest";
		"$preName|Backups|New Bytes All (%25)"=$newSummary."bytes_modified_sent_percent_sum";
	    }
	    $VM | New-vCOpsMetric -expectMinutes 30 -metric (New-Object -type psobject -property $formattedMetrics) -showPost:([boolean]$showPost)
        } else {
    	    $summary
        } } 
	else {
		Write-Verbose "No backup exists for $($VM.name)"
	
	}
    }
}



Function New-vCOpsMetric {
	[CmdletBinding()]
    Param (
           [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
           [psobject]$VM,
	   [psobject[]]$Metric,
	   [Datetime]$Date,
	   $expectMinutes=5,
           [Boolean]$showPost
	)
	Process {
	    if (-not $DefaultvCOPsServer) {
                Throw "No connection to a vCOps Server found, please use Connect-vCOpsServer to connect to a server"
            }
		 
	    if(!$Date) { 
		$Date = Get-Date
	    }
	     
	    $UDateMS = [math]::round(([decimal](($Date).ToUniversalTime() | Get-Date -UFormat "%s")*1000),0)

	    #resourceName,adapterKindKey,resourceKindKey,identifiers,resourceDescription,monitoringInterval,storeOnly, 
	    #  sourceAdapter, disableResourceCreation
	    #metricName,alarmLevel,alarmMessage,date,value,thresholdHigh,thresholdLow


	    [array]$postBody = "$($VM.Name),VMWARE,VirtualMachine,VMEntityObjectID::$($VM.ExtensionData.MoRef.Value)`$`$VMEntityVCID::$($VM.ExtensionData.client.ServiceContent.About.InstanceUuid),'no description',$($expectMinutes),false,,true"
	    $metric | %{ 
		if(!$_.Date) { $tmpDate = $UDateMS } else { $tmpDate = [math]::round(([decimal](($_.Date).ToUniversalTime() | Get-Date -UFormat "%s")*1000),0) }
		$_.psobject.properties | where {$_.name -ne "date"} | %{ 
			$max = if($_.Name -match "perc|%") { 100 } else {}  
			[array]$postBody += "$($_.Name),0,`"NoValue`",$($tmpDate),$($_.Value),$($max),0"
	    	} 
	    }

	    [string]$strpostBody = $postBody -join "`r"

            if($showPost) {
                Write-Host ($postBody -join "`n")
                return
            }

            Write-Verbose ($postBody -join "`n")
          
            $global:http_request = new-object System.Net.WebClient
	    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		
	    $global:http_request.Credentials = (New-Object System.Net.NetworkCredential($DefaultvCOpsServer.Username,$DefaultvCOpsServer.Password))
	    try {
		$tmpDate = if($metric[0].date) { $metric[0].date } else { $Date }
	        Write-Host "Posting metrics from $($tmpDate.GetDateTimeFOrmats("O")) to VM ($($VM.Name))"
		$post = $global:http_request.UploadString($DefaultvCOpsServer.APIURL,$strpostBody)
		Write-Host "$(Get-Date): Post Completed`nvCOps Response: $($post)"
	    } catch {
		Write-Error "Problem with post"
		Throw ($_ | Out-String)
	    }
	}
}
