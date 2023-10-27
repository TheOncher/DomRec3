# Requires
#Requires -PSEdition Desktop

# Constants
Set-Variable -Option "Constant" -Name "ConstDomRecVersion" -Value "DomRec3 v1"
Set-Variable -Option "Constant" -Name "ConstDockerServiceName" -Value "com.docker.service"
Set-Variable -Option "Constant" -Name "ConstDockerServiceNameDefault" -Value "com.docker.service"
Set-Variable -Option "Constant" -Name "ConstScriptName" -Value $(Split-Path -Path $($MyInvocation.InvocationName) -Leaf)
Set-Variable -Option "Constant" -Name "ConstContainerName_BackendDatabaseConnector" -Value "BE Service - Database Connector"
Set-Variable -Option "Constant" -Name "ConstContainerName_FrontendGUI" -Value "FE Service - GUI"
Set-Variable -Option "Constant" -Name "ConstDatabasesList" -Value $([ordered]@{"1" = "PostgresSQL"; "2" = "MongoDB"; "3" = "MicrosoftSQL"; "4" = "MySQL"; "5" = "SQLite" })
Set-Variable -Option "Constant" -Name "ConstDatabasesCredentialsSchema" -Value $([PSCustomObject]@{"Address" = ""; "Port/Path" = ""; "Username" = ""; "Password" = ""; "CredsTable" = "DomRec-Credentials" })

# ------------------------------------------------------------------------- #

# Function Test-Administrator
Function Test-Administrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

# Function Check-Dependencies
Function Check-Dependencies {
    Clear-Host
    # Check Docker Service Status
    $DockerServiceStatus = (Get-Service -Name "$ConstDockerServiceName" -ErrorAction SilentlyContinue ).Status

    # Docker not Installed, exit WindowsSetup.ps1
    if ($null -eq $DockerServiceStatus) {
        Write-Host "Looks Like Docker is not installed, Please refer to the Docker website and install it first `nAnd make sure the service name is '$ConstDockerServiceNameDefault', if you have modified the Docker service name, `ncheck the $ConstScriptName code and modify the 'DockerServiceName' variable in the Constants section"
        Write-Host "Click anything to exit"
        $Host.UI.ReadLine()
        exit
    }

    # Check if Docker is Running
    while ($DockerServiceStatus -ne "Running") {
        $Answer = (Read-Host -Prompt "Docker Service isnt Running, Do you want to start it? [Y/n]").ToLower()

        # User doesnt want to start docker service, then exit
        if ($Answer -eq "n") { 
            Write-Host "Well Then, Cheers!"; $Host.UI.ReadLine(); exit 
        }

        # Resubmit answer
        elseif (($Answer -ne "y") -and ($Answer -ne "")) {}

        # Request admin access to start the service
        elseif ( (($Answer -eq "y") -or ($Answer -eq "")) -and (!(Test-Administrator)) ) {
            $StartProcessArguments = '-c "Start-Service -Name ' + $ConstDockerServiceName + '"'
            Start-Process -FilePath "powershell.exe" -ArgumentList $StartProcessArguments -Verb RunAs
        }

        # Attempt to start Docker
        elseif ( (($Answer -eq "y") -or ($Answer -eq "")) -and (Test-Administrator) ) {
            try { Start-Service -Name "$ConstDockerServiceName" }
            catch { Write-Host "Cannot Start Docker Service, Please try Manually"; $Host.UI.RTeadLine(); exit }
        }

        # ReChecking for docker service status
        Start-Sleep -Seconds 4 
        $DockerServiceStatus = (Get-Service -Name "$ConstDockerServiceName" -ErrorAction SilentlyContinue ).Status
    }

    # Docker is up!
    Write-Host "Docker is up!"
    Clear-Host
}

# Function Get-DatabaseListInfo
Function Get-DatabaseListInfo {
    # Parameters
    Param (
        [Parameter()][switch]$DBAmount,
        [Parameter()][switch]$DBListMenu,
        [Parameter()][switch]$DBNumbersListArray,
        [Parameter()][switch]$DBSchemaListArray,
        [Parameter()][string]$DBNumberFromName = "",
        [Parameter()][int]$DBNameFromNumber = 0,
        [Parameter()][hashtable]$DBHashtable,
        [Parameter()][PSCustomObject]$DBSchema
    )

    # Return how many Databases are in the Hashtable
    if ($DBAmount.IsPresent) { return $DBHashtable.Count }

    # Return a string menu with all of the Databases
    if ($DBListMenu.IsPresent) {
        $DBListMenuString = ""
        $DBHashtable.GetEnumerator() | ForEach-Object {
            $DBListMenuString += "$($_.Name). $($_.Value)`n"
        }
        return $DBListMenuString
    }

    # Returns an array of the databases number in a string format with "/" as seperators
    if ($DBNumbersListArray.IsPresent) {
        $DBNumbersArray = ""
        $DBHashtable.GetEnumerator() | ForEach-Object {
            $DBNumbersArray += "$($_.Name)/"
        }
        $DBNumbersArray = $DBNumbersArray.Substring(0, ($DBNumbersArray.Length) - 1)
        return $DBNumbersArray
    }
    
    # Returns an array of the databases configuration in an list format with "/" as seperators
    if ($DBSchemaListArray.IsPresent) {
        $DBSchemaArray = @()
        $DBSchema.PSObject.Properties | ForEach-Object {
            $DBSchemaArray += "$($_.Name)"
        }
        return $DBSchemaArray
    }

    # Return the number of a Database from its name
    if ($DBNumberFromName -ne "") {
        $DBNumberFromName = [string]$DBNumberFromName 
        $DBHashtable.GetEnumerator() | ForEach-Object {
            if ($($_.Value) -eq $DBNumberFromName )
            { return $_.Name; break }
        }
    }

    # Return the name of a Database from its number
    if ($DBNameFromNumber -ne 0) {
        $DBNameFromNumber = [string]$DBNameFromNumber 
        $DBHashtable.GetEnumerator() | ForEach-Object {
            if ($($_.Name) -eq $DBNameFromNumber )
            { return $_.Value; break }
        }
    }
}

# Function Get-MSSQLInstancesPort
Function Get-MSSQLInstancesPort {

    param ([string]$Server)

    [system.reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
    [system.reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | Out-Null
    $mc = new-object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer $Server
    $Instances = $mc.ServerInstances

    foreach ($Instance in $Instances) {
        $port = @{Name = "Port"; Expression = { $_.ServerProtocols['Tcp'].IPAddresses['IPAll'].IPAddressProperties['TcpPort'].Value } }
        $Parent = @{Name = "Parent"; Expression = { $_.Parent.Name } }
        $Instance | Select-Object $Parent, Name, $Port
    }
}


# Function Test-DatabaseCredentials
Function Test-DatabaseCredentials {
    # Parameters
    Param(
        [Parameter()][string]$DBName,
        [Parameter()][PSCustomObject]$DBCreds
    )

    # Trying to connect to Databases
    Switch ($DBName) {
        # Testing Connection to 
        "PostgresSQL" {
            
        }
        # Testing Connection to 
        "MongoDB" {

        }
        # Testing Connection to 
        "MicrosoftSQL" {
            # Testing Connection to SQL Server
            if ((New-Object System.Net.Sockets.TCPClient ($DBCreds.Address),($DBCreds."Port/Path")).Connected -ne "True")
            { return $False }

            # Importing SqlServer Module for powershell
            Import-Module -Name "$PSScriptRoot\Dependencies\SqlServer\22.1.1\SqlServer.psd1"

            # Getting the MSSQL Instance
            $DatabaseWindowsUsername = Read-Host -Prompt "Please enter a user for the Windows Database Server"
            $DatabaseWindowsPassword = Read-Host -Prompt "Please enter a password for the Windows Database Server" -AsSecureString
            #$Pass = ConvertTo-SecureString "password" -AsPlainText -Force
            $Creds = [pscredential](New-Object System.Management.Automation.PSCredential ($DatabaseWindowsUsername, $DatabaseWindowsPassword))

            $VarGetMSSQLInstancesPort = ${function:Get-MSSQLInstancesPort}
            $MSSQLInstanceName = Invoke-Command -ComputerName ($DBCreds.Address) -Credential $Creds -ScriptBlock ${function:Get-MSSQLInstancesPort} -Argumentlist ($DBCreds.Address)
            Write-Host $MSSQLInstanceName
            return $True
            

        }
        # Testing Connection to 
        "MySQL" {

        }
        # Testing Connection to 
        "SQLite" {

        }

        # Ignore switch statement if DBName is incorrect
        default {}
    }

}

# Function Invoke-DatabaseConnector
Function Invoke-DatabaseConnector {

    # Setting Variables for upcoming text
    $DatabasesAmount = Get-DatabaseListInfo -DBAmount -DBHashtable $ConstDatabasesList;
    $DatabasesMenu = Get-DatabaseListInfo -DBListMenu -DBHashtable $ConstDatabasesList;
    $DatabasesNumbersArray = Get-DatabaseListInfo -DBNumbersListArray -DBHashtable $ConstDatabasesList;
    $DatabasesSchemaArray = Get-DatabaseListInfo -DBSchemaListArray -DBSchema $ConstDatabasesCredentialsSchema;

    # Acquiring DB Credentials Json from the Backend Database Connector Service
    if (Test-Path -Path "$PSScriptRoot\\$ConstContainerName_BackendDatabaseConnector\\Configuration\\DBCredentials.json")
    { $DBConnectorCredentials = [PSCustomObject](Get-Content -Path "$PSScriptRoot\\$ConstContainerName_BackendDatabaseConnector\\Configuration\\DBCredentials.json" | ConvertFrom-Json) }
    else {
        $DBConnectorCredentials = [PSCustomObject]@{} #$ConstDatabasesCredentialsSchema }
    }
    Write-Host "DBConnectorCredentials: $DBConnectorCredentials"

    # Starting the Databases Configuration
    $StopDBConfigurationFlag = $False
    While ($StopDBConfigurationFlag -eq $False) {
        Clear-Host
        Clear-Host
        Write-Host "At First you need to set up your Database `n$ConstDomRecVersion Supports $DatabasesAmount Different Databases, `n$DatabasesMenu  `nYou can set up one of each and they will work simultaneously, `nAll Data will be saved to all of them for back up, `nIf you choose to configure more Databases in the future, the existing data will not be replicated,`n Future data will be added to the newly configured databases "

        # Ask for what DB to be configured
        $DatabaseNumber = [string](Read-Host "What Database do you want to configure? [$DatabasesNumbersArray] or [0] to Save")

        # Configuring each Database
        Clear-Host
        Switch ($DatabaseNumber) {

            # Saving Configuration and writing to DBCredentials.json file
            "0" {
                Write-Host "Saving Configuration"
                Out-File -FilePath "$PSScriptRoot\\$ConstContainerName_BackendDatabaseConnector\\Configuration\\DBCredentials.json" -InputObject $($DBConnectorCredentials | ConvertTo-Json)
                $StopDBConfigurationFlag = $True
            }

            # Configuration for all available database number
            "$DatabaseNumber" {

                # Break if number doesnt exist in DB numbers array
                if ( !($DatabasesNumbersArray.Contains($DatabaseNumber)) -or ("" -eq $DatabaseNumber)) { break }

                # Starting to edit the configuration
                $DBConfigurationEntry = ""
                While ($DBConfigurationEntry -ne "Save") {

                    # Continue Configuration if number exist in DB numbers array
                    $SelectedDatabaseConfigurationName = $(Get-DatabaseListInfo -DBNameFromNumber $DatabaseNumber -DBHashtable $ConstDatabasesList)
                    Write-Host "`n-------------------------------------------------------------------------------"
                    Write-Host "Current Configuration for '$SelectedDatabaseConfigurationName'"

                    # Create empty configuration if doesnt exist
                    if ($null -eq $($DBConnectorCredentials.$SelectedDatabaseConfigurationName))
                    { $DBConnectorCredentials | Add-Member -MemberType NoteProperty -Name "$SelectedDatabaseConfigurationName" -Value $($ConstDatabasesCredentialsSchema.PsObject.Copy()) }
                    Write-Host $($DBConnectorCredentials.$SelectedDatabaseConfigurationName)
                    Write-Host "-------------------------------------------------------------------------------"

                    # Asking for entry to edit
                    $DBConfigurationEntry = (Read-Host -Prompt "`nWhat entry would you like to edit [Exmaple: Address] `n Write [Save] to Exit and Save Configuration")
                    Switch ($DBConfigurationEntry) {
                        "" { }

                        # if entry exist than edit it
                        "$DBConfigurationEntry" { 
                            if ( $DatabasesSchemaArray.Contains($DBConfigurationEntry) ) {
                                $DBConfigurationEntryValue = (Read-Host -Prompt "What is the Value you would like to enter for the $SelectedDatabaseConfigurationName [$DBConfigurationEntry]")
                                $($DBConnectorCredentials.$SelectedDatabaseConfigurationName).$DBConfigurationEntry = $DBConfigurationEntryValue
                            }
                            Clear-Host
                        }

                        # Ask again if user hits enter or misspelled
                        default { }
                    }
                }
               
                # Trying Credentials to Connect Database
                $DatabaseConnectionStatus = Test-DatabaseCredentials -DBName $SelectedDatabaseConfigurationName -DBCreds $($DBConnectorCredentials.$SelectedDatabaseConfigurationName)

                # Return Database Connection Status
                if ($DatabaseConnectionStatus -eq $True) 
                { Write-Host "Connection to $SelectedDatabaseConfigurationName was Succsesfull!" }
                else 
                { Write-Host "Connection to $SelectedDatabaseConfigurationName was unSuccsesfull!" }
                Start-Sleep -Seconds 10
                Clear-Host

            }
            
            # User hit enter, so asking again for number
            default { }
        }
    }

}


# Function Invoke-Container
Function Invoke-Container {
    # Parameters
    Param (
        [Parameter(HelpMessage = "The Container Full Path")]
        [string]$ContainerPath
    )

    # Choosing The Database



    
    
    Write-Host "The Container '$($ContainerPath | Split-Path -Leaf)' Supports The Following Databases:"
    $DBCredentials = (Get-Content -Path "$ContainerPath\\Configuration\\DBCredentials.json" | ConvertFrom-Json)
    ($DBCredentials | Get-Member  -MemberType "NoteProperty").Name | Foreach-Object { 
        Write-Host $_
    }
    
}

# ---------------------------------------------------------------- #

# Start of Main Code
Write-Host "Warming up..."
Start-Sleep -Seconds 3
Clear-Host

# Checking for Checking Dependencies
Check-Dependencies

# Starting Database Connector
Invoke-DatabaseConnector

# Starting Frontend GUI

# Looping through all Backend Services and Starting them
