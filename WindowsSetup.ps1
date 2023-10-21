# Requires
#Requires -PSEdition Desktop

# Constants
$ConstDomRecVersion = "DomRec3 v1"
$ConstDockerServiceName = "com.docker.service"
$ConstDockerServiceNameDefault = "com.docker.service"
$ConstScriptName = Split-Path -Path $($MyInvocation.InvocationName) -Leaf
$ConstContainerName_BackendDatabaseConnector = "BE Service - Database Connector"
$ConstContainerName_FrontendGUI = "FE Service - GUI"
$ConstDatabasesList = [ordered]@{"1" = "PostgresSQL"; "2" = "MongoDB"; "3" = "MicrosoftSQL"; "4" = "MySQL"; "5" = "SQLite" }
$ConstDatabasesCredentialsSchema = [PSCustomObject]@{"Address" = ""; "Port/Path" = ""; "Username" = ""; "Password" = ""; "CredsTable" = "DomRec-Credentials" }

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
        [Parameter()][switch]$DBListArray,
        [Parameter()][string]$DBNumberFromName = "",
        [Parameter()][int]$DBNameFromNumber = 0,
        [Parameter(Mandatory = $True)][hashtable]$DBHashtable
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
    if ($DBListArray.IsPresent) {
        $DBNumbersArray = ""
        $DBHashtable.GetEnumerator() | ForEach-Object {
            $DBNumbersArray += "$($_.Name)/"
        }
        $DBNumbersArray = $DBNumbersArray.Substring(0, ($DBNumbersArray.Length) - 1)
        return $DBNumbersArray
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

# Function Invoke-DatabaseConnector
Function Invoke-DatabaseConnector {

    # Setting Variables for upcoming text
    $DatabasesAmount = Get-DatabaseListInfo -DBAmount -DBHashtable $ConstDatabasesList
    $DatabasesMenu = Get-DatabaseListInfo -DBListMenu -DBHashtable $ConstDatabasesList
    $DatabasesNumbersArray = Get-DatabaseListInfo -DBListArray -DBHashtable $ConstDatabasesList

    # Acquiring DB Credentials Json from the Backend Database Connector Service
    if (Test-Path -Path "$PSScriptRoot\\$ConstContainerName_BackendDatabaseConnector\\Configuration\\DBCredentials.json")
    { $DBConnectorCredentials = (Get-Content -Path "$PSScriptRoot\\$ConstContainerName_BackendDatabaseConnector\\Configuration\\DBCredentials.json" | ConvertFrom-Json) }
    else { $DBConnectorCredentials = $ConstDatabasesCredentialsSchema }

    # Starting the Databases Configuration
    $StopDBConfigurationFlag = $False
    While ($StopDBConfigurationFlag -eq $False) {
        Clear-Host
        Write-Host "At First you need to set up your Database `n$ConstDomRecVersion Supports $DatabasesAmount Different Databases, `n$DatabasesMenu  `nYou can set up one of each and they will work simultaneously, `nAll Data will be saved to all of them for back up, `nIf you choose to configure more Databases in the future, the existing data will not be replicated,`n Future data will be added to the newly configured databases "

        # Ask for what DB to be configured
        $DatabaseNumber = [string](Read-Host "What Database do you want to configure? [$DatabasesNumbersArray] or [0] to Save")

        # Configuring each Database
        Switch ($DatabaseNumber) { 
            # Saving Configuration and writing to DBCredentials.json file
            "0" { Write-Host "Saving Configuration"; $StopDBConfigurationFlag = $True }

            # Configuration for all available database number
            "$DatabaseNumber" {

                # Break if number doesnt exist in DB numbers array
                if ( !($DatabasesNumbersArray.Contains($DatabaseNumber)) -or ("" -eq $DatabaseNumber)) { break }

                # Continue Configuration if number exist in DB numbers array
                Write-Host "`nCurrent Configuration for '$(Get-DatabaseListInfo -DBNameFromNumber $DatabaseNumber -DBHashtable $ConstDatabasesList)'"
                Write-Host $DBConnectorCredentials.$(Get-DatabaseListInfo -DBNameFromNumber $DatabaseNumber -DBHashtable $ConstDatabasesList)
                $DBConfigurationEntry = (Read-Host -Prompt "`nWhat entry would you like to edit [Exmaple: Address]")
                $Host.UI.ReadLine()
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
