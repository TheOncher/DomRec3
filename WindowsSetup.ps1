# Requires
#Requires -PSEdition Desktop

# Constants
$DomRecVersion = "DomRec3 v1"
$DatabasesList = [ordered]@{"1" = "PostgresSQL"; "2" = "MongoDB"; "3" = "MicrosoftSQL"; "4" = "MySQL"; "5" = "SQLite" }
$DockerServiceNameDefault = "com.docker.service"
$DockerServiceName = "com.docker.service"
$ScriptName = Split-Path -Path $($MyInvocation.InvocationName) -Leaf
$BackendDatabaseConnector = "BE Service - Database Connector"

# ------------------------------------------------------------------------- #

# Function Test-Administrator
Function Test-Administrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

# Function Get-DatabaseListInfo
Function Get-DatabaseListInfo {
    # Parameters
    Param (
        [Parameter()][switch]$DBAmount,
        [Parameter()][switch]$DBListMenu,
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

# Function Check-Dependencies
Function Check-Dependencies {
    Clear-Host
    # Check Docker Service Status
    $DockerServiceStatus = (Get-Service -Name "$DockerServiceName" -ErrorAction SilentlyContinue ).Status

    # Docker not Installed
    if ($null -eq $DockerServiceStatus) {
        Write-Host "Looks Like Docker is not installed, Please refer to the Docker website and install it first `nAnd make sure the service name is '$DockerServiceNameDefault', if you have modified the Docker service name, `ncheck the $ScriptName code and modify the 'DockerServiceName' variable in the Constants section"
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
            $StartProcessArguments = '-c "Start-Service -Name ' + $DockerServiceName + '"'
            Start-Process -FilePath "powershell.exe" -ArgumentList $StartProcessArguments -Verb RunAs
        }
        # Attempt to start Docker
        elseif ( (($Answer -eq "y") -or ($Answer -eq "")) -and (Test-Administrator) ) {
            try { Start-Service -Name "$DockerServiceName" }
            catch { Write-Host "Cannot Start Docker Service, Please try Manually"; $Host.UI.RTeadLine(); exit }
        }
        # ReChecking for docker service status
        Start-Sleep -Seconds 4 
        $DockerServiceStatus = (Get-Service -Name "$DockerServiceName" -ErrorAction SilentlyContinue ).Status
    }
    # Docker is up!
    Write-Host "Docker is up!"
    Clear-Host
}

# Function Invoke-DatabaseConnector
Function Invoke-DatabaseConnector {
    # Starting Database Connector Explanation, How to Configure
    Write-Host "At First you need to set up your Database `n$DomRecVersion Supports $($DatabasesList.Count) Different Databases, `n$(Get-DatabaseListInfo -DBListInString $True) `nYou can set up one of each and they will work simultaneously, `nAll Data will be saved to all of them for back up"

    # Acquiring DB Credentials Json from the Backend Database Connector Service
    $DBCredentials = (Get-Content -Path "$PSScriptRoot\\$BackendDatabaseConnector\\Configuration\\DBCredentials.json" | ConvertFrom-Json)

    # Starting the Databases Configuration
    #While ($DatabaseNumber)
    $DatabaseNumber = [string](Read-Host "What Database do you want to configure? [1/2/3/4/5]")
    $DatabasesDictionary = Get-DatabaseListInfo -DatabaseNumber $DatabaseNumber -DatabasesList $DatabasesList
    Switch ($DatabaseNumber) { 
        "1" { Write-Host $($DatabasesDictionary[$DatabaseNumber]) }
        default { Write-Host "dd" }
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
