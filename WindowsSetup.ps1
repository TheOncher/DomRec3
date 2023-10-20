# Requires
#Requires -PSEdition Desktop

# Function Invoke-Container
Function Invoke-Container{
    # Parameters
    Param (
        [Parameter(HelpMessage = "The Container Full Path")]
        [string]$ContainerPath
    )

    # Choosing The Database



    b
    
    Write-Host "The Container '$($ContainerPath | Split-Path -Leaf)' Supports The Following Databases:"
    $DBCredentials = (Get-Content -Path "$ContainerPath\\Configuration\\DBCredentials.json" | ConvertFrom-Json)
    ($DBCredentials | Get-Member  -MemberType "NoteProperty").Name | Foreach-Object { 
        Write-Host $_
    }
    
}


# Retrieving all Containers Folders
$ContainerFolders = (Get-ChildItem -Path "$PSScriptRoot" -Filter "*Service - Act*" | Select-Object FullName).FullName

# Foreach Container Folder ask for Credentials to DB
$ContainerFolders | Foreach-Object {
    Invoke-Container -ContainerPath $_
}
    # Add Credentials to DBCredentials.json
    # Start the Container
