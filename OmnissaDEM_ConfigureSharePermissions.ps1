function Set-SharePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [Parameter(Mandatory = $true)]
        [string]$SharePath,
        
        [Parameter(Mandatory = $true)]
        [string]$AdminGroup,
        
        [Parameter(Mandatory = $true)]
        [string]$UserGroup
    )

    Write-Host "Processing share: $ShareName at $SharePath"

    # Ensure the folder exists
    if (!(Test-Path $SharePath)) {
        New-Item -Path $SharePath -ItemType Directory -Force
        Write-Host "Created folder: $SharePath"
    }

    # Create the share if it doesn't exist, otherwise update permissions
    if (!(Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name $ShareName -Path $SharePath -FullAccess $AdminGroup `
            -ErrorAction Stop
        Grant-SmbShareAccess -Name $ShareName -AccountName $UserGroup -AccessRight Read -Force
        # Remove Everyone if it exists
        Revoke-SmbShareAccess -Name $ShareName -AccountName "Everyone" -Force -ErrorAction SilentlyContinue
        Write-Host "Created SMB Share: $ShareName"
    } else {
        Write-Host "SMB Share $ShareName already exists. Updating permissions..."
        Grant-SmbShareAccess -Name $ShareName -AccountName $UserGroup -AccessRight Read -Force
        Grant-SmbShareAccess -Name $ShareName -AccountName $AdminGroup -AccessRight Full -Force
        # Remove Everyone if it exists
        Revoke-SmbShareAccess -Name $ShareName -AccountName "Everyone" -Force -ErrorAction SilentlyContinue
    }

    # Set NTFS Permissions
    Write-Host "Configuring NTFS permissions for $SharePath..."
    $Acl = Get-Acl -Path $SharePath

    # Disable inheritance (do not copy existing permissions)
    $Acl.SetAccessRuleProtection($True, $False)
    Set-Acl -Path $SharePath -AclObject $Acl

    # Define NTFS permissions using the proper .NET enum values
    $Permissions = @(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $AdminGroup,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "SYSTEM",
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $UserGroup,
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ),
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            "CREATOR OWNER",
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [System.Security.AccessControl.PropagationFlags]::InheritOnly,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    )

    # Apply the new NTFS permissions
    foreach ($Permission in $Permissions) {
        $Acl.AddAccessRule($Permission)
    }

    Set-Acl -Path $SharePath -AclObject $Acl

    Write-Host "Permissions configured successfully for $ShareName."
}

# Share 1: AdminGroup gets FullAccess, UserGroup gets Read
Set-SharePermissions -ShareName "Share1" -SharePath "C:\Test\Share1" -AdminGroup "home.local\TestAdmin" -UserGroup "home.local\TestUser"

# Share 2: AdminGroup gets FullAccess, but a different user group gets Read
Set-SharePermissions -ShareName "Share2" -SharePath "C:\Test\Share2" -AdminGroup "home.local\TestAdmin" -UserGroup "home.local\TestUser2"
