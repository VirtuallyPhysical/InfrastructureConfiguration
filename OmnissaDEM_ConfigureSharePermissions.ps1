# Define shares and their paths
$Shares = @(
    @{ Name = "Profiles"; Path = "C:\Profiles" },
    @{ Name = "Configuration"; Path = "C:\Configuration" }
)

# Define security groups
$AdminGroup = "DOMAIN\RoamingProfiles_Admins"
$UserGroup = "DOMAIN\RoamingProfiles_Users"

foreach ($Share in $Shares) {
    $ShareName = $Share.Name
    $SharePath = $Share.Path

    Write-Host "Processing share: $ShareName at $SharePath"

    # Ensure the folder exists
    if (!(Test-Path $SharePath)) {
        New-Item -Path $SharePath -ItemType Directory -Force
        Write-Host "Created folder: $SharePath"
    }

    # Create the share if it doesn't exist
    if (!(Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name $ShareName -Path $SharePath -FullAccess $AdminGroup -ChangeAccess "Authenticated Users"
        Write-Host "Created SMB Share: $ShareName"
    } else {
        Write-Host "SMB Share $ShareName already exists. Updating permissions..."
        Grant-SmbShareAccess -Name $ShareName -AccountName "Authenticated Users" -AccessRight Change -Force
        Grant-SmbShareAccess -Name $ShareName -AccountName $AdminGroup -AccessRight Full -Force
        # Remove Everyone if it exists
        Revoke-SmbShareAccess -Name $ShareName -AccountName "Everyone" -Force -ErrorAction SilentlyContinue
    }

    # Set NTFS Permissions
    Write-Host "Configuring NTFS permissions for $SharePath..."
    $Acl = Get-Acl -Path $SharePath

    # Remove inheritance (optional but recommended)
    $Acl.SetAccessRuleProtection($True, $False)  # Disable inheritance, do not copy existing permissions
    Set-Acl -Path $SharePath -AclObject $Acl

    # Define NTFS permissions
    $Permissions = @(
        New-Object System.Security.AccessControl.FileSystemAccessRule($AdminGroup, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"),
        New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"),
        New-Object System.Security.AccessControl.FileSystemAccessRule($UserGroup, "ReadAndExecute", "None", "None", "Allow"),
        New-Object System.Security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", "ContainerInherit, ObjectInherit", "InheritOnly", "Allow")
    )

    # Apply new permissions
    foreach ($Permission in $Permissions) {
        $Acl.AddAccessRule($Permission)
    }

    # Save NTFS changes
    Set-Acl -Path $SharePath -AclObject $Acl

    Write-Host "Permissions configured successfully for $ShareName."
}

Write-Host "All shares processed successfully."