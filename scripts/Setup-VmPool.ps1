# Axiom Hive DDM Lab Environment Setup Script (Windows)
# Sets up VM pool for kernel matrix testing using Hyper-V

param(
    [switch]$Force
)

#Requires -RunAsAdministrator
#Requires -Version 5.1

Write-Host "Setting up Axiom Hive DDM Lab Environment on Windows..." -ForegroundColor Green

# Check for Hyper-V
if (-not (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State -eq "Enabled") {
    Write-Error "Hyper-V is not enabled. Please enable Hyper-V and restart."
    exit 1
}

# Enable Hyper-V features if needed
$hypervFeatures = @(
    "Microsoft-Hyper-V",
    "Microsoft-Hyper-V-Management-Clients",
    "Microsoft-Hyper-V-Management-PowerShell"
)

foreach ($feature in $hypervFeatures) {
    if ((Get-WindowsOptionalFeature -Online -FeatureName $feature).State -ne "Enabled") {
        Write-Host "Enabling $feature..."
        Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
    }
}

# Create VM pool directory
$VmPoolDir = "$env:USERPROFILE\ddm-vm-pool"
if (-not (Test-Path $VmPoolDir)) {
    New-Item -ItemType Directory -Path $VmPoolDir -Force
}

# Kernel versions and Ubuntu versions
$KernelMap = @{
    "5.10" = "focal"    # Ubuntu 20.04
    "5.15" = "impish"   # Ubuntu 21.10
    "6.1"  = "jammy"    # Ubuntu 22.04
    "6.6"  = "noble"    # Ubuntu 24.04
}

function New-DdmVm {
    param(
        [string]$KernelVersion,
        [string]$UbuntuCodename
    )

    $VmName = "ddm-kernel-$KernelVersion"
    Write-Host "Creating VM for kernel $KernelVersion..."

    # Check if VM already exists
    if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Write-Host "Removing existing VM $VmName..."
            Remove-VM -Name $VmName -Force
        } else {
            Write-Host "VM $VmName already exists. Use -Force to recreate."
            return
        }
    }

    # Download Ubuntu cloud image
    $ImageUrl = "https://cloud-images.ubuntu.com/${UbuntuCodename}/current/${UbuntuCodename}-server-cloudimg-amd64.vhdx.zip"
    $ImageZip = "$VmPoolDir\${UbuntuCodename}-server-cloudimg-amd64.vhdx.zip"
    $ImageFile = "$VmPoolDir\${UbuntuCodename}-server-cloudimg-amd64.vhdx"

    if (-not (Test-Path $ImageFile)) {
        Write-Host "Downloading Ubuntu ${UbuntuCodename} cloud image..."
        try {
            Invoke-WebRequest -Uri $ImageUrl -OutFile $ImageZip
            Expand-Archive -Path $ImageZip -DestinationPath $VmPoolDir
            Remove-Item $ImageZip
        } catch {
            Write-Error "Failed to download Ubuntu image: $_"
            return
        }
    }

    # Create VM
    $VmPath = "$VmPoolDir\$VmName.vhdx"
    Copy-Item $ImageFile $VmPath

    New-VM -Name $VmName -MemoryStartupBytes 4GB -VHDPath $VmPath -Generation 2 |
        Set-VM -ProcessorCount 2 -AutomaticStartAction Nothing -AutomaticStopAction ShutDown

    # Configure networking
    $SwitchName = "DDM-Lab-Switch"
    if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $SwitchName -SwitchType Internal
    }
    Get-VM -Name $VmName | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -VMSwitchName $SwitchName

    # Create cloud-init config
    $CiDir = "$VmPoolDir\$VmName-ci"
    if (-not (Test-Path $CiDir)) {
        New-Item -ItemType Directory -Path $CiDir -Force
    }

    # User data
    $UserData = @"
#cloud-config
hostname: ${VmName}
manage_etc_hosts: true
users:
  - name: ddm
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin
    home: /home/ddm
    shell: /bin/bash
    lock_passwd: false
    passwd: `$6`$rounds=4096`$salt`$hashed_password
ssh_pwauth: true
ssh_authorized_keys:
  - $(Get-Content "$env:USERPROFILE\.ssh\id_rsa.pub" -ErrorAction SilentlyContinue)
package_update: true
packages:
  - build-essential
  - clang
  - llvm
  - libbpf-dev
  - linux-tools-generic
  - git
  - vim
runcmd:
  - echo "DDM Lab VM for kernel ${KernelVersion}" > /etc/motd
  - git clone https://github.com/axiom-hive/ddm.git /opt/ddm
"@

    $UserData | Out-File -FilePath "$CiDir\user-data" -Encoding UTF8

    # Meta data
    $MetaData = @"
instance-id: ${VmName}
local-hostname: ${VmName}
"@

    $MetaData | Out-File -FilePath "$CiDir\meta-data" -Encoding UTF8

    # Create ISO for cloud-init (requires Windows ADK or alternative)
    # For now, we'll skip cloud-init and provide manual setup instructions

    Write-Host "VM $VmName created successfully"
    Write-Host "Note: Cloud-init setup requires additional tools. Please configure manually."
}

# Create VMs for each kernel version
foreach ($kernel in $KernelMap.Keys) {
    New-DdmVm -KernelVersion $kernel -UbuntuCodename $KernelMap[$kernel]
}

# Setup PTP simulation (Windows Time service)
Write-Host "Configuring Windows Time service for PTP simulation..."
w32tm /config /manualpeerlist:"time.nist.gov" /syncfromflags:manual /reliable:YES /update
Restart-Service w32time

# Create management script
$ManageScript = @'
param([string]$Action)

switch ($Action) {
    "start" {
        Get-VM | Where-Object Name -like "ddm-kernel-*" | Start-VM
    }
    "stop" {
        Get-VM | Where-Object Name -like "ddm-kernel-*" | Stop-VM
    }
    "status" {
        Get-VM | Where-Object Name -like "ddm-kernel-*" | Select-Object Name, State
    }
    default {
        Write-Host "Usage: .\Manage-Vms.ps1 {start|stop|status}"
    }
}
'@

$ManageScript | Out-File -FilePath "$VmPoolDir\Manage-Vms.ps1" -Encoding UTF8

Write-Host "VM pool setup complete!" -ForegroundColor Green
Write-Host "Use $VmPoolDir\Manage-Vms.ps1 to control VMs"
Write-Host "Connect to VMs via PowerShell Direct: Enter-PSSession -VMName <vm-name>"