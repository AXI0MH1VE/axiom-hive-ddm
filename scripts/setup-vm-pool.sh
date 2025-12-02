#!/bin/bash

# Axiom Hive DDM Lab Environment Setup Script
# Sets up VM pool for kernel matrix testing

set -e

echo "Setting up Axiom Hive DDM Lab Environment..."

# Check for virtualization support
if ! grep -q vmx /proc/cpuinfo && ! grep -q svm /proc/cpuinfo; then
    echo "ERROR: Virtualization not supported on this CPU"
    exit 1
fi

# Install required packages
echo "Installing virtualization tools..."
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients virt-manager cloud-image-utils

# Start libvirt service
sudo systemctl enable --now libvirtd

# Create VM pool directory
VM_POOL_DIR="$HOME/ddm-vm-pool"
mkdir -p "$VM_POOL_DIR"

# Kernel versions and corresponding Ubuntu versions
declare -A KERNEL_MAP=(
    ["5.10"]="focal"    # Ubuntu 20.04
    ["5.15"]="impish"   # Ubuntu 21.10
    ["6.1"]="jammy"     # Ubuntu 22.04
    ["6.6"]="noble"     # Ubuntu 24.04
)

# Function to create VM
create_vm() {
    local kernel_version=$1
    local ubuntu_codename=$2
    local vm_name="ddm-kernel-${kernel_version}"

    echo "Creating VM for kernel $kernel_version..."

    # Download Ubuntu cloud image
    local image_url="https://cloud-images.ubuntu.com/${ubuntu_codename}/current/${ubuntu_codename}-server-cloudimg-amd64.img"
    local image_file="$VM_POOL_DIR/${ubuntu_codename}-server-cloudimg-amd64.img"

    if [ ! -f "$image_file" ]; then
        echo "Downloading Ubuntu ${ubuntu_codename} cloud image..."
        wget -O "$image_file" "$image_url"
    fi

    # Create VM disk
    local vm_disk="$VM_POOL_DIR/${vm_name}.qcow2"
    qemu-img create -f qcow2 -b "$image_file" "$vm_disk" 20G

    # Create cloud-init config
    local ci_dir="$VM_POOL_DIR/${vm_name}-ci"
    mkdir -p "$ci_dir"

    # User data for cloud-init
    cat > "$ci_dir/user-data" << EOF
#cloud-config
hostname: ${vm_name}
manage_etc_hosts: true
users:
  - name: ddm
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin
    home: /home/ddm
    shell: /bin/bash
    lock_passwd: false
    passwd: \$6\$rounds=4096\$salt\$hashed_password
ssh_pwauth: true
ssh_authorized_keys:
  - $(cat ~/.ssh/id_rsa.pub 2>/dev/null || echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...")
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
  - echo "DDM Lab VM for kernel ${kernel_version}" > /etc/motd
  - git clone https://github.com/axiom-hive/ddm.git /opt/ddm
EOF

    # Meta data
    cat > "$ci_dir/meta-data" << EOF
instance-id: ${vm_name}
local-hostname: ${vm_name}
EOF

    # Create ISO for cloud-init
    cloud-localds "$VM_POOL_DIR/${vm_name}-ci.iso" "$ci_dir/user-data" "$ci_dir/meta-data"

    # Create VM
    virt-install \
        --name "$vm_name" \
        --ram 4096 \
        --vcpus 2 \
        --disk path="$vm_disk",format=qcow2 \
        --disk path="$VM_POOL_DIR/${vm_name}-ci.iso",device=cdrom \
        --network network=default,model=virtio \
        --os-variant ubuntu22.04 \
        --graphics none \
        --console pty,target_type=serial \
        --import

    echo "VM $vm_name created successfully"
}

# Create VMs for each kernel version
for kernel in "${!KERNEL_MAP[@]}"; do
    create_vm "$kernel" "${KERNEL_MAP[$kernel]}"
done

# Setup PTP simulation
echo "Setting up PTP simulation..."
sudo apt install -y linuxptp chrony

# Configure chrony for PTP
sudo tee /etc/chrony/chrony.conf > /dev/null << EOF
server time.nist.gov iburst
allow 192.168.122.0/24
local stratum 10
EOF

sudo systemctl restart chrony

# Create management script
cat > "$VM_POOL_DIR/manage-vms.sh" << 'EOF'
#!/bin/bash

case "$1" in
    start)
        for vm in $(virsh list --name | grep ddm-kernel); do
            virsh start "$vm"
        done
        ;;
    stop)
        for vm in $(virsh list --name | grep ddm-kernel); do
            virsh shutdown "$vm"
        done
        ;;
    status)
        virsh list --all
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        ;;
esac
EOF

chmod +x "$VM_POOL_DIR/manage-vms.sh"

echo "VM pool setup complete!"
echo "Use $VM_POOL_DIR/manage-vms.sh to control VMs"
echo "Connect to VMs: ssh ddm@<vm-ip>"