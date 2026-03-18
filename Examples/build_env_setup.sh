
#!/usr/bin/env bash
# working on ubuntu 24.04
set -euo pipefail

echo "[+] Updating system"
sudo apt update

echo "[+] Installing base build tools"
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-tools-common \
    linux-headers-$(uname -r) \
    pkg-config \
    gcc-multilib \
    make

echo "[+] Verifying clang BPF target support"
if ! clang -target bpf -v >/dev/null 2>&1; then
    echo "[-] Clang does not support BPF target"
    exit 1
fi

echo "[+] Checking for BTF support"
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "[-] BTF not enabled in kernel. CO-RE will not work."
    echo "    You need CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi

echo "[+] Environment ready."
echo "    You can now build CO-RE eBPF programs."
