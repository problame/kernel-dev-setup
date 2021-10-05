#!/usr/bin/env bash

usage() {
	echo "Usage: $1 <disk image>"
	echo "Prepare a Debian disk image for use as dev VM."
}

fail() {
	echo "error: $*"
	exit 1
}

img=${1?$(usage "$0" >/dev/stderr)}
nbd=/dev/nbd0
vm_hostname=$(hostname -s)-vm

qemu-img resize "$img" 20G || fail "could not resize image"

if [[ ! -f "$nbd" ]]; then
	modprobe nbd || fail "could not load nbd module"
fi

qemu-nbd -c "$nbd" "$img" || fail "could not connect nbd"
echo "wait for nbd..." && sleep 1
mount "$nbd"p1 /mnt || fail "could not mount vm image"

pushd /mnt

# passwordless root login
sed -i 's/^root:\*/root:/' etc/shadow || fail "could not remove root password"
# set hostname
echo "$vm_hostname" > etc/hostname

# Kernel tree setup
if [[ ! -d usr/src/linux-host ]]; then
	mkdir usr/src/linux-host
	echo "kernelfs /usr/src/linux-host 9p nofail 0 0" >> etc/fstab
fi

# passwordless SSH login
sed -i 's/.*PasswordAuthentication .*/PasswordAuthentication yes/' etc/ssh/sshd_config
sed -i 's/.*PermitEmptyPasswords .*/PermitEmptyPasswords yes/' etc/ssh/sshd_config
sed -i 's/.*PermitRootLogin .*/PermitRootLogin yes/' etc/ssh/sshd_config

# enable locales
sed -i 's/^# \(en_US.UTF-8\)/\1/' etc/locale.gen

echo chroot...
systemd-nspawn --directory=. --machine="$vm_hostname" sh -c '
locale-gen
systemctl disable unattended-upgrades.service
dpkg-reconfigure openssh-server
'

popd

umount /mnt || fail "could not unmount /mnt"
qemu-nbd -d "$nbd" || fail "could not disconnect nbd"
