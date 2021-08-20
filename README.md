The scripts in this directory will help you to stand up a development environment:

* Develop on the host system, using your text editor of choice.
* Build & run kernel modules inside a qemu/KVM-based VM (mounted via local NFS share)
    * Easy PCIe & NVDIMM/PMEM passthrough

### Development Workflow

#### (Once) Prepare Disk Image (Part 1)

* Download a Debian Bullseye VM cloud image (qcow2, generic cloud image)
    * https://cloud.debian.org/images/cloud/
* Resize the image using qemu-resize
* Mount the image using `losetup`, or `nbd`
* Repair GPT & resize root partition (e.g. using `parted`)
* Make `root` user passwdless by removing the `*` in `/mnt/etc/shadow`
* Unmount image / nbd

For the next sections, we assume the disk image to be `./devvm.qcow2`

#### Prepare Kernel Tree

*for booting a kernel built on the host system*

* Enable kernel options for virtio and 9p (no modules)
  * `CONFIG_VIRTIO_BLK=y`
  * `CONFIG_9P_FS=y`
  * `CONFIG_NET_9P=y`
  * `CONFIG_NET_9P_VIRTIO=y`
* Build bzImage and modules
* After launching the VM with `--kernel-tree`
  * Mount the kernel tree (e.g., via `/etc/fstab`)
    * `kernelfs /usr/src/linux-host 9p nofail 0 0`
  * Link the kernel tree to the modules directory
    * `ln -s /usr/src/linux-host /lib/modules/$(uname -r)`
  * Run `depmod`
* After a reboot, the VM should successfully load kernel modules

#### (Every Boot Of The Host)

* Start docker daemon
* Configure the bridge interface & iptables using Ansible
    * `sudo ansible-playbook setup-vm-network.ansible.yml `
* Fedora / `firewalld`: add the bridge interface to the trusted zone
    * `sudo firewall-cmd --add-interface=devbr0 --zone=trusted --permanent`
    * Re-run the ansible playbook to fixup our iptables NAT rules
* Run dnsmasq in foreground (use tmux or similar)
    * Maybe kill other dnsmasqs (think before copy-pasting) `sudo killall dnsmask`
    *  `sudo mkdir -p dnsmasq-hostsdir && sudo dnsmasq -C dnsmasq.conf`
* Start NFS server (runs in foreground, use tmux or similar)
    * `modprobe nfsd`
    * `modprobe nfs`
    * ```
      sudo ./docker_nfs_server.bash 192.168.124.1 192.168.124.50 /directory/to/share ...
                                    ^             ^              ^ 
                                    HOST_IP       GUEST_IP       PATHS that land in container's /etc/exports
      ```

#### Launch VM

Start the VM in a tmux pane like so:

```
sudo ./launch-vm.py \
    --hdd-qcow2-image devvm.qcow2 \
    --bridge devbr0 \
    --name i30pc62-vm1 \
    -m 4096 \
    --smp 8,sockets=1,cores=8,threads=1 \
    --nvdimm /dev/dax0.0,size=1G,pmem=off \
    --vfio-passthrough 0000:00:04.0
```

The VM starts in the foreground (`qemu -nographic` mode) with the VM's console/serial (?) on stdout.
The `devbr0` was created by the Ansible playbook.

(`./launch-vm.py` uses argparse, so try `--help` to see options.
Feel encouraged to hack around in the file.)

#### (Once) Prepare Disk Image (Part 2)

On first launch, use the serial console to log in as `root` (passwordless, see above).
Then

* disable unattended upgrades (`systemctl disable unattended-upgrades.service`)
* create a user account with the same user ID as on the host
* grant that user passwdless sudo for convenience
* you will use that user account to log into the VM via SSH, so setup `authorized_keys` appropriately
* generate ssh server keys (`dpkg-reconfigure openssh-server`)
* enable & start ssh server
* poweroff VM


### Workflow

* SSH login into the VM
* Mount the NFS share
  ```
  sudo mount -t nfs -o vers=4 192.168.124.1:/host/directory/to/share /wrk
                                            ^!!!!! 'host' prefix, as indicated by ./docker_nfs_server.bash
  ```
* **On the host system**: open a text editor, start hacking
* **In the VM**: change into /wrk directory, compile & test there

#### Debugging Using kgdb

TODO

