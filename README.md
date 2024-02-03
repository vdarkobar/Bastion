# Bastion
## SSH connectivity to all of the VMs

> *Create <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/Proxmox.md#proxmox">Proxmox</a> VM: (1CPU/1GBRAM/16GBHDD) using <a href="https://www.debian.org/">Debian server</a>.  
> Add SSH Server during installation.*  
> *Do not set root password during installation, this way created user will gain sudo privileges.* 

### *Run this command*:
```
sudo apt -y install git
RED='\033[0;31m'; echo -ne "${RED}Enter directory name: "; read NAME; mkdir -p "$NAME"; \
cd "$NAME" && git clone https://github.com/vdarkobar/Bastion.git . && \
chmod +x create.sh && \
./create.sh
```
