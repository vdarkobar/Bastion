<p align="left">
  <a href="https://github.com/vdarkobar/Home-Cloud/tree/main?tab=readme-ov-file#create-bastion--jump-server">Home</a>
</p>  
  
# Bastion
## SSH connectivity to all of the VMs

<p align="center">
  <img src="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/bastion.webp">
</p>

> *Create <a href="https://www.debian.org/">Debian server</a> VM: (2CPU/2GBRAM/16GBHDD).  
> *Do not set root password during installation, this way created user will gain sudo privileges.*   
> *Add SSH Server during installation.*  
  
### *Run this command and follow the instructions*:
```
clear
sudo apt -y install git && \
RED='\033[0;31m'; NC='\033[0m'; echo -ne "${RED}Enter directory name: ${NC}"; read NAME; mkdir -p "$NAME"; \
cd "$NAME" && git clone https://github.com/vdarkobar/Bastion.git . && \
chmod +x create.sh && \
rm README.md && \
./create.sh
```


<br><br>
*(steps used to configure <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/Bastion.md#bastion">Bastion Server</a>)*

