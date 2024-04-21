<p align="left">
  <a href="https://github.com/vdarkobar/Home-Cloud/tree/main?tab=readme-ov-file#create-bastion--jump-server">Home</a>
</p>  
  
# Bastion
## SSH connectivity to all of the VMs

<p align="center">
  <img src="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/bastion.webp">
</p>

> *Create Debian server VM/CT: (2CPU/2GBRAM/16GBHDD).  
> *Do not set root password during installation (VM), this way created user will gain sudo privileges.*   
> *Add SSH Server during installation.*  
  
### *Run this command and follow the instructions*:
*VM/CT*:
```
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/Bastion/main/setup.sh)"
```


<br><br>
*(steps used to configure <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/Bastion.md#bastion">Bastion Server</a>)*

