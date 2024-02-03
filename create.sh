#!/bin/bash

##############################################################
# Define ANSI escape sequence for green, red and yellow font #
##############################################################
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'

########################################################
# Define ANSI escape sequence to reset font to default #
########################################################
NC='\033[0m'


#################
# Intro message #
#################
echo
echo -e "${GREEN} Securely access remote instances with a Bastion Host | Jump Server ${NC}"

sleep 1 # delay for 1 seconds
echo

echo -e "${GREEN}REMEMBER: ${NC}"
echo
sleep 0.5 # delay for 0.5 seconds

echo -e "${GREEN} - You should be on a clean Debian Server/Server VM before running this script ${NC}"
echo -e "${GREEN} - You should be logged in as a non root user ${NC}"
echo -e "${GREEN} - To copy generated Private SSH key, your Remote Hosts should be up and running (optional) ${NC}"

sleep 1 # delay for 1 seconds
echo

######################################
# Prompt user to confirm script start#
######################################
while true; do
    echo -e "${GREEN}Start Linux Server Hardening? (y/n) ${NC}"
    read choice

    # Check if user entered "y" or "Y"
    if [[ "$choice" == [yY] ]]; then

        # Execute first command and echo -e message when done
        echo -e "${GREEN}Updating the apt package index and installing necessary packages ${NC}"
        sleep 1.5 # delay for 1.5 seconds
        sudo apt-get update
        sudo apt-get install -y \
            ufw \
            git \
            curl \
            wget \
            gnupg2 \
            fail2ban \
            libpam-tmpdir \
            qemu-guest-agent \
            unattended-upgrades \
            libpam-google-authenticator
        echo -e "${GREEN}Done. ${NC}"
        sleep 1 # delay for 1 second
        echo
        break

    # If user entered "n" or "N", exit the script
    elif [[ "$choice" == [nN] ]]; then
        echo -e "${RED}Aborting script. ${NC}"
        exit

    # If user entered anything else, ask them to correct it
    else
        echo -e "${YELLOW}Invalid input. Please enter 'y' or 'n'.${NC}"
    fi
done

######################################################################
# Creating a backup of files before making changes using the script. #
######################################################################

sudo cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.bak

sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

sudo cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak

sudo cp /etc/fstab /etc/fstab.bak

sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak

sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak

sudo cp /etc/sysctl.conf /etc/sysctl.bak

############################################
# Automatically enable unnatended-upgrades #
############################################
  echo -e "${GREEN}Enabling unnatended-upgrades ${NC}"
  echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | sudo debconf-set-selections && sudo dpkg-reconfigure -f noninteractive unattended-upgrades

  sleep 1.5 # delay for 1.5 seconds

  # Define the file path
  FILEPATH="/etc/apt/apt.conf.d/50unattended-upgrades"

  # Uncomment the lines
  sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";|g' $FILEPATH
  sudo sed -i 's|//Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|Unattended-Upgrade::Remove-New-Unused-Dependencies "true";|g' $FILEPATH
  sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|g' $FILEPATH
  sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "false";|g' $FILEPATH
  sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot-Time "02:00";|Unattended-Upgrade::Automatic-Reboot-Time "02:00";|g' $FILEPATH

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

#################
# Seting up UFW #
#################
  echo -e "${GREEN}Seting up UFW ${NC}"
  # Limit SSH to Port 22/tcp
  sudo ufw limit 22/tcp comment "SSH"
  # Enable UFW without prompt
  sudo ufw --force enable
  # Global blocks
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw reload

  echo -e "${GREEN}Done. ${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

######################
# Seting up Fail2Ban #
######################
  echo -e "${GREEN}Seting up Fail2Ban ${NC}"
  # To preserve your custom settings...
  sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
  # Fixing Debian bug
  sudo sed -i 's|backend = auto|backend = systemd|g' /etc/fail2ban/jail.local

  echo

  echo -e "${GREEN}Enabling Fail2Ban protection for the SSH service ${NC}"
  # Set the path to the sshd configuration file
  config_file="/etc/fail2ban/jail.local"
  # Use awk to add the line "enabled = true" below the second line containing "[sshd]" (first is a comment)
  sudo awk '/\[sshd\]/ && ++n == 2 {print; print "enabled = true"; next}1' "$config_file" > temp_file
  # Overwrite the original configuration file with the modified one
  sudo mv temp_file "$config_file"
  # Change bantime to 60m
  sudo sed -i 's|bantime  = 10m|bantime  = 15m|g' /etc/fail2ban/jail.local
  # Change maxretry to 3
  sudo sed -i 's|maxretry = 5|maxretry = 3|g' /etc/fail2ban/jail.local

  echo -e "${GREEN}Done. ${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

##########################
# Securing Shared Memory #
##########################
  echo -e "${GREEN}Securing Shared Memory ${NC}"
  # Define the line to append
  LINE="none /run/shm tmpfs defaults,ro 0 0"
  # Append the line to the end of the file
  echo "$LINE" | sudo tee -a /etc/fstab > /dev/null

  echo -e "${GREEN}Done. ${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

###############################
# Setting up system variables #
###############################
  echo -e "${GREEN}Setting up system variables ${NC}"

  # Define the file path
  FILEPATH="/etc/sysctl.conf"

  # Uncomment the next two lines to enable Spoof protection (reverse-path filter)
  # Turn on Source Address Verification in all interfaces to
  # prevent some spoofing attacks
  sudo sed -i 's|#net.ipv4.conf.default.rp_filter=1|net.ipv4.conf.default.rp_filter=1|g' $FILEPATH
  sudo sed -i 's|#net.ipv4.conf.all.rp_filter=1|net.ipv4.conf.all.rp_filter=1|g' $FILEPATH

  # Do not accept ICMP redirects (prevent MITM attacks)
  sudo sed -i 's|#net.ipv4.conf.all.accept_redirects = 0|net.ipv4.conf.all.accept_redirects = 0|g' $FILEPATH
  sudo sed -i 's|#net.ipv6.conf.all.accept_redirects = 0|net.ipv6.conf.all.accept_redirects = 0|g' $FILEPATH

  # Do not send ICMP redirects (we are not a router)
  sudo sed -i 's|#net.ipv4.conf.all.send_redirects = 0|net.ipv4.conf.all.send_redirects = 0|g' $FILEPATH

  sudo sed -i 's|#net.ipv4.conf.all.accept_source_route = 0|net.ipv4.conf.all.accept_source_route = 0|g' $FILEPATH
  sudo sed -i 's|#net.ipv6.conf.all.accept_source_route = 0|net.ipv6.conf.all.accept_source_route = 0|g' $FILEPATH

  # Log Martian Packets
  sudo sed -i 's|#net.ipv4.conf.all.log_martians = 1|net.ipv4.conf.all.log_martians = 1|g' $FILEPATH

  # Check if the last command was successful
  if [ $? -eq 0 ]; then
      echo -e "${GREEN}Configuration updated successfully. Reloading sysctl...${NC}"
      sudo sysctl -p
  else
      echo -e "${RED}Error occurred during configuration update.${NC}"
  fi

  echo -e "${GREEN}Done. ${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

#################################
# Locking root account password #
#################################
  echo -e "${GREEN}Locking root account password ${NC}"
  sudo passwd -l root

  echo -e "${GREEN}Done. ${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

######################################################
# Editing the PAM configuration for the SSHD Service #
######################################################
  echo -e "${GREEN}Editing the PAM configuration for the SSHD Service ${NC}"

  # Define the file path
  FILEPATH="/etc/pam.d/sshd"

  # Change the default auth so that SSH won’t prompt users for a password if they don’t present a 2-factor token, comment out:
  # Standard Un*x authorization
  sudo sed -i 's|@include common-auth|#@include common-auth|g' $FILEPATH

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds

  echo

  # Tell SSH to require the use of 2-factor auth
  echo -e "${GREEN}Making SSH to require the use of 2-factor auth ${NC}"
  # Define the line to append
  LINE="auth required pam_google_authenticator.so nullok"

  # Append the line to the end of the file
  echo "$LINE" | sudo tee -a /etc/pam.d/sshd > /dev/null

  echo -e "${GREEN}Done. ${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

############################
# Setting up SSH variables #
############################
  echo -e "${GREEN}Setting up SSH variables ${NC}"

  # Define the file path
  FILEPATH="/etc/ssh/sshd_config"

  # ... enable challenge-response passwords ...
  sudo sed -i 's|KbdInteractiveAuthentication no|#KbdInteractiveAuthentication no|g' $FILEPATH

  # Changing Log level (default INFO)
  sudo sed -i 's|#LogLevel INFO|LogLevel VERBOSE|g' $FILEPATH

  # Determines whether the root user can log in to the system remotely via SSH
  sudo sed -i 's|#PermitRootLogin prohibit-password|PermitRootLogin no|g' $FILEPATH

  # Enforce additional security restrictions
  sudo sed -i 's|#StrictModes yes|StrictModes yes|g' $FILEPATH

  # Limit number of authentication attempts to prevent brute-force attacks
  sudo sed -i 's|#MaxAuthTries 6|MaxAuthTries 3|g' $FILEPATH

  # Maximum number of Sessions
  sudo sed -i 's|#MaxSessions 10|MaxSessions 2|g' $FILEPATH

  # Disable empty passwords and weak passwords
  sudo sed -i 's|#IgnoreRhosts yes|IgnoreRhosts yes|g' $FILEPATH

  # Disable empty passwords and weak passwords
  sudo sed -i 's|#PasswordAuthentication yes|PasswordAuthentication no|g' $FILEPATH

  # Disable empty passwords and weak passwords
  sudo sed -i 's|#PermitEmptyPasswords no|PermitEmptyPasswords no|g' $FILEPATH

###  # Disable X11 forwarding (unless you need it)
###  sudo sed -i 's|X11Forwarding yes|#X11Forwarding yes|g' $FILEPATH

###  # Disable SSH agent forwarding (unless you need it)
###  sudo sed -i 's|#AllowAgentForwarding yes|AllowAgentForwarding no|g' $FILEPATH

  #(test)
  sudo sed -i 's|#AllowAgentForwarding yes|AllowAgentForwarding yes|g' $FILEPATH


###  # Allow users to authenticate using SSH challenge-response mechanisms
###  sudo sed -i 's|ChallengeResponseAuthentication no|ChallengeResponseAuthentication yes|g' $FILEPATH

  # Use GSSAPIAuthentication (allows for IP address-based authentication in SSH)
  sudo sed -i 's|#GSSAPIAuthentication no|GSSAPIAuthentication no|g' $FILEPATH

  # Update SSH settings to use stronger encryption and key exchange algorithms
  sudo sed -i '/# Ciphers and keying/a Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' $FILEPATH
  sudo sed -i '/chacha20-poly1305/a KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256' $FILEPATH

  # It is set by default but Lynus will flag it if it isn't specified
  sudo sed -i '/curve25519-sha256/a Protocol 2' $FILEPATH
  
  echo -e "${GREEN}Done.${NC}"
  sleep 1.5 # delay for 1.5 seconds
  echo

################################################
# Enabling Keyboard-interactive authentication #
################################################
  echo -e "${GREEN}Enabling Keyboard-interactive authentication ${NC}"
  # Define the line to append
  LINE="AuthenticationMethods keyboard-interactive"

  # Append the line to the end of the file
  #AuthenticationMethods publickey,keyboard-interactive		 # If you are using PKI
  echo "$LINE" | sudo tee -a /etc/ssh/sshd_config > /dev/null

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

#######################################################
# Enabling ChallengeResponseAuthentication explicitly #
#######################################################
  echo -e "${GREEN}Enabling ChallengeResponseAuthentication ${NC}"
  # Define the line to append
  LINE="ChallengeResponseAuthentication yes"

  # Append the line to the end of the file
  echo "$LINE" | sudo tee -a /etc/ssh/sshd_config > /dev/null

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

#############################################
# Allow SSH only for the current Linux user #
#############################################
  echo -e "${GREEN}Allowing SSH only for the current Linux user ${NC}"
  # Get the current Linux user
  user=$(whoami)

  # Append the user's username to /etc/ssh/sshd_config
  echo "AllowUsers $user" | sudo tee -a /etc/ssh/sshd_config >/dev/null
  sudo systemctl restart ssh

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

####################################################################################
# Generating an Ed25519 SSH key with a key derivation function rounds value of 200 #
####################################################################################
  echo -e "${GREEN}Generating an Ed25519 SSH key with a key derivation function rounds value of 200 ${NC}"
  ssh-keygen -t ed25519 -a 200 -N "" -f ~/.ssh/id_ed25519

  echo -e "${GREEN}Done. ${NC}"
  sleep 2 # delay for 2 seconds
  echo

################
# Restart sshd #
################
  echo -e "${GREEN}Restarting sshd ${NC}"
  sudo systemctl restart sshd

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

###################################################################
# Setting up Two-Factor Authentication using Google-Authenticator #
###################################################################
  echo -e "${GREEN}Setting up Two-Factor Authentication using Google-Authenticator ${NC}"
  echo -e "${GREEN}Use it to setup Google Authenticator app on your smartphone. Save scratch codes. ${NC}"

  echo

  sleep 3 # delay for 3 seconds
  google-authenticator -d -f -t -r 3 -R 30 -W

  echo

  # Options used:
  #    disallow reuse of the same token twice,
  #    forces the creation of a new secret key for the Google Authenticator
  #    issue time-based rather than counter-based codes,
  #    limit the user to a maximum of three logins every 30 seconds.
  #    "warm-up" codes when first setting up Google Authenticator

###############################################################
# Prompt user if they want to copy SSH key to another machine #
###############################################################
while true; do
  echo -e "${GREEN}Do you want to copy your SSH key to another machine? (y/n): ${NC}"
  read answer

  if [[ "$answer" =~ ^[yY](es)*$ ]]; then
    # Prompt user for username and local IP address
    echo -e "${GREEN}Enter the username of the target machine: ${NC}"
    read username
    echo -e "${GREEN}Enter the local IP address of the target machine: ${NC}"
    read ip_address

    # Check if IP address is valid
    if ! [[ "$ip_address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo -e "${RED}Invalid IP address format. Please enter a valid IP address. ${NC}"
      exit 1
    fi

    sleep 1 # delay for 1 second
    echo

##################################
# Copy SSH key to target machine #
##################################
    echo -e "${GREEN}Attempting to copy SSH key to target machine ${NC}"
    ssh-copy-id -i ~/.ssh/id_ed25519.pub $username@$ip_address || {
      echo -e "${RED}Failed to copy SSH key to target machine. ${NC}"
      # continue executing other commands
    }
    echo -e "${GREEN}Done. ${NC}"

  elif [[ "$answer" =~ ^[nN](o)*$ ]]; then
    echo -e "${GREEN}Skipping SSH key copy. ${NC}"
    break
  else
    echo -e "${YELLOW}Invalid response. Please enter 'y' for yes or 'n' for no. ${NC}"
    continue
  fi
done

sleep 1 # delay for 1 second
echo

#################################
# Changing the SSH default port #
#################################

# Set the initial SSH port number
current_ssh_port=22

# Prompt the user to change the SSH standard port
echo -e "${GREEN}Change SSH default port (22) to a non-standard port to reduce risk of automated attacks. ${NC}"

echo
sleep 1 # delay for 1 second

while true; do
  echo -e "${GREEN}Do you want to change the SSH standard port? (y/n) ${NC}"
  read choice

  if [[ "$choice" =~ ^[yY](es)*$ ]]; then
      # Generate a random number between 49152 and 65535 using shuf
      random_num=$(shuf -i 49152-65535 -n 1)
      current_ssh_port=$random_num

      # Define the file path
      FILEPATH="/etc/ssh/sshd_config"

      # Replace the standard SSH port with the random number in the sshd_config file
      sudo sed -i "s/#Port 22/Port $random_num/g" $FILEPATH

      # Open the new SSH port in UFW
      sudo ufw limit $random_num/tcp comment "SSH"

      # Automatically delete the default SSH port rule from UFW (1, refresh, 2)
      yes | sudo ufw delete 1 && yes | sudo ufw delete 2

      echo -e "${GREEN}UFW rules adjusted to reflect port change. ${NC}"

      echo ""

      sleep 1 # delay for 1 second

      # Restart the SSH service
      sudo systemctl restart sshd.service

      # Print the new SSH standard port to the console
      echo -e "${GREEN}                    ############# ${NC}"
      echo -e "${GREEN}The new SSH port is ##  ${RED}$random_num ${NC} ${GREEN}## ${NC}"
      echo -e "${GREEN}                    #############${NC}"
      break
  elif [[ "$choice" =~ ^[nN](o)*$ ]]; then
      echo -e "${GREEN}No changes were made to the SSH standard port. ${NC}"
      break
  else
      echo -e "${YELLOW}Invalid input. Please enter 'y' for yes or 'n' for no.${NC}"
  fi
done

sleep 1 # delay for 1 seconds

echo
echo -e "${GREEN}Making Fail2Ban configuration reflect SSH port change ${NC}"
sudo sed -i "s|port    = ssh|port    = $random_num|g" /etc/fail2ban/jail.local
sudo sed -i "s/port     = ssh/port     = $random_num/g" /etc/fail2ban/jail.local
echo

sleep 1.5 # delay for 1.5 seconds

echo -e "${GREEN}SSH configuration and UFW rules updated. ${NC}"
echo

sleep 1.5 # delay for 1.5 seconds

################
# Disable IPv6 #
################
while true; do
    # Prompt the user for action
    echo -e "${GREEN}Do you want to disable IPv6? (y/n) ${NC}"
    read choice
    case $choice in
        y|Y)
            echo -e "${GREEN}Disabling IPv6... ${NC}"
            # Temporarily disable IPv6
            sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null
            sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null

			echo ""

            # Persistently disable IPv6
            echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
            echo "net.ipv6.conf.default.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf

			echo ""

            echo -e "${GREEN}IPv6 has been disabled and the setting is now persistent. ${NC}"
            break
            ;;
        n|N)
            echo -e "${GREEN}IPv6 will not be disabled. ${NC}"
            break
            ;;
        *)
            echo -e "${YELLOW}Invalid input. Please enter 'y' or 'n'. ${NC}"
            ;;
    esac
done

echo
sleep 1.5 # delay for 1.5 seconds

############
# Reminder #
############
  username=$(whoami)
  ip_address=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{ print $2}' | cut -d/ -f1)
  # command that shows only first identified ip v4 address
  #ip_address=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{ print $2}' | cut -d/ -f1 | head -n 1)
  echo -e "${GREEN}Everything is set. Your new Bastion Host | Jump Server is ready! ${NC}"

  sleep 1.5 # delay for 1.5 seconds

  echo
  echo -e "${GREEN}Please DO NOT forget to remember the SSH port number ${NC}"
  echo
  echo -e "${GREEN}You can always use Proxmox VM Console to find the SSH port number in '/etc/ssh/sshd_config' file ${NC}"
  echo

  echo -e "${GREEN}SSH port is ##  ${RED}$current_ssh_port ${NC} ${GREEN}## ${NC}"          #default port number (22) can be omitted

  echo
  echo -e "${GREEN}SSH to this Server using the command: ${NC}"
  echo
  echo -e "${RED}ssh $username@$ip_address -p $current_ssh_port ${NC}"
  echo
  echo -e "${GREEN}To jump to a remote host (from your local machine) use the command: ${NC}"
  echo
  echo -e "${RED}ssh -J $username@$ip_address:$current_ssh_port username@remote_host ${NC}"
  echo

  sleep 1.5 # delay for 1.5 seconds

#####################################
# Prompt user for action at the end #
#####################################
echo -e "${GREEN}Take appropriate action to finish the script: ${NC}"

echo ""

# Function to revert system changes
revert_changes() {
    echo -e "${GREEN}Reverting system changes...${NC}"
    echo ""

    # Revert configuration files to their backups

    # Revert /etc/apt/apt.conf.d/50unattended-upgrades
    if [ -f /etc/apt/apt.conf.d/50unattended-upgrades.bak ]; then
        sudo mv /etc/apt/apt.conf.d/50unattended-upgrades.bak /etc/apt/apt.conf.d/50unattended-upgrades
    fi

    # Revert /etc/ssh/sshd_config
    if [ -f /etc/ssh/sshd_config.bak ]; then
        sudo mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    fi

    # Revert /etc/fail2ban/jail.local
    if [ -f /etc/fail2ban/jail.local.bak ]; then
        sudo mv /etc/fail2ban/jail.local.bak /etc/fail2ban/jail.local
    fi

    # Revert /etc/fstab for shared memory
    if [ -f /etc/fstab.bak ]; then
        sudo mv /etc/fstab.bak /etc/fstab
    fi

    # Revert /etc/sysctl.conf
    if [ -f /etc/sysctl.conf.bak ]; then
        sudo mv /etc/sysctl.conf.bak /etc/sysctl.conf
    fi

    # Revert /etc/pam.d/sshd
    if [ -f /etc/pam.d/sshd.bak ]; then
        sudo mv /etc/pam.d/sshd.bak /etc/pam.d/sshd
    fi

    cd ~ && \
    cd dotfiles && \
    ./uninstall.sh
    cd ~
	rm -rf /home/$USER/dotfiles/

    # Ask user if the SSH key was used for authentication purposes
    while true; do
        echo -e "${YELLOW}Was the generated SSH key (id_ed25519) used for authentication purposes? (y/n)${NC}"
        read -r response

        echo ""

        case $response in
            [yY][eE][sS]|[yY])
                echo -e "${RED}SSH key deletion skipped. Please manually manage the key if necessary.${NC}"
                break
                ;;
            [nN][oO]|[nN])
                # Delete generated SSH keys
                echo -e "${GREEN}Deleting generated SSH keys...${NC}"
                if [ -f ~/.ssh/id_ed25519 ]; then
                    rm ~/.ssh/id_ed25519
                fi

                if [ -f ~/.ssh/id_ed25519.pub ]; then
                    rm ~/.ssh/id_ed25519.pub
                fi

                echo ""

                echo -e "${GREEN}SSH keys deleted.${NC}"
                break
                ;;
            *)
                echo -e "${YELLOW}Please enter 'y' for yes or 'n' for no.${NC}"
                ;;
        esac
    done

    echo ""

    # Restart affected services
    echo -e "${GREEN}Restarting services to apply changes...${NC}"
    sudo systemctl restart sshd
    sudo systemctl restart fail2ban

    echo ""

    echo -e "${GREEN}Revert process completed.${NC}"
}

####################################
# Seting up bash and tmux dotfiles #
####################################
  echo -e "${GREEN}Seting up bash and tmux dotfiles ${NC}"

  cd ~ && \
  git clone https://github.com/vdarkobar/dotfiles.git && \
  cd dotfiles && \
  chmod +x install.sh && chmod +x uninstall.sh && \
  ./install.sh

  cd ~
  
  # Find all dot files then if the original file exists, create a backup
  # Once backed up to {file}.dtbak symlink the new dotfile in place

  echo -e "${GREEN}Done. ${NC}"
  sleep 1 # delay for 1 seconds
  echo

#################################################
# Ask user to accept changes, reboot, or revert #
#################################################

while true; do
  echo -e "${GREEN}Reboot the machine now (recommended), revert changes or exit the script? (reboot/revert/exit): ${NC}"
  read action

  case $action in
    reboot)
      echo -e "${GREEN}This machine will reboot in 2 seconds. ${NC}"
      sleep 2 # delay for 2 seconds
      sudo shutdown -r now
      break # Exit the loop after initiating reboot
      ;;
    exit)
      echo -e "${GREEN}Changes accepted. Exiting script. ${NC}"
      sleep 1 # delay for 1 seconds
      echo -e "${RED}Remember to reboot later! ${NC}"
      exit 0
      ;;
    revert)
      revert_changes
      break
      ;;
    *)
      echo -e "${YELLOW}Invalid input. Please enter 'reboot', 'exit', or 'revert'.${NC}"
      ;;
  esac
done

