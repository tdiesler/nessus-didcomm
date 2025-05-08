
* Rocky 9

### Setup the core user

```
ssh root@vps

HOSTNAME=vps8c.uk.gridley
RSA_PUBKEY="ssh-rsa ..."

dnf install -y bind-utils buildah git httpd-tools jq tar

NUSER=core
useradd -G root -m $NUSER -s /bin/bash
mkdir /home/$NUSER/.ssh
echo "${RSA_PUBKEY}" > /home/$NUSER/.ssh/authorized_keys
chmod 700 /home/$NUSER/.ssh
chown -R $NUSER.$NUSER /home/$NUSER/.ssh

cat << EOF > /etc/sudoers.d/user-privs-$NUSER
$NUSER ALL=(ALL:ALL) NOPASSWD: ALL
EOF

echo $HOSTNAME | sudo tee /etc/hostname
sudo hostname -b $HOSTNAME

echo 'export PS1="[\u@\H \W]\$ "' >> /home/$NUSER/.bash_profile
```

### Harden SSH access

```
# ------------------------------------------------------------------------------
# SSH login to core@xxx.xxx.xxx.xxx from another terminal
# ------------------------------------------------------------------------------

# Assign a random SSH port above 10000
rnd=$((10000+$RANDOM%20000))
sudo sed -i "s/#Port 22$/Port $rnd/" /etc/ssh/sshd_config

# Disable password authentication
sudo sed -i "s/PasswordAuthentication yes$/PasswordAuthentication no/" /etc/ssh/sshd_config

# Disable challenge response authentication
sudo sed -i "s/ChallengeResponseAuthentication yes$/ChallengeResponseAuthentication no/" /etc/ssh/sshd_config

# Disable root login
sudo sed -i "s/PermitRootLogin yes$/PermitRootLogin no/" /etc/ssh/sshd_config

# Disable X11Forwarding
sudo sed -i "s/X11Forwarding yes$/X11Forwarding no/" /etc/ssh/sshd_config

sudo cat /etc/ssh/sshd_config | egrep "^Port"
sudo cat /etc/ssh/sshd_config | egrep "PasswordAuthentication"
sudo cat /etc/ssh/sshd_config | egrep "ChallengeResponseAuthentication"
sudo cat /etc/ssh/sshd_config | egrep "PermitRootLogin"
sudo cat /etc/ssh/sshd_config | egrep "X11Forwarding"

sudo systemctl restart sshd
```

### Install extra packages

```
sudo dnf install -y epel-release && sudo crb enable
sudo dnf install -y htop
```

### Install lnav

https://snapcraft.io/docs/installing-snap-on-rocky

```
sudo dnf install -y epel-release \
&& sudo dnf install -y snapd \
&& sudo systemctl enable --now snapd.socket

sudo snap install lnav
```
