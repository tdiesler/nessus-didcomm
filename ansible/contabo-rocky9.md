
* Rocky 9

### Setup the core user

```
ssh root@vps

HOSTNAME=vps8c.uk.gridley
RSA_PUBKEY="ssh-rsa ..."

dnf install -y bind-utils git tar

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

### Install Git Server

```
NUSER=git
RSA_PUBKEY=$(cat ~/.ssh/authorized_keys)
sudo useradd -G root -m $NUSER -s /bin/bash
sudo mkdir /home/$NUSER/.ssh
echo "${RSA_PUBKEY}" | sudo tee /home/$NUSER/.ssh/authorized_keys
sudo chmod 700 /home/$NUSER/.ssh
sudo chown -R $NUSER.$NUSER /home/$NUSER/.ssh

PROJECT=nessus-gridley
git config --global init.defaultBranch main

sudo mkdir -p /opt/git/${PROJECT} \
    && sudo chown -R git /opt/git
sudo su git - \
    && cd /opt/git/${PROJECT} \
    && git init --bare \
    && exit

git push ssh://git@host:port/home/git/your-project
```

### Install Golang

https://go.dev/doc/install

```
GOLANG_VERSION=1.24.1

wget https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz \
&& sudo rm -rf /usr/local/go \
&& sudo tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz \
&& pushd /usr/local/bin \
&& sudo ln -s ../go/bin/go go \
&& popd
 ```

### Install Python

```
PYTHON_VERSION=3.11.6

sudo dnf install -y gcc bzip2-devel libffi-devel openssl-devel sqlite-devel zlib-devel make

curl -sO "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
&& tar -xzf Python-${PYTHON_VERSION}.tgz \
&& pushd Python-${PYTHON_VERSION} \
&& sudo ./configure --enable-optimizations \
&& sudo make -j8 \
&& sudo make altinstall \
&& popd

ls -l /usr/local/bin/python*

pushd /usr/local/bin \
&& sudo rm -f python3 pip3 \
&& sudo ln -s python3.11 python3 \
&& sudo ln -s pip3.11 pip3 \
&& popd

PATH=/usr/local/bin:${PATH}
```

### Install Poetry

https://python-poetry.org/docs/

```
curl -sSL https://install.python-poetry.org | python3 -
poetry config virtualenvs.in-project true

PATH=$HOME/.local/bin:${PATH}
```

### Install lnav

https://snapcraft.io/docs/installing-snap-on-rocky

```
sudo dnf install -y epel-release \
&& sudo dnf install -y snapd \
&& sudo systemctl enable --now snapd.socket

sudo snap install lnav
```

### Resize a partition

```
sudo lsblk
sudo parted /dev/sda

(parted) print                                                  
Number  Start   End     Size    File system  Name  Flags
 1      1049kB  2097kB  1049kB                     bios_grub
 2      2097kB  2099MB  2097MB  ext4
 3      2099MB  53.7GB  51.6GB  ext4

(parted) resizepart 3                                                     
End?  [53.7GB]? 100% 

(parted) print                                                  
Number  Start   End     Size    File system  Name  Flags
 1      1049kB  2097kB  1049kB                     bios_grub
 2      2097kB  2099MB  2097MB  ext4
 3      2099MB  107GB   105GB   ext4

sudo resize2fs /dev/sda3
The filesystem on /dev/sda3 is now 25701883 (4k) blocks long.
```
