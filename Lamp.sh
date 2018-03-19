#! /bin/bash
echo "Hello $USER."
echo "Today is $(date)"
echo "Current working directory : $(pwd)"
echo '**************************************************************************'
echo '                                'Update
echo '**************************************************************************'
# install all the update 
sudo apt-get -y update
sudo apt-get -y upgrade
#Adding log file
sudo touch /var/log/installs
sudo chown root:sudo /var/log/installs
echo -e "Finsh Installing Updates" > /var/log/installs
# adding time zone
timedatectl set-timezone America/Chicago
echo '**************************************************************************'
echo '                        'Implement Firewall Rulls
echo '**************************************************************************'

# add firewall rules
sudo touch /etc/iptables.firewall.rules
sudo chmod 777 /etc/iptables.firewall.rules
sudo cat<<EOF>>/etc/iptables.firewall.rules
*filter

#  Allow all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A INPUT -d 127.0.0.0/8 -j REJECT

#  Accept all established inbound connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#  Allow all outbound traffic - you can modify this to only allow certain traffic
-A OUTPUT -j ACCEPT

#  Allow HTTP and HTTPS connections from anywhere (the normal ports for websites and SSL).
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

#  Allow Application Server connections from anywhere (the normal port for Tomcat).
-A INPUT -p tcp --dport 8080 -j ACCEPT
-A INPUT -p tcp --dport 8443 -j ACCEPT

# all DNS connections from anywhere
-A INPUT -p tcp --dport 53 -j ACCEPT
-A INPUT -p udp --dport 53 -j ACCEPT

#allow LDAP connections from anywhere
-A INPUT -p tcp --dport 389 -j ACCEPT
-A INPUT -p udp --dport 389 -j ACCEPT
-A INPUT -p tcp --dport 636 -j ACCEPT
-A INPUT -p tcp --dport 3268 -j ACCEPT
-A INPUT -p tcp --dport 3269 -j ACCEPT

# allow mysql connections from anywhere
-A INPUT -p tcp --dport 3306 -j ACCEPT
-A INPUT -p udp --dport 3306 -j ACCEPT

#  Allow SSH connections
#  The -dport number should be the same port number you set in sshd_config
-A INPUT -p tcp -m state --state NEW --dport 22 -j ACCEPT

#  Allow ping
-A INPUT -p icmp -j ACCEPT

#  Log iptables denied calls
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

#  Drop all other inbound - default deny unless explicitly allowed policy
-A INPUT -j DROP
-A FORWARD -j DROP

COMMIT
EOF
sudo chmod 644 /etc/iptables.firewall.rules
sudo touch /etc/network/if-pre-up.d/firewall
sudo chmod 777 /etc/network/if-pre-up.d/firewall
sudo iptables-restore < /etc/iptables.firewall.rules
sudo cat<<EOF>>/etc/network/if-pre-up.d/firewall
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.firewall.rules
EOF
sudo chmod 771 /etc/network/if-pre-up.d/firewall
echo -e "Finsh Implentment Firewall rules" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Fail2ban
echo '**************************************************************************'

##install jail program
sudo apt-get -y install fail2ban
#Set max retries and lockout time in configuration file
sudo touch /etc/fail2ban/jail.local
sudo chown root:root /etc/fail2ban/jail.local
sudo chmod 666 /etc/fail2ban/jail.local
sudo cat<<EOF>>/etc/fail2ban/jail.local
maxtry = 5
bantime = 600
EOF

sudo chmod 777 /etc/fail2ban/jail.local
echo -e "Finsh installing Fail2ban" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Mysql
echo '**************************************************************************'
sudo touch /var/log/installs
sudo chown root:sudo /var/log/installs

#install mysql
sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password password Wbyrnygr'
sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password Wbyrnygr'
sudo apt-get -y install mysql-server


if grep -q -F [client] /etc/mysql/my.cnf; then
    echo -e "--\nmy.cnf was NOT changed" >> /var/log/install
else
    echo -e "[client]\nuser = root\npassword = Wbyrnygr" >> /etc/mysql/my.cnf
fi


echo -e "--\nMySQL installed, changed my.cnf" >> /var/log/install
echo ""


#Create database
mysql -e "CREATE database it410_data;" #-u root -p'Wbyrnygr'
#Grant access
mysql -e "GRANT All on it410_data.* to 'xxl13b'@'localhost' identified by 'Wbyrnygr';" #-u root -p'Wbyrnygr'
mysql -e "Grant SELECT on *.* to 'splunkuser@%' identified by 'Wbyrnygr';"
mysql -e "grant all on *.* to 'root'@'%' identified by 'Wbyrnygr';"
mysql -e "FLUSH PRIVILEGES;"
echo -e "Finsh installing Mysql" >> /var/log/installs
echo '**************************************************************************'
echo '                      ' Mysql_Secure_Installation
echo '**************************************************************************'

# mysql_secure_installation
mysql -u root -p'Wbyrnygr' -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('Wbyrnygr');"
mysql -u root -p'Wbyrnygr' -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -u root -p'Wbyrnygr' -e "DELETE FROM mysql.user WHERE User='';"
mysql -u root -p'Wbyrnygr' -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';"
mysql -u root -p'Wbyrnygr' -e "FLUSH PRIVILEGES;"

#echo  $DATE >> log.text /var/log/installs
echo -e "Finsh Mysql_Secure_Installation" >> /var/log/installs
echo '**************************************************************************'
echo '                             'Openssl
echo '**************************************************************************'

# set correct permission on public key
echo Start making dir
mkdir .ssh
chown -R xxl13b:xxl13b .ssh
chmod 700 .ssh
touch .ssh/authorized_keys
chmod 600 .ssh/authorized_keys

#set "PermitRootLogin no"
sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
echo -e "Finsh Changing OpenSSL" >> /var/log/installs
echo '**************************************************************************'
echo '                          'Install Apache2
echo '**************************************************************************'

sudo apt-get -y install apache2
sudo a2enmod ssl
sudo service apache2 restart
sudo mkdir /etc/apache2/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache.key -out /etc/apache2/ssl/apache.crt -subj "/C=US/ST=Texas/L=Abilene/O=ACU/CN=150.252.118.199"

#add virtual host 443. Insert file with port 80 info into itself and make appropriate changes for port 443 
#port 80:
sudo chmod 777 -R /etc/apache2/sites-available/000-default.conf
sudo sed -i 's/ServerAdmin.*/ServerAdmin xxl13b@acu.edu/' /etc/apache2/sites-available/000-default.conf
sudo sed -i '/ServerAdmin.*/a \               \ ServerName xxl13b-acu.edu:80' /etc/apache2/sites-available/000-default.conf
sudo sed -i 's@DocumentRoot.*@DocumentRoot /var/www/html@' /etc/apache2/sites-available/000-default.conf

#port 443
sudo chmod 777 -R /etc/apache2/sites-available/default-ssl.conf
sudo sed -i 's/ServerAdmin.*/ServerAdmin xxl13b@acu.edu/' /etc/apache2/sites-available/default-ssl.conf
sudo sed -i '/ServerAdmin.*/a \               \ ServerName xxl13b-acu.edu:443' /etc/apache2/sites-available/default-ssl.conf
sudo sed -i 's@DocumentRoot.*@DocumentRoot /var/www/html@' /etc/apache2/sites-available/default-ssl.conf
sudo sed -i '/SSLEngine.*/a \                 \ SSLCertificateFile /etc/apache2/ssl/apache.crt\n \                 \SSLCertificateKeyFile /etc/apache2/ssl/apache.key' /etc/apache2/sites-available/default-ssl.conf
cd /etc/apache2/sites-available
sudo a2ensite default-ssl.conf
sudo service apache2 reload
cd ~
sudo service apache2 restart
echo -e "Finsh installing Apache2" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Phpmyadmin
echo '**************************************************************************'

#install php, phpmyadmin and mail 
sudo apt-get -y install php php-mysql libapache2-mod-php php-curl php-pear php-db php-ldap php-gd php-xmlrpc mailutils ssmtp php-intl php-soap php-xml php-intl php-zip 

echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
echo "phpmyadmin phpmyadmin/app-password-confirm password Wbyrnygr" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/admin-pass password Wbyrnygr" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/app-pass password Wbyrnygr" | debconf-set-selections
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections

sudo apt-get -y install phpmyadmin

sudo cp /etc/phpmyadmin/apache.conf /etc/apache2/conf.d
sudo service apache2 restart
sudo service mysql restart
echo -e "Finsh installing Phpmyadmin" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Maldecter
echo '**************************************************************************'

#install maldecter
sudo wget https://www.rfxn.com/downloads/maldetect-current.tar.gz
tar xfz maldetect-current.tar.gz
cd maldetect-*
./install.sh
#sudo service ssh restart
