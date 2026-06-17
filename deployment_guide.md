# AWS EC2 Deployment Guide

This guide provides step-by-step instructions to deploy the **Secure Cloud Data Vault** web application onto a Free Tier **AWS EC2 instance** running **Ubuntu Server 22.04 LTS**, utilizing **Gunicorn** as the WSGI server, **Nginx** as a reverse proxy, and **MySQL** as the backend database.

---

## 🏗️ Deployment Architecture
```text
┌─────────────────┐     HTTP/HTTPS     ┌──────────────┐     Reverse Proxy      ┌──────────────┐     WSGI      ┌──────────────┐
│  Client Browser │  ────────────────>  │  Nginx (80)  │  ──────────────────>  │  Gunicorn    │  ──────────>  │ Flask App    │
└─────────────────┘                    └──────────────┘     localhost:5000     │  (Port 5000) │               └──────────────┘
                                                                               └──────────────┘                      │
                                                                                      │                              │ SQLAlchemy
                                                                                      ▼                              ▼
                                                                             ┌─────────────────┐            ┌─────────────────┐
                                                                             │   secret.key    │            │   MySQL Server  │
                                                                             │ (instance/dir)  │            │   (Port 3306)   │
                                                                             └─────────────────┘            └─────────────────┘
```

---

## 📋 System Requirements
*   **Instance Type:** AWS EC2 `t2.micro` (or `t3.micro`), eligible for the AWS Free Tier.
*   **Operating System:** Ubuntu Server 22.04 LTS (HVM), SSD Volume Type.
*   **Storage:** 8 GB GP3 EBS Volume (Default).

---

## 🔒 Step 1: Configure AWS Security Group
Before launching your EC2 instance, create or assign a security group with the following inbound firewalls:

| Protocol | Port Range | Source | Purpose |
|---|---|---|---|
| **SSH** | `22` | My IP (Recommended) | Secure terminal access |
| **HTTP** | `80` | `0.0.0.0/0` | Public web access |
| **HTTPS** | `443` | `0.0.0.0/0` | Secure public web access (SSL) |

> [!CAUTION]
> Do NOT open port `5000` (Flask/Gunicorn) or port `3306` (MySQL) to the public (`0.0.0.0/0`). This exposes internal ports directly to the internet, inviting brute-force and vulnerability scanning. Nginx will securely route public port `80` traffic to Gunicorn internally.

---

## ⚙️ Step 2: Install System Dependencies
Connect to your EC2 instance via SSH:
```bash
ssh -i "your-key.pem" ubuntu@your-ec2-public-ip
```

Update the Ubuntu package index and install required compilers, Python 3, pip, Nginx, and MySQL Server:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-dev python3-venv nginx mysql-server git build-essential libssl-dev libffi-dev
```

---

## 🗄️ Step 3: Configure MySQL Database
Start and enable the MySQL database service:
```bash
sudo systemctl start mysql
sudo systemctl enable mysql
```

Secure the MySQL installation:
```bash
sudo mysql_secure_installation
```
*(Answer `Y` to enable password validation and clean default testing configurations).*

Open the MySQL shell:
```bash
sudo mysql
```

Run database setup commands manually, creating the database, database user, and granting credentials:
```sql
-- Create database with Unicode support
CREATE DATABASE secure_vault CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create a dedicated application database user (Replace 'StrongDBPassword123!' with a secure password)
CREATE USER 'vault_user'@'localhost' IDENTIFIED BY 'StrongDBPassword123!';

-- Grant required permissions
GRANT ALL PRIVILEGES ON secure_vault.* TO 'vault_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Now import the database tables and default capabilities from the `database.sql` script:
```bash
# Clone the repository code if you have not, or upload files, then navigate to files:
# mysql -u vault_user -p secure_vault < database.sql
```

---

## 🚀 Step 4: Clone & Configure Application
Navigate to your web app folder (usually `/var/www/` or your home directory `/home/ubuntu/`):
```bash
cd /home/ubuntu
git clone <your-repository-url> secure-vault
cd secure-vault
```

Set up a isolated Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

Install packages specified in `requirements.txt`:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Verify that the environment can run without errors:
```bash
python -c "import cryptography, flask, pymysql"
```

---

## 📝 Step 5: Configure Gunicorn Service (systemd)
Create a systemd service unit file to manage Gunicorn. This runs Gunicorn in the background as a daemon and automatically restarts it if the system crashes or reboots.

Create the service file:
```bash
sudo nano /etc/systemd/system/gunicorn.service
```

Paste the following configurations (adjust user, directories, and database environment variables):
```ini
[Unit]
Description=Gunicorn instance to serve Secure Cloud Data Vault
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/home/ubuntu/secure-vault
Environment="PATH=/home/ubuntu/secure-vault/venv/bin"
# Set environment variables for MySQL connection
Environment="DB_USER=vault_user"
Environment="DB_PASSWORD=StrongDBPassword123!"
Environment="DB_HOST=localhost"
Environment="DB_NAME=secure_vault"
Environment="USE_SQLITE=False"
Environment="SESSION_COOKIE_SECURE=True"
ExecStart=/home/ubuntu/secure-vault/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app

[Install]
WantedBy=multi-user.target
```

Save and exit `nano` (`Ctrl+O`, `Enter`, `Ctrl+X`).

Start and enable the Gunicorn service:
```bash
sudo systemctl start gunicorn
sudo systemctl enable gunicorn
```

Check the status of the service to verify it is running:
```bash
sudo systemctl status gunicorn
```

---

## 🌐 Step 6: Configure Nginx Reverse Proxy
Nginx acts as the front gate, receiving public HTTP traffic and passing it to the local Gunicorn daemon.

Create an Nginx configuration file for the vault:
```bash
sudo nano /etc/nginx/sites-available/secure-vault
```

Paste the following server block configuration (Replace `your_domain_or_ip` with your EC2 public IP or domain name):
```nginx
server {
    listen 80;
    server_name your_domain_or_ip;

    # Limit request body sizes to mitigate Denial of Service (DoS)
    client_max_body_size 5M;

    # Static Assets Cache optimization
    location /static/ {
        alias /home/ubuntu/secure-vault/static/;
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    # Pass all other requests to Gunicorn
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Disable buffering to handle live logs streaming
        proxy_buffering off;
    }
}
```

Enable the site configuration by creating a symlink in `sites-enabled`:
```bash
sudo ln -s /etc/nginx/sites-available/secure-vault /etc/nginx/sites-enabled/
```

Remove the default Nginx configurations:
```bash
sudo rm /etc/nginx/sites-enabled/default
```

Test the Nginx configuration for syntax correctness:
```bash
sudo nginx -t
```

If the test is successful, restart Nginx:
```bash
sudo systemctl restart nginx
```

---

## 🔒 Step 7: Secure the Site with SSL (HTTPS)
For production deployment, you must secure the login credentials and decrypted profiles with HTTPS. You can easily do this for free using Certbot and Let's Encrypt (requires a domain name mapped to your EC2 public IP):

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```
*(Follow prompt to automatically configure redirecting HTTP to HTTPS).*
