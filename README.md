# SharePoint Backup App

A Flask-based web application to back up SharePoint (Microsoft 365) site libraries using Microsoft Graph. Includes authentication, role-based access (admin/operator/readonly), per-site scheduling, backup progress UI, history, and a modern dashboard with charts.

## Features
- Authentication and account management (create/edit users after login)
- Roles: admin (full control), operator (run backups), readonly (view only)
- Site management: add (bulk), edit, delete
- Scheduling: per-site schedules with different times and backup type (full/incremental)
- Run now: full/incremental backup on demand
- Backup progress bar + status endpoint
- Backup history with ability to delete entries and clear all (admin)
- Dashboard charts (7-day and 30-day range)
- Disk usage card for backup target

## Requirements
- Ubuntu 20.04/22.04+ (or any Linux server)
- Python 3.10+
- A Microsoft Entra app registration (Client ID, Secret, Tenant ID)

## Project Structure (key files)
```
sharepoint-backup-app/
├── app.py                 # Flask app (routes, scheduler, RBAC)
├── backup.py              # Microsoft Graph logic, backup/history
├── schedule.py            # Schedules persistence helpers
├── wsgi.py                # WSGI entrypoint for Gunicorn
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates (Jinja2)
│   ├── dashboard.html
│   ├── backup_history.html
│   ├── schedules.html
│   ├── edit_schedule.html
│   ├── login.html
│   ├── register.html
│   └── account.html
├── .env                   # Environment variables (create this)
├── users.json             # Users store (auto-created)
├── sites.txt              # Sites store (auto-created)
├── schedules.txt          # Schedules store (auto-created)
└── backup_history.json    # Backup history (auto-created)
```

## Environment Variables (.env)
Create a `.env` file in the project root:
```
CLIENT_ID=your-entra-client-id
CLIENT_SECRET=your-entra-client-secret
TENANT_ID=your-tenant-id
BACKUP_PATH=/mnt/backup
DEFAULT_ADMIN_USER=admin
DEFAULT_ADMIN_PASSWORD=ChangeMe123!
SECRET_KEY=replace-with-a-strong-random-string
```
Notes:
- Do not commit `.env` to git.
- DEFAULT_ADMIN_* are used to seed the first admin user if none exist.

## Quick Start (development)
```
cd /home/ubuntu/sharepoint-backup-app
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python app.py
```
Visit: http://127.0.0.1:5000 (login is required)

## Production Deployment (Gunicorn + systemd + Nginx)
Run a single Gunicorn worker to avoid duplicate APScheduler jobs; add threads for concurrency.

### 1) Python environment
```
cd /home/ubuntu/sharepoint-backup-app
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -c "import wsgi; print('WSGI import OK')"
```

### 2) systemd service (Gunicorn)
Create `/etc/systemd/system/sharepoint-backup.service`:
```
[Unit]
Description=SharePoint Backup App (Gunicorn)
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/home/ubuntu/sharepoint-backup-app
Environment="PATH=/home/ubuntu/sharepoint-backup-app/venv/bin"
Environment="PYTHONUNBUFFERED=1"
ExecStart=/home/ubuntu/sharepoint-backup-app/venv/bin/gunicorn -w 1 --threads 8 -b 127.0.0.1:8000 wsgi:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```
Enable and start:
```
sudo systemctl daemon-reload
sudo systemctl enable sharepoint-backup
sudo systemctl start sharepoint-backup
sudo systemctl status sharepoint-backup
```
Health checks:
```
ss -ltnp | grep 8000
curl -I http://127.0.0.1:8000/login
sudo journalctl -u sharepoint-backup -f
```

### 3) Nginx reverse proxy
Install and configure:
```
sudo apt -y install nginx
sudo tee /etc/nginx/sites-available/sharepoint-backup >/dev/null <<'EOF'
upstream spbackup {
    server 127.0.0.1:8000;
}
server {
    listen 80;
    listen [::]:80;
    server_name YOUR_PUBLIC_IP_OR_DOMAIN;

    client_max_body_size 50m;

    location / {
        proxy_pass http://spbackup;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
    }
}
EOF
sudo ln -s /etc/nginx/sites-available/sharepoint-backup /etc/nginx/sites-enabled/sharepoint-backup
sudo nginx -t
sudo systemctl reload nginx
```
Open firewall for HTTP/HTTPS (UFW):
```
sudo ufw allow 'Nginx Full'
```
Access in browser: `http://YOUR_PUBLIC_IP/` (or your domain)

### HTTPS (optional, recommended)
```
sudo apt -y install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

## Scheduler: single worker
- The app starts APScheduler inside Flask. Running multiple Gunicorn workers would create duplicate jobs. Keep `-w 1` and add threads for concurrency (`--threads 8` or more). Scaling out requires moving the scheduler to a separate process or using a distributed lock.

## Initial Login
- On first start (with empty `users.json`), the app seeds a default admin using `DEFAULT_ADMIN_USER` / `DEFAULT_ADMIN_PASSWORD` from `.env`.
- Log in, then manage users at `/users` (admin only).

## Data Files (local JSON stores)
- `users.json`         -> users with password hashes and roles
- `sites.txt`          -> list of SharePoint sites
- `schedules.txt`      -> schedules with cron and per-schedule site lists
- `backup_history.json`-> backup runs (status, details)

## GitHub: initialize and push
Create a `.gitignore` to avoid committing secrets and local data:
```
# .gitignore
venv/
__pycache__/
*.pyc
.env
users.json
sites.txt
schedules.txt
backup_history.json
.DS_Store
```
Initialize and push:
```
cd /home/ubuntu/sharepoint-backup-app
git init
git add .
git commit -m "Initial commit: SharePoint backup app"
# Create a new repo on GitHub (via web or gh CLI) and add the remote
git remote add origin https://github.com/YOUR_USER/YOUR_REPO.git
git branch -M main
git push -u origin main
```

## Common Issues
- `curl: (7) Failed to connect` → Gunicorn not running or wrong bind address. Check `systemctl status` and `journalctl`.
- Port 8000 not accessible publicly → Bind Gunicorn to 127.0.0.1 and use Nginx on port 80/443 instead (recommended).
- `-w command not found` → `-w` is a Gunicorn option; run with the `gunicorn` command, not by itself.
- `failed to enable unit` → File must be `/etc/systemd/system/sharepoint-backup.service` (singular), then `systemctl daemon-reload`.

## License
This project is provided as-is without warranty. Ensure your use complies with Microsoft Graph and your organization’s policies.
