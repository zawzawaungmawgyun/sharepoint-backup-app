import os
import json
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, render_template_string, request, redirect, url_for, flash, session, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from backup import run_backup, get_disk_space, progress, backup_results, load_backup_history
from schedule import load_schedules, add_schedule, edit_schedule, delete_schedule, save_schedules
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = 'your_secret_key'
# Configure APScheduler with safe defaults for multiple jobs
scheduler = BackgroundScheduler(
    executors={
        'default': {'type': 'threadpool', 'max_workers': int(os.getenv('SCHED_MAX_WORKERS', '5'))}
    },
    job_defaults={
        'coalesce': True,
        'max_instances': 1,
        'misfire_grace_time': 600
    },
    timezone=os.getenv('TZ', 'UTC')
)
# Force fresh login after each server start by tracking start time
app.config['SERVER_STARTED_AT'] = int(time.time())

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

SITES_FILE = 'sites.txt'
USERS_FILE = 'users.json'

class User(UserMixin):
    def __init__(self, id, username, password_hash, role='readonly'):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role

def load_sites():
    if os.path.exists(SITES_FILE):
        with open(SITES_FILE, 'r') as f:
            return json.load(f)
    return []

def save_sites(sites):
    with open(SITES_FILE, 'w') as f:
        json.dump(sites, f)

def load_users():
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                data = f.read().strip()
                if not data:
                    return []
                return json.loads(data)
    except Exception:
        return []
    return []

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# Initialize site URLs from persisted storage
site_urls = load_sites()

# Ensure a default admin user exists with provided env values
def ensure_default_admin():
    users = load_users()
    username = os.getenv('DEFAULT_ADMIN_USER', 'admin')
    password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'ChangeMe123!')
    if not any(u.get('username') == username for u in users):
        try:
            next_id = str(max([int(u.get('id', 0)) for u in users] or [0]) + 1)
        except Exception:
            next_id = str(len(users) + 1)
        user = {
            'id': next_id,
            'username': username,
            'password_hash': generate_password_hash(password),
            'role': 'admin'
        }
        users.append(user)
        save_users(users)
        print(f"[Init] Created default admin user -> username: {username} password: {password}")
    else:
        print(f"[Init] Default admin user '{username}' already exists")

ensure_default_admin()

def migrate_user_roles():
    users = load_users()
    changed = False
    default_admin = os.getenv('DEFAULT_ADMIN_USER', 'admin')
    for u in users:
        if not u.get('role'):
            if u.get('username') == default_admin or u.get('id') == '1':
                u['role'] = 'admin'
            else:
                u['role'] = 'readonly'
            changed = True
    if changed:
        save_users(users)
        print("[Init] Migrated user roles for existing users")

migrate_user_roles()

# Enforce re-authentication after a server restart
@app.before_request
def enforce_fresh_login():
    if current_user.is_authenticated:
        login_at = session.get('login_at')
        if not login_at or login_at < app.config.get('SERVER_STARTED_AT', 0):
            # Invalidate stale session and require fresh login
            logout_user()
            session.clear()
            return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    for u in users:
        if u['id'] == user_id:
            return User(u['id'], u['username'], u['password_hash'], u.get('role', 'readonly'))
    return None

# Role-based access control decorator
from functools import wraps

def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if getattr(current_user, 'role', 'readonly') not in roles:
                flash('Permission denied.', 'danger')
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return decorated
    return wrapper

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    global site_urls
    if request.method == 'POST':
        if getattr(current_user, 'role', 'readonly') != 'admin':
            flash('Permission denied.', 'danger')
            return redirect(url_for('dashboard'))
        urls_text = request.form.get('site_urls_text') or request.form.get('site_url')
        if urls_text:
            raw_lines = urls_text.replace(',', '\n').splitlines()
            candidates = [u.strip() for u in raw_lines if u.strip()]
            added = 0
            skipped = 0
            for u in candidates:
                if u not in site_urls:
                    site_urls.append(u)
                    added += 1
                else:
                    skipped += 1
            if added:
                save_sites(site_urls)
                if skipped:
                    flash(f'Added {added} site(s). Skipped {skipped} duplicate(s).', 'info')
                else:
                    flash(f'Added {added} site(s).', 'success')
            else:
                flash('No new sites to add.', 'warning')
    disk = get_disk_space(os.getenv('BACKUP_PATH'))
    # Prepare 7-day backup history summary for charts
    history = load_backup_history()
    today = datetime.now().date()
    range_param = request.args.get('range', '30')
    days = 7 if range_param == '7' else 30
    labels = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(days-1, -1, -1)]
    success_counts = [0]*days
    fail_counts = [0]*days
    for entry in history:
        ts = entry.get('timestamp', '')
        date_str = ts[:10]
        if date_str in labels:
            idx = labels.index(date_str)
            if entry.get('status') == 'success':
                success_counts[idx] += 1
            else:
                fail_counts[idx] += 1
    return render_template(
        'dashboard.html',
        site_urls=site_urls,
        disk=disk,
        backup_results=backup_results,
        chart_labels=labels,
        chart_success=success_counts,
        chart_fail=fail_counts,
        selected_range=days
    )

@app.route('/backup_now')
@login_required
@roles_required('admin', 'operator')
def backup_now():
    run_backup(site_urls, incremental=False)
    flash('Full backup started!', 'info')
    return redirect(url_for('dashboard'))

@app.route('/backup_incremental')
@login_required
@roles_required('admin', 'operator')
def backup_incremental():
    run_backup(site_urls, incremental=True)
    flash('Incremental backup started!', 'info')
    return redirect(url_for('dashboard'))

from backup import progress

@app.route('/progress')
def get_progress():
    # Make a copy so we can safely adjust the response without mutating global state
    data = dict(progress)
    if data.get('status') == 'Done':
        # Force 100% on completion in case the client missed the final increment
        data['current'] = data.get('total', data.get('current', 0))
        data['percent'] = 100
    resp = make_response(jsonify(data))
    # Prevent browser/proxy caching to keep the progress live
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp

def scheduled_backup():
    run_backup(site_urls, incremental=True)

# Schedule incremental backup every day at 2am (managed job)
scheduler.add_job(
    scheduled_backup,
    'cron',
    id='daily_incremental',
    hour=2,
    minute=0,
    replace_existing=True,
    max_instances=1
)

@app.route('/schedules', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def schedules():
    schedules = load_schedules()
    if request.method == 'POST':
        # Bulk creation mode: create per-site schedules with different times
        if request.form.get('bulk') == '1':
            created = 0
            prefix = request.form.get('bulk_name_prefix', 'Backup')
            for idx, url in enumerate(site_urls):
                if request.form.get(f'row_{idx}_enabled'):
                    frequency = request.form.get(f'row_{idx}_frequency')
                    time_str = request.form.get(f'row_{idx}_time')
                    backup_type = request.form.get(f'row_{idx}_backup_type')
                    if frequency and time_str and backup_type:
                        cron = frequency_to_cron(frequency, time_str)
                        name = f"{prefix} - {url}"
                        add_schedule(name, cron, backup_type, sites=[url])
                        created += 1
            if created:
                flash(f'Created {created} schedule(s).', 'success')
                register_schedules()
            else:
                flash('No schedules created. Select at least one site and fill required fields.', 'warning')
            return redirect(url_for('schedules'))
        # Single schedule mode
        name = request.form.get('name')
        frequency = request.form.get('frequency')
        time_str = request.form.get('time')
        backup_type = request.form.get('backup_type')
        selected_sites = request.form.getlist('sites')
        cron = frequency_to_cron(frequency, time_str)
        add_schedule(name, cron, backup_type, sites=selected_sites)
        flash('Schedule added!', 'success')
        register_schedules()
        return redirect(url_for('schedules'))
    return render_template('schedules.html', schedules=schedules, site_urls=site_urls)

@app.route('/schedules/edit/<int:idx>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def edit_schedules(idx):
    schedules = load_schedules()
    if request.method == 'POST':
        name = request.form.get('name')
        frequency = request.form.get('frequency')
        time_str = request.form.get('time')
        backup_type = request.form.get('backup_type')
        selected_sites = request.form.getlist('sites')
        cron = frequency_to_cron(frequency, time_str)
        edit_schedule(idx, name, cron, backup_type, sites=selected_sites)
        flash('Schedule updated!', 'success')
        register_schedules()
        return redirect(url_for('schedules'))
    schedule = schedules[idx]
    return render_template('edit_schedule.html', schedule=schedule, idx=idx, site_urls=site_urls)

@app.route('/schedules/delete/<int:idx>')
@login_required
@roles_required('admin')
def delete_schedules(idx):
    delete_schedule(idx)
    flash('Schedule deleted!', 'info')
    return redirect(url_for('schedules'))

# Site management (admin only)
@app.post('/sites/edit/<int:idx>')
@login_required
@roles_required('admin')
def sites_edit(idx):
    global site_urls
    new_url = (request.form.get('url') or '').strip()
    if not (0 <= idx < len(site_urls)):
        flash('Invalid site index.', 'danger')
        return redirect(url_for('dashboard'))
    if not new_url:
        flash('URL cannot be empty.', 'danger')
        return redirect(url_for('dashboard'))
    if new_url in site_urls and site_urls.index(new_url) != idx:
        flash('That URL already exists in the list.', 'warning')
        return redirect(url_for('dashboard'))
    old_url = site_urls[idx]
    site_urls[idx] = new_url
    save_sites(site_urls)
    # Update schedules that reference this site
    schedules = load_schedules()
    changed = False
    for s in schedules:
        if isinstance(s.get('sites'), list) and old_url in s['sites']:
            s['sites'] = [new_url if u == old_url else u for u in s['sites']]
            changed = True
    if changed:
        save_schedules(schedules)
    flash('Site updated.', 'success')
    return redirect(url_for('dashboard'))

@app.get('/sites/delete/<int:idx>')
@login_required
@roles_required('admin')
def sites_delete(idx):
    global site_urls
    if not (0 <= idx < len(site_urls)):
        flash('Invalid site index.', 'danger')
        return redirect(url_for('dashboard'))
    old_url = site_urls.pop(idx)
    save_sites(site_urls)
    # Remove from schedules
    schedules = load_schedules()
    changed = False
    for s in schedules:
        if isinstance(s.get('sites'), list) and old_url in s['sites']:
            s['sites'] = [u for u in s['sites'] if u != old_url]
            changed = True
    if changed:
        save_schedules(schedules)
    flash('Site deleted.', 'info')
    return redirect(url_for('dashboard'))

def make_backup_job(backup_type, sites):
    def job():
        targets = sites if sites else site_urls
        run_backup(targets, incremental=(backup_type == 'incremental'))
    return job

def register_schedules():
    scheduler.remove_all_jobs()
    schedules = load_schedules()
    for idx, sched in enumerate(schedules):
        cron_parts = sched['cron'].split()
        backup_type = sched.get('backup_type', 'incremental')
        sites = sched.get('sites', [])
        if len(cron_parts) == 5:
            scheduler.add_job(
                make_backup_job(backup_type, sites),
                'cron',
                id=f'schedule_{idx}',
                minute=cron_parts[0],
                hour=cron_parts[1],
                day=cron_parts[2],
                month=cron_parts[3],
                day_of_week=cron_parts[4],
                replace_existing=True,
                max_instances=1
            )

# Initialize scheduler and register managed schedules
scheduler.start()
register_schedules()

def frequency_to_cron(frequency, time_str):
    hour, minute = map(int, time_str.split(':'))
    if frequency == 'daily':
        return f"{minute} {hour} * * *"
    elif frequency == 'weekly':
        return f"{minute} {hour} * * 0"
    elif frequency == 'monthly':
        return f"{minute} {hour} 1 * *"
    elif frequency == 'quarterly':
        return f"{minute} {hour} 1 1,4,7,10 *"
    elif frequency == 'yearly':
        return f"{minute} {hour} 1 1 *"
    else:
        return f"{minute} {hour} * * *"

@app.route('/backup_history')
@login_required
def backup_history():
    history = load_backup_history()
    return render_template('backup_history.html', backup_history=history)

@app.route('/backup_history/delete/<int:idx>')
@login_required
@roles_required('admin')
def backup_history_delete(idx):
    history = load_backup_history()
    if 0 <= idx < len(history):
        history.pop(idx)
        with open('backup_history.json', 'w') as f:
            json.dump(history, f)
        flash('History entry deleted.', 'info')
    else:
        flash('Invalid history entry.', 'danger')
    return redirect(url_for('backup_history'))

@app.route('/backup_history/clear')
@login_required
@roles_required('admin')
def backup_history_clear():
    with open('backup_history.json', 'w') as f:
        json.dump([], f)
    flash('All history cleared.', 'info')
    return redirect(url_for('backup_history'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()
        if any(u['username'] == username for u in users):
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        role = request.form.get('role', 'readonly')
        user = {
            'id': str(len(users) + 1),
            'username': username,
            'password_hash': generate_password_hash(password),
            'role': role
        }
        users.append(user)
        save_users(users)
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()
        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password_hash'], password):
            login_user(User(user['id'], user['username'], user['password_hash'], user.get('role', 'readonly')))
            session['login_at'] = int(time.time())
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    users = load_users()
    user = next((u for u in users if u['id'] == current_user.id), None)
    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']
        if new_username:
            user['username'] = new_username
        if new_password:
            user['password_hash'] = generate_password_hash(new_password)
        save_users(users)
        flash('Account updated.', 'success')
        return redirect(url_for('account'))
    return render_template('account.html', user=user)

# User management (admin only)
@app.route('/users')
@login_required
@roles_required('admin')
def users_list():
    users = load_users()
    return render_template_string('''
    <!doctype html><html><head>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container py-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h3 class="mb-0">Users</h3>
      <div>
        <a class="btn btn-outline-secondary" href="{{ url_for('dashboard') }}">Back</a>
        <a class="btn btn-success" href="{{ url_for('register') }}">Create User</a>
      </div>
    </div>
    <table class="table table-striped bg-white">
      <thead><tr><th>ID</th><th>Username</th><th>Role</th><th></th></tr></thead>
      <tbody>
      {% for u in users %}
        <tr>
          <td>{{ u.id if u.id is defined else u['id'] }}</td>
          <td>{{ u.username if u.username is defined else u['username'] }}</td>
          <td>{{ u.role if u.role is defined else u.get('role','readonly') }}</td>
          <td>
            <a class="btn btn-sm btn-primary" href="{{ url_for('users_edit', user_id=(u.id if u.id is defined else u['id'])) }}">Edit</a>
            <a class="btn btn-sm btn-danger" href="{{ url_for('users_delete', user_id=(u.id if u.id is defined else u['id'])) }}" onclick="return confirm('Delete this user?');">Delete</a>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    </div></body></html>
    ''', users=users)

@app.route('/users/edit/<user_id>', methods=['GET','POST'])
@login_required
@roles_required('admin')
def users_edit(user_id):
    users = load_users()
    user = next((u for u in users if u.get('id') == user_id), None)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('users_list'))
    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_role = request.form.get('role', user.get('role','readonly'))
        new_password = request.form.get('password', '')
        # Prevent removing last admin
        admins = [u for u in users if u.get('role') == 'admin']
        if user.get('role') == 'admin' and new_role != 'admin' and len(admins) <= 1:
            flash('Cannot demote the last admin user.', 'danger')
            return redirect(url_for('users_edit', user_id=user_id))
        if new_username:
            user['username'] = new_username
        user['role'] = new_role
        if new_password:
            user['password_hash'] = generate_password_hash(new_password)
        save_users(users)
        flash('User updated.', 'success')
        return redirect(url_for('users_list'))
    return render_template_string('''
    <!doctype html><html><head>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"></head>
    <body class="bg-light"><div class="container py-4" style="max-width:720px;">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h3 class="mb-0">Edit User</h3>
      <a class="btn btn-outline-secondary" href="{{ url_for('users_list') }}">Back</a>
    </div>
    <div class="card"><div class="card-body">
    <form method="POST">
      <div class="mb-3">
        <label class="form-label">Username</label>
        <input class="form-control" name="username" value="{{ user.username if user.username is defined else user['username'] }}" required>
      </div>
      <div class="mb-3">
        <label class="form-label">Role</label>
        <select class="form-select" name="role">
          {% set r = user.role if user.role is defined else user.get('role','readonly') %}
          <option value="admin" {{ 'selected' if r=='admin' else '' }}>Admin</option>
          <option value="operator" {{ 'selected' if r=='operator' else '' }}>Operator</option>
          <option value="readonly" {{ 'selected' if r=='readonly' else '' }}>Read-only</option>
        </select>
      </div>
      <div class="mb-3">
        <label class="form-label">New Password (leave blank to keep)</label>
        <input class="form-control" type="password" name="password" placeholder="New password">
      </div>
      <button class="btn btn-primary" type="submit">Save</button>
    </form>
    </div></div>
    </div></body></html>
    ''', user=user)

@app.route('/users/delete/<user_id>')
@login_required
@roles_required('admin')
def users_delete(user_id):
    users = load_users()
    user = next((u for u in users if u.get('id') == user_id), None)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('users_list'))
    # Prevent deleting last admin
    admins = [u for u in users if u.get('role') == 'admin']
    if user.get('role') == 'admin' and len(admins) <= 1:
        flash('Cannot delete the last admin user.', 'danger')
        return redirect(url_for('users_list'))
    users = [u for u in users if u.get('id') != user_id]
    save_users(users)
    flash('User deleted.', 'info')
    return redirect(url_for('users_list'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)