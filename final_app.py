from flask import Flask, request, render_template, redirect, url_for, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import paramiko
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import traceback
import ldap3
import csv
import io
import logging
from logging.handlers import RotatingFileHandler
import sys
from datetime import datetime, timedelta
import pytz
from flask import request, session, redirect, url_for, jsonify

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///servers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Active Directory Configuration
app.config['AD_SERVER'] = '10.4.0.4'
app.config['AD_DOMAIN'] = 'example.com'
app.config['AD_BASE_DN'] = 'dc=example,dc=com'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

db = SQLAlchemy(app)

# Logging Configuration
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# Auth Logger
auth_logger = logging.getLogger('auth')
auth_logger.setLevel(logging.INFO)
auth_handler = RotatingFileHandler(
    os.path.join(LOGS_DIR, 'auth.log'),
    maxBytes=1024*1024*5,  # 5MB
    backupCount=3,
    encoding='utf-8'
)
auth_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
auth_handler.setFormatter(auth_formatter)
auth_logger.addHandler(auth_handler)

# Application Logger
app_logger = logging.getLogger('app')
app_logger.setLevel(logging.INFO)
app_handler = RotatingFileHandler(
    os.path.join(LOGS_DIR, 'app.log'),
    maxBytes=1024*1024*10,  # 10MB
    backupCount=5,
    encoding='utf-8'
)
app_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - [%(user)s] [%(action)s] [%(target)s] - %(message)s'
)
app_handler.setFormatter(app_formatter)
app_logger.addHandler(app_handler)

# Console Handler for Errors
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.ERROR)
app_logger.addHandler(console_handler)

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False, unique=True)
    hostname = db.Column(db.String(50))
    tags = db.Column(db.String(200), default='')

with app.app_context():
    db.create_all()

ARTIFACTS_FOLDER = "artifacts"
os.makedirs(ARTIFACTS_FOLDER, exist_ok=True)

def get_server(ip):
    with app.app_context():
        return Server.query.filter_by(ip=ip).first()
@app.before_request
def before_request():
    # Skip for static files and auth endpoints
    if request.endpoint in ['static', 'login', 'logout', 'update_activity', 'check_session']:
        return

    # Initialize session settings
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)  # 1 minute timeout
    
    if current_user.is_authenticated:
        now = datetime.utcnow().replace(tzinfo=pytz.UTC)
        
        # Initialize session tracking
        if 'last_activity' not in session:
            session['last_activity'] = now
            session['original_path'] = request.path
        
        # Ensure timezone awareness
        last_activity = session['last_activity']
        if last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=pytz.UTC)
            session['last_activity'] = last_activity
        
        time_since = now - last_activity
        
        # Check session expiration
        if time_since > timedelta(minutes=1):
            logout_user()
            session.clear()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'expired'}), 401
            return redirect(url_for('login', session_expired=1, next=request.path))
        
        # Set warning flag
        session['show_timeout_warning'] = time_since > timedelta(seconds=30)
        
        # Update activity for non-activity endpoints
        if request.endpoint != 'update_activity':
            session['last_activity'] = now
            session['original_path'] = request.path
    
    # Redirect unauthenticated users
    elif request.endpoint not in ['login', 'static']:
        return redirect(url_for('login', next=request.path))

@app.route('/update_activity', methods=['POST'])
@login_required
def update_activity():
    session['last_activity'] = datetime.utcnow().replace(tzinfo=pytz.UTC)
    session.pop('show_timeout_warning', None)
    return jsonify({'status': 'success'})

@app.route('/check_session')
@login_required
def check_session():
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    last_activity = session.get('last_activity', now)
    
    if last_activity.tzinfo is None:
        last_activity = last_activity.replace(tzinfo=pytz.UTC)
    
    time_since = now - last_activity
    expires_in = timedelta(minutes=1) - time_since
    
    return jsonify({
        'show_timeout_warning': time_since > timedelta(seconds=30),
        'time_remaining': expires_in.total_seconds()
    })

@app.route('/extend_session', methods=['POST'])
@login_required
def extend_session():
    session['last_activity'] = datetime.utcnow().replace(tzinfo=pytz.UTC)
    session.pop('show_timeout_warning', None)
    return jsonify({'status': 'success'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Handle redirect after login
    next_page = request.args.get('next') or url_for('index')

    # If already logged in, redirect to target page
    if current_user.is_authenticated:
        return redirect(next_page)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = request.remote_addr

        try:
            # Active Directory authentication
            server = ldap3.Server(app.config['AD_SERVER'])
            conn = ldap3.Connection(
                server,
                user=f"{username}@{app.config['AD_DOMAIN']}",
                password=password
            )

            if conn.bind():
                # Successful login
                auth_logger.info(f"SUCCESS - User: {username} - IP: {client_ip}")
                user = User(username)
                login_user(user)

                # Initialize session tracking
                session['ad_password'] = password
                session['last_activity'] = datetime.utcnow().replace(tzinfo=pytz.UTC)
                session['original_path'] = next_page  # Store where to redirect after login

                # Redirect to either the next page or index
                return redirect(next_page)

            # Failed login
            auth_logger.warning(f"FAILURE - User: {username} - IP: {client_ip}")
            return render_template("login.html",
                                error="Invalid credentials",
                                next=request.args.get('next'))

        except Exception as e:
            auth_logger.error(f"ERROR - User: {username} - IP: {client_ip} - {str(e)}", exc_info=True)
            return render_template("login.html",
                                error=f"Login error: {str(e)}",
                                next=request.args.get('next'))

    # GET request - show login form
    return render_template("login.html",
                         next=request.args.get('next'),
                         session_expired=request.args.get('session_expired'))

@app.route('/logout')
@login_required
def logout():
    client_ip = request.remote_addr
    username = current_user.id

    # Log the logout
    auth_logger.info(f"LOGOUT - User: {username} - IP: {client_ip}")

    # Clear session and logout
    logout_user()
    session.clear()

    # Redirect to login with optional next parameter
    next_page = request.args.get('next') or url_for('index')
    return redirect(url_for('login', next=next_page))

@app.route('/')
@login_required
def index():
    with app.app_context():
        servers = Server.query.all()
    return render_template("index.html", servers=servers)

def clear_artifacts():
    try:
        for f in os.listdir(ARTIFACTS_FOLDER):
            file_path = os.path.join(ARTIFACTS_FOLDER, f)
            if os.path.isfile(file_path):
                os.remove(file_path)
    except Exception as e:
        app_logger.error(f"Error clearing artifacts: {e}", exc_info=True)

def log_command(ssh, command, username, ip, action):
    """Log detailed command execution to app.log"""
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_code = stdout.channel.recv_exit_status()
    stdout_output = stdout.read().decode().strip()
    stderr_output = stderr.read().decode().strip()
    
    app_logger.info(
        f"Command executed: {command}\n"
        f"Exit code: {exit_code}\n"
        f"STDOUT: {stdout_output or 'None'}\n"
        f"STDERR: {stderr_output or 'None'}",
        extra={
            'user': username,
            'action': action,
            'target': ip
        }
    )
    return stdout_output, stderr_output, exit_code

def log_action(action, servers, status="started", extra=None):
    log_data = {
        'user': current_user.id if current_user.is_authenticated else 'system',
        'action': action,
        'target': ', '.join(servers),
        'status': status,
        'extra': str(extra) if extra else None
    }
    app_logger.info(f"Action {status.upper()} - {action} on {len(servers)} servers", extra=log_data)

def process_action(action, servers):
    log_action(action, servers, "initiated")
    results = []
    
    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for ip in servers:
                if action == "reboot":
                    futures.append(executor.submit(run_command, ip, "reboot", current_user.id, session.get('ad_password')))
                elif action == "shutdown":
                    futures.append(executor.submit(run_command, ip, "shutdown", current_user.id, session.get('ad_password')))
                elif action == "check_patches":
                    futures.append(executor.submit(run_patch_update, ip, False, current_user.id, session.get('ad_password')))
                elif action == "apply_patches":
                    futures.append(executor.submit(run_patch_update, ip, True, current_user.id, session.get('ad_password')))
                elif action == "apply_patches_and_reboot":
                    futures.append(executor.submit(apply_patches_and_reboot, ip, current_user.id, session.get('ad_password')))

            for future in as_completed(futures):
                res = future.result()
                if len(res) == 4:
                    results.append((res[0], res[1], res[2], None, res[3], None))
                else:
                    results.append(res)
        
        log_action(action, servers, "completed", {"results": results})
        return results
    except Exception as e:
        app_logger.error(f"Action FAILED - {action} - {str(e)}", exc_info=True,
            extra={
                'user': current_user.id,
                'action': action,
                'target': ', '.join(servers)
            })
        raise

@app.route("/reboot", methods=["GET", "POST"])
@login_required
def reboot_servers():
    clear_artifacts()
    if 'selected_ips' not in session or session.get('action') != "reboot":
        return redirect(url_for('index'))
    servers = session.pop('selected_ips', [])
    session.pop('action', None)
    results = process_action("reboot", servers)
    return render_template("results.html", results=results, action="reboot")

@app.route("/shutdown", methods=["GET", "POST"])
@login_required
def shutdown_servers():
    clear_artifacts()
    if 'selected_ips' not in session or session.get('action') != "shutdown":
        return redirect(url_for('index'))
    servers = session.pop('selected_ips', [])
    session.pop('action', None)
    results = process_action("shutdown", servers)
    return render_template("results.html", results=results, action="shutdown")

@app.route("/check_patches", methods=["GET", "POST"])
@login_required
def check_patch_status():
    clear_artifacts()
    if 'selected_ips' not in session or session.get('action') != "check_patches":
        return redirect(url_for('index'))
    servers = session.pop('selected_ips', [])
    session.pop('action', None)
    results = process_action("check_patches", servers)
    return render_template("results.html", results=results, action="check_patches")

@app.route("/apply_patches", methods=["GET", "POST"])
@login_required
def apply_patch_updates():
    clear_artifacts()
    if 'selected_ips' not in session or session.get('action') != "apply_patches":
        return redirect(url_for('index'))
    servers = session.pop('selected_ips', [])
    session.pop('action', None)
    results = process_action("apply_patches", servers)
    return render_template("results.html", results=results, action="apply_patches")

@app.route("/apply_patches_and_reboot", methods=["GET", "POST"])
@login_required
def patch_and_reboot():
    clear_artifacts()
    if 'selected_ips' not in session or session.get('action') != "apply_patches_and_reboot":
        return redirect(url_for('index'))
    servers = session.pop('selected_ips', [])
    session.pop('action', None)
    results = process_action("apply_patches_and_reboot", servers)
    return render_template("results.html", results=results, action="apply_patches_and_reboot")

@app.route('/health_check', methods=['POST'])
@login_required
def health_check():
    selected_ips = list(set(request.form.getlist('server_ips')))
    
    if not selected_ips:
        return redirect(url_for('index'))

    username = current_user.id if current_user.is_authenticated else None
    password = session.get('ad_password')
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda ip: check_server_health(ip, username, password), selected_ips))
    
    log_action('health_check', selected_ips, "completed", {"results": results})
    return render_template('health_results.html', results=results)

@app.route('/add_server', methods=['POST'])
@login_required
def add_server():
    ip = request.form.get('ip')
    hostname = request.form.get('hostname')
    tags = request.form.get('tags', '').strip()

    if not ip:
        return "IP address is required", 400

    try:
        with app.app_context():
            existing_server = Server.query.filter_by(ip=ip).first()
            if existing_server:
                existing_server.hostname = hostname
                existing_server.tags = tags
                action = 'update'
            else:
                new_server = Server(ip=ip, hostname=hostname, tags=tags)
                db.session.add(new_server)
                action = 'create'
            db.session.commit()
        
        app_logger.info(f"Server {action}d: {ip}", extra={
            'user': current_user.id,
            'action': f'server_{action}',
            'target': ip
        })
        return redirect(url_for('index'))
    except Exception as e:
        app_logger.error(f"Server {action} failed: {ip} - {str(e)}", exc_info=True,
            extra={
                'user': current_user.id,
                'action': f'server_{action}',
                'target': ip
            })
        return f"Error: {str(e)}", 500

@app.route('/delete_server/<int:server_id>')
@login_required
def delete_server(server_id):
    try:
        with app.app_context():
            server = Server.query.get_or_404(server_id)
            ip = server.ip
            db.session.delete(server)
            db.session.commit()
        
        app_logger.info(f"Server deleted: {ip}", extra={
            'user': current_user.id,
            'action': 'server_delete',
            'target': ip
        })
        return redirect(url_for('index'))
    except Exception as e:
        app_logger.error(f"Server delete failed: {server_id} - {str(e)}", exc_info=True,
            extra={
                'user': current_user.id,
                'action': 'server_delete',
                'target': f'ID:{server_id}'
            })
        return f"Error: {str(e)}", 500


@app.route('/bulk_upload', methods=['POST'])
@login_required
def bulk_upload():
    servers = []
    
    try:
        if 'csv_file' in request.files:
            file = request.files['csv_file']
            if file and file.filename.endswith('.csv'):
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_reader = csv.DictReader(stream)
                for row in csv_reader:
                    servers.append(Server(
                        ip=row['ip'],
                        hostname=row.get('hostname', ''),
                        tags=row.get('tags', '')
                    ))

        if not servers:
            bulk_text = request.form.get('bulk_servers', '')
            for line in bulk_text.split('\n'):
                parts = [p.strip() for p in line.split(',') if p.strip()]
                if len(parts) >= 1:
                    servers.append(Server(
                        ip=parts[0],
                        hostname=parts[1] if len(parts) > 1 else '',
                        tags=parts[2] if len(parts) > 2 else ''
                    ))

        if not servers:
            return "No valid servers found in upload data", 400

        with app.app_context():
            added_ips = []
            for server in servers:
                if not Server.query.filter_by(ip=server.ip).first():
                    db.session.add(server)
                    added_ips.append(server.ip)
            db.session.commit()
        
        app_logger.info(f"Bulk upload: {len(added_ips)} servers added", extra={
            'user': current_user.id,
            'action': 'bulk_upload',
            'target': ', '.join(added_ips)
        })
        return redirect(url_for('index'))

    except Exception as e:
        app_logger.error(f"Bulk upload failed: {str(e)}", exc_info=True,
            extra={
                'user': current_user.id,
                'action': 'bulk_upload',
                'target': 'multiple'
            })
        traceback.print_exc()
        return f"Error processing upload: {str(e)}", 400


def detect_os(ssh):
    commands = ["cat /etc/os-release", "lsb_release -a", "uname -a", "free -h", "df -h"]
    for cmd in commands:
        try:
            stdout_output, stderr_output, exit_code = log_command(ssh, cmd, '', '', 'os_detection')
            output = stdout_output.lower()
            if "ubuntu" in output:
                return "ubuntu"
            elif "debian" in output:
                return "debian"
            elif "centos" in output:
                return "centos"
            elif "red hat" in output:
                return "rhel"
            elif "suse" in output:
                return "suse"
        except:
            continue
    return "unknown"

def run_command(ip, action, username, password):
    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)

        app_logger.info(f"Executing {action} on {ip}", extra={
            'user': username,
            'action': action,
            'target': ip
        })

        artifact_data = f"System Information for {ip}\n{'='*40}\n"
        services_file = os.path.join(ARTIFACTS_FOLDER, f"{ip}_services.txt")
        failed_services = []
        uptime = "N/A"

        # Log initial system info commands
        commands = ["cat /etc/os-release", "date", "uptime -p", "free -h", "df -h"]
        for cmd in commands:
            stdout_output, stderr_output, exit_code = log_command(ssh, cmd, username, ip, action)
            artifact_data += f"\nCommand: {cmd}\n{stdout_output}\n"

        if action == "reboot":
            # Get list of running services before reboot
            list_services_cmd = "systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'"
            stdout_output, stderr_output, exit_code = log_command(ssh, list_services_cmd, username, ip, action)
            initial_services = [s.strip() for s in stdout_output.splitlines() if s.strip()]
            with open(services_file, "w") as f:
                f.write("\n".join(initial_services))

            # Execute reboot command
            reboot_cmd = "sudo shutdown -r now"
            stdout_output, stderr_output, exit_code = log_command(ssh, reboot_cmd, username, ip, action)
            artifact_data += f"\nReboot command executed: {reboot_cmd}\nExit code: {exit_code}\n"
            
            # Close connection before server reboots
            ssh.close()
            ssh = None
            
            # Wait for server to go down
            time.sleep(5)
            
            # Try to reconnect after reboot
            max_attempts = 10
            attempt = 0
            connected = False
            
            while attempt < max_attempts:
                try:
                    attempt += 1
                    time.sleep(30)  # Wait before each attempt
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(ip, username=username, password=password, timeout=15)
                    connected = True
                    break
                except:
                    continue

            if not connected:
                raise Exception("Server did not come back online after reboot")

            # Get uptime after reboot
            stdout_output, stderr_output, exit_code = log_command(ssh, "uptime -p || uptime", username, ip, action)
            uptime = stdout_output or "N/A"
            artifact_data += f"\nPost-reboot uptime: {uptime}\n"

            # Get list of running services after reboot
            stdout_output, stderr_output, exit_code = log_command(ssh, list_services_cmd, username, ip, action)
            post_services = [s.strip() for s in stdout_output.splitlines() if s.strip()]

            # Find missing services
            missing_services = list(set(initial_services) - set(post_services))
            restart_failed = []

            if missing_services:
                artifact_data += "\nService Recovery Attempts:\n"
                for service in missing_services:
                    restart_cmd = f"sudo systemctl restart {service}"
                    stdout_output, stderr_output, exit_code = log_command(ssh, restart_cmd, username, ip, action)
                    artifact_data += f"Restart {service}: {'Success' if exit_code == 0 else 'Failed'}\n"
                    if exit_code != 0:
                        restart_failed.append(service)
                    time.sleep(1)

                # Verify final service status
                stdout_output, stderr_output, exit_code = log_command(ssh, list_services_cmd, username, ip, action)
                final_services = [s.strip() for s in stdout_output.splitlines() if s.strip()]
                still_missing = list(set(missing_services) - set(final_services))

                failed_services = list(set(still_missing + restart_failed))

            status = "✅ Reboot Successful" if not failed_services else "⚠️ Reboot Completed with Service Issues"
            color = "green" if not failed_services else "orange"

            artifact_filename = f"{ip}_reboot_artifact.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)

            return (ip, status, color, uptime, artifact_filename, failed_services if failed_services else [])

        elif action == "shutdown":
            # Execute shutdown command
            shutdown_cmd = "sudo shutdown -h now"
            stdout_output, stderr_output, exit_code = log_command(ssh, shutdown_cmd, username, ip, action)
            artifact_data += f"\nShutdown command executed: {shutdown_cmd}\nExit code: {exit_code}\n"

            artifact_filename = f"{ip}_shutdown_artifact.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)

            return (ip, "✅ Shutdown Initiated", "green", "N/A", artifact_filename, None)

    except paramiko.ssh_exception.NoValidConnectionsError:
        app_logger.error(f"Connection failed: {ip}", extra={
            'user': username,
            'action': action,
            'target': ip
        })
        return (ip, "❌ Connection Failed", "red", "N/A", None, ["---"])
    except Exception as e:
        app_logger.error(f"Command failed: {action} on {ip} - {str(e)}", exc_info=True,
            extra={
                'user': username,
                'action': action,
                'target': ip
            })
        return (ip, f"❌ Error: {str(e)}", "red", "N/A", None, ["---"])
    finally:
        try:
            if ssh: ssh.close()
        except: pass

def check_cpu_usage(ssh, username, ip):
    cmd = "grep '^cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'"
    stdout_output, stderr_output, exit_code = log_command(ssh, cmd, username, ip, 'health_check')
    try:
        usage = float(stdout_output)
        return 'Yes' if usage < 80 else 'No'
    except:
        return 'Error'

def check_memory_usage(ssh, username, ip):
    cmd = "awk '/MemTotal/ {total=$2} /MemAvailable/ {avail=$2} END {print (total-avail)/total*100}' /proc/meminfo"
    stdout_output, stderr_output, exit_code = log_command(ssh, cmd, username, ip, 'health_check')
    try:
        usage = float(stdout_output)
        return 'Yes' if usage < 80 else 'No'
    except:
        return 'Error'

def check_compliance(ssh, username, ip):
    try:
        os_type = detect_os(ssh)
        app_logger.info(f"Compliance check OS detection: {os_type}", extra={
            'user': username,
            'action': 'compliance_check',
            'target': ip
        })
        
        if os_type in ["ubuntu", "debian"]:
            log_command(ssh, "sudo apt-get update", username, ip, 'compliance_check')
            stdout_output, stderr_output, exit_code = log_command(ssh, "sudo apt-get -s upgrade", username, ip, 'compliance_check')
            output = stdout_output.lower()
            return 'Yes' if '0 upgraded' in output else 'No'
            
        elif os_type in ["centos", "rhel"]:
            stdout_output, stderr_output, exit_code = log_command(ssh, "sudo yum check-update", username, ip, 'compliance_check')
            return 'No' if exit_code == 100 else 'Yes'
            
        elif os_type == "suse":
            stdout_output, stderr_output, exit_code = log_command(ssh, "sudo zypper --non-interactive list-updates", username, ip, 'compliance_check')
            output = stdout_output.lower()
            return 'No' if 'no updates found' not in output else 'Yes'
            
        else:
            return 'Error: Unsupported OS'
            
    except Exception as e:
        return f'Error: {str(e)}'

def check_selinux(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "getenforce", username, ip, 'health_check')
    try:
        status = stdout_output.strip()
        return 'Yes' if status == 'Enforcing' else 'No'
    except:
        return 'Error'

def check_reboot_required(ssh, username, ip):
    # Check Debian/Ubuntu
    stdout_output, _, _ = log_command(ssh, "[ -f /var/run/reboot-required ] && echo Yes || echo No", username, ip, 'health_check')
    if 'Yes' in stdout_output:
        return 'Yes'
    
    # Check RHEL/CentOS
    stdout_output, _, _ = log_command(ssh, "needs-restarting -r &>/dev/null; echo $?", username, ip, 'health_check')
    if stdout_output.strip() == '1':
        return 'Yes'
    
    # Check SUSE
    stdout_output, _, _ = log_command(ssh, "[ -f /var/run/reboot-needed ] && echo Yes || echo No", username, ip, 'health_check')
    return 'Yes' if 'Yes' in stdout_output else 'No'

def check_disk_usage(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "df -h | awk '$5 > 80 {print $1}'", username, ip, 'health_check')
    try:
        return 'No' if len(stdout_output.strip()) == 0 else 'Yes'
    except:
        return 'Error'

def check_disk_inodes(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "df -i | awk '$5 > 80 {print $1}'", username, ip, 'health_check')
    try:
        return 'No' if len(stdout_output.strip()) == 0 else 'Yes'
    except:
        return 'Error'

def check_load_average(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "cat /proc/loadavg | awk '{print $1, $2, $3}'", username, ip, 'health_check')
    try:
        load = [float(x) for x in stdout_output.strip().split()]
        return 'Yes' if all(l < 2.0 for l in load) else 'No'
    except:
        return 'Error'

def check_firewall(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "sudo ufw status | grep 'Status: active'", username, ip, 'health_check')
    try:
        return 'Yes' if 'active' in stdout_output else 'No'
    except:
        return 'Error'

def check_ssh_config(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "sudo sshd -t", username, ip, 'health_check')
    try:
        return 'Yes' if stderr_output == '' else 'No'
    except:
        return 'Error'

def check_uptime(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "cat /proc/uptime | awk '{print $1}'", username, ip, 'health_check')
    try:
        uptime_seconds = float(stdout_output)
        return 'Yes' if uptime_seconds < 3600 else 'No'  # 1 hour threshold
    except:
        return 'Error'

def get_kernel_version(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "uname -r", username, ip, 'health_check')
    return stdout_output.strip() if exit_code == 0 else 'Error'

def check_time_sync(ssh, username, ip):
    stdout_output, stderr_output, exit_code = log_command(ssh, "timedatectl | grep 'System clock synchronized'", username, ip, 'health_check')
    try:
        return 'Yes' if 'yes' in stdout_output.lower() else 'No'
    except:
        return 'Error'

def check_fstab(ssh, username, ip):
    cmd = "sudo diff <(cat /etc/fstab | grep -v '^#') <(df -h | awk '{print $1}')"
    stdout_output, stderr_output, exit_code = log_command(ssh, cmd, username, ip, 'health_check')
    try:
        return 'Yes' if stdout_output.strip() == '' else 'No'
    except:
        return 'Error'

def check_server_health(ip, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=30)
        result = {
            'ip': ip,
            'reachable': True,
            'cpu_usage': check_cpu_usage(ssh, username, ip),
            'memory_usage': check_memory_usage(ssh, username, ip),
            'compliance': check_compliance(ssh, username, ip),
            'reboot_required': check_reboot_required(ssh, username, ip),
            'disk_usage': check_disk_usage(ssh, username, ip),
            'disk_inodes': check_disk_inodes(ssh, username, ip),
            'load_average': check_load_average(ssh, username, ip),
            'firewall_rules': check_firewall(ssh, username, ip),
            'ssh_config': check_ssh_config(ssh, username, ip),
            'uptime': check_uptime(ssh, username, ip),
            'kernel_version': get_kernel_version(ssh, username, ip),
            'time_sync': check_time_sync(ssh, username, ip),
            'fstab_matches': check_fstab(ssh, username, ip),
            'selinux_status': check_selinux(ssh, username, ip)
        }
        ssh.close()
        return result

    except Exception as e:
        return {'ip': ip, 'error': str(e), 'reachable': False}

def run_patch_update(ip, apply_patches=False, username=None, password=None):
    artifact_data = f"Patch Update Information for {ip}\n{'='*40}\n"
    artifact_data += f"Start Time: {datetime.now().isoformat()}\n"
    artifact_filename = None
    ssh = None

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=20)
        os_type = detect_os(ssh)
        artifact_data += f"\nOS Detection:\n- Detected OS: {os_type}\n"
        
        app_logger.info(f"Patch {'check' if not apply_patches else 'apply'} on {ip}", extra={
            'user': username,
            'action': 'patch_update',
            'target': ip
        })

        cmd_config = {
            "ubuntu": {
                "update": "sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq",
                "check": "apt list --upgradable 2>/dev/null",
                "upgrade": "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq",
            },
            "debian": {
                "update": "sudo apt-get update -yq",
                "check": "apt list --upgradable 2>/dev/null",
                "upgrade": "sudo apt-get upgrade -yq",
            },
            "centos": {
                "update": "sudo yum clean all && sudo yum makecache fast",
                "check": "sudo yum check-update || true",
                "upgrade": "sudo yum update -y",
            },
            "rhel": {
                "update": "sudo yum clean all && sudo yum makecache fast",
                "check": "sudo yum check-update || true",
                "upgrade": "sudo yum update -y",
            },
            "suse": {
                "update": "sudo zypper --non-interactive refresh",
                "check": "sudo zypper --non-interactive list-updates || true",
                "upgrade": "sudo zypper --non-interactive update -y",
            }
        }

        cmds = cmd_config.get(os_type)
        if not cmds:
            app_logger.error(f"Unsupported OS: {ip}", extra={
                'user': username,
                'action': 'patch_update',
                'target': ip
            })
            return (ip, "❌ Unsupported OS", "red", None)

        artifact_data += "\n=== Updating repositories ===\n"
        stdout_output, stderr_output, exit_code = log_command(ssh, cmds['update'], username, ip, 'patch_update')
        artifact_data += f"\nUpdate output:\n{stdout_output}\n"

        artifact_data += "\n=== Checking for updates ===\n"
        stdout_output, stderr_output, exit_code = log_command(ssh, cmds['check'], username, ip, 'patch_update')
        artifact_data += f"\nCheck output:\n{stdout_output}\n"

        updates_available = False

        # Handle based on OS
        if os_type in ["ubuntu", "debian"]:
            updates_available = any("upgradable" in line.lower() for line in stdout_output.splitlines())
        elif os_type in ["centos", "rhel"]:
            clean_lines = [line.strip() for line in stdout_output.splitlines() if line and not line.lower().startswith("could not retrieve")]
            updates_available = any(line for line in clean_lines if not line.startswith("Loaded plugins"))
        elif os_type == "suse":
            updates_available = "No updates found" not in stdout_output

        if not apply_patches:
            status = "⚠️ Updates available" if updates_available else "✅ System up-to-date"
            color = "blue" if updates_available else "green"
            artifact_filename = f"{ip}_patch_check.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)
            return (ip, status, color, artifact_filename)

        if not updates_available:
            artifact_filename = f"{ip}_patch_up_to_date.txt"
            artifact_data += "\nSystem is already up-to-date. No action taken.\n"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)
            return (ip, "✅ System already up-to-date", "green", artifact_filename)

        artifact_data += "\n=== Applying patches ===\n"
        stdout_output, stderr_output, exit_code = log_command(ssh, cmds['upgrade'], username, ip, 'patch_update')
        artifact_data += f"\nUpgrade output:\n{stdout_output}\n"

        if exit_code != 0:
            app_logger.error(f"Patch installation failed: {ip}", extra={
                'user': username,
                'action': 'patch_update',
                'target': ip
            })
            artifact_filename = f"{ip}_patch_error.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)
            return (ip, "❌ Patch installation failed", "red", artifact_filename)

        artifact_filename = f"{ip}_patch_results.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)

        app_logger.info(f"Patches successfully applied on {ip}", extra={
            'user': username,
            'action': 'patch_update',
            'target': ip
        })
        return (ip, "✅ Patches installed successfully", "green", artifact_filename)

    except Exception as e:
        error_msg = f"Critical Error: {str(e)}"
        artifact_filename = f"{ip}_critical_error.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(f"{artifact_data}\n{error_msg}")
        app_logger.error(f"Patch operation failed on {ip} - {str(e)}", exc_info=True,
            extra={
                'user': username,
                'action': 'patch_update',
                'target': ip
            })
        return (ip, f"❌ {error_msg}", "red", artifact_filename)
    finally:
        try:
            if ssh:
                ssh.close()
        except:
            pass



def apply_patches_and_reboot(ip, username, password):
    try:
        # Step 1: Apply patches
        patch_result = run_patch_update(ip, apply_patches=True, username=username, password=password)
        ip_patch, status_patch, color_patch, artifact_patch = patch_result

        if "❌" in status_patch:
            return (ip, status_patch, color_patch, "N/A", artifact_patch, ["---"])

        # Step 2: Check if reboot is needed
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)

        os_type = detect_os(ssh)
        reboot_required = False

        if os_type in ["ubuntu", "debian"]:
            stdout_output, _, _ = log_command(ssh, "[ -f /var/run/reboot-required ] && echo 'reboot required' || echo 'ok'", username, ip, 'patch_and_reboot')
            reboot_required = "reboot required" in stdout_output
        elif os_type in ["centos", "rhel"]:
            stdout_output, _, _ = log_command(ssh, "needs-restarting -r &> /dev/null; echo $?", username, ip, 'patch_and_reboot')
            reboot_required = stdout_output.strip() == "1"
        elif os_type == "suse":
            stdout_output, _, _ = log_command(ssh, "[ -f /var/run/reboot-needed ] && echo 'reboot required' || echo 'ok'", username, ip, 'patch_and_reboot')
            reboot_required = "reboot required" in stdout_output

        ssh.close()

        # Step 3: If reboot needed, execute and combine results
        if reboot_required:
            reboot_result = run_command(ip, 'reboot', username, password)
            _, reboot_status, reboot_color, uptime, reboot_artifact, services_status = reboot_result

            # Combine patch & reboot status
            combined_status = f"{status_patch} + {reboot_status}"
            #combined_artifacts = artifact_patch + reboot_artifact if artifact_patch and reboot_artifact else ["---"]
            combined_filename = f"artifacts/{ip}_combined_artifact.txt"

# Safely combine contents into a new file
            with open(combined_filename, "w") as f:
             if artifact_patch and os.path.exists(artifact_patch):
                with open(artifact_patch, "r") as f1:
                    f.write(f1.read() + "\n")
             if reboot_artifact and os.path.exists(reboot_artifact):
                with open(reboot_artifact, "r") as f2:
                    f.write(f2.read())

            combined_artifacts = combined_filename

            return (
                ip,
                combined_status,
                reboot_color if "❌" in reboot_status else color_patch,  # Use reboot color if failed, else patch color
                uptime,
                combined_artifacts,
                services_status
            )

        # If no reboot needed, return patch status only
        uptime_output = run_command(ip, 'uptime', username, password)
        _, _, _, uptime, _, _ = uptime_output

        return (
            ip,
            f"{status_patch} (No reboot required)",
            color_patch,
            uptime,
            artifact_patch,
            ["---"]
        )

    except Exception as e:
        app_logger.error(f"Patch & reboot failed on {ip} - {str(e)}", exc_info=True,
            extra={
                'user': username,
                'action': 'patch_and_reboot',
                'target': ip
            })
        return (ip, f"❌ Error: {str(e)}", "red", "N/A", None, ["---"])

@app.route('/handle_action', methods=['POST'])
@login_required
def handle_action():
    selected_ips = list(set(request.form.getlist('server_ips')))
    action = request.form.get('action')

    if not selected_ips:
        return "No servers selected", 400

    if action == 'delete':
        try:
            with app.app_context():
                for ip in selected_ips:
                    server = Server.query.filter_by(ip=ip).first()
                    if server:
                        db.session.delete(server)
                db.session.commit()
            
            app_logger.info(f"Bulk delete: {len(selected_ips)} servers", extra={
                'user': current_user.id,
                'action': 'bulk_delete',
                'target': ', '.join(selected_ips)
            })
            return redirect(url_for('index'))
        except Exception as e:
            app_logger.error(f"Bulk delete failed: {str(e)}", exc_info=True,
                extra={
                    'user': current_user.id,
                    'action': 'bulk_delete',
                    'target': ', '.join(selected_ips)
                })
            return f"Error: {str(e)}", 500

    session['selected_ips'] = selected_ips
    session['action'] = action
    session.modified = True

    if action in ['reboot', 'shutdown']:
        return redirect(url_for('confirm_action', action=action))
    elif action in ['check_patches', 'apply_patches', 'apply_patches_and_reboot']:
        return redirect(url_for('process_servers', action=action))

    return redirect(url_for('index'))


@app.route('/confirm/<action>')
@login_required
def confirm_action(action):
    if session.get('action') != action or 'selected_ips' not in session:
        return redirect(url_for('index'))
    return render_template("confirm.html", action=action)

@app.route('/process/<action>', methods=['GET', 'POST'])
@login_required
def process_servers(action):
    if 'selected_ips' not in session or session.get('action') != action:
        return redirect(url_for('index'))

    servers = session.pop('selected_ips', [])
    session.pop('action', None)
    username = current_user.id
    password = session.get('ad_password')

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for ip in servers:
            if action == "check_patches":
                futures.append(executor.submit(run_patch_update, ip, False, username, password))
            elif action == "apply_patches":
                futures.append(executor.submit(run_patch_update, ip, True, username, password))
            elif action == "apply_patches_and_reboot":
                futures.append(executor.submit(apply_patches_and_reboot, ip, username, password))
            elif action == "health_check":
                futures.append(executor.submit(check_server_health, ip, username, password))

        for future in as_completed(futures):
            results.append(future.result())

    return render_template("results.html", results=results, action=action)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        return send_from_directory(
            ARTIFACTS_FOLDER, 
            filename, 
            as_attachment=True,
            mimetype='text/plain'
        )
    except Exception as e:
        app_logger.error(f"Failed to download file {filename}: {str(e)}", exc_info=True,
            extra={
                'user': current_user.id,
                'action': 'download',
                'target': filename
            })
        return "File not found", 404

@app.after_request
def log_response(response):
    if response.status_code >= 400:
        app_logger.error(f"HTTP {response.status_code} - {request.method} {request.path}",
            extra={
                'user': current_user.id if current_user.is_authenticated else 'anonymous',
                'action': 'http_error',
                'target': request.url
            }
        )
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)


@app.route('/process/<action>', methods=['GET', 'POST'])
@login_required
def process_servers(action):
    clear_artifacts()
    if 'selected_ips' not in session or session.get('action') != action:
        return redirect(url_for('index'))

    servers = session.pop('selected_ips', [])
    session.pop('action', None)
    username = current_user.id
    password = session.get('ad_password')

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for ip in servers:
            if action == "reboot":
                futures.append(executor.submit(run_command, ip, "reboot", username, password))
            elif action == "shutdown":
                futures.append(executor.submit(run_command, ip, "shutdown", username, password))
            elif action == "check_patches":
                futures.append(executor.submit(run_patch_update, ip, False, username, password))
            elif action == "apply_patches":
                futures.append(executor.submit(run_patch_update, ip, True, username, password))
            elif action == "apply_patches_and_reboot":
                futures.append(executor.submit(apply_patches_and_reboot, ip, username, password))

        for future in as_completed(futures):
            results.append(future.result())

    return render_template("results.html", results=results, action=action)

