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

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///servers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Active Directory Configuration
app.config['AD_SERVER'] = '10.4.0.5'
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
auth_handler.setFormatter(a_formatter)
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = request.remote_addr
        
        try:
            server = ldap3.Server(app.config['AD_SERVER'])
            conn = ldap3.Connection(
                server, 
                user=f"{username}@{app.config['AD_DOMAIN']}", 
                password=password
            )
            if conn.bind():
                auth_logger.info(f"SUCCESS - User: {username} - IP: {client_ip}")
                user = User(username)
                login_user(user)
                session['ad_password'] = password
                return redirect(url_for('index'))
            auth_logger.warning(f"FAILURE - User: {username} - IP: {client_ip}")
            return "Invalid credentials", 401
        except Exception as e:
            auth_logger.error(f"ERROR - User: {username} - IP: {client_ip} - {str(e)}", exc_info=True)
            return f"AD Error: {str(e)}", 500
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    client_ip = request.remote_addr
    auth_logger.info(f"LOGOUT - User: {current_user.id} - IP: {client_ip}")
    logout_user()
    session.pop('ad_password', None)
    return redirect(url_for('login'))

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
        with ThreadPoolExecutor() as executor:
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
    
    with ThreadPoolExecutor() as executor:
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

@app.route("/confirm/<action>")
@login_required
def confirm_action(action):
    if session.get('action') != action or 'selected_ips' not in session:
        return redirect(url_for('index'))
    return render_template("confirm.html", action=action)

def detect_os(ssh):
    commands = ["cat /etc/os-release", "lsb_release -a", "uname -a", "free -h", "df -h"]
    for cmd in commands:
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().lower()
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

        commands = ["cat /etc/os-release", "date", "uptime -p", "free -h", "df -h"]
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip() or 'N/A'
            artifact_data += f"\nCommand: {cmd}\n{output}\n"

        if action == "reboot":
            stdin, stdout, stderr = ssh.exec_command(
                "systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'"
            )
            initial_services = [s.strip() for s in stdout.read().decode().splitlines() if s.strip()]
            with open(services_file, "w") as f:
                f.write("\n".join(initial_services))

            ssh.exec_command("sudo shutdown -r now")
            time.sleep(180)

            try:
                ssh.connect(ip, username=username, password=password, timeout=15)
                stdin, stdout, stderr = ssh.exec_command("uptime -p || uptime")
                uptime = stdout.read().decode().strip() or "N/A"

                stdin, stdout, stderr = ssh.exec_command(
                    "systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'"
                )
                post_services = [s.strip() for s in stdout.read().decode().splitlines() if s.strip()]

                missing_services = list(set(initial_services) - set(post_services))
                restart_failed = []

                if missing_services:
                    artifact_data += "\nService Recovery Attempts:\n"
                    for service in missing_services:
                        stdin, stdout, stderr = ssh.exec_command(f"sudo systemctl restart {service}")
                        exit_code = stdout.channel.recv_exit_status()
                        artifact_data += f"Restart {service}: {'Success' if exit_code == 0 else 'Failed'}\n"
                        if exit_code != 0:
                            restart_failed.append(service)
                        time.sleep(1)

                    stdin, stdout, stderr = ssh.exec_command(
                        "systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'"
                    )
                    final_services = [s.strip() for s in stdout.read().decode().splitlines() if s.strip()]
                    still_missing = list(set(missing_services) - set(final_services))

                    failed_services = list(set(still_missing + restart_failed))

                status = "✅ Reboot Successful" if not failed_services else "⚠️ Reboot Completed with Service Issues"
                color = "green" if not failed_services else "orange"

            except Exception as e:
                status = "❌ Reboot Failed"
                color = "red"
                uptime = "N/A"
                failed_services = ["---"]
                artifact_data += f"\nPost-reboot Error: {str(e)}"

            artifact_filename = f"{ip}_reboot_artifact.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)

            return (ip, status, color, uptime, artifact_filename, failed_services if failed_services else [])

        elif action == "shutdown":
            artifact_filename = f"{ip}_shutdown_artifact.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)

            ssh.exec_command("sudo shutdown -h now")
            time.sleep(2)
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
            ssh.close()
        except:
            pass

def check_cpu_usage(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'")
        usage = float(stdout.read().decode().strip())
        return 'Yes' if usage < 80 else 'No'
    except:
        return 'Error'

def check_memory_usage(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("free | awk '/Mem:/ {printf(\"%.2f\", $3/$2 * 100.0)}'")
        usage = float(stdout.read().decode().strip())
        return 'Yes' if usage < 80 else 'No'
    except:
        return 'Error'

def check_compliance(ssh):
    try:
        os_type = detect_os(ssh)
        
        if os_type in ["ubuntu", "debian"]:
            stdin, stdout, stderr = ssh.exec_command("sudo apt-get update && sudo apt-get -s upgrade")
            output = stdout.read().decode().lower()
            return 'Yes' if '0 upgraded' in output else 'No'
            
        elif os_type in ["centos", "rhel"]:
            stdin, stdout, stderr = ssh.exec_command("sudo yum check-update")
            exit_code = stdout.channel.recv_exit_status()
            return 'No' if exit_code == 100 else 'Yes'
            
        elif os_type == "suse":
            stdin, stdout, stderr = ssh.exec_command("sudo zypper --non-interactive list-updates")
            output = stdout.read().decode().lower()
            return 'No' if 'no updates found' not in output else 'Yes'
            
        else:
            return 'Error: Unsupported OS'
            
    except Exception as e:
        return f'Error: {str(e)}'

def check_selinux(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("getenforce")
        status = stdout.read().decode().strip()
        return 'Yes' if status == 'Enforcing' else 'No'
    except:
        return 'Error'

def check_reboot_required(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("[ -f /var/run/reboot-required ] && echo Yes || echo No")
        return stdout.read().decode().strip()
    except:
        return 'Error'

def check_disk_usage(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("df -h | awk '$5 > 80 {print $1}'")
        return 'No' if len(stdout.read().decode().strip()) == 0 else 'Yes'
    except:
        return 'Error'

def check_disk_inodes(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("df -i | awk '$5 > 80 {print $1}'")
        return 'No' if len(stdout.read().decode().strip()) == 0 else 'Yes'
    except:
        return 'Error'

def check_load_average(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("cat /proc/loadavg | awk '{print $1, $2, $3}'")
        load = [float(x) for x in stdout.read().decode().strip().split()]
        return 'Yes' if all(l < 2.0 for l in load) else 'No'
    except:
        return 'Error'

def check_firewall(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("sudo ufw status | grep 'Status: active'")
        return 'Yes' if 'active' in stdout.read().decode() else 'No'
    except:
        return 'Error'

def check_ssh_config(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("sudo sshd -t")
        return 'Yes' if stderr.read().decode() == '' else 'No'
    except:
        return 'Error'

def check_uptime(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("uptime -p || uptime")
        raw_uptime = stdout.read().decode().strip().lower()
        
        if not raw_uptime.startswith('up'):
            up_index = raw_uptime.find('up')
            if up_index == -1:
                return 'Error'
            raw_uptime = raw_uptime[up_index:]

        time_units = {
            'minute': 1/60,
            'minutes': 1/60,
            'hour': 1,
            'hours': 1,
            'day': 24,
            'days': 24,
            'week': 168,
            'weeks': 168,
            'month': 720,
            'months': 720,
            'year': 8760,
            'years': 8760
        }

        total_hours = 0.0
        components = raw_uptime.replace('up', '').replace(',', '').split()
        
        i = 0
        while i < len(components):
            if components[i].isdigit():
                quantity = int(components[i])
                if i+1 < len(components) and components[i+1] in time_units:
                    unit = components[i+1]
                    total_hours += quantity * time_units[unit]
                    i += 2
                    continue
            i += 1

        if 'min' in raw_uptime and total_hours == 0:
            minutes = int(components[0])
            total_hours = minutes / 60

        return 'Yes' if total_hours < 1 else 'No'

    except Exception as e:
        return f"Error: {str(e)}"

def get_kernel_version(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("uname -r")
        return stdout.read().decode().strip()
    except:
        return 'Error'

def check_time_sync(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("timedatectl | grep 'System clock synchronized'")
        return 'Yes' if 'yes' in stdout.read().decode().lower() else 'No'
    except:
        return 'Error'

def check_fstab(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command("sudo diff <(cat /etc/fstab | grep -v '^#') <(df -h | awk '{print $1}')")
        return 'Yes' if stdout.read().decode().strip() == '' else 'No'
    except:
        return 'Error'

def check_server_health(ip, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15) 
        result = {
            'ip': ip,
            'reachable': True,
            'cpu_usage': check_cpu_usage(ssh),
            'memory_usage': check_memory_usage(ssh),
            'compliance': check_compliance(ssh),
            'reboot_required': check_reboot_required(ssh),
            'disk_usage': check_disk_usage(ssh),
            'disk_inodes': check_disk_inodes(ssh),
            'load_average': check_load_average(ssh),
            'firewall_rules': check_firewall(ssh),
            'ssh_config': check_ssh_config(ssh),
            'uptime': check_uptime(ssh),
            'kernel_version': get_kernel_version(ssh),
            'time_sync': check_time_sync(ssh),
            'fstab_matches': check_fstab(ssh),
            'selinux_status': check_selinux(ssh)
        }
        ssh.close()
        return result

    except Exception as e:
        return {'ip': ip, 'error': str(e), 'reachable': False}

def run_patch_update(ip, apply_patches=False, username=None, password=None):
    artifact_data = f"Patch Update Information for {ip}\n{'='*40}\n"
    artifact_data += f"Start Time: {datetime.now().isoformat()}\n"
    artifact_filename = None

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)
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
                "check": "apt-get -s upgrade -V",
                "upgrade": "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq",
                "check_phrase": "The following packages will be upgraded:"
            },
            "debian": {
                "update": "sudo DEBIAN_FRONTEND=noninteractive apt update -y",
                "check": "apt list --upgradable",
                "upgrade": "sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y",
                "check_phrase": "upgradable"
            },
            "centos": {
                "update": "sudo yum clean all && sudo yum makecache",
                "check": "sudo yum check-update",
                "upgrade": "sudo yum update -y",
                "check_phrase": "updates available"
            },
            "rhel": {
                "update": "sudo yum clean all && sudo yum makecache",
                "check": "sudo yum check-update",
                "upgrade": "sudo yum update -y",
                "check_phrase": "updates available"
            },
            "suse": {
                "update": "sudo zypper --non-interactive refresh",
                "check": "sudo zypper --non-interactive list-updates",
                "upgrade": "sudo zypper --non-interactive update -y",
                "check_phrase": "No updates found",
                "exit_code_has_updates": 100
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

        initial_update_needed = False
        artifact_data += "\n=== Initial Update Check ===\n"
        for cmd in [cmds['update'], cmds['check']]:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            
            if os_type in ["centos", "rhel"]:
                initial_update_needed = exit_code == cmds.get('exit_code_has_updates', 100)
            else:
                check_phrase_lower = cmds['check_phrase'].lower()
                output_lower = output.lower()
                initial_update_needed = check_phrase_lower not in output_lower

        if not apply_patches:
            status = "⚠️ Updates available" if initial_update_needed else "✅ System up-to-date"
            color = "blue" if initial_update_needed else "green"
            artifact_filename = f"{ip}_patch_check.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
               f.write(artifact_data)
            return (ip, status, color, artifact_filename)

        if not initial_update_needed:
            artifact_filename = f"{ip}_patch_up_to_date.txt"
            artifact_data += "\nSystem is already up-to-date. No action taken.\n"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
               f.write(artifact_data)
            return (ip, "✅ System already up-to-date", "green", artifact_filename)

        stdin, stdout, stderr = ssh.exec_command(cmds['upgrade'])
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            app_logger.error(f"Patch installation failed: {ip}", extra={
                'user': username,
                'action': 'patch_update',
                'target': ip
            })
            return (ip, "❌ Patch installation failed", "red", artifact_filename)

        final_update_needed = False
        if os_type in ["centos", "rhel"]:
            final_update_needed = exit_code == 100
        else:
            stdin, stdout, stderr = ssh.exec_command(cmds['check'])
            output = stdout.read().decode().strip()
            final_update_needed = cmds['check_phrase'] not in output

        status_msg = "✅ Updates installed" if not final_update_needed else "⚠️ Partial updates installed"
        color = "green" if not final_update_needed else "orange"
        artifact_filename = f"{ip}_patch_results.txt"

        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)

        app_logger.info(f"Patch {'applied' if not final_update_needed else 'partially applied'} on {ip}", extra={
            'user': username,
            'action': 'patch_update',
            'target': ip
        })
        return (ip, status_msg, color, artifact_filename)

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
            ssh.close()
        except:
            pass

def apply_patches_and_reboot(ip, username, password):
    try:
        patch_result = run_patch_update(ip, apply_patches=True,  username=username, password=password)
        ip_patch, status_patch, color_patch, artifact_patch = patch_result

        if "❌" in status_patch:
            return (ip, status_patch, color_patch, "N/A", artifact_patch, ["---"])

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)

        os_type = detect_os(ssh)
        reboot_required = False
        reboot_reason = ""

        if os_type in ["ubuntu", "debian"]:
            stdin, stdout, stderr = ssh.exec_command("[ -f /var/run/reboot-required ] && echo 'reboot required' || echo 'ok'")
            reboot_required = "reboot required" in stdout.read().decode()
        elif os_type in ["centos", "rhel"]:
            stdin, stdout, stderr = ssh.exec_command("needs-restarting -r &> /dev/null; echo $?")
            reboot_required = stdout.read().decode().strip() == "1"
        elif os_type == "suse":
            stdin, stdout, stderr = ssh.exec_command("[ -f /var/run/reboot-needed ] && echo 'reboot required' || echo 'ok'")
            reboot_required = "reboot required" in stdout.read().decode()

        ssh.close()

        if reboot_required:
            reboot_result = run_command(ip, 'reboot')
            return reboot_result

        return (ip, f"{status_patch} (No reboot required)", color_patch, "Not rebooted", artifact_patch, ["---"])

    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", "N/A", None, ["---"])

@app.route("/process/<action>", methods=["GET", "POST"])
@login_required
def process_servers(action):
    try:
        for f in os.listdir(ARTIFACTS_FOLDER):
            file_path = os.path.join(ARTIFACTS_FOLDER, f)
            if os.path.isfile(file_path):
                os.remove(file_path)
    except Exception as e:
        print(f"Error clearing artifacts: {e}")

    if 'selected_ips' not in session or session.get('action') != action:
        return redirect(url_for('index'))

    servers = session.pop('selected_ips', [])
    session.pop('action', None)

    username = current_user.id if current_user.is_authenticated else None
    password = session.get('ad_password')

    results = []
    with ThreadPoolExecutor() as executor:
        futures = []
        for ip in servers:
            if action == "reboot" or action == "shutdown":
                futures.append(executor.submit(run_command, ip, action, username, password))
            elif action == "apply_patches_and_reboot":
                futures.append(executor.submit(apply_patches_and_reboot, ip, username, password))
            elif action == "health_check":
                futures.append(executor.submit(check_server_health, ip,  username, password))
            else:
                apply_patches = (action == "apply_patches")
                futures.append(executor.submit(run_patch_update, ip, apply_patches, username, password))

        for future in as_completed(futures):
            res = future.result()
            if len(res) == 4:
                results.append((res[0], res[1], res[2], None, res[3], None))
            else:
                results.append(res)

    return render_template("results.html", results=results, action=action)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
