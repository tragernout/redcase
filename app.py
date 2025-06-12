from flask import Flask, request, redirect, render_template, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, VirtualMachine,Pwn
from uuid import uuid4
import click
from flask.cli import with_appcontext
import os
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import subprocess
import re
import platform
import psutil
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/avatars'
vboxmanage_path = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_uuid):
    return User.query.filter_by(uuid=user_uuid).first()

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin or current_user.is_creator:
            return render_template('index_admin.html', user=current_user, active_page="index")
        return render_template('index_authorized.html', user=current_user, active_page="index")
    else:
        return render_template('index_unauthorized.html')


@app.route("/servers")
def servers():
    vms = VirtualMachine.query.all()
    print(vms)
    return render_template("servers.html", virtual_machines=vms, active_page="servers")


@app.route("/server/<vm_uuid>", methods=["GET"])
@login_required
def server_details(vm_uuid):
    vm = VirtualMachine.query.get(vm_uuid)
    if not vm:
        flash("Машина не найдена.", "danger")
        return redirect(url_for("index"))

    already_solved = Pwn.query.filter_by(user_uuid=current_user.uuid, vm_uuid=vm.uuid).first() is not None

    author = User.query.get(vm.author_uuid)
    first_blood = User.query.get(vm.first_blood_uuid) if vm.first_blood_uuid else None

    author_name = author.nickname if author else "Неизвестно"
    first_blood_name = first_blood.nickname if first_blood else "—"

    return render_template(
        "server_details.html",
        vm=vm,
        already_solved=already_solved,
        author_name=author_name,
        first_blood_name=first_blood_name
    )


@app.route("/server/<vm_uuid>", methods=["POST"])
def submit_flag(vm_uuid):
    vm = VirtualMachine.query.get(vm_uuid)
    if not vm:
        flash("Машина не найдена.", "danger")
        return redirect(url_for("index"))

    submitted_flag = request.form.get("flag", "").strip()

    if submitted_flag != vm.flag:
        flash("Неверный флаг!", "danger")
        return redirect(url_for("server_details", vm_uuid=vm_uuid))

    # Проверка: сдавал ли пользователь уже эту машину
    existing_pwn = Pwn.query.filter_by(user_uuid=current_user.uuid, vm_uuid=vm.uuid).first()
    if existing_pwn:
        flash("Вы уже сдали флаг этой машины.", "info")
        return redirect(url_for("server_details", vm_uuid=vm_uuid))

    # Обновляем счётчики
    vm.solve_count += 1

    user = User.query.get(current_user.uuid)
    user.solved_vms += 1
    user.score += vm.score

    # First blood (если первый)
    if not vm.first_blood_uuid:
        vm.first_blood_uuid = current_user.uuid
        user.first_bloods += 1

    # Добавляем запись в Pwn
    new_pwn = Pwn(
        uuid=str(uuid4()),
        user_uuid=current_user.uuid,
        vm_uuid=vm.uuid
    )
    db.session.add(new_pwn)

    try:
        db.session.commit()
        flash("Флаг успешно принят! Очки начислены.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Ошибка при сохранении данных. Попробуйте позже.", "danger")

    return redirect(url_for("server_details", vm_uuid=vm_uuid))


@app.route('/add_virtual_machine', methods=['POST'])
@login_required
def add_virtual_machine():
    if not current_user.is_admin:
        flash('Доступ запрещён: только для администраторов', 'danger')
        return redirect(url_for('servers_info'))

    try:
        name = request.form['name']
        flag = request.form['flag']
        platform = request.form['platform']
        difficulty = int(request.form['difficulty'])
        score = int(request.form['score'])
        ip_address = request.form['ip_address']
        description = request.form['description']

        new_vm = VirtualMachine(
            uuid=str(uuid4()),
            name=name,
            flag=flag,
            platform=platform,
            difficulty=difficulty,
            description=description,
            score=score,
            ip_address=ip_address,
            solve_count=0,
            first_blood_uuid=None,
            author_uuid=current_user.uuid  # Убедись, что у пользователя есть поле uuid
        )

        db.session.add(new_vm)
        db.session.commit()
        flash(f'Виртуальная машина "{name}" добавлена успешно!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при добавлении ВМ: {str(e)}', 'danger')

    return redirect(url_for('servers_info'))


@app.route('/users_info')
@login_required
def users_info():
    if not current_user.is_admin:
        flash('Доступ запрещён: только для администраторов', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('users_info.html', users=users, active_page="users_info")


@app.route('/delete_user/<user_uuid>', methods=['POST'])
@login_required
def delete_user(user_uuid):
    if not current_user.is_admin:
        flash('Доступ запрещён: только для администраторов', 'danger')
        return redirect(url_for('users_info'))

    if user_uuid == current_user.uuid:
        flash('Нельзя удалить самого себя.', 'warning')
        return redirect(url_for('users_info'))

    user = User.query.filter_by(uuid=user_uuid).first()
    if not user:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('users_info'))

    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'Пользователь {user.nickname} успешно удалён.', 'success')
    except Exception:
        db.session.rollback()
        flash('Ошибка при удалении пользователя.', 'danger')

    return redirect(url_for('users_info'))


@app.route('/toggle_admin/<user_uuid>', methods=['POST'])
@login_required
def toggle_admin(user_uuid):
    if not current_user.is_admin:
        flash('Доступ запрещён: только для администраторов', 'danger')
        return redirect(url_for('users_info'))

    if user_uuid == current_user.uuid:
        flash('Нельзя менять свои права администратора.', 'warning')
        return redirect(url_for('users_info'))

    user = User.query.filter_by(uuid=user_uuid).first()
    if not user:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('users_info'))

    user.is_admin = not user.is_admin
    try:
        db.session.commit()
        status = "назначен" if user.is_admin else "снят"
        flash(f'Пользователь {user.nickname} {status} администратором.', 'success')
    except Exception:
        db.session.rollback()
        flash('Ошибка при изменении прав пользователя.', 'danger')

    return redirect(url_for('users_info'))


@app.route('/servers_info')
@login_required
def servers_info():
    if not current_user.is_admin:
        flash('Доступ запрещён: только для администраторов', 'danger')
        return redirect(url_for('index'))

    vms = get_vms_info()
    virtual_machines = VirtualMachine.query.all()

    # Собираем все уникальные UUID пользователей из полей author и first_blood
    user_uuids = set()
    for vm in virtual_machines:
        user_uuids.add(vm.author_uuid)
        if vm.first_blood_uuid:
            user_uuids.add(vm.first_blood_uuid)

    users = User.query.filter(User.uuid.in_(user_uuids)).all()
    users_dict = {user.uuid: user.nickname for user in users}

    # Привязываем имена
    for vm in virtual_machines:
        vm.author_name = users_dict.get(vm.author_uuid, 'Неизвестен')
        vm.first_blood_name = users_dict.get(vm.first_blood_uuid, '—') if vm.first_blood_uuid else '—'

    return render_template('servers_info.html', vms=vms, virtual_machines=virtual_machines)


def get_vms_info():
    result = subprocess.run([vboxmanage_path, 'list', 'vms'], capture_output=True, text=True)
    vms = []
    if result.returncode != 0:
        return vms

    for line in result.stdout.strip().splitlines():
        name_match = re.match(r'"(.+?)"\s+\{(.+?)\}', line)
        if name_match:
            name = name_match.group(1)
            uuid = name_match.group(2)
            vm_info = {'name': name, 'uuid': uuid}

            state_cmd = subprocess.run([vboxmanage_path, 'showvminfo', name, '--machinereadable'], capture_output=True, text=True)
            state_match = re.search(r'VMState="(.+?)"', state_cmd.stdout)
            vm_info['state'] = state_match.group(1) if state_match else 'unknown'

            interfaces = []
            for i in range(4):
                key = f"/VirtualBox/GuestInfo/Net/{i}/V4/IP"
                ip_result = subprocess.run([vboxmanage_path, 'guestproperty', 'get', name, key], capture_output=True, text=True)
                if "Value" in ip_result.stdout:
                    ip = ip_result.stdout.split("Value:")[1].strip()
                    interfaces.append({'interface': f'Net{i}', 'ip': ip})
            vm_info['interfaces'] = interfaces
            vms.append(vm_info)

    return vms


@app.route('/edit_vm/<uuid>', methods=['GET', 'POST'])
@login_required
def edit_vm(uuid):
    if not current_user.is_admin:
        flash('Доступ запрещён: только для администраторов', 'danger')
        return redirect(url_for('index'))

    vm = VirtualMachine.query.get_or_404(uuid)

    if request.method == 'POST':
        vm.name = request.form['name']
        vm.flag = request.form['flag']
        vm.platform = request.form['platform']
        vm.difficulty = int(request.form['difficulty'])
        vm.description = request.form['description']
        vm.score = int(request.form['score'])
        vm.ip_address = request.form['ip_address']
        db.session.commit()
        flash('Виртуальная машина успешно обновлена', 'success')
        return redirect(url_for('servers_info'))

    return render_template('edit_vm.html', vm=vm)


@app.route('/delete_vm/<uuid>', methods=['POST'])
@login_required
def delete_vm(uuid):
    if not current_user.is_admin:
        flash('Доступ запрещён: только для администраторов', 'danger')
        return redirect(url_for('index'))

    vm = VirtualMachine.query.get_or_404(uuid)
    db.session.delete(vm)
    db.session.commit()
    flash('Виртуальная машина удалена', 'success')
    return redirect(url_for('servers_info'))


@app.route('/vm_action/<vm_name>/<action>', methods=['POST'])
@login_required
def vm_action(vm_name, action):
    if not current_user.is_admin:
        flash('Недостаточно прав', 'danger')
        return redirect(url_for('servers_info'))

    valid_actions = {
        'start': [vboxmanage_path, 'startvm', vm_name, '--type', 'headless'],
        'poweroff': [vboxmanage_path, 'controlvm', vm_name, 'poweroff'],
        'acpipowerbutton': [vboxmanage_path, 'controlvm', vm_name, 'acpipowerbutton'],
        'reset': [vboxmanage_path, 'snapshot', vm_name, 'restore', 'RESET'],
        'delete': [vboxmanage_path, 'unregistervm', vm_name, '--delete']
    }

    cmd = valid_actions.get(action)
    if cmd:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            if action == 'delete':
                flash(f'ВМ {vm_name} успешно удалена.', 'danger')
            else:
                flash(f'Операция {action} на {vm_name} выполнена.', 'success')
        else:
            flash(f'Ошибка при выполнении {action} на {vm_name}: {result.stderr}', 'danger')
    else:
        flash('Недопустимое действие.', 'warning')

    return redirect(url_for('servers_info'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def update_settings():
    if request.method == 'POST':
        form = request.form
        nickname = form.get('nickname')
        first_name = form.get('first_name')
        last_name = form.get('last_name')
        email = form.get('email')
        telegram = form.get('telegram')
        password = form.get('password')
        description = form.get('description')

        if not nickname or not telegram or not password:
            return render_template("settings.html", user=current_user, message="Пожалуйста, заполните обязательные поля", active_page="settings")

        current_user.nickname = nickname
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.email = email
        current_user.telegram = telegram
        current_user.profile_description = description
        current_user.password = generate_password_hash(password)

        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar and avatar.filename != '':
                ext = os.path.splitext(avatar.filename)[1].lower()
                if ext in ['.jpg', '.jpeg', '.png']:
                    # Удаляем все существующие аватары с таким же uuid и разными расширениями
                    for old_ext in ['.jpg', '.jpeg', '.png']:
                        old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{current_user.uuid}{old_ext}")
                        if os.path.exists(old_file_path):
                            os.remove(old_file_path)

                    filename = secure_filename(f"{current_user.uuid}{ext}")
                    avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        db.session.commit()
        return render_template("settings.html", user=current_user, message="Профиль обновлён успешно", active_page="settings")

    return render_template("settings.html", user=current_user, active_page="settings")

@app.route('/rating', methods=['GET'])
@login_required
def rating():
    users = User.query.order_by(User.score.desc()).all()
    return render_template('rating.html', users=users, active_page="rating")

@app.route('/about', methods=['GET', 'POST'])
@login_required
def about():
    if request.method == 'GET':
        return render_template('about.html', active_page="about")
    return None


@app.route('/register', methods=['GET', 'POST'])
def register():
    def find_free_vpn_config():
        configs_dir = os.path.join(app.root_path, 'wireguard', 'clients')
        all_configs = [f"client{i}.conf" for i in range(1, 255)]
        used_configs = {u.vpn_config for u in User.query.filter(User.vpn_config.isnot(None)).all()}
        free_configs = [c for c in all_configs if c not in used_configs]
        if not free_configs:
            return None
        # Сортировка по числовому значению X в clientX.conf
        free_configs.sort(key=lambda name: int(name.replace("client", "").replace(".conf", "")))
        return free_configs[0]

    if request.method == 'POST':
        data = request.form
        used_invite = data.get('used_invite')

        inviter = User.query.filter(
            User.invite_code == used_invite,
            (User.is_admin == True) | (User.is_creator == True)
        ).first()
        if not inviter:
            return render_template('register.html', error="Неверный инвайт-код или недостаточные права пригласившего.")

        if User.query.filter_by(nickname=data['nickname']).first():
            return render_template('register.html', error="Пользователь с таким никнеймом уже существует.")

        free_config = find_free_vpn_config()
        if not free_config:
            return render_template('register.html', error="Нет доступных VPN-конфигураций. Обратитесь к администратору.")

        user_uuid = str(uuid4())
        hashed_password = generate_password_hash(data['password'])
        personal_invite = str(uuid4())[:8]

        new_user = User(
            uuid=user_uuid,
            nickname=data['nickname'],
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            email=data.get('email'),
            telegram=data['telegram'],
            password=hashed_password,
            first_bloods=0,
            solved_vms=0,
            score=0,
            profile_description=data.get('profile_description', ''),
            invite_code=personal_invite,
            used_invite_code=used_invite,
            is_admin=False,
            is_creator=False,
            vpn_config=free_config
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(nickname=data['nickname']).first()
        if user and check_password_hash(user.password, data['password']):
            login_user(user)
            return redirect(url_for('index'))
        return render_template('login.html', error="Неверный никнейм или пароль.")

    return render_template('login.html')


@app.route('/download_vpn')
@login_required
def download_vpn():
    if not current_user.vpn_config:
        return "VPN-конфиг не назначен.", 404
    config_path = os.path.join(app.root_path, 'wireguard', 'clients', current_user.vpn_config)
    if not os.path.exists(config_path):
        return "Файл конфигурации не найден.", 404
    return send_file(config_path, as_attachment=True, download_name=current_user.vpn_config)


@app.route('/profile')
@login_required
def profile():
    avatar_url = None
    avatar_folder = app.config['UPLOAD_FOLDER']
    for ext in ['.jpg', '.jpeg', '.png']:
        avatar_path = os.path.join(avatar_folder, f"{current_user.uuid}{ext}")
        if os.path.isfile(avatar_path):
            avatar_url = url_for('static', filename=f'avatars/{current_user.uuid}{ext}')
            break

    return render_template("profile.html", user=current_user, avatar_url=avatar_url, active_page="profile")


@app.route('/profile/<user_uuid>')
def public_profile(user_uuid):
    user = User.query.filter_by(uuid=user_uuid).first()
    if not user:
        return render_template('404.html'), 404  # или свой шаблон ошибки

    # Определяем url аватара (поиск файла с расширением)
    avatar_url = None
    for ext in ['.jpg', '.jpeg', '.png']:
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{user.uuid}{ext}")
        if os.path.exists(avatar_path):
            avatar_url = url_for('static', filename=f"avatars/{user.uuid}{ext}")
            break

    return render_template("public_profile.html", user=user, avatar_url=avatar_url, active_page=None)


def get_system_info():
    # ОС и ядро
    os_info = platform.system()
    distro = ' '.join(platform.linux_distribution()) if hasattr(platform, 'linux_distribution') else platform.platform()
    kernel = platform.release()
    arch = platform.machine()

    # CPU
    cpu_model = platform.processor()
    cpu_cores = psutil.cpu_count(logical=False)
    cpu_threads = psutil.cpu_count(logical=True)

    # RAM
    mem = psutil.virtual_memory()
    total_ram = f"{mem.total / (1024**3):.2f} GB"
    free_ram = f"{mem.available / (1024**3):.2f} GB"

    # Диски
    disks = []
    for part in psutil.disk_partitions():
        usage = psutil.disk_usage(part.mountpoint)
        disks.append({
            'device': part.device,
            'size': f"{usage.total / (1024**3):.2f} GB",
            'used': f"{usage.used / (1024**3):.2f} GB",
            'free': f"{usage.free / (1024**3):.2f} GB",
        })

    # Сеть
    net_ifaces = []
    addrs = psutil.net_if_addrs()
    for iface_name, iface_addrs in addrs.items():
        addresses = []
        for addr in iface_addrs:
            if addr.family.name in ['AF_INET', 'AF_INET6']:
                addresses.append(addr.address)
        net_ifaces.append({'name': iface_name, 'addresses': addresses})

    # Нагрузка и uptime
    load_avg = ', '.join(map(str, psutil.getloadavg()))
    uptime_seconds = (datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())).total_seconds()
    uptime_str = str(datetime.timedelta(seconds=int(uptime_seconds)))

    # Версии ПО (пример)
    import flask
    import sys
    python_version = sys.version.split()[0]
    flask_version = flask.__version__
    # БД и другое нужно получать по специфике проекта
    db_version = "PostgreSQL 15.3"  # пример
    other_versions = ["Nginx 1.18.0", "Redis 6.2"]  # пример

    # Топ 5 процессов по CPU
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except psutil.NoSuchProcess:
            continue
    processes.sort(key=lambda p: p['cpu_percent'], reverse=True)
    top_procs = processes[:5]

    return {
        'os': os_info,
        'distro': distro,
        'kernel': kernel,
        'architecture': arch,
        'cpu_model': cpu_model,
        'cpu_cores': cpu_cores,
        'cpu_threads': cpu_threads,
        'total_ram': total_ram,
        'free_ram': free_ram,
        'disks': disks,
        'network_interfaces': net_ifaces,
        'load_average': load_avg,
        'uptime': uptime_str,
        'python_version': python_version,
        'flask_version': flask_version,
        'db_version': db_version,
        'other_versions': other_versions,
        'top_processes': top_procs,
    }

@app.route('/system_info')
def system_info():
    info = get_system_info()
    return render_template('system_info.html', system=info, active_page="system_info")


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def create_default_user():
    existing = User.query.filter_by(nickname='trager').first()
    if not existing:
        default_user = User(
            uuid=str(uuid4()),
            nickname='trager',
            first_name=None,
            last_name=None,
            email='tragernout@yandex.ru',
            telegram='@trager',
            password=generate_password_hash('trager'),
            first_bloods=0,
            solved_vms=0,
            score=0,
            profile_description='',
            invite_code=str(uuid4())[:8],
            used_invite_code='-',
            is_admin=True,
            is_creator=True
        )
        db.session.add(default_user)
        db.session.commit()

        # Вставка тестовой виртуальной машины
        test_vm = VirtualMachine(
            uuid='vm-001',
            name='TestMachine',
            flag="testflag",
            platform='Linux',
            difficulty=3,
            description='Это тестовая виртуальная машина для отладки интерфейса.',
            score=100,
            ip_address='10.8.0.5',
            solve_count=0,
            first_blood_uuid=None,
            author_uuid=default_user.uuid  # Связь с автором
        )
        db.session.add(test_vm)
        db.session.commit()

        test_vm = VirtualMachine(
            uuid='vm-002',
            name='EthernalBlue',
            flag="testflag1",
            platform='Windows',
            difficulty=5,
            description='Это тестовая виртуальная машина для отладки интерфейса.',
            score=100,
            ip_address='10.8.0.7',
            solve_count=0,
            first_blood_uuid=None,
            author_uuid=default_user.uuid  # Связь с автором
        )
        db.session.add(test_vm)
        db.session.commit()


@click.command('init-db')
@with_appcontext
def init_db_command():
    db.create_all()
    create_default_user()
    print("✅ База данных и пользователь trager созданы.")

def register_commands(app):
    app.cli.add_command(init_db_command)

register_commands(app)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_user()
    app.run(debug=True)
