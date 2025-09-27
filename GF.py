#!/usr/bin/env python3
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import subprocess, tempfile, platform, os, socket, time, json

# ==== Библиотеки для разных протоколов ====
try:
    import paramiko
except:
    paramiko = None

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except:
    requests = None

try:
    import winrm
except:
    winrm = None

try:
    from ncclient import manager as nc_manager
except:
    nc_manager = None

try:
    from vncdotool import api as vnc_api
except:
    vnc_api = None


# ==== Общие настройки ====
COMMON_PORTS = {
    'ssh': 22,
    'telnet': 23,
    'http': 80,
    'https': 443,
    'winrm_http': 5985,
    'winrm_https': 5986,
    'netconf': 830,
    'rdp': 3389,
    'vnc': 5900,
}
TIMEOUT = 3


# ==== Вспомогательные функции ====
def is_port_open(host, port, timeout=TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def banner_grab(host, port, timeout=TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                raw = s.recv(2048)
            except socket.timeout:
                raw = b''
            return raw.decode('utf-8', errors='ignore').strip()
    except Exception:
        return ''


# ==== Проверки разных протоколов ====
def try_ssh_with_2fa(host, user, pwd, port=22, timeout=8):
    import paramiko
    from tkinter import simpledialog
    import time, json

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    result = {
        "host": host,
        "protocol": "ssh",
        "port": port,
        "attempts": [],
        "detected": None,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        # Первая попытка (без 2FA)
        client.connect(hostname=host, port=port, username=user, password=pwd,
                       timeout=timeout, look_for_keys=False, allow_agent=False)

        stdin, stdout, stderr = client.exec_command("whoami")
        output = stdout.read().decode(errors="ignore").strip()
        result["attempts"].append({"ok": True, "info": output})
        result["detected"] = {"ok": True, "info": output}
        client.close()
        return result

    except paramiko.ssh_exception.AuthenticationException as e:
        # Только если первая аутентификация НЕ прошла — запрашиваем 2FA
        fa2 = simpledialog.askstring("2FA", f"Введите одноразовый код для {user}@{host}:")
        if fa2:
            try:
                client.connect(hostname=host, port=port, username=user,
                               password=pwd + fa2, timeout=timeout,
                               look_for_keys=False, allow_agent=False)
                stdin, stdout, stderr = client.exec_command("whoami")
                output = stdout.read().decode(errors="ignore").strip()
                result["attempts"].append({"ok": True, "info": f"2FA: {output}"})
                result["detected"] = {"ok": True, "info": f"SSH authenticated with 2FA: {output}"}
                client.close()
                return result
            except Exception as e2:
                result["attempts"].append({"ok": False, "info": f"SSH 2FA failed: {e2}"})
                result["detected"] = {"ok": False, "info": f"SSH 2FA failed: {e2}"}
                return result
        else:
            result["attempts"].append({"ok": False, "info": "2FA required but not provided"})
            result["detected"] = {"ok": False, "info": "2FA required but not provided"}
            return result

    except Exception as e:
        result["attempts"].append({"ok": False, "info": str(e)})
        result["detected"] = {"ok": False, "info": str(e)}
        return result

def try_http_basic(host, user, pwd, use_https=False, timeout=5):
    if requests is None:
        return False, "requests not installed"
    scheme = 'https' if use_https else 'http'
    url = f"{scheme}://{host}/"
    try:
        r = requests.get(url, auth=(user, pwd), timeout=timeout, verify=False)
        if r.status_code == 401:
            fa2 = simpledialog.askstring("2FA", "Введите одноразовый код:")
            if fa2:
                r2 = requests.get(url, auth=(user, pwd + fa2), timeout=timeout, verify=False)
                return (r2.status_code < 400), f"HTTP status {r2.status_code} (with 2FA)"
        return (r.status_code < 400), f"HTTP status {r.status_code}"
    except Exception as e:
        return False, str(e)


def try_winrm(host, user, pwd, use_ssl=False, timeout=10):
    if winrm is None:
        return False, "pywinrm not installed"
    proto = 'https' if use_ssl else 'http'
    port = 5986 if use_ssl else 5985
    endpoint = f'{proto}://{host}:{port}/wsman'
    try:
        s = winrm.Session(endpoint, auth=(user, pwd))
        r = s.run_cmd('whoami')
        ok = (r.status_code == 0)
        out = r.std_out.decode(errors='ignore') if r.std_out else r.std_err.decode(errors='ignore')
        return ok, out
    except Exception as e:
        return False, str(e)


def try_netconf(host, user, pwd, port=830, timeout=10):
    if nc_manager is None:
        return False, "ncclient not installed"
    try:
        with nc_manager.connect(host=host, port=port, username=user, password=pwd,
                                hostkey_verify=False, timeout=timeout) as m:
            caps = list(m.server_capabilities)
            return True, "NETCONF caps: " + ", ".join(caps[:5])
    except Exception as e:
        return False, str(e)


def try_vnc(host, user, pwd, port=5900, timeout=10):
    if vnc_api is None:
        return False, "vncdotool not installed"
    try:
        client = vnc_api.connect(host, password=pwd)
        client.disconnect()
        return True, "VNC authentication successful"
    except Exception as e:
        return False, str(e)


def try_rdp_with_creds(host, user, pwd, timeout=10):
    system = platform.system()
    if system == "Windows":
        try:
            subprocess.run(
                ["cmdkey", "/generic:TERMSRV/" + host, "/user:" + user, "/pass:" + pwd],
                check=True
            )

            rdp_content = f"""
screen mode id:i:2
desktopwidth:i:1280
desktopheight:i:720
session bpp:i:32
full address:s:{host}
username:s:{user}
authentication level:i:0
prompt for credentials:i:0
negotiate security layer:i:1
"""
            with tempfile.NamedTemporaryFile(delete=False, suffix=".rdp", mode="w", encoding="utf-16-le") as f:
                rdp_path = f.name
                f.write(rdp_content)

            subprocess.Popen(["mstsc", rdp_path, "/admin"])
            time.sleep(5)

            return True, f"Запущено RDP-подключение к {host}"
        except Exception as e:
            return False, str(e)
        finally:
            if 'rdp_path' in locals() and os.path.exists(rdp_path):
                try:
                    os.remove(rdp_path)
                except:
                    pass
    else:
        return False, f"RDP поддерживается только на Windows (у вас {system})"


# ==== Основная логика ====
def detect_protocol(host, user, pwd):
    result = {
        'host': host,
        'tried_ports': {},
        'banners': {},
        'attempts': {},
        'detected': None,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    open_ports = {}
    for name, port in COMMON_PORTS.items():
        if is_port_open(host, port):
            open_ports[port] = name
    result['tried_ports'] = open_ports

    for p in open_ports.keys():
        result['banners'][p] = banner_grab(host, p)

    if 22 in open_ports:
        res = try_ssh_with_2fa(host, user, pwd, port=22)
        result["attempts"].update({"ssh:22": res["detected"]})
        if res["detected"]["ok"]:
            result["detected"] = {"protocol": "ssh", "port": 22, "info": res["detected"]["info"]}
            return result
    if 830 in open_ports:
        ok, info = try_netconf(host, user, pwd, port=830)
        result['attempts']['netconf:830'] = {'ok': ok, 'info': info}
        if ok:
            result['detected'] = {'protocol': 'netconf', 'port': 830, 'info': info}
            return result

    if 80 in open_ports or 443 in open_ports:
        use_https = 443 in open_ports
        ok, info = try_http_basic(host, user, pwd, use_https=use_https)
        result['attempts'][f'http:{"443" if use_https else "80"}'] = {'ok': ok, 'info': info}
        if ok:
            result['detected'] = {'protocol': 'https' if use_https else 'http',
                                  'port': 443 if use_https else 80,
                                  'info': info}
            return result

    if 5985 in open_ports or 5986 in open_ports:
        use_ssl = 5986 in open_ports
        ok, info = try_winrm(host, user, pwd, use_ssl=use_ssl)
        result['attempts'][f'winrm:{5986 if use_ssl else 5985}'] = {'ok': ok, 'info': info}
        if ok:
            result['detected'] = {'protocol': 'winrm',
                                  'port': 5986 if use_ssl else 5985,
                                  'info': info}
            return result

    if 3389 in open_ports:
        ok, info = try_rdp_with_creds(host, user, pwd)
        result['attempts']['rdp:3389'] = {'ok': ok, 'info': info}
        if ok:
            result['detected'] = {'protocol': 'rdp', 'port': 3389, 'info': info}
            return result

    if 5900 in open_ports:
        ok, info = try_vnc(host, user, pwd, port=5900)
        result['attempts']['vnc:5900'] = {'ok': ok, 'info': info}
        if ok:
            result['detected'] = {'protocol': 'vnc', 'port': 5900, 'info': info}
            return result

    return result


# ==== GUI ====
def run_detection():
    host = entry_host.get()
    user = entry_user.get()
    pwd = entry_pwd.get()

    if not host or not user or not pwd:
        messagebox.showerror("Ошибка", "Заполните все поля!")
        return

    result = detect_protocol(host, user, pwd)
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, json.dumps(result, indent=2, ensure_ascii=False))


root = tk.Tk()
root.title("Protocol Detector")
root.geometry("700x600")

tk.Label(root, text="IP / Домен:").pack()
entry_host = tk.Entry(root, width=50)
entry_host.pack()

tk.Label(root, text="Логин:").pack()
entry_user = tk.Entry(root, width=50)
entry_user.pack()

tk.Label(root, text="Пароль:").pack()
entry_pwd = tk.Entry(root, show="*", width=50)
entry_pwd.pack()

def toggle_password():
    if entry_pwd.cget("show") == "":
        entry_pwd.config(show="*")
    else:
        entry_pwd.config(show="")

chk_show_pwd = tk.Checkbutton(root, text="Показать пароль", command=toggle_password)
chk_show_pwd.pack()

btn_run = tk.Button(root, text="Проверить", command=run_detection)
btn_run.pack(pady=10)

text_output = scrolledtext.ScrolledText(root, width=80, height=25)
text_output.pack()

root.mainloop()
