#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         ad_enum.py  —  Active Directory Enumerator          ║
║              Constan4 / Ciber-AD Repository                 ║
╚══════════════════════════════════════════════════════════════╝

Descripción:
    Herramienta de reconocimiento de Active Directory via LDAP.
    Enumera usuarios, grupos, equipos y GPOs. Identifica automáticamente
    usuarios vulnerables a Kerberoasting y AS-REP Roasting.

Módulo MITRE ATT&CK:
    T1018  - Remote System Discovery
    T1069  - Permission Groups Discovery
    T1087  - Account Discovery

Requisitos:
    pip install ldap3

Uso:
    # Enumeración completa
    python3 ad_enum.py --dc 192.168.1.10 --domain empresa.local -u juan -p Pass123

    # Solo rutas de ataque (Kerberoast + AS-REP)
    python3 ad_enum.py --dc 192.168.1.10 --domain empresa.local -u juan -p Pass123 --attack-paths

    # Guardar resultados en JSON
    python3 ad_enum.py --dc 192.168.1.10 --domain empresa.local -u juan -p Pass123 --output resultados.json

    # Null session (si el DC lo permite)
    python3 ad_enum.py --dc 192.168.1.10 --domain empresa.local --null-session
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Optional

# ── Colores ANSI ────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    GRAY   = "\033[90m"

def banner():
    print(C.CYAN + C.BOLD + r"""
  ╔═══════════════════════════════════════════════╗
  ║   AD_ENUM — Active Directory Enumerator       ║
  ║   Ciber-AD | github.com/Constan4/Ciber-AD     ║
  ╚═══════════════════════════════════════════════╝
""" + C.RESET)

def ok(msg):
    print(C.GREEN + "  [+]" + C.RESET + " " + msg)

def info(msg):
    print(C.BLUE + "  [*]" + C.RESET + " " + msg)

def warn(msg):
    print(C.YELLOW + "  [!]" + C.RESET + " " + msg)

def crit(msg):
    print(C.RED + C.BOLD + "  [CRITICAL]" + C.RESET + " " + msg)

def err(msg):
    print(C.RED + "  [-]" + C.RESET + " " + msg)


# ══════════════════════════════════════════════════════════════
# CONSTANTES LDAP
# ══════════════════════════════════════════════════════════════

# userAccountControl flags
UAC_DISABLED        = 2
UAC_PASSWD_NOTREQD  = 32
UAC_NORMAL_ACCOUNT  = 512
UAC_DONT_EXPIRE_PWD = 65536
UAC_DONT_REQ_PREAUTH = 4194304  # AS-REP Roastable

# Grupos de alto valor
HIGH_VALUE_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Backup Operators", "Account Operators",
    "Print Operators", "Server Operators", "Group Policy Creator Owners",
    "Remote Management Users", "DnsAdmins",
]

# Atributos a consultar para usuarios
USER_ATTRS = [
    "cn", "sAMAccountName", "description", "memberOf",
    "servicePrincipalName", "userAccountControl",
    "pwdLastSet", "lastLogon", "adminCount",
    "mail", "telephoneNumber", "title", "department",
    "distinguishedName",
]

# Atributos para equipos
COMPUTER_ATTRS = [
    "cn", "dNSHostName", "operatingSystem",
    "operatingSystemVersion", "lastLogonDate",
    "userAccountControl", "distinguishedName",
]


# ══════════════════════════════════════════════════════════════
# CONEXIÓN LDAP
# ══════════════════════════════════════════════════════════════

def connect_ldap(dc: str, domain: str, user: Optional[str], password: Optional[str], use_ssl: bool = False):
    """
    Establece conexión con el DC via LDAP o LDAPS.

    Returns:
        Tuple (conn, base_dn) o (None, None) si falla.
    """
    try:
        from ldap3 import Server, Connection, ALL, NTLM, ANONYMOUS
    except ImportError:
        err("ldap3 no instalado. Ejecuta: pip install ldap3")
        sys.exit(1)

    port   = 636 if use_ssl else 389
    proto  = "ldaps" if use_ssl else "ldap"
    base   = "DC=" + domain.replace(".", ",DC=")

    info("Conectando a " + proto + "://" + dc + ":" + str(port))

    server = Server(dc, port=port, use_ssl=use_ssl, get_info=ALL)

    try:
        if user and password:
            # Autenticación NTLM con usuario de dominio
            user_upn = user if "@" in user else user + "@" + domain
            conn = Connection(
                server,
                user=user_upn,
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )
        else:
            # Null session (anónima)
            conn = Connection(server, authentication=ANONYMOUS, auto_bind=True)

        ok("Conexion establecida con " + dc)
        return conn, base

    except Exception as e:
        err("Error de conexion: " + str(e))
        # Intentar con LDAPS si LDAP falla
        if not use_ssl:
            warn("Reintentando con LDAPS (puerto 636)...")
            return connect_ldap(dc, domain, user, password, use_ssl=True)
        return None, None


# ══════════════════════════════════════════════════════════════
# ENUMERACIÓN DE USUARIOS
# ══════════════════════════════════════════════════════════════

def enum_users(conn, base: str) -> list:
    """Enumera todos los usuarios del dominio con sus atributos."""
    info("Enumerando usuarios del dominio...")

    conn.search(
        search_base   = base,
        search_filter = "(objectClass=user)",
        attributes    = USER_ATTRS,
    )

    users = []
    for entry in conn.entries:
        uac = int(entry.userAccountControl.value or 512)

        user = {
            "sam":              str(entry.sAMAccountName),
            "cn":               str(entry.cn),
            "description":      str(entry.description) if entry.description else "",
            "uac":              uac,
            "admin_count":      int(entry.adminCount.value) if entry.adminCount else 0,
            "spn":              list(entry.servicePrincipalName) if entry.servicePrincipalName else [],
            "groups":           list(entry.memberOf) if entry.memberOf else [],
            "dn":               str(entry.distinguishedName),
            # Flags derivados
            "disabled":         bool(uac & UAC_DISABLED),
            "no_preauth":       bool(uac & UAC_DONT_REQ_PREAUTH),  # AS-REP Roastable
            "pwd_not_required": bool(uac & UAC_PASSWD_NOTREQD),
            "pwd_never_expires":bool(uac & UAC_DONT_EXPIRE_PWD),
            "kerberoastable":   bool(entry.servicePrincipalName),
        }
        users.append(user)

    ok("Usuarios encontrados: " + str(len(users)))
    return users


# ══════════════════════════════════════════════════════════════
# ENUMERACIÓN DE GRUPOS
# ══════════════════════════════════════════════════════════════

def enum_groups(conn, base: str) -> list:
    """Enumera todos los grupos con sus miembros."""
    info("Enumerando grupos...")

    conn.search(
        search_base   = base,
        search_filter = "(objectClass=group)",
        attributes    = ["cn", "member", "description", "adminCount", "distinguishedName"],
    )

    groups = []
    for entry in conn.entries:
        groups.append({
            "cn":          str(entry.cn),
            "description": str(entry.description) if entry.description else "",
            "admin_count": int(entry.adminCount.value) if entry.adminCount else 0,
            "members":     [str(m).split(",")[0].replace("CN=", "") for m in (entry.member or [])],
            "member_count":len(list(entry.member)) if entry.member else 0,
            "dn":          str(entry.distinguishedName),
            "high_value":  str(entry.cn) in HIGH_VALUE_GROUPS,
        })

    ok("Grupos encontrados: " + str(len(groups)))
    return groups


# ══════════════════════════════════════════════════════════════
# ENUMERACIÓN DE EQUIPOS
# ══════════════════════════════════════════════════════════════

def enum_computers(conn, base: str) -> list:
    """Enumera todos los equipos del dominio."""
    info("Enumerando equipos del dominio...")

    conn.search(
        search_base   = base,
        search_filter = "(objectClass=computer)",
        attributes    = COMPUTER_ATTRS,
    )

    computers = []
    for entry in conn.entries:
        uac = int(entry.userAccountControl.value or 0)
        computers.append({
            "cn":         str(entry.cn),
            "dns":        str(entry.dNSHostName) if entry.dNSHostName else "",
            "os":         str(entry.operatingSystem) if entry.operatingSystem else "Desconocido",
            "os_version": str(entry.operatingSystemVersion) if entry.operatingSystemVersion else "",
            "disabled":   bool(uac & UAC_DISABLED),
            "dn":         str(entry.distinguishedName),
        })

    ok("Equipos encontrados: " + str(len(computers)))
    return computers


# ══════════════════════════════════════════════════════════════
# IDENTIFICACIÓN DE VECTORES DE ATAQUE
# ══════════════════════════════════════════════════════════════

def find_attack_paths(users: list, groups: list) -> dict:
    """Identifica los vectores de ataque más relevantes."""

    kerberoastable   = [u for u in users if u["kerberoastable"] and not u["disabled"]]
    asrep_roastable  = [u for u in users if u["no_preauth"] and not u["disabled"]]
    pwd_not_required = [u for u in users if u["pwd_not_required"] and not u["disabled"]]
    pwd_never_expires= [u for u in users if u["pwd_never_expires"] and not u["disabled"]]
    desc_passwords   = [u for u in users
                        if u["description"] and
                        any(w in u["description"].lower()
                            for w in ["pass", "pwd", "password", "clave", "contraseña"])]
    admin_count      = [u for u in users if u["admin_count"] == 1]
    high_value_grps  = [g for g in groups if g["high_value"] and g["member_count"] > 0]

    return {
        "kerberoastable":    kerberoastable,
        "asrep_roastable":   asrep_roastable,
        "pwd_not_required":  pwd_not_required,
        "pwd_never_expires": pwd_never_expires,
        "desc_passwords":    desc_passwords,
        "admin_count":       admin_count,
        "high_value_groups": high_value_grps,
    }


# ══════════════════════════════════════════════════════════════
# REPORTE EN CONSOLA
# ══════════════════════════════════════════════════════════════

def print_report(users, groups, computers, attack_paths, domain):
    sep = "─" * 60

    print("\n" + C.BOLD + "  " + sep + C.RESET)
    print(C.BOLD + "  RESULTADOS — " + domain.upper() + C.RESET)
    print("  " + sep)

    # Estadísticas generales
    active_users = [u for u in users if not u["disabled"]]
    print("  Usuarios totales    : " + str(len(users)) +
          " (" + str(len(active_users)) + " activos)")
    print("  Grupos              : " + str(len(groups)))
    print("  Equipos             : " + str(len(computers)))
    print()

    # ── CRÍTICO: Kerberoastables ──────────────────────────────
    kerberoast = attack_paths["kerberoastable"]
    if kerberoast:
        print(C.RED + C.BOLD + "  [CRITICO] Usuarios Kerberoastables (" +
              str(len(kerberoast)) + "):" + C.RESET)
        for u in kerberoast:
            print("    * " + u["sam"])
            for spn in u["spn"]:
                print("      SPN: " + str(spn))
        print()
        print("  Comando Kerberoasting:")
        print(C.GRAY + "    python3 ../02-Kerberos/scripts/kerberoast.py \\" + C.RESET)
        print(C.GRAY + "        --dc DC_IP --domain " + domain + " -u USER -p PASS" + C.RESET)
        print()

    # ── CRITICO: AS-REP Roastables ───────────────────────────
    asrep = attack_paths["asrep_roastable"]
    if asrep:
        print(C.RED + C.BOLD + "  [CRITICO] Usuarios AS-REP Roastables (" +
              str(len(asrep)) + "):" + C.RESET)
        for u in asrep:
            print("    * " + u["sam"])
        print()
        print("  Comando AS-REP Roasting:")
        print(C.GRAY + "    impacket-GetNPUsers " + domain + "/ -usersfile users.txt -no-pass -format hashcat" + C.RESET)
        print()

    # ── ALTO: Grupos de alto valor ───────────────────────────
    hvg = attack_paths["high_value_groups"]
    if hvg:
        print(C.YELLOW + C.BOLD + "  [ALTO] Grupos privilegiados con miembros:" + C.RESET)
        for g in hvg:
            print("    * " + g["cn"] + " — " + str(g["member_count"]) + " miembro(s)")
            for m in g["members"][:5]:
                print("      - " + m)
            if g["member_count"] > 5:
                print("      ... +" + str(g["member_count"] - 5) + " más")
        print()

    # ── ALTO: AdminCount ─────────────────────────────────────
    ac = attack_paths["admin_count"]
    if ac:
        print(C.YELLOW + "  [ALTO] Usuarios con adminCount=1 (AdminSDHolder protegidos):" + C.RESET)
        for u in ac:
            print("    * " + u["sam"])
        print()

    # ── MEDIO: Contraseñas en descripcion ────────────────────
    desc = attack_paths["desc_passwords"]
    if desc:
        print(C.YELLOW + "  [MEDIO] Posibles contraseñas en atributo 'description':" + C.RESET)
        for u in desc:
            print("    * " + u["sam"] + ": " + u["description"][:80])
        print()

    # ── INFORMATIVO: Contraseñas sin expiración ──────────────
    ne = attack_paths["pwd_never_expires"]
    if ne:
        print(C.BLUE + "  [INFO] Usuarios con contraseña que nunca expira (" +
              str(len(ne)) + "):" + C.RESET)
        for u in ne[:10]:
            print("    * " + u["sam"])
        if len(ne) > 10:
            print("    ... +" + str(len(ne) - 10) + " más")
        print()

    # ── Lista de usuarios activos ─────────────────────────────
    print(C.BOLD + "  Usuarios activos del dominio:" + C.RESET)
    for u in active_users[:20]:
        flags = ""
        if u["kerberoastable"]:   flags += C.RED + " [KERBEROAST]" + C.RESET
        if u["no_preauth"]:       flags += C.RED + " [ASREP]" + C.RESET
        if u["admin_count"] == 1: flags += C.YELLOW + " [ADMIN]" + C.RESET
        print("    " + u["sam"].ljust(25) + flags)
    if len(active_users) > 20:
        print("    ... +" + str(len(active_users) - 20) + " usuarios más")
    print()

    # ── Resumen de equipos ────────────────────────────────────
    if computers:
        print(C.BOLD + "  Equipos del dominio:" + C.RESET)
        for c in computers:
            print("    " + (c["cn"] + " / " + c["dns"]).ljust(40) +
                  " — " + c["os"][:40])
        print()

    print("  " + sep)
    print(C.BOLD + "  Siguiente paso recomendado:" + C.RESET)
    if kerberoast:
        print("    → Kerberoasting: python3 ../02-Kerberos/scripts/kerberoast.py")
    elif asrep:
        print("    → AS-REP Roasting: python3 ../02-Kerberos/scripts/asrep_roast.py")
    else:
        print("    → Password Spray: python3 ../03-Credenciales/scripts/credential_attack.py")
    print()


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="ad_enum.py — Enumeración de Active Directory via LDAP",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--dc",          required=True,  help="IP del Domain Controller")
    p.add_argument("--domain",      required=True,  help="Dominio (ej: empresa.local)")
    p.add_argument("-u", "--user",   default=None,  help="Usuario de dominio")
    p.add_argument("-p", "--password",default=None, help="Contraseña")
    p.add_argument("--null-session", action="store_true",
                   help="Intentar sesión anónima (sin credenciales)")
    p.add_argument("--attack-paths", action="store_true",
                   help="Mostrar solo vectores de ataque identificados")
    p.add_argument("--output",      default=None,
                   help="Guardar resultados en archivo JSON")
    p.add_argument("--ldaps",       action="store_true",
                   help="Usar LDAPS (puerto 636) en vez de LDAP (389)")
    return p.parse_args()


def main():
    banner()
    args = parse_args()

    if not args.null_session and (not args.user or not args.password):
        err("Proporciona --user y --password, o usa --null-session")
        sys.exit(1)

    # Conexión al DC
    conn, base = connect_ldap(
        dc       = args.dc,
        domain   = args.domain,
        user     = args.user if not args.null_session else None,
        password = args.password if not args.null_session else None,
        use_ssl  = args.ldaps,
    )

    if conn is None:
        err("No se pudo conectar al DC. Verifica IP, credenciales y conectividad.")
        sys.exit(1)

    # Enumeración
    users     = enum_users(conn, base)
    groups    = enum_groups(conn, base)
    computers = enum_computers(conn, base)

    # Identificar vectores de ataque
    attack_paths = find_attack_paths(users, groups)

    # Mostrar reporte
    print_report(users, groups, computers, attack_paths, args.domain)

    # Guardar JSON
    if args.output:
        results = {
            "domain":       args.domain,
            "dc":           args.dc,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "users":        users,
            "groups":       groups,
            "computers":    computers,
            "attack_paths": {
                "kerberoastable":   [u["sam"] for u in attack_paths["kerberoastable"]],
                "asrep_roastable":  [u["sam"] for u in attack_paths["asrep_roastable"]],
                "desc_passwords":   [{"sam": u["sam"], "desc": u["description"]}
                                     for u in attack_paths["desc_passwords"]],
            },
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        ok("Resultados guardados en: " + args.output)

    conn.unbind()


if __name__ == "__main__":
    main()
