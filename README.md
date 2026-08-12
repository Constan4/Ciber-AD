# ⚔️ Ciber-AD — Active Directory Penetration Testing

<p align="center">
  <img src="https://img.shields.io/badge/Enfoque-Red%20Team%20%2F%20Ofensivo-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Objetivo-Active%20Directory-blue?style=for-the-badge&logo=windows"/>
  <img src="https://img.shields.io/badge/Tools-Impacket%20%7C%20BloodHound%20%7C%20CrackMapExec-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

<p align="center">
  <b>Guía completa de ataque a infraestructuras Active Directory.</b><br/>
  Desde el reconocimiento inicial hasta la dominancia total del dominio.
</p>

---

## Kill Chain — De usuario a Domain Admin

```
  [Acceso inicial]
        │
        ▼
  01 Reconocimiento ──► LDAP Enum · BloodHound · PowerView
        │
        ▼
  02 Ataques Kerberos ──► Kerberoasting · AS-REP Roasting
        │
        ▼
  03 Credenciales ──► Password Spray · Credential Dumping
        │
        ▼
  04 Movimiento lateral ──► PTH · PTT · WMIExec · PSExec
        │
        ▼
  05 Escalada ──► ACL Abuse · GPO Abuse · SeImpersonate
        │
        ▼
  06 Dominancia ──► DCSync · Golden Ticket · Silver Ticket
        │
        ▼
  07 Persistencia ──► AdminSDHolder · SID History · Skeleton Key
```

---

## Módulos

| # | Módulo | Técnicas | Script |
|---|--------|----------|--------|
| 01 | [Reconocimiento](01-Reconocimiento/) | LDAP, BloodHound, PowerView | `ad_enum.py` |
| 02 | [Kerberos](02-Kerberos/) | Kerberoasting, AS-REP Roasting | `kerberoast.py` |
| 03 | [Credenciales](03-Credenciales/) | Password Spray, Dumping, NTLM | `credential_attack.py` |
| 04 | [Lateral Movement](04-Lateral-Movement/) | PTH, PTT, WMIExec, SMBExec | `lateral_move.py` |
| 05 | [Privilege Escalation](05-Privilege-Escalation/) | ACL Abuse, GPO, Potato Attacks | `privesc_scanner.py` |
| 06 | [Domain Dominance](06-Domain-Dominance/) | DCSync, Golden/Silver Ticket | `domain_pwn.py` |
| 07 | [Persistencia](07-Persistencia/) | AdminSDHolder, SID History | `persistence.py` |
| 08 | [Evasion](08-Evasion/) | AMSI Bypass, AV Evasion, ETW | `evasion_toolkit.py` |

---

## Arquitectura del laboratorio

```
┌─────────────────────────────────────────────────────┐
│                Red de laboratorio                    │
│                 192.168.1.0/24                       │
│                                                      │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │ Kali Linux   │    │  Windows Server 2022     │   │
│  │ (Atacante)   │◄──►│  (Domain Controller)     │   │
│  │ 192.168.1.35 │    │  dominio: empresa.local  │   │
│  └──────────────┘    │  192.168.1.10            │   │
│                      └──────────────────────────┘   │
│                                                      │
│                      ┌──────────────────────────┐   │
│                      │  Windows 10/11           │   │
│                      │  (Workstation)           │   │
│                      │  WKSTN01.empresa.local   │   │
│                      │  192.168.1.41            │   │
│                      └──────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## Herramientas esenciales

| Herramienta | Uso | Instalación |
|-------------|-----|-------------|
| **Impacket** | Suite completa de ataques AD | `pip install impacket` |
| **BloodHound** | Grafo de relaciones AD + rutas de ataque | `apt install bloodhound` |
| **CrackMapExec** | Swiss army knife para AD | `apt install crackmapexec` |
| **Kerbrute** | Enumeración de usuarios Kerberos | GitHub |
| **Responder** | LLMNR/NBT-NS poisoning | `apt install responder` |
| **evil-winrm** | Shell WinRM | `gem install evil-winrm` |
| **Rubeus** | Ataques Kerberos (desde Windows) | GitHub |
| **Mimikatz** | Credential dumping (desde Windows) | GitHub |

---

## Configuración rápida del laboratorio

Ver [lab/setup-laboratorio.md](lab/setup-laboratorio.md) para la guía completa.

```bash
# Instalar herramientas en Kali
sudo apt update
sudo apt install -y bloodhound crackmapexec responder evil-winrm
pip install impacket ldap3

# Clonar el repo
git clone https://github.com/Constan4/Ciber-AD.git
cd Ciber-AD

# Primer ataque — Enumerar el dominio
python3 01-Reconocimiento/scripts/ad_enum.py \
    --dc 192.168.1.10 \
    --domain empresa.local \
    --user usuario \
    --password Contraseña123
```

---

## Referencias MITRE ATT&CK

Este repositorio mapea las técnicas con MITRE ATT&CK:
- [T1018](https://attack.mitre.org/techniques/T1018/) — Remote System Discovery
- [T1558](https://attack.mitre.org/techniques/T1558/) — Steal or Forge Kerberos Tickets
- [T1003](https://attack.mitre.org/techniques/T1003/) — OS Credential Dumping
- [T1550](https://attack.mitre.org/techniques/T1550/) — Use Alternate Authentication Material
- [T1484](https://attack.mitre.org/techniques/T1484/) — Domain Policy Modification

---

## ⚠️ Aviso Legal

> Todo el contenido es **exclusivamente para fines educativos** en entornos de laboratorio propios.
> El acceso no autorizado a sistemas es un delito penal (Art. 197 y 264 del Código Penal español).

---

*Constan4 — Red Team / Active Directory*
