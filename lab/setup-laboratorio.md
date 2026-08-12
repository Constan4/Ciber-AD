# Configuración del Laboratorio Active Directory

Guía completa para montar un dominio AD vulnerable en un entorno controlado.

---

## Arquitectura objetivo

```
Kali Linux (atacante) ◄──► DC Windows Server 2022 ◄──► Workstation Windows 10/11
   192.168.1.35              192.168.1.10                  192.168.1.41
                             empresa.local
```

---

## 1. Windows Server 2022 — Instalar Active Directory

### 1.1 Configurar IP estática

En PowerShell como Administrador:

```powershell
# Configurar IP estática
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.1.10 `
    -PrefixLength 24 -DefaultGateway 192.168.1.1

# DNS apuntando a sí mismo (será el DNS del dominio)
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.1.10

# Cambiar nombre del servidor
Rename-Computer -NewName "DC01" -Restart
```

### 1.2 Instalar el rol de Active Directory

```powershell
# Instalar AD DS
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promover a Domain Controller
Install-ADDSForest `
    -DomainName "empresa.local" `
    -DomainNetbiosName "EMPRESA" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "Admin123!" -AsPlainText -Force) `
    -Force

# El servidor se reiniciará automáticamente
```

### 1.3 Crear usuarios y grupos para el laboratorio

```powershell
# Importar módulo AD
Import-Module ActiveDirectory

# ── Crear Unidades Organizativas ──
New-ADOrganizationalUnit -Name "Usuarios_Lab" -Path "DC=empresa,DC=local"
New-ADOrganizationalUnit -Name "Equipos_Lab"  -Path "DC=empresa,DC=local"
New-ADOrganizationalUnit -Name "Servidores"   -Path "DC=empresa,DC=local"

# ── Crear usuarios con diferentes privilegios ──
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force

# Usuario estándar (punto de entrada del atacante)
New-ADUser -Name "juan.garcia" -AccountPassword $password `
    -Enabled $true -Path "OU=Usuarios_Lab,DC=empresa,DC=local" `
    -Description "Usuario de soporte técnico"

# Usuario con SPN (vulnerable a Kerberoasting)
New-ADUser -Name "svc-sql" -AccountPassword $password `
    -Enabled $true -Path "OU=Usuarios_Lab,DC=empresa,DC=local" `
    -Description "Cuenta de servicio SQL Server"

# Añadir SPN al usuario de servicio (¡esto lo hace Kerberoastable!)
Set-ADUser svc-sql -ServicePrincipalNames @{Add="MSSQLSvc/db01.empresa.local:1433"}

# Usuario sin pre-autenticación Kerberos (vulnerable a AS-REP Roasting)
New-ADUser -Name "maria.lopez" -AccountPassword $password `
    -Enabled $true -Path "OU=Usuarios_Lab,DC=empresa,DC=local"
Set-ADAccountControl maria.lopez -DoesNotRequirePreAuth $true

# Usuario administrador local de workstations
New-ADUser -Name "admin.local" -AccountPassword $password `
    -Enabled $true -Path "OU=Usuarios_Lab,DC=empresa,DC=local"

# ── Crear grupos ──
New-ADGroup -Name "IT-Helpdesk" -GroupScope Global `
    -Path "OU=Usuarios_Lab,DC=empresa,DC=local"
New-ADGroup -Name "Server-Admins" -GroupScope Global `
    -Path "OU=Usuarios_Lab,DC=empresa,DC=local"

# Añadir usuarios a grupos
Add-ADGroupMember -Identity "IT-Helpdesk"    -Members "juan.garcia", "maria.lopez"
Add-ADGroupMember -Identity "Server-Admins"  -Members "admin.local"

# ── Dar privilegios de administrador local a IT-Helpdesk en workstations (GPO) ──
# (Se configura via GPO, ver sección 1.4)

Write-Host "Lab AD configurado correctamente" -ForegroundColor Green
```

### 1.4 Configurar GPO vulnerable (para práctica de GPO abuse)

```powershell
# Crear GPO que añade IT-Helpdesk como admin local
$gpo = New-GPO -Name "IT-Admins-Local"
New-GPLink -Name "IT-Admins-Local" -Target "OU=Equipos_Lab,DC=empresa,DC=local"

# Nota: La configuración de Restricted Groups se hace desde
# Group Policy Management > Configuración de equipo > Configuración de Windows
# > Configuración de seguridad > Grupos restringidos
```

---

## 2. Windows 10/11 — Unir al dominio

```powershell
# Configurar DNS del dominio
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.1.10

# Unir la workstation al dominio
Add-Computer -DomainName "empresa.local" `
    -Credential (Get-Credential) `
    -OUPath "OU=Equipos_Lab,DC=empresa,DC=local" `
    -NewName "WKSTN01" `
    -Restart

# Después del reinicio, iniciar sesión con EMPRESA\juan.garcia
```

---

## 3. Kali Linux — Instalar herramientas de ataque

```bash
# Actualizar
sudo apt update && sudo apt upgrade -y

# Herramientas principales
sudo apt install -y bloodhound neo4j crackmapexec responder evil-winrm \
                    ldap-utils smbclient john hashcat

# Impacket (la suite más importante para ataques AD)
pip install impacket

# ldap3 (para nuestros scripts Python)
pip install ldap3

# Kerbrute (enumeración Kerberos)
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64 && sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

# Verificar conectividad con el DC
ping 192.168.1.10
nmap -sV -p 88,389,445,636,3268 192.168.1.10
```

### 3.1 Configurar /etc/hosts y resolución DNS

```bash
# Añadir el DC a /etc/hosts
echo "192.168.1.10    empresa.local DC01.empresa.local DC01" | sudo tee -a /etc/hosts

# Configurar DNS del sistema para que resuelva el dominio
sudo bash -c 'echo "nameserver 192.168.1.10" > /etc/resolv.conf'

# Verificar resolución
nslookup empresa.local
nslookup DC01.empresa.local
```

---

## 4. Verificar que el lab funciona

```bash
# Verificar conectividad con el DC
crackmapexec smb 192.168.1.10

# Autenticación con credenciales
crackmapexec smb 192.168.1.10 -u juan.garcia -p 'Password123!' -d empresa.local

# Enumerar usuarios via LDAP (sin credenciales — null session, si está habilitada)
ldapsearch -x -H ldap://192.168.1.10 -b "DC=empresa,DC=local" -s sub "(objectClass=user)" cn

# Con credenciales
ldapsearch -x -H ldap://192.168.1.10 -D "juan.garcia@empresa.local" \
    -w 'Password123!' -b "DC=empresa,DC=local" "(objectClass=user)" cn sAMAccountName
```

---

## 5. Puertos relevantes del DC

| Puerto | Protocolo | Servicio | Uso en ataques |
|--------|-----------|---------|----------------|
| 53 | TCP/UDP | DNS | Enumeración, DNS poisoning |
| 88 | TCP | Kerberos | Kerberoasting, AS-REP, Pass-the-Ticket |
| 135 | TCP | MSRPC | DCOM attacks, WMI |
| 139/445 | TCP | SMB | PTH, relay attacks, lateral movement |
| 389 | TCP | LDAP | Enumeración de AD |
| 636 | TCP | LDAPS | Enumeración cifrada |
| 3268 | TCP | Global Catalog | Búsquedas entre dominios |
| 3389 | TCP | RDP | Acceso remoto, PTH con restricted admin |
| 5985 | TCP | WinRM | evil-winrm, remote execution |

---

## 6. Cheklist de verificación del lab

```bash
# Desde Kali — ejecutar antes de cada sesión de práctica
python3 01-Reconocimiento/scripts/ad_enum.py \
    --dc 192.168.1.10 \
    --domain empresa.local \
    --user juan.garcia \
    --password 'Password123!'
```

Si el script devuelve los usuarios del dominio, el lab está listo.
