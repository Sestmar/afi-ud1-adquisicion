# Notas de trabajo — Adquirir un equipo comprometido

**Examinador:** Sergio Estudillo Marabot  
**Caso:** ALMADRABA-PC-ADMIN  
**Máquina investigada:** FORENSIC_10 (VMware Workstation Pro 26), Windows 7 SP1, equipo FORENSE-06  
**USB de respuesta:** Philips UFD exFAT ~31 GB, unidad D: en la VM  
**Fecha adquisición en vivo:** 30/10/2026  
**Fecha adquisición post-mortem:** 31/10/2026 (disco) · 03/11/2026 (pendrive)

---

## Antes de empezar

### Hora del sistema

| Referencia | Valor |
|---|---|
| Hora VM (FORENSE-06) | 16:27 · 30/10/2026 |
| Hora real (host) | 16:28 · 30/10/2026 |
| Desfase efectivo | 0 — el minuto de diferencia es el intervalo entre capturas, no un reloj mal configurado |
| Zona horaria | UTC+1 |

Capturas: `01-pantalla-inicial-marca-reloj.png`, `01b-reloj-host.png`.

### USB de respuesta

Philips UFD conectado a la VM desde el menú VMware *Removable Devices*. Windows instaló el driver y asignó unidad D:. Se eligió *Continue without scanning* en el diálogo de reparación y *Open folder* en AutoPlay.

Al intentar crear la carpeta de salida (`mkdir D:\USB-RESPUESTA\salida\ALMADRABA-PC-ADMIN`) el volumen estaba marcado como sucio. Se ejecutó `chkdsk D: /F /X` desde la VM: corrupción encontrada en `1DAM\...` (carpeta ajena al kit, preexistente). Windows corrigió sin sectores dañados. ~11 GB libres tras la reparación.

### Marca de adquisición

**~16:24** — Se dejó la marca en la máquina (excepción del enunciado; primera acción anotada en el acta):

1. Bloc de notas abierto, sin guardar, con el texto `AFI-SergioEstudillo-20261030`.
2. Fichero `marca-sergioestudillo.txt` creado en el escritorio del Administrador con el mismo texto. Windows ocultó la extensión, resultando en `marca-sergioestudillo.txt.txt` en el sistema de ficheros.
3. El fichero de marca se copió al pendrive (Philips UFD) desde el host Windows el 03/11/2026, dado que FORENSIC_10 ya estaba apagada en ese momento. Contenido idéntico: `AFI-SergioEstudillo-20261030`. Incidencia documentada en el acta.

---

## Parte 1 · Adquisición en vivo (30/10/2026)

### 1. Estado inicial

Captura de pantalla de la sesión activa del Administrador, hora del sistema y desfase. Ver capturas `01` y `01b`.

### 2. Volcado de RAM

**16:58–16:59 — DumpIt 3.6.20230117 x64**

```
D:\USB-RESPUESTA\herramientas\DumpIt.exe
```

Fallo `0xC0000428` (firma de controlador no válida en Windows 7 con Secure Boot / Driver Signing). Se intentó copiar `DumpIt.sys` a `C:\Windows\System32\Drivers` y limpiar el registro, sin éxito. No se instaló ningún runtime en C: de la evidencia.

**Por qué DumpIt:** es la herramienta recomendada en el enunciado para volcado de RAM. Se descartó después del fallo.

**17:02–17:04 — WinPmem (alternativa)**

```
D:\USB-RESPUESTA\herramientas\winpmem_mini_x64_rc2.exe D:\USB-RESPUESTA\salida\ALMADRABA-PC-ADMIN\PC-ADMIN-ram.raw
```

Resultado: volcado correcto. `PC-ADMIN-ram.raw`, 1.073.741.824 bytes (1 GB).

```
sha256sum PC-ADMIN-ram.raw
f72fc35dd1942d7f8f32884c3a7e4cc0aa09b45217b28dc15c67baf895e1889d
```

**Por qué WinPmem:** única alternativa disponible en el kit compatible con Windows 7 SP1 sin necesidad de instalar drivers firmados. El fallo de DumpIt queda documentado en el acta como incidencia.

Captura: `03-winpmem-ram-ok.png`.

### 3. Datos volátiles

**17:10 — respuesta-en-vivo.ps1**

```
D:\USB-RESPUESTA\herramientas\respuesta-en-vivo.ps1 -Triaje
```

Fallo en línea 353: PowerShell 2.0 (Windows 7) no admite el operador `-in`. El script requiere PS 3.0+. No se instaló ninguna actualización en la evidencia.

**17:12–17:19 — Comandos nativos cmd (alternativa)**

Se recogieron 21 ficheros de datos volátiles en `salida\ALMADRABA-PC-ADMIN\triaje\` con comandos nativos ejecutados desde cmd:

| Fichero | Comando |
|---|---|
| 01_fecha.txt | `date /t & time /t` |
| 02_netstat.txt | `netstat -ano` |
| 03_arp.txt | `arp -a` |
| 04_dns_cache.txt | `ipconfig /displaydns` |
| 05_ipconfig.txt | `ipconfig /all` |
| 06_rutas.txt | `route print` |
| 07_netbios.txt | `nbtstat -s` |
| 08_procesos_tasklist.txt | `tasklist /v` |
| 09_procesos_detalle.txt | `tasklist /svc` |
| 10_sesiones.txt | `query session` |
| 11_whoami.txt | `whoami /all` |
| 12_recursos_compartidos.txt | `net share` |
| 20_systeminfo.txt | `systeminfo` |
| 21_hostname.txt | `hostname` |
| 22_servicios.txt | `sc query type= all` |
| 23_tareas.txt | `schtasks /query /fo LIST /v` |
| 24_bcdedit.txt | `bcdedit` |
| 25_discos.txt | `diskpart list disk` |
| 26_usuarios.txt | `net user` |
| 27_drivers.txt | `driverquery` |
| 28_autoruns_reg.txt | `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |

**Por qué comandos nativos:** ante el fallo de PS1 y Velociraptor (binario Win10+, no ejecutable en Win7), y sin alternativa de KAPE compatible, los comandos nativos de cmd son la única vía para recoger datos volátiles sin instalar nada en la evidencia.

Velociraptor: *not a valid Win32 application* en Windows 7. FTK Imager 8.3 en la VM: falta `api-ms-win-crt-runtime-l1-1-0.dll` (UCRT, no disponible en Win7 sin actualización). No se instalaron runtimes en C: de la evidencia.

### 4. Tráfico de red

**17:23–17:26** — Captura desde el host (sin instalar nada en la evidencia):

```
vnetsniffer.exe /e /w C:\...\FORENSIC_10\red.pcap VMnet0
```

Adaptador de red en puente (VMnet0). Se detuvo con Ctrl+C tras ~3 minutos. Fichero `red.pcap`, 2982 bytes. Poco tráfico: principalmente mDNS.

```
sha256sum red.pcap
60206481a6c429112ab76e4f4d11cf1a41b48ead1e25547dae180c7beb2564a7
```

**Por qué vnetsniffer desde el host:** el enunciado pide capturar "como haría un TAP, sin instalar nada en la máquina". VMware Workstation permite captura de tráfico a nivel de hipervisor con vnetsniffer, equivalente funcional al VBoxManage nictrace del enunciado (que asume VirtualBox). Se eligió esta herramienta porque la VM corre en VMware, no en VirtualBox.

### 5. Triaje

Ver sección 3 — datos volátiles nativos. KAPE y Velociraptor no ejecutables en Windows 7 SP1.

### 6. Cifrado

**17:33 — VSS (incidencia)**

```
wmic shadowcopy call create Volume=C:\
```

ShadowID `{1F9E046F-4873-4395-877D-3973B55906D8}` creado. Intento de copiar `$MFT` en vivo: fallido (`\\?\GLOBALROOT` y `\\.\` no accesibles desde cmd). Se abandonó; el `$MFT` se obtendrá de la imagen E01.

**17:52 — BitLocker**

```
manage-bde -status
```

Resultado: C: y D: `Fully Decrypted`, `Protection Off`, sin protectores activos. No hay BitLocker.

Captura: `04-manage-bde-sin-cifrado.png`.

**17:53 — EDD (Encryption Detection and Decryption)**

```
D:\USB-RESPUESTA\herramientas\EDD.exe /batch
```

Resultado: PhysicalDrive0 (VMware SCSI 34 GB) OK; PhysicalDrive1 (Philips USB exFAT 31 GB) OK. Ningún volumen cifrado detectado: TrueCrypt, PGP, BitLocker, VeraCrypt, SafeBoot, BestCrypt, CheckPoint, Sophos, Symantec — todos negativos.

Captura: `05-edd-sin-cifrado.png`.

**Decisión:** sin cifrado activo. No es necesario extraer claves ni suspender el sistema para preservar el estado de RAM de descifrado.

### 7. Apagado

**~17:53 — Power Off (corte de corriente virtual)**

**Decisión y justificación:** se eligió Power Off (equivalente a desconectar el cable de corriente) en lugar de apagado ACPI ordenado por las siguientes razones:

1. No hay cifrado de disco: un apagado ordenado no revelaría claves de cifrado que ya no existen.
2. Sin RAID ni volúmenes que requieran desmontaje limpio.
3. El apagado ACPI ejecuta rutinas del SO que podrían borrar artefactos volátiles en memoria, modificar registros y ejecutar procesos de cierre. Power Off preserva el estado tal como está.
4. Se descartó Hibernate/Suspend: generaría un fichero `hiberfil.sys` con contenido de RAM mezclado con el estado del disco, complicando el análisis posterior.

La expulsión segura del USB desde el invitado no estaba disponible. Se desconectó el Philips desde el menú VMware *Removable Devices* antes del Power Off.

---

## Parte 2 · Adquisición post-mortem

### Disco de la máquina (31/10/2026, CAINE 14.0 Lightstream)

**Hash del disco original antes del post-mortem (17:59, 30/10/2026):**

```
sha256sum FORENSIC_10-disk1.vmdk
8c68c5c479f153cd2d85cf9126f5cd1d7f63a00ffba9f543240e098871bcd0d9  (12.280.608.256 bytes)
```

**Configuración en CAINE:**

VM CAINE creada con ISO CAINE 14.0 Lightstream (SHA-256 verificado: `2702226cf9ee131ee54e9649d6d90008f3fe851ba35939f43ae8cb614a00d564`), arranque en vivo sin instalación. Disco `FORENSIC_10-disk1.vmdk` adjuntado como **Independent Nonpersistent** (equivalente a inmutable: las escrituras van a un disco temporal descartable, el original no se toca). Disco destino `Caine-e01-destino.vmdk` 20 GB, formato ext4, etiqueta `E01DEST`.

**Por qué CAINE + Guymager:** CAINE no monta automáticamente los discos al arrancar (no-automount), lo que garantiza que el disco original no se modifica. Guymager es la herramienta de adquisición E01 integrada en CAINE, con verificación de imagen incorporada.

**Primer intento (~16:35) — fallido:**

Origen `/dev/sdb` → destino `/media/philips/USB-RESPUESTA/salida/ALMADRABA-PC-ADMIN/`. Resultado: *Aborted – Image verify error* (error de I/O / espacio insuficiente en el USB exFAT). Se eliminaron los trozos incompletos; RAM y triaje se conservaron.

**Segundo intento (~18:50–19:00) — correcto:**

Origen `/dev/sdc` (34,4 GB) → destino `/media/e01/PCADMINDisco` (disco persistente `E01DEST`).

Parámetros Guymager:
- Case number: `ALMADRABA-PC-ADMIN`
- Evidence number: `1`
- Examiner: `Sergio Estudillo Marabot`
- Verify image: ON

Resultado: *Finished successfully / Image verification OK*.

```
SHA-256 contenido imagen: ead1bbdb0b81228739a20792ff1a897906411a7bd8bfd7664c88616071a44fb1
MD5:                       55ade5b44b4b0156c6303f5867fad086
```

Capturas: `10` a `16`, `21` a `22`.

**Hash del disco original después del post-mortem:**

```
8c68c5c479f153cd2d85cf9126f5cd1d7f63a00ffba9f543240e098871bcd0d9
```

Idéntico al anterior: el original no fue modificado. Captura: `hashes/disco-original-antes.sha256` y `hashes/disco-original-despues.sha256`.

**Copia de trabajo (~20:00–20:11):**

```bash
cp PCADMINDisco.E0{1,2,3} /media/e01/copia-trabajo/
sha256sum PCADMINDisco.E01 PCADMINDisco.E02 PCADMINDisco.E03
```

Hashes maestra = copia de trabajo (trozo a trozo):

```
2810093c9ea09be4a7c9b670623bf163c111eaf7eaa520c8160a8d4d21135f3a  E01
11b3ef60c44135a1cec4e1d2d538e94c7080887858fe397d0ab7f95278f641b0  E02
3cab12953e5a2f873c051bc38c7b63907c4bec93b9b5c50ade321415bb19f2e0  E03
```

Capturas: `23`, `24`, `25`.

### Pendrive encontrado (03/11/2026, host Windows)

**Descripción del pendrive:** Philips UFD, exFAT, 29,3 GB (31.457.280.000 bytes). Serie: `5643371227407628126`. El mismo dispositivo usado como USB de respuesta, autorizado por el profesor al no disponer de un segundo pendrive.

**Marca en el pendrive:**

El fichero `marca-sergioestudillo.txt` (contenido: `AFI-SergioEstudillo-20261030`) se creó directamente en la raíz del pendrive desde el host Windows el 03/11/2026, dado que FORENSIC_10 ya estaba apagada. El contenido es idéntico al fichero del escritorio del Administrador (visible en la imagen E01 y en la RAM).

**Bloqueo de escritura (10:15–10:16):**

Script `bloqueo-usb.ps1` ejecutado como administrador en el host Windows:

1. Política global activada (`WriteProtect=1`).
2. USB desconectado y reconectado para aplicar la política.
3. Comprobación: *"Disco 1 D: : no deja escribir → PROTEGIDO"*.

Log guardado en `hashes/bloqueo-usb.log`. Captura: `26-bloqueo-usb-protegido.png`.

**Por qué bloqueo por software:** sin bloqueador de escritura por hardware disponible. El script `bloqueo-usb.ps1` del kit establece la clave de registro `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect=1`, que Windows aplica a todos los dispositivos USB conectados posteriormente.

**Imagen E01 con FTK Imager 8.3 (host Windows, 03/11/2026):**

```
File → Create Disk Image → Physical Drive → \\.\PHYSICALDRIVE1
Formato: E01
Destino: C:\temp-pendrive\PCADMINPendrive
Verify images after they are created: ON
```

Parámetros:
- Case number: `ALMADRABA-PC-ADMIN`
- Evidence number: `2`
- Examiner: `Sergio Estudillo Marabot`
- Description: `Pendrive encontrado en la escena - Philips UFD 32GB`
- Notes: `Adquisicion post-mortem con bloqueo de escritura por software (bloqueo-usb.ps1)`

**Por qué FTK Imager:** herramienta disponible en el host Windows, compatible con adquisición de dispositivos físicos y generación de imágenes E01 verificadas. CAINE no estaba disponible para esta adquisición.

Resultado: verificación OK. Sin bad blocks.

```
MD5:  1dd4e418b676f5211ff7043d93377f42
SHA1: 88be57900d8c1b206bbb75e28c44007dd9db59f3
```

Adquisición: 10:25:48 – 10:45:09 (03/11/2026). Verificación: 10:45:09 – 10:47:58.  
7 segmentos: PCADMINPendrive.E01 – E07. Log: `hashes/PCADMINPendrive-ftk-hashes.txt`.  
Captura: `27-ftk-pendrive-verified-ok.png`.

---

## Parte 3 · Búsqueda de la marca

### En la RAM

Desde CAINE, con la imagen montada:

```bash
strings -el PC-ADMIN-ram.raw | grep "AFI-"
```

Resultado: `AFI-SergioEstudillo-20261030` encontrado. Captura: `20-marca-en-ram.png`.

### En el triaje ($MFT)

```bash
strings -el '$MFT' | grep "marca-"
```

Resultado: `marca-sergioestudillo.txt.txt` y `.lnk` encontrados en UTF-16. Captura: `19-marca-en-mft.png`.

### En la imagen del disco

Imagen montada en solo lectura. Fichero localizado en `/media/loop1p2/Users/Administrador/Desktop/`. Capturas: `17-marca-en-imagen-escritorio.png`, `18-marca-en-imagen-contenido.png`.

### En la imagen del pendrive

Imagen montada en FTK Imager (host Windows). Fichero `marca-sergioestudillo.txt` localizado en `PHILIPS UFD [exFAT]/[root]/`, 29 bytes, contenido `AFI-SergioEstudillo-20261030`. Captura: `28-marca-en-pendrive.png`.

---

## Incidencias y decisiones

| # | Incidencia | Decisión tomada |
|---|---|---|
| 1 | Hipervisor real es VMware, no VirtualBox (enunciado) | Se documentan equivalentes: vnetsniffer/VMnet0 ≈ VBoxManage nictrace; Independent Nonpersistent ≈ disco inmutable |
| 2 | DumpIt falla (0xC0000428, firma de driver en Win7) | Se usa WinPmem como alternativa; fallo documentado |
| 3 | respuesta-en-vivo.ps1 falla (PS 2.0 sin -in) | Datos volátiles recogidos con comandos nativos cmd |
| 4 | Velociraptor: not a valid Win32 application (Win7) | Sin triaje estructurado; se documentan datos volátiles manuales |
| 5 | KAPE no disponible en el kit | Sin triaje KAPE |
| 6 | chkdsk del USB por volumen sucio | Documentado; corrupción ajena al kit |
| 7 | Primer Guymager: Aborted – Image verify error | Reintento en disco virtual persistente; verificación OK |
| 8 | $MFT en vivo: copia fallida | $MFT obtenido de la imagen E01 |
| 9 | No hay segundo pendrive | Profesor autorizó usar el mismo Philips UFD; documentado |
| 10 | Marca en pendrive creada desde host (VM apagada) | Contenido idéntico al fichero original; documentado en acta |
