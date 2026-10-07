#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HashTriageVT
------------
Herramienta de triage automatizado de archivos para Linux.
Calcula el SHA-256, obtiene la API Key desde un archivo cifrado con GPG,
consulta la API v3 de VirusTotal y genera un reporte en texto plano.

La API Key se guarda cifrada con GPG (AES256) y se solicita la
passphrase cada vez que el programa la necesita.
"""

import sys
import os
import subprocess
import hashlib
import datetime

NOMBRE_HERRAMIENTA = "HashTriageVT"
VERSION = "1.0.0"

CONFIG_DIR = os.path.expanduser("~/.config/hashtriagevt")
API_KEY_FILE = os.path.join(CONFIG_DIR, "api.key.gpg")


# ---------------------------------------------------------
# 0. Utilidades básicas
# ---------------------------------------------------------
def clear_screen():
    """Limpia la pantalla de la terminal."""
    subprocess.run(["clear"], check=False)


def pausa(mensaje="Presioná Enter para continuar..."):
    """Pausa hasta que el usuario presione Enter."""
    input(f"\n{mensaje}")


def mostrar_logo():
    """Muestra el logo ASCII de HashTriageVT con colores."""
    VERDE = "\033[92m"
    ROJO = "\033[91m"
    RESET = "\033[0m"

    logo_lineas = [
        "  ██╗  ██╗ █████╗ ███████╗██╗  ██╗████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗██╗   ██╗████████╗",
        "  ██║  ██║██╔══██╗██╔════╝██║  ██║╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝██║   ██║╚══██╔══╝",
        "  ███████║███████║███████╗███████║   ██║   ██████╔╝██║███████║██║  ███╗█████╗  ██║   ██║   ██║",
        "  ██╔══██║██╔══██║╚════██║██╔══██║   ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝  ╚██╗ ██╔╝   ██║",
        "  ██║  ██║██║  ██║███████║██║  ██║   ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗ ╚████╔╝    ██║",
        "  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ╚═══╝     ╚═╝",
    ]

    print()
    for i, linea in enumerate(logo_lineas):
        color = VERDE if i % 2 == 0 else ROJO
        print(f"{color}{linea}{RESET}")
    print()
    print(f"  {VERDE}HashTriageVT{RESET} {ROJO}{VERSION}{RESET}")
    print(f"  {VERDE}Triage de archivos: SHA-256 + VirusTotal{RESET}")
    print()


# ---------------------------------------------------------
# 1. Verificación e instalación de dependencias
# ---------------------------------------------------------
def asegurar_dependencias():
    """Comprueba que 'requests', 'gpg' y 'pinentry' estén instalados."""
    # --- 1. Python: requests ---
    try:
        import requests  # noqa: F401
    except ImportError:
        print(f"[!] {NOMBRE_HERRAMIENTA}: falta la dependencia 'requests'.")
        print("[*] Se instalará con: sudo pacman -S python-requests --noconfirm")
        print("[*] Se te pedirá la contraseña de root.\n")
        try:
            subprocess.run(
                ["sudo", "pacman", "-S", "python-requests", "--noconfirm"],
                check=True
            )
            print("\n[+] 'requests' instalado correctamente.\n")
        except subprocess.CalledProcessError:
            print("[X] La instalación falló. Instalalo manualmente:")
            print("    sudo pacman -S python-requests")
            sys.exit(1)

    # --- 2. Sistema: gpg y pinentry ---
    for paquete in ["gnupg", "pinentry"]:
        r = subprocess.run(
            ["pacman", "-Q", paquete],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"[!] Falta el paquete '{paquete}'.")
            print(f"[*] Se instalará con: sudo pacman -S {paquete} --noconfirm")
            print("[*] Se te pedirá la contraseña de root.\n")
            try:
                subprocess.run(
                    ["sudo", "pacman", "-S", paquete, "--noconfirm"],
                    check=True
                )
                print(f"\n[+] '{paquete}' instalado correctamente.\n")
            except subprocess.CalledProcessError:
                print(f"[X] La instalación falló. Instalalo manualmente:")
                print(f"    sudo pacman -S {paquete}")
                sys.exit(1)


asegurar_dependencias()
import requests  # noqa: E402


# ---------------------------------------------------------
# 2. Gestión de la API Key cifrada con GPG
# ---------------------------------------------------------
def api_key_existe():
    """Devuelve True si el archivo cifrado con la API Key existe."""
    return os.path.isfile(API_KEY_FILE)


def validar_api_key(api_key):
    """Valida la API Key haciendo una consulta de prueba a VirusTotal.
    Devuelve True si es válida, False si no."""
    hash_prueba = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    url = f"https://www.virustotal.com/api/v3/files/{hash_prueba}"
    headers = {"x-apikey": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=30)
    except requests.exceptions.RequestException:
        print("\n[!] No se pudo conectar con VirusTotal para validar la clave.")
        print("    Verificá tu conexión a internet.")
        return False

    if r.status_code == 200:
        return True
    elif r.status_code == 401:
        return False
    elif r.status_code == 429:
        print("\n[!] Límite de peticiones alcanzado durante la validación.")
        print("    Esperá un minuto y volvé a intentar.")
        return False
    else:
        return False


def guardar_api_key():
    """Pide la API Key, la valida contra VirusTotal y la guarda cifrada con GPG."""
    os.makedirs(CONFIG_DIR, exist_ok=True)

    clear_screen()
    mostrar_logo()
    print(" No se encontró una API Key guardada.")
    print(" Vamos a guardarla cifrada con GPG (AES256).")
    print()
    print(" Obtené una API Key gratuita en:")
    print("   https://www.virustotal.com/gui/my-apikey")
    print()
    pausa("Presioná Enter para continuar...")

    # ---- Bucle de validación de la API Key ----
    api_key = None
    while True:
        clear_screen()
        mostrar_logo()
        print(" PASO 1: API KEY DE VIRUSTOTAL")
        print()
        print(" Pegá tu API Key de VirusTotal.")
        print(" El script va a verificar que sea válida antes de guardarla.")
        print()
        entrada = input("API Key: ").strip()
        if not entrada:
            print("[X] No ingresaste nada. Intentá de nuevo.")
            pausa()
            continue

        print("\n[*] Validando la API Key contra VirusTotal...")
        if validar_api_key(entrada):
            print("[+] API Key válida.")
            api_key = entrada
            break
        else:
            print("\n[X] La API Key no es válida o fue rechazada por VirusTotal.")
            print("    Verificá que la copiaste completa y sin espacios extra.")
            print("    Podés obtener una en: https://www.virustotal.com/gui/my-apikey")
            print()
            reintentar = input("¿Intentar de nuevo? [S/n]: ").strip().lower()
            if reintentar in ("n", "no"):
                print("[i] Saliendo.")
                sys.exit(1)

    # ---- Guardar cifrada con GPG ----
    clear_screen()
    mostrar_logo()
    print(" PASO 2: PASSPHRASE DE CIFRADO")
    print()
    print(" A continuación, GPG te solicitará una passphrase dos veces.")
    print(" Esa passphrase es la que vas a usar para descifrar la API Key.")
    print()
    pausa("Presioná Enter para que GPG te pida la passphrase...")

    try:
        proc = subprocess.run(
            [
                "gpg", "--symmetric",
                "--cipher-algo", "AES256",
                "--batch", "--yes",
                "-o", API_KEY_FILE
            ],
            input=api_key.encode("utf-8"),
            check=False
        )
        if proc.returncode != 0:
            print("\n[X] GPG falló al cifrar. Verificá que esté bien instalado.")
            sys.exit(1)
    except FileNotFoundError:
        print("[X] No se encontró 'gpg'. Instalalo con:")
        print("    sudo pacman -S gnupg")
        sys.exit(1)

    # Verificar que el archivo se creó
    if not os.path.isfile(API_KEY_FILE):
        print("\n[X] El archivo cifrado no se creó correctamente.")
        sys.exit(1)

    # Asegurar permisos restrictivos
    try:
        os.chmod(API_KEY_FILE, 0o600)
    except Exception:
        pass

    print("\n[+] API Key validada y guardada cifrada correctamente.")
    pausa()


def obtener_api_key():
    """Descifra y devuelve la API Key usando GPG.
    Si la passphrase es incorrecta, avisa y permite reintentar."""
    while True:
        print("[*] Descifrando API Key con GPG...")
        print("    (Se te va a pedir la passphrase.)")
        try:
            r = subprocess.run(
                ["gpg", "--quiet", "--decrypt", API_KEY_FILE],
                capture_output=True, text=True, timeout=120
            )
        except FileNotFoundError:
            print("[X] No se encontró 'gpg'. Instalalo con:")
            print("    sudo pacman -S gnupg")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print("[X] Tiempo de espera agotado esperando la passphrase.")
            sys.exit(1)

        if r.returncode == 0 and r.stdout.strip():
            print("[+] API Key descifrada correctamente.")
            return r.stdout.strip()

        # Si llegamos acá, GPG falló. Puede ser passphrase incorrecta o cancelación.
        print()
        print("[X] No se pudo descifrar la API Key.")
        print("    Posibles causas:")
        print("      - La passphrase ingresada es incorrecta.")
        print("      - Cancelaste el diálogo de GPG.")
        print()
        reintentar = input("¿Reintentar? [s/N]: ").strip().lower()
        if reintentar not in ("s", "si", "sí", "y", "yes"):
            print("[i] Saliendo.")
            sys.exit(1)

        # Matar el agente para forzar que vuelva a pedir la passphrase
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False)
        clear_screen()
        mostrar_logo()


# ---------------------------------------------------------
# 3. Funciones de triage
# ---------------------------------------------------------
def calcular_sha256(ruta):
    """Calcula el SHA-256 del archivo leyéndolo por bloques (4 KB)."""
    sha = hashlib.sha256()
    try:
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(4096), b""):
                sha.update(bloque)
    except FileNotFoundError:
        print(f"[X] Archivo no encontrado: {ruta}")
        sys.exit(1)
    except PermissionError:
        print(f"[X] Sin permisos para leer: {ruta}")
        sys.exit(1)
    return sha.hexdigest()


def info_archivo(ruta):
    """Devuelve tamaño legible y fecha de modificación."""
    try:
        st = os.stat(ruta)
        tamaño = st.st_size
        for unidad in ["B", "KB", "MB", "GB", "TB"]:
            if tamaño < 1024:
                tamaño_str = f"{tamaño:.2f} {unidad}"
                break
            tamaño /= 1024
        fecha_mod = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        tamaño_str, fecha_mod = "Desconocido", "Desconocida"
    return tamaño_str, fecha_mod


def consultar_virustotal(hash_sha256, api_key):
    """Consulta la API v3 de VirusTotal por hash. Devuelve (status, data)."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_sha256}"
    headers = {"x-apikey": api_key}

    try:
        r = requests.get(url, headers=headers, timeout=30)
    except requests.exceptions.RequestException as e:
        return "error_red", str(e)

    if r.status_code == 200:
        return "ok", r.json()
    elif r.status_code == 404:
        return "no_encontrado", None
    elif r.status_code == 401:
        return "api_invalida", None
    elif r.status_code == 429:
        return "limite", None
    else:
        return "error", f"HTTP {r.status_code}: {r.text[:200]}"


def construir_reporte(ruta, hash_sha256, status, data):
    """Devuelve el contenido del reporte como string."""
    nombre = os.path.basename(ruta)
    ruta_abs = os.path.abspath(ruta)
    tamaño_str, fecha_mod = info_archivo(ruta)
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lineas = []
    lineas.append("=" * 64)
    lineas.append(f"  REPORTE DE TRIAGE — {NOMBRE_HERRAMIENTA} v{VERSION}")
    lineas.append("=" * 64)
    lineas.append(f"Nombre del archivo : {nombre}")
    lineas.append(f"Ruta absoluta      : {ruta_abs}")
    lineas.append(f"Tamaño             : {tamaño_str}")
    lineas.append(f"Fecha de modif.    : {fecha_mod}")
    lineas.append(f"Fecha del triage   : {ahora}")
    lineas.append(f"Hash SHA-256       : {hash_sha256}")
    lineas.append("-" * 64)

    if status == "no_encontrado":
        lineas.append("RESULTADO: Hash libre de coincidencias asociadas a Malware.")
        lineas.append("(VirusTotal no tiene registro previo de este hash.)")

    elif status == "ok":
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless

        lineas.append("RESULTADO VIRUSTOTAL:")
        lineas.append(f"  Detecciones maliciosas : {malicious}/{total}")
        lineas.append(f"  Sospechosas            : {suspicious}/{total}")
        lineas.append(f"  No detectadas          : {undetected}/{total}")
        lineas.append(f"  Inofensivas            : {harmless}/{total}")

        names = attrs.get("names", [])
        if names:
            lineas.append("")
            lineas.append("Nombres reportados:")
            for n in names[:5]:
                lineas.append(f"  - {n}")

        lineas.append("")
        if malicious > 0 or suspicious > 0:
            lineas.append("VEREDICTO: [!] MALWARE / SOSPECHOSO DETECTADO")
        else:
            lineas.append("VEREDICTO: [OK] Sin detecciones maliciosas")

        resultados = attrs.get("last_analysis_results", {})
        detectores = [
            (motor, info.get("result", "N/A"))
            for motor, info in resultados.items()
            if info.get("category") in ("malicious", "suspicious")
        ]
        if detectores:
            lineas.append("")
            lineas.append("Motores que lo detectan:")
            for motor, nombre_mal in detectores:
                lineas.append(f"  - {motor:<15}: {nombre_mal}")

    else:
        lineas.append("RESULTADO: No se pudo completar la consulta.")
        lineas.append(f"Detalle: {data}")

    lineas.append("=" * 64)
    lineas.append(f"Fin del reporte — {NOMBRE_HERRAMIENTA}")
    lineas.append("=" * 64)
    return "\n".join(lineas)


# ---------------------------------------------------------
# 4. Flujo principal
# ---------------------------------------------------------
def main():
    clear_screen()

    # ---- Configuración inicial ----
    if not api_key_existe():
        guardar_api_key()

    # ---- Banner ----
    clear_screen()
    mostrar_logo()

    # ---- Pedir ruta ----
    ruta = input("\nRuta del archivo a triar: ").strip().strip("'\"")
    if not ruta:
        print("[X] No ingresaste ninguna ruta.")
        sys.exit(1)

    ruta = os.path.expanduser(os.path.expandvars(ruta))
    if not os.path.isfile(ruta):
        print(f"[X] No es un archivo válido: {ruta}")
        sys.exit(1)

    # ---- Obtener API Key (pide passphrase, permite reintentar) ----
    clear_screen()
    mostrar_logo()
    api_key = obtener_api_key()

    # ---- Calcular hash ----
    clear_screen()
    mostrar_logo()
    print("[*] Calculando SHA-256...")
    hash_sha256 = calcular_sha256(ruta)
    print(f"[+] SHA-256: {hash_sha256}")

    # ---- Consultar VT ----
    print("\n[*] Consultando VirusTotal...")
    status, data = consultar_virustotal(hash_sha256, api_key)

    if status == "api_invalida":
        print("[X] API Key inválida o expirada.")
        sys.exit(1)
    if status == "limite":
        print("[X] Límite de consultas alcanzado (4 por minuto en cuenta gratuita de VirusTotal). Espere 1 minuto y reintente")
        sys.exit(1)
    if status == "error_red":
        print(f"[X] Error de red: {data}")
        sys.exit(1)
    if status == "error":
        print(f"[X] Error inesperado: {data}")
        sys.exit(1)

    # ---- Mostrar reporte ----
    clear_screen()
    mostrar_logo()
    reporte = construir_reporte(ruta, hash_sha256, status, data)
    print(reporte)

    # ---- Guardar reporte ----
    print()
    guardar = input("¿Guardar el reporte en un .txt? [s/N]: ").strip().lower()
    if guardar in ("s", "si", "sí", "y", "yes"):
        nombre_base = os.path.splitext(os.path.basename(ruta))[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        archivo_salida = f"HashTriageVT_{nombre_base}_{timestamp}.txt"
        try:
            with open(archivo_salida, "w", encoding="utf-8") as f:
                f.write(reporte)
            print(f"[+] Reporte guardado en: {os.path.abspath(archivo_salida)}")
        except Exception as e:
            print(f"[X] No se pudo guardar el reporte: {e}")
    else:
        print("[i] Reporte no guardado. Saliendo.")

    # ---- Matar el agente GPG ----
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[i] Cancelado por el usuario.")
        sys.exit(0)