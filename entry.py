import os
import base64
import json
import dataclasses
from dataclasses import dataclass
from urllib.parse import urlparse

import docker

DOCKER_IMAGE = "secsi/ffuf:latest"

HTTPS_PORTS = {443, 8443}


@dataclass
class SubProcessResult:
    path:     str
    status:   int
    size:     int
    words:    int
    lines:    int
    redirect: str = ""
    base_url: str = ""   # URL de base du scan (ex: http://10.105.1.69:3000)


# ── Helpers accès dataclass-ou-dict ──────────────────────────────────────────

def _get(obj, key, default=None):
    """Lit une clé sur un dict ou un attribut sur un objet."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _svc_to_dict(svc) -> dict:
    """Normalise un service (dataclass ou dict) en dict pur."""
    if isinstance(svc, dict):
        return svc
    if dataclasses.is_dataclass(svc) and not isinstance(svc, type):
        return dataclasses.asdict(svc)
    if hasattr(svc, "__dict__"):
        return vars(svc)
    return {}


def _extract_host_from_services(services: list) -> str:
    """
    Extrait l'adresse IP/host depuis la sortie nmap quand target n'est pas fourni
    directement. Cherche dans les scripts ou dans un attribut 'host' éventuel.
    Retourne une string vide si introuvable.
    """
    # Les objets Service nmap ne stockent pas l'IP — elle est sur l'hôte nmap,
    # pas sur le port. On ne peut donc pas la récupérer depuis les services.
    # Cette fonction est un guard : elle retourne "" pour forcer l'erreur claire.
    return ""


# ── Normalisation de la cible ─────────────────────────────────────────────────

def normalize_targets(host: str, services: list | None = None) -> list[str]:
    """
    Construit la liste d'URLs ffuf depuis :
      - host  : IP ou domaine pur (ex: "10.105.1.69" ou "example.com")
                Une URL complète est renvoyée telle quelle avec /FUZZ.
      - services : liste de services nmap (dicts ou dataclasses Service).
                   On ne retient que les ports http/https pour construire les URLs.
                   Sans services → fallback sur les ports courants.
    """
    host = host.strip()

    # URL complète → une seule cible
    parsed = urlparse(host)
    if parsed.scheme in ("http", "https"):
        return [host.rstrip("/") + "/FUZZ" if "FUZZ" not in host else host]

    # host:port explicite
    if "://" not in host and ":" in host:
        parts = host.rsplit(":", 1)
        if parts[1].isdigit():
            h, p = parts[0], int(parts[1])
            scheme = "https" if p in HTTPS_PORTS else "http"
            return [f"{scheme}://{h}:{p}/FUZZ"]

    # Ports web depuis les services nmap
    targets = []
    if services:
        for svc in services:
            d    = _svc_to_dict(svc)
            name = d.get("name", "")
            port = d.get("port")
            if name in ("http", "https") and port:
                scheme = "https" if name == "https" or port in HTTPS_PORTS else "http"
                targets.append(f"{scheme}://{host}:{port}/FUZZ")

    if targets:
        return targets

    # Fallback : ports courants
    for port in [80, 8080, 8000, 8888, 3000, 4000, 5000]:
        targets.append(f"http://{host}:{port}/FUZZ")
    for port in [443, 8443]:
        targets.append(f"https://{host}:{port}/FUZZ")

    return targets


# ── Parsing ffuf ──────────────────────────────────────────────────────────────

def decode_ffuf_path(value: str) -> str:
    try:
        return base64.b64decode(value).decode("utf-8")
    except Exception:
        return value


def parse_ffuf(output: str, base_url: str = "") -> list[SubProcessResult]:
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item     = json.loads(line)
            fuzz_raw = item.get("input", {}).get("FUZZ", "")
            fuzz     = decode_ffuf_path(fuzz_raw)
            results.append(SubProcessResult(
                path     = fuzz,
                status   = int(item.get("status", 0)),
                size     = item.get("length", 0),
                words    = item.get("words", 0),
                lines    = item.get("lines", 0),
                redirect = item.get("redirectlocation", ""),
                base_url = base_url,
            ))
        except Exception as e:
            print(f"[ffuf] Failed parsing line: {e}")
    return results


# ── Docker ────────────────────────────────────────────────────────────────────

def run_ffuf(client, target_url: str, wordlist_container: str, volumes: dict) -> list[SubProcessResult]:
    print(f"[ffuf] → ffuf -u {target_url} -w {wordlist_container} -json")
    container = client.containers.run(
        image        = DOCKER_IMAGE,
        command      = ["-u", target_url, "-w", wordlist_container, "-json"],
        volumes      = volumes,
        remove       = False,
        detach       = True,
        network_mode = "host",
    )
    container.wait()
    stdout = container.logs(stdout=True,  stderr=False).decode("utf-8")
    stderr = container.logs(stdout=False, stderr=True).decode("utf-8")
    container.remove()

    # ffuf écrit sa bannière sur stderr — on ne l'affiche qu'en cas d'erreur réelle
    stderr_clean = "\n".join(
        l for l in stderr.splitlines()
        if l.strip() and not set(l.strip()).issubset(set(r"/'\_,. "))
    )
    if stderr_clean:
        print(f"[ffuf] stderr: {stderr_clean[:300]}")

    # base_url = URL sans /FUZZ pour l'affichage dans le rapport
    base_url = target_url.replace("/FUZZ", "")
    return parse_ffuf(stdout, base_url=base_url)


# ── Print ─────────────────────────────────────────────────────────────────────

def print_results(results: list[SubProcessResult]) -> None:
    print("\n#-----------------------------------------")
    print("  > Résultats du scan ffuf :")
    print("#-----------------------------------------\n")
    for r in results:
        print(f"  [{r.status}] /{r.path}  ({r.size}B, {r.words}w, {r.lines}l)"
              + (f"  → {r.redirect}" if r.redirect else ""))
    if not results:
        print("  Aucun chemin trouvé.")
    print()


# ── Point d'entrée Argos ──────────────────────────────────────────────────────

def main(args: dict) -> list[SubProcessResult]:
    """
    Args attendus :
      {
        "target":      "10.105.1.69"       # IP, domaine, IP:port ou URL complète
        "wordlist":    "C:\\...\\fuzz.txt" # chemin absolu hôte
        "permutation": "False"             # ignoré pour l'instant
        "services":    [...]               # optionnel — sortie nmap (Service ou dict)
      }
    """
    target   = args.get("target",   "")
    wordlist = args.get("wordlist", "")
    services = args.get("services") or []

    # Robustesse : le moteur peut injecter une liste au lieu d'un scalaire
    if isinstance(target,   list): target   = target[0]   if target   else ""
    if isinstance(wordlist, list): wordlist = wordlist[0] if wordlist else ""
    if isinstance(services, dict): services = [services]

    # Si target est un objet Service (ou une liste de Services) passé par erreur
    # depuis $Nmap scan.output, on extrait l'IP depuis le premier service nmap disponible.
    # La vraie correction est dans le workflow (utiliser $inputs.domaine), mais on
    # gère le cas gracieusement ici aussi.
    target_str = str(target).strip()
    if target_str.startswith("Service(") or (
        not target_str.startswith("http") and "port=" in target_str
    ):
        print("[ffuf] WARN: target reçu = objet Service. Extraction de l'IP depuis services nmap.")
        target_str = _extract_host_from_services(services) or ""
        if not target_str:
            print("[ffuf] ERROR: Impossible d'extraire l'IP. Passe $inputs.domaine comme target dans le workflow.")
            return []

    target   = target_str
    wordlist = str(wordlist).strip()

    if not target:
        print("[ffuf] ERROR: No target provided.")
        return []
    if not wordlist:
        print("[ffuf] ERROR: No wordlist provided.")
        return []

    # Résolution des URLs — on passe les services pour détecter les ports web
    target_urls = normalize_targets(target, services)
    print(f"[ffuf] Cibles résolues ({len(target_urls)}) :")
    for u in target_urls:
        print(f"  {u}")

    # Montage de la wordlist
    wordlist_host_dir  = os.path.abspath(os.path.dirname(wordlist))
    wordlist_filename  = os.path.basename(wordlist)
    wordlist_container = f"/wordlists/{wordlist_filename}"
    volumes = {wordlist_host_dir: {"bind": "/wordlists", "mode": "ro"}}

    client      = docker.from_env()
    all_results: list[SubProcessResult] = []

    for url in target_urls:
        results = run_ffuf(client, url, wordlist_container, volumes)
        all_results.extend(results)

    print_results(all_results)
    return all_results


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        main({"target": sys.argv[1], "wordlist": sys.argv[2]})
    else:
        print("Usage: python entry.py <target> <wordlist_path>")
        print("  target : IP, IP:port, http://IP:port, domaine.com")