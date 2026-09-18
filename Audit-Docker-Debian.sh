#!/usr/bin/env bash
set -uo pipefail

# Nur-Lese-Audit-Runner fuer Checklist-Docker-Debian-Audit.md.
# Installations-, Login-, Pull-, Clone-, Build- und dienstveraendernde Kommandos werden nicht ausgefuehrt.

SCRIPT_NAME="$(basename "$0")"
OUT_DIR="${AUDIT_OUT_DIR:-./docker-audit-results-$(date +%Y%m%d-%H%M%S)}"
AUDIT_ROOT="${AUDIT_ROOT:-.}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
IMAGE_NAME="${IMAGE_NAME:-}"
IMAGE_REF="${IMAGE_REF:-}"
CONTAINER_NAME="${CONTAINER_NAME:-}"
REGISTRY_FQDN="${REGISTRY_FQDN:-}"
REPOSITORY="${REPOSITORY:-}"
RUN_OPTIONAL=0
FAILURES=0
SKIPS=0
COMMAND_INDEX=0
CURRENT_SECTION='00 Tool inventory'

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [--optional] [--out DIR]

Nur-Lese-Audit-Runner fuer Docker/Debian.

Das Ausgabeverzeichnis enthaelt audit.log, commands/*.txt (eine Datei je Pruefung)
und cis-results.tsv (PASS/FAIL/SKIP mit CIS-Kontext).

Umgebungsvariablen fuer eingegrenzte Pruefungen:
  AUDIT_ROOT       Repository- oder Compose-Wurzel (Standard: .)
  COMPOSE_FILE     Compose-Datei (Standard: docker-compose.yml)
  IMAGE_NAME       Lokale Image-Referenz fuer Image-/SBOM-Pruefungen
  IMAGE_REF        Registry-Image-Referenz fuer Signatur-/Provenienz-Pruefungen
  CONTAINER_NAME   Container fuer Laufzeitpruefungen
  REGISTRY_FQDN    Registry-Hostname fuer Registry-Pruefungen
  REPOSITORY       Registry-Repository fuer Crane-Pruefungen

Examples:
  # Standardlauf, Ausgabe unter ./docker-audit-results-<timestamp>
  ./$SCRIPT_NAME

  # Pruefungen auf ein Projekt und dessen Compose-Datei eingrenzen, festes Ausgabeverzeichnis
  AUDIT_ROOT=/srv/app COMPOSE_FILE=/srv/app/docker-compose.yml \
    ./$SCRIPT_NAME --out /tmp/audit-app

  # Image-, Registry- und Container-Pruefungen sowie optionale Tools einschliessen
  IMAGE_NAME=myapp:1.2.3 IMAGE_REF=registry.example.com/myapp:1.2.3 \\
    CONTAINER_NAME=myapp REGISTRY_FQDN=registry.example.com REPOSITORY=myapp \\
    ./$SCRIPT_NAME --optional
EOF
}

while (($# > 0)); do
  case "$1" in
    --optional) RUN_OPTIONAL=1 ;;
    --out)
      shift
      (($# > 0)) || { echo "Fehlender Wert fuer --out" >&2; exit 2; }
      OUT_DIR="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unbekanntes Argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

# Schnappschuss, damit ein Bereinigungsdurchlauf am Ende versehentlich hier abgelegte Fremdverzeichnisse erkennen kann.
INVOCATION_DIR=$(pwd -P)
mapfile -t PRE_EXISTING_DIRS < <(find "$INVOCATION_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null)

if ! mkdir -p "$OUT_DIR"; then
  echo "Ausgabeverzeichnis kann nicht angelegt werden: $OUT_DIR" >&2
  exit 1
fi
OUT_DIR=$(cd "$OUT_DIR" && pwd -P)
LOG_FILE="$OUT_DIR/audit.log"
COMMAND_DIR="$OUT_DIR/commands"
RESULTS_FILE="$OUT_DIR/cis-results.tsv"
if ! mkdir -p "$COMMAND_DIR"; then
  echo "Kommando-Ausgabeverzeichnis kann nicht angelegt werden: $COMMAND_DIR" >&2
  exit 1
fi
printf 'id\tstatus\tsection\tcommand\toutput_file\tcis_control\n' > "$RESULTS_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# Cache- und State-Dateien von Scanner-/CLI-Tools weder in OUT_DIR (das nur die Audit-Ergebnisse enthalten soll)
# noch im Aufrufverzeichnis ablegen (Ursache des urspruenglichen ./log-Lecks); stattdessen ein beim Beenden entferntes Scratch-Verzeichnis nutzen.
TOOL_CACHE_DIR=$(mktemp -d)
trap 'rm -rf "$TOOL_CACHE_DIR"' EXIT
export XDG_CACHE_HOME="$TOOL_CACHE_DIR/cache"
export XDG_DATA_HOME="$TOOL_CACHE_DIR/data"
export XDG_STATE_HOME="$TOOL_CACHE_DIR/state"
export TRIVY_CACHE_DIR="$XDG_CACHE_HOME/trivy"
mkdir -p "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"

# Sicherheitsnetz: entfernt jedes neue, noch leere Verzeichnis, das ein Tool im Aufrufverzeichnis hinterlassen hat.
cleanup_stray_dirs() {
  local dir_name is_preexisting entry
  while IFS= read -r dir_name; do
    [[ "$INVOCATION_DIR/$dir_name" == "$OUT_DIR" ]] && continue
    is_preexisting=0
    for entry in "${PRE_EXISTING_DIRS[@]:-}"; do
      [[ "$entry" == "$dir_name" ]] && { is_preexisting=1; break; }
    done
    ((is_preexisting)) && continue
    if [[ -d "$INVOCATION_DIR/$dir_name" && -z "$(ls -A "$INVOCATION_DIR/$dir_name" 2>/dev/null)" ]]; then
      rmdir "$INVOCATION_DIR/$dir_name" 2>/dev/null \
        && printf 'HINWEIS: leeres Fremdverzeichnis eines externen Tools entfernt: %s\n' "$INVOCATION_DIR/$dir_name"
    fi
  done < <(find "$INVOCATION_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null)
}

# Protokolliert einen Abbruch, statt den laufenden 'run'-Befehl mitten in der Pruefung stillschweigend sterben zu lassen.
on_interrupt() {
  local signal="$1"
  printf '\nABGEBROCHEN: Audit-Lauf hat Signal %s erhalten, wird nach der laufenden Pruefung beendet\n' "$signal"
  exit $((128 + $(kill -l "$signal")))
}
trap 'on_interrupt INT' INT
trap 'on_interrupt TERM' TERM

timestamp() { date -Is 2>/dev/null || date; }
section() { CURRENT_SECTION="$1"; printf '\n===== %s [%s] =====\n' "$1" "$(timestamp)"; }

have() { command -v "$1" >/dev/null 2>&1; }

cis_context() {
  case "$CURRENT_SECTION" in
    0.*|1.*) printf 'CIS 1 Host-Konfiguration' ;;
    2.*) printf 'CIS 1 Host-Konfiguration' ;;
    3.*) printf 'CIS 1 Host-Konfiguration / CIS 2 Daemon-Konfiguration / CIS 3 Konfigurationsdateien' ;;
    4.*) printf 'CIS 2 Daemon-Konfiguration / CIS 5 Container-Laufzeit' ;;
    5.*) printf 'CIS 5 Container-Laufzeit / CIS 6 Sicherheitsbetrieb' ;;
    6.*) printf 'CIS 4 Images und Build-Dateien' ;;
    7.*) printf 'CIS 4 Images / CIS 6 Sicherheitsbetrieb' ;;
    8.*) printf 'CIS 6 Sicherheitsbetrieb' ;;
    9.*) printf 'CIS 4 Images und Build-Dateien' ;;
    *) printf 'CIS Docker Benchmark: gegen die gewaehlte Version pruefen' ;;
  esac
}

# Kontrolle/Titel je CIS-Docker-Benchmark-Check, ersetzt den groben Section-Fallback oben.
declare -A CIS_CONTROLS=(
  ['Available commands']='Voraussetzung - Tool-Inventar fuer nachfolgende CIS-Pruefungen'
  ['Docker version']='CIS 1.1.2 - Sicherstellen, dass eine unterstuetzte Docker-Version verwendet wird'
  ['Compose version']='Voraussetzung - Versionsinventar des Compose-Plugins'
  ['Buildx version']='Voraussetzung - Versionsinventar des Buildx-Plugins'
  ['containerd version']='Voraussetzung - Versionsinventar von containerd'
  ['runc version']='Voraussetzung - Versionsinventar von runc'
  ['Hostname']='CIS 1 - Host-Konfiguration, Asset-Identifikation'
  ['OS release']='CIS 1.1.1 - Sicherstellen, dass der Container-Host gehaertet wurde (OS-Baseline)'
  ['Kernel']='CIS 1.1.1 - Linux-Kernelversion zur Pruefung der Host-Haertung'
  ['Container inventory']='CIS 1 - Host-Konfiguration, Inventar (Container, Images, Volumes, Netzwerke)'
  ['Docker configuration files']='CIS 3 - Auffinden der Docker-Daemon-Konfigurationsdateien'
  ['Upgradeable packages']='CIS 1.1.2 - Sicherstellen, dass Container-Host und Docker aktuell gehalten werden'
  ['Docker package policy']='CIS 1.1.2 - Sicherstellen, dass Docker aus einer vertrauenswuerdigen, aktuellen Quelle installiert ist'
  ['Unattended upgrades service']='CIS 1.1.2 - Sicherstellen, dass Sicherheitsupdates des Betriebssystems automatisch eingespielt werden'
  ['APT unattended-upgrade configuration']='CIS 1.1.2 - Konfiguration der automatischen Sicherheitsupdates'
  ['Running services']='CIS 1.1.3 - Laufende Dienste auf dem Container-Host minimieren'
  ['Listening ports']='CIS 1.1.3 - Netzwerkexposition des Container-Hosts einschraenken'
  ['Open network files']='CIS 1.1.3 - Offene Netzwerk-Sockets von Host-Prozessen pruefen'
  ['Firewall rules']='CIS 1.1.3 - Sicherstellen, dass die Host-Firewall unnoetigen Datenverkehr unterbindet'
  ['Kernel sysctls']='CIS 1.1.1 / 5.1 - Kernel-Haertungsparameter (userns, ASLR, kptr, dmesg, Forwarding, rp_filter)'
  ['AppArmor status']='CIS 5.1 - Sicherstellen, dass ein AppArmor-Profil aktiviert ist'
  ['Seccomp and cgroups']='CIS 5.21 / 5.29 - Standard-Seccomp-Profil und Cgroups-Nutzung'
  ['Docker package sources']='CIS 1.1.2 - Sicherstellen, dass Docker aus einer vertrauenswuerdigen, aktuellen Quelle installiert ist'
  ['Docker service']='CIS 2 - Zustand des Docker-Daemon-Dienstes'
  ['Docker enabled state']='CIS 2 - Sicherstellen, dass docker.service wie vorgesehen beim Systemstart aktiviert ist'
  ['Docker unit']='CIS 3.1 / 3.2 - Sicherstellen, dass Eigentuemer und Rechte von docker.service korrekt sind'
  ['Docker journal']='CIS 6.1 - Sicherstellen, dass Audit-Logging fuer den Docker-Daemon konfiguriert ist'
  ['Daemon configuration']='CIS 2.11 / 2.12 - Sicherstellen, dass daemon.json existiert und auf Sicherheitsoptionen geprueft wurde'
  ['Daemon baseline fields']='CIS 2.5 / 2.6 / 2.14 / 2.15 - log-driver, userns-remap, no-new-privileges, live-restore, icc, iptables, hosts'
  ['Docker socket and API']='CIS 2.1 - Sicherstellen, dass der Docker-Daemon nicht ungesichert per TCP ohne TLS erreichbar ist'
  ['Docker config permissions']='CIS 3.1-3.9 - Eigentuemer und Rechte der Docker-Daemon-Konfigurationsdateien'
  ['Docker socket permissions']='CIS 3.3 - Sicherstellen, dass Eigentuemer und Rechte von docker.socket korrekt sind'
  ['TLS and authorization']='CIS 2.7 / 2.8 - Konfiguration von TLS-Authentifizierung und Autorisierungs-Plugin'
  ['Docker access']='CIS 2 - Sicherstellen, dass nur vertrauenswuerdige Benutzer den Docker-Daemon steuern koennen (docker-Gruppenmitglieder)'
  ['Rootless and user namespaces']='CIS 2.6 / 5.29 - Rootless-Modus und userns-remap'
  ['Container runtime settings']='CIS 5.3-5.31 - Haertung der Container-Laufzeit (Capabilities, Privileged-Modus, Ressourcenlimits, Sicherheitsoptionen)'
  ['Compose security patterns']='CIS 5.5 / 5.9 / 5.19 - Sensible Host-Mounts, Host-Networking, docker.sock-Exposition in Compose-Dateien'
  ['Docker networks']='CIS 5.29 - Haertung der Docker-Netzwerkkonfiguration'
  ['Docker mounts and resources']='CIS 5.5 / 5.10 / 5.11 - Sensible Verzeichnis-Mounts und Ressourcenlimits'
  ['Ulimits']='CIS 5.28 - Sicherstellen, dass ein angemessenes Standard-Ulimit konfiguriert ist'
  ['Compose config']='CIS 4.10 / 5 - Rendern der Compose-Datei zur Pruefung von Secrets und Sicherheit'
  ['Compose services']='CIS 4.10 / 5 - Compose-Services zur Eingrenzung der Laufzeitpruefungen auflisten'
  ['Environment and secret patterns']='CIS 4.10 - Sicherstellen, dass Secrets nicht in Umgebungsvariablen oder Compose-Dateien liegen'
  ['Volume and filesystem state']='CIS 1.2 / 5.12 - Haertung von Docker-Storage-Treiber und Volume-Dateisystem'
  ['Sensitive file permissions']='CIS 3.1-3.9 - Rechte sensibler Dateien (Schluessel, Secrets, Zertifikate)'
  ['Image inventory and identities']='CIS 4 - Image-Inventar sowie Identitaets-/Digest-Pruefung'
  ['Dockerfile review']='CIS 4.1 / 4.6 / 4.9 / 4.10 - Nicht-root USER, HEALTHCHECK, COPY statt ADD, keine eingebetteten Secrets'
  ['Trivy image']='CIS 4.4 - Sicherstellen, dass Images gescannt und mit Sicherheitspatches neu gebaut werden'
  ['Grype image']='CIS 4.4 - Sicherstellen, dass Images auf bekannte Schwachstellen gescannt werden'
  ['Syft CycloneDX SBOM']='CIS 4 - Erstellung einer Software-Stueckliste (SBOM) zur Image-Herkunft'
  ['Syft SPDX SBOM']='CIS 4 - Erstellung einer Software-Stueckliste (SBOM) zur Image-Herkunft'
  ['Docker image healthcheck']='CIS 4.6 - Sicherstellen, dass HEALTHCHECK-Anweisungen in Container-Images vorhanden sind'
  ['Trivy config']='CIS 4 - Fehlkonfigurationspruefung von Dockerfiles und IaC'
  ['Trivy filesystem']='CIS 4 / 5 - Dateisystem-Scan auf Schwachstellen, Secrets und Fehlkonfigurationen'
  ['Cosign signature']='CIS 4.5 - Sicherstellen, dass Image-Signaturen/Content Trust aktiviert sind'
  ['Cosign tree']='CIS 4.5 - Signatur- und Attestierungsbaum zur Image-Herkunft pruefen'
  ['Cosign provenance']='CIS 4.5 - SLSA-Provenienz-Attestierung verifizieren'
  ['Notation inspect']='CIS 4.5 - Notation-Signaturen zur Image-Integritaet inspizieren'
  ['Notation verify']='CIS 4.5 - Notation-Signaturen zur Image-Integritaet verifizieren'
  ['Buildx manifest inspection']='CIS 4 - Integritaet der Multi-Arch-Manifestliste pruefen'
  ['Registry configuration']='CIS 2 - Sicherstellen, dass nur vertrauenswuerdige, sichere Registries konfiguriert sind'
  ['Registry configuration files']='CIS 2 - Sicherstellen, dass keine unsicheren Registries/Mirrors konfiguriert sind'
  ['Crane repository listing']='CIS 4 - Inventar der Registry-Repository-Inhalte'
  ['Skopeo image inspection']='CIS 4 - Remote-Image-Inspektion ohne Pull'
  ['Docker event history']='CIS 6.2 - Sicherstellen, dass Container-Ereignisse erfasst und ueberwacht werden'
  ['Docker daemon journal']='CIS 6.1 - Sicherstellen, dass Audit-Logging fuer den Docker-Daemon konfiguriert ist'
  ['Auditd status']='CIS 1.1.4 - Sicherstellen, dass Auditing fuer den Docker-Daemon konfiguriert ist'
  ['Auditd rules']='CIS 1.1.4 - Sicherstellen, dass Auditing fuer Docker-Dateien und -Verzeichnisse konfiguriert ist'
  ['Sudo journal']='CIS 6 - Sicherstellen, dass administrative Aktionen auf dem Docker-Host protokolliert werden'
  ['Timers and cron']='CIS 6 - Geplante Jobs mit Auswirkung auf den Docker-Host pruefen'
  ['Cron entries']='CIS 6 - Geplante Jobs mit Auswirkung auf den Docker-Host pruefen'
  ['Compose validation']='CIS 4 / 5 - Syntax der Compose-Datei vor der Sicherheitspruefung validieren'
  ['Hadolint Dockerfiles']='CIS 4.1-4.10 - Statische Analyse von Dockerfile-Best-Practices'
  ['Shellcheck scripts']='CIS 4 - Statische Analyse von Build-/Betriebs-Shellskripten'
  ['Yamllint YAML files']='CIS 4 / 5 - Statische Analyse der Compose-/Kubernetes-YAML-Syntax'
  ['Falco version']='CIS 6 - Verfuegbarkeit von Tooling zur Laufzeit-Bedrohungserkennung'
  ['Falco service']='CIS 6 - Dienststatus der Laufzeit-Bedrohungserkennung'
  ['Falco']='CIS 6 - Verfuegbarkeit von Tooling zur Laufzeit-Bedrohungserkennung'
  ['Docker Scout quickview']='CIS 4.4 - Sicherstellen, dass Images auf Schwachstellen gescannt werden (Docker Scout)'
  ['Docker Scout']='CIS 4.4 - Sicherstellen, dass Images auf Schwachstellen gescannt werden (Docker Scout)'
)

cis_lookup() {
  local name="$1"
  if [[ -n "${CIS_CONTROLS[$name]:-}" ]]; then
    printf '%s' "${CIS_CONTROLS[$name]}"
  else
    cis_context
  fi
}

tsv_escape() {
  local value="$1"
  value=${value//$'\t'/ }
  value=${value//$'\r'/ }
  value=${value//$'\n'/ }
  # Entfernt verbleibende Steuerzeichen (z. B. versehentliche ANSI-Escapes), damit der Import in Tabellenkalkulationen sauber bleibt.
  printf '%s' "$value" | tr -d '\000-\010\013\014\016-\037'
}

record_result() {
  local id="$1" status="$2" name="$3" output_file="$4" command_text="$5"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(tsv_escape "$id")" \
    "$(tsv_escape "$status")" \
    "$(tsv_escape "$CURRENT_SECTION")" \
    "$(tsv_escape "$command_text")" \
    "$(tsv_escape "$output_file")" \
    "$(tsv_escape "$(cis_lookup "$name")")" >> "$RESULTS_FILE"
}

command_output_file() {
  local name="$1" safe_name
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  safe_name=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//')
  printf '%s/%03d-%s.txt' "$COMMAND_DIR" "$COMMAND_INDEX" "${safe_name:-command}"
}

record_skip() {
  local name="$1" reason="$2" output_file
  output_file=$(command_output_file "$name")
  {
    printf 'PRUEFUNG: %s\n' "$name"
    printf 'CIS-KONTROLLE: %s\n' "$(cis_lookup "$name")"
    printf 'ABSCHNITT: %s\n' "$CURRENT_SECTION"
    printf 'STATUS: SKIP\n'
    printf 'GRUND: %s\n' "$reason"
  } > "$output_file"
  record_result "$COMMAND_INDEX" 'SKIP' "$name" "$output_file" "$reason"
  SKIPS=$((SKIPS + 1))
}

run() {
  local name="$1"
  local output_file command_text status
  shift
  output_file=$(command_output_file "$name")
  command_text=$(printf '%q ' "$@")
  printf '\n--- %s ---\n' "$name"
  printf 'AUSGABE: %s\n' "$output_file"
  {
    printf 'PRUEFUNG: %s\n' "$name"
    printf 'CIS-KONTROLLE: %s\n' "$(cis_lookup "$name")"
    printf 'ABSCHNITT: %s\n' "$CURRENT_SECTION"
    printf 'BEFEHL: %s\n' "$command_text"
    printf 'BEGINN: %s\n' "$(timestamp)"
    printf -- '----------------------------------------\n'
  } > "$output_file"
  "$@" >> "$output_file" 2>&1
  status=$?
  printf 'ENDE: %s\nEXIT_CODE: %s\n' "$(timestamp)" "$status" >> "$output_file"
  if ((status == 0)); then
    printf 'ERGEBNIS: PASS\n'
    record_result "$COMMAND_INDEX" 'PASS' "$name" "$output_file" "$command_text"
  else
    printf 'ERGEBNIS: FAIL (Exit-Code %s)\n' "$status"
    record_result "$COMMAND_INDEX" 'FAIL' "$name" "$output_file" "$command_text"
    FAILURES=$((FAILURES + 1))
  fi
  return 0
}

run_shell() {
  local name="$1"
  local command="$2"
  local output_file status
  output_file=$(command_output_file "$name")
  printf '\n--- %s ---\n%s\n' "$name" "$command"
  printf 'AUSGABE: %s\n' "$output_file"
  {
    printf 'PRUEFUNG: %s\n' "$name"
    printf 'CIS-KONTROLLE: %s\n' "$(cis_lookup "$name")"
    printf 'ABSCHNITT: %s\n' "$CURRENT_SECTION"
    printf 'BEFEHL: %s\n' "$command"
    printf 'BEGINN: %s\n' "$(timestamp)"
    printf -- '----------------------------------------\n'
  } > "$output_file"
  bash -o pipefail -c "$command" >> "$output_file" 2>&1
  status=$?
  printf 'ENDE: %s\nEXIT_CODE: %s\n' "$(timestamp)" "$status" >> "$output_file"
  if ((status == 0)); then
    printf 'ERGEBNIS: PASS\n'
    record_result "$COMMAND_INDEX" 'PASS' "$name" "$output_file" "$command"
  else
    printf 'ERGEBNIS: FAIL (Exit-Code %s)\n' "$status"
    record_result "$COMMAND_INDEX" 'FAIL' "$name" "$output_file" "$command"
    FAILURES=$((FAILURES + 1))
  fi
  return 0
}

require_command() {
  if have "$1"; then
    return 0
  fi
  printf 'SKIP: fehlendes Kommando: %s\n' "$1"
  record_skip "Voraussetzung $1" "Kommando nicht gefunden: $1"
  return 1
}

require_value() {
  local name="$1"
  local value="$2"
  if [[ -n "$value" ]]; then
    return 0
  fi
  printf 'SKIP: %s fuer diese Pruefung setzen\n' "$name"
  record_skip "Eingabe $name" "Umgebungsvariable ist leer: $name"
  return 1
}

run_as_root() {
  if ((EUID == 0)); then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    printf 'SKIP: Root-Rechte oder sudo erforderlich: %s\n' "$*"
    return 1
  fi
}

section '0. Tool-Inventar'
run_shell 'Available commands' 'for command_name in docker jq git curl ss lsof column lynis shellcheck yamllint skopeo trivy syft grype hadolint cosign crane aa-status auditctl; do printf "%-12s " "$command_name"; command -v "$command_name" || true; done'
run 'Docker version' docker version
run 'Docker info' docker info
run 'Compose version' docker compose version
run 'Buildx version' docker buildx version
run 'containerd version' containerd --version
run 'runc version' runc --version

section '1. Host und Inventar'
run 'Hostname' hostnamectl
run 'OS release' cat /etc/os-release
run 'Kernel' uname -a
run_shell 'Container inventory' 'docker ps --no-trunc; docker ps -a --no-trunc; docker images --digests; docker volume ls; docker network ls; docker system df -v; docker compose ls'
run_shell 'Docker configuration files' 'find /etc/docker -maxdepth 2 -type f -print 2>/dev/null; find /opt /srv /home -maxdepth 5 \( -name "docker-compose*.yml" -o -name "compose*.yaml" -o -name "Dockerfile*" \) -print 2>/dev/null'

section '2. Debian-Host-Grundhaertung'
run 'Upgradeable packages' bash -c 'apt list --upgradable 2>/dev/null'
run_shell 'Docker package policy' 'apt-cache policy docker-ce docker-ce-cli docker.io containerd.io docker-buildx-plugin docker-compose-plugin'
run 'Unattended upgrades service' systemctl status unattended-upgrades --no-pager
run_shell 'APT unattended-upgrade configuration' 'grep -R "Unattended-Upgrade" /etc/apt/apt.conf.d/ 2>/dev/null || true'
run 'Running services' systemctl --type=service --state=running --no-pager
run 'Listening ports' run_as_root ss -tulpen
run 'Open network files' run_as_root lsof -i -P -n
run_shell 'Firewall rules' 'nft list ruleset 2>/dev/null || iptables -S'
run 'Kernel sysctls' sysctl kernel.unprivileged_userns_clone kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv6.conf.all.disable_ipv6
run 'AppArmor status' run_as_root aa-status
run 'Seccomp and cgroups' bash -c 'grep Seccomp /proc/self/status; docker info --format "{{json .SecurityOptions}}"; docker info --format "Cgroup Driver: {{.CgroupDriver}} | Cgroup Version: {{.CgroupVersion}}"; mount | grep cgroup || true'

section '3. Docker-Installation und Daemon'
run_shell 'Docker package sources' 'apt-cache policy docker-ce docker.io containerd.io; grep -R "download.docker.com\|docker" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true; dpkg -l | grep -E "docker|containerd|runc" || true'
run 'Docker service' systemctl status docker --no-pager
run 'Docker enabled state' systemctl is-enabled docker
run 'Docker unit' systemctl cat docker
run 'Docker journal' journalctl -u docker -n 200 --no-pager
run_shell 'Daemon configuration' 'test -f /etc/docker/daemon.json && jq . /etc/docker/daemon.json || echo "Keine daemon.json gefunden"; docker info --format "{{json .SecurityOptions}}"; docker info --format "Logging Driver: {{.LoggingDriver}}"; docker info --format "Live Restore: {{.LiveRestoreEnabled}}"'
run_shell 'Daemon baseline fields' 'jq "{log_driver: .[\"log-driver\"], log_opts: .[\"log-opts\"], userns_remap: .[\"userns-remap\"], no_new_privileges: .[\"no-new-privileges\"], live_restore: .[\"live-restore\"], icc: .icc, iptables: .iptables, hosts: .hosts}" /etc/docker/daemon.json 2>/dev/null || true'
run_shell 'Docker socket and API' 'ss -tulpen | grep -E ":(2375|2376)\b" || true; ls -l /var/run/docker.sock; getent group docker; find /etc/systemd/system /lib/systemd/system -type f -name "*docker*" -exec grep -H "tcp://" {} \; 2>/dev/null || true'
run_shell 'Docker config permissions' 'stat -c "%A %a %U:%G %n" /etc/docker /etc/docker/daemon.json /lib/systemd/system/docker.service /lib/systemd/system/docker.socket /etc/systemd/system/docker.service.d/* /etc/docker/*.json /etc/docker/*.pem /etc/docker/*.key 2>/dev/null || true; find /etc/docker /etc/systemd/system/docker.service.d /lib/systemd/system -maxdepth 2 -type f \( -name "*docker*" -o -name "daemon.json" -o -name "*.key" -o -name "*.pem" \) -perm /022 -ls 2>/dev/null || true'
run 'Docker socket permissions' run_as_root stat -c '%A %a %U:%G %n' /etc/docker /var/run/docker.sock
run_shell 'TLS and authorization' 'systemctl show docker -p ExecStart --value; jq "{hosts, tls, tlsverify, tlscacert, tlscert, tlskey, authorization_plugins: .[\"authorization-plugins\"]}" /etc/docker/daemon.json 2>/dev/null || true; docker info --format "{{json .SecurityOptions}}"'

section '4. Zugriff und Laufzeitsicherheit'
run_shell 'Docker access' 'getent group docker; for user_name in $(getent group docker | awk -F: "{print \$4}" | tr "," " "); do id "$user_name"; done; grep -R "docker" /etc/sudoers /etc/sudoers.d 2>/dev/null || true'
run_shell 'Rootless and user namespaces' 'docker info --format "{{json .SecurityOptions}}" | grep -i rootless || true; dockerd-rootless-setuptool.sh check 2>/dev/null || true; grep "$(whoami)" /etc/subuid /etc/subgid 2>/dev/null || true; sysctl kernel.unprivileged_userns_clone'
run_shell 'Container runtime settings' 'for id in $(docker ps -q); do docker inspect "$id" --format "{{.Name}} User={{.Config.User}} Privileged={{.HostConfig.Privileged}} CapAdd={{.HostConfig.CapAdd}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} Tmpfs={{.HostConfig.Tmpfs}} Memory={{.HostConfig.Memory}} NanoCPUs={{.HostConfig.NanoCpus}} PidsLimit={{.HostConfig.PidsLimit}} Restart={{.HostConfig.RestartPolicy.Name}} Healthcheck={{json .Config.Healthcheck}} NetworkMode={{.HostConfig.NetworkMode}} PidMode={{.HostConfig.PidMode}} IpcMode={{.HostConfig.IpcMode}} Devices={{json .HostConfig.Devices}}"; done'
run_shell 'Compose security patterns' 'grep -RInE "privileged:|network_mode:\s*host|pid:\s*host|ipc:\s*host|/var/run/docker.sock|/proc:|/sys:|/etc:|/var/lib/docker|devices:|/dev:" "$AUDIT_ROOT" 2>/dev/null || true'
run_shell 'Docker networks' 'docker network ls; docker network inspect bridge; for network in $(docker network ls -q); do docker network inspect "$network" --format "{{.Name}} Driver={{.Driver}} Internal={{.Internal}} Attachable={{.Attachable}} Containers={{json .Containers}}"; done'
run_shell 'Docker mounts and resources' 'docker ps -q | xargs -r docker inspect --format "{{.Name}} {{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Mode}}) {{end}}"; docker stats --no-stream'
run_shell 'Ulimits' 'jq ".ulimits // {}" /etc/docker/daemon.json 2>/dev/null || true; for id in $(docker ps -q); do docker inspect "$id" --format "{{.Name}} Ulimits={{json .HostConfig.Ulimits}} PidsLimit={{.HostConfig.PidsLimit}}"; done'

section '5. Compose, Secrets und Storage'
if [[ -f "$COMPOSE_FILE" ]] && have docker; then
  run 'Compose config' docker compose -f "$COMPOSE_FILE" config
  run 'Compose services' docker compose -f "$COMPOSE_FILE" config --services
else
  printf 'SKIP: Compose-Datei nicht gefunden: %s\n' "$COMPOSE_FILE"
  record_skip 'Compose config' "Compose-Datei nicht gefunden: $COMPOSE_FILE"
fi
run_shell 'Environment and secret patterns' 'find "$AUDIT_ROOT" -maxdepth 4 -type f \( -name ".env*" -o -name "*compose*.yml" -o -name "*compose*.yaml" \) -print; grep -RInE "PASSWORD=|PASS=|TOKEN=|SECRET=|KEY=|PRIVATE_KEY|AWS_ACCESS_KEY|AZURE_CLIENT_SECRET" "$AUDIT_ROOT" --exclude-dir=.git 2>/dev/null || true'
run_shell 'Volume and filesystem state' 'docker volume ls; docker volume inspect $(docker volume ls -q) 2>/dev/null || true; du -sh /var/lib/docker/volumes/* 2>/dev/null | sort -h; findmnt -T /var/lib/docker; lsblk -f; df -h /var/lib/docker; mount | grep -E "/var/lib/docker|/tmp|/var/tmp" || true'
run_shell 'Sensitive file permissions' 'find /opt /srv /etc/docker -type f \( -name "*.env" -o -name "*secret*" -o -name "*key*" -o -name "*.pem" -o -name "*.crt" \) -exec ls -l {} \; 2>/dev/null; find /opt /srv /etc/docker -type f -perm -004 -print 2>/dev/null'

section '6. Images und Builds'
run_shell 'Image inventory and identities' 'docker images --digests --no-trunc; docker ps --format "{{.Names}} {{.Image}}"; docker inspect $(docker ps -q) --format "{{.Name}} Image={{.Config.Image}} ImageID={{.Image}}" 2>/dev/null || true'
run_shell 'Dockerfile review' 'find "$AUDIT_ROOT" -name "Dockerfile*" -print -exec sed -n "1,220p" {} \; 2>/dev/null; find "$AUDIT_ROOT" -name ".dockerignore" -print -exec sed -n "1,220p" {} \; 2>/dev/null; grep -RInE "FROM .*:latest|USER root|ADD http|curl .*\|.*sh|wget .*\|.*sh|--privileged|PASSWORD|TOKEN|SECRET" "$AUDIT_ROOT" --exclude-dir=.git 2>/dev/null || true'
if require_value IMAGE_NAME "$IMAGE_NAME"; then
  if require_command trivy; then run 'Trivy image' trivy image --severity HIGH,CRITICAL --ignore-unfixed "$IMAGE_NAME"; fi
  if require_command grype; then run 'Grype image' grype "$IMAGE_NAME"; fi
  if require_command syft; then
    run 'Syft CycloneDX SBOM' bash -c 'syft "$1" -o cyclonedx-json > "$2"' bash "$IMAGE_NAME" "$OUT_DIR/sbom.cyclonedx.json"
    run 'Syft SPDX SBOM' bash -c 'syft "$1" -o spdx-json > "$2"' bash "$IMAGE_NAME" "$OUT_DIR/sbom.spdx.json"
  fi
  run 'Docker image healthcheck' docker image inspect "$IMAGE_NAME" --format 'Healthcheck={{json .Config.Healthcheck}}'
else
  printf 'SKIP: Image-Pruefungen erfordern IMAGE_NAME\n'
fi
if require_command trivy; then
  run 'Trivy config' bash -c 'trivy config "$1"' bash "$AUDIT_ROOT"
  run 'Trivy filesystem' bash -c 'trivy fs --scanners vuln,secret,misconfig "$1"' bash "$AUDIT_ROOT"
fi

section '7. Registry und Signaturen'
if require_value IMAGE_REF "$IMAGE_REF"; then
  if require_command cosign; then
    run 'Cosign signature' cosign verify "$IMAGE_REF"
    run 'Cosign tree' cosign tree "$IMAGE_REF"
    run 'Cosign provenance' cosign verify-attestation --type slsaprovenance "$IMAGE_REF"
  fi
  if require_command notation; then
    run 'Notation inspect' notation inspect "$IMAGE_REF"
    run 'Notation verify' notation verify "$IMAGE_REF"
  fi
  run 'Buildx manifest inspection' docker buildx imagetools inspect "$IMAGE_REF"
fi
if require_value REGISTRY_FQDN "$REGISTRY_FQDN"; then
  run 'Registry configuration' docker info --format '{{json .RegistryConfig}}'
  run_shell 'Registry configuration files' 'jq ".insecure-registries // []" /etc/docker/daemon.json 2>/dev/null || true; grep -RIn "insecure-registries\|registry-mirrors" /etc/docker "$AUDIT_ROOT" 2>/dev/null || true'
fi
if require_value REPOSITORY "$REPOSITORY"; then
  run 'Crane repository listing' crane ls "$REPOSITORY"
fi
if require_command skopeo; then
  if [[ -n "$IMAGE_REF" ]]; then run 'Skopeo image inspection' skopeo inspect "docker://$IMAGE_REF"; fi
fi

section '8. Logging, Audit und Betrieb'
run 'Docker event history' docker events --since '1h' --until '0s'
run 'Docker daemon journal' journalctl -u docker --since '7 days ago' --no-pager
run 'Auditd status' run_as_root auditctl -s
run 'Auditd rules' bash -c 'auditctl -l 2>/dev/null | grep -E "/etc/docker|/var/lib/docker|docker\\.service|docker\\.socket" || true'
run 'Sudo journal' run_as_root journalctl _COMM=sudo --since '7 days ago' --no-pager
run 'Timers and cron' systemctl list-timers --all --no-pager
run_shell 'Cron entries' 'crontab -l 2>/dev/null || true; ls -l /etc/cron.* /var/spool/cron/crontabs 2>/dev/null || true'

section '9. Linter und optionale Pruefungen'
run 'Compose validation' bash -c 'docker compose -f "$1" config --quiet' bash "$COMPOSE_FILE"
if require_command hadolint; then
  run_shell 'Hadolint Dockerfiles' 'find "$AUDIT_ROOT" -name "Dockerfile*" -print0 | xargs -0 -r -n1 hadolint'
fi
if require_command shellcheck; then
  run_shell 'Shellcheck scripts' 'find "$AUDIT_ROOT" -type f \( -name "*.sh" -o -name "*.bash" \) -print0 | xargs -0 -r -n1 shellcheck'
fi
if require_command yamllint; then
  run_shell 'Yamllint YAML files' 'find "$AUDIT_ROOT" -type f \( -name "*.yml" -o -name "*.yaml" \) -print0 | xargs -0 -r -n1 yamllint'
fi
if ((RUN_OPTIONAL)); then
  if have falco; then run 'Falco version' falco --version; run 'Falco service' systemctl status falco --no-pager; fi
  if have falco; then
    :
  else
    record_skip 'Falco' 'Kommando falco nicht gefunden'
  fi
  if have docker && [[ -n "$IMAGE_NAME" ]] && docker scout version >/dev/null 2>&1; then
    run 'Docker Scout quickview' docker scout quickview "$IMAGE_NAME"
  else
    record_skip 'Docker Scout' 'Docker Scout nicht verfuegbar oder IMAGE_NAME ist leer'
  fi
else
  record_skip 'Optional checks' 'optionale Pruefungen deaktiviert; --optional verwenden'
fi

cleanup_stray_dirs

section 'Zusammenfassung'
printf 'ZUSAMMENFASSUNG\n'
printf 'Ausgabeverzeichnis: %s\n' "$OUT_DIR"
printf 'Zu pruefende Kommandofehler: %s\n' "$FAILURES"
printf 'Uebersprungene Pruefungen: %s\n' "$SKIPS"
printf 'CIS-Ergebnismatrix: %s\n' "$RESULTS_FILE"
printf 'Ausgabeverzeichnis je Kommando: %s\n' "$COMMAND_DIR"
printf 'Installations-, Login-, Pull-, Clone-, Build- und dienstveraendernde Kommandos wurden nicht ausgefuehrt.\n'