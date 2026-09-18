#!/usr/bin/env bash
set -euo pipefail

# Installiert die optionalen CLI-Tools, die von Audit-Docker-Debian.sh genutzt werden (Tool-Inventar aus
# Section 0 sowie die Scanner aus Section 6/7/9). Gefahrlos erneut ausfuehrbar; bereits vorhandene
# Tools bleiben unangetastet.

SCRIPT_NAME="$(basename "$0")"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
DO_APT=1
DO_BINARIES=0
DO_FALCO=0
DO_DOCKER_SCOUT=0
UNINSTALL=0
DRY_RUN=0

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [--skip-apt] [--all] [--falco] [--docker-scout] [--uninstall] [--bin-dir DIR] [--dry-run]

Installiert (oder entfernt mit --uninstall) die optionalen Kommandos, die von
Audit-Docker-Debian.sh referenziert werden. --uninstall kehrt die unten
angegebenen Auswahl-Flags um; daher dieselben Flags wie bei der Installation verwenden.

  (Standard)       APT-Pakete installieren/entfernen: jq git curl iproute2 lsof
                    bsdextrautils lynis shellcheck yamllint apparmor-utils auditd
  --skip-apt       APT-Pakete nicht installieren/entfernen
  --all            Zusaetzlich Scanner-/Signier-Binaries installieren/entfernen: trivy syft
                    grype hadolint cosign crane notation
  --falco          Zusaetzlich das Falco-APT-Repository und -Paket hinzufuegen/entfernen
                    (aendert APT-Quellen; installiert einen Kernel-/eBPF-Treiber)
  --docker-scout   Zusaetzlich das Docker-Scout-CLI-Plugin fuer den aktuellen Benutzer installieren/entfernen
  --uninstall      Entfernen statt installieren
  --bin-dir DIR    Zielverzeichnis fuer heruntergeladene Binaerdateien (Standard: $BIN_DIR)
  --dry-run        Aktionen nur anzeigen, ohne sie auszufuehren
EOF
}

while (($# > 0)); do
  case "$1" in
    --skip-apt) DO_APT=0 ;;
    --all) DO_BINARIES=1 ;;
    --falco) DO_FALCO=1 ;;
    --docker-scout) DO_DOCKER_SCOUT=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --bin-dir)
      shift
      (($# > 0)) || { echo "Fehlender Wert fuer --bin-dir" >&2; exit 2; }
      BIN_DIR="$1"
      ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unbekanntes Argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

have() { command -v "$1" >/dev/null 2>&1; }
log() { printf '[%s] %s\n' "$(date +%T)" "$*"; }

require_command() {
  if have "$1"; then
    return 0
  fi
  if ((DRY_RUN)); then
    log "TESTLAUF: erforderliches Kommando fehlt: $1 (wuerde einen echten Lauf abbrechen)"
    return 0
  fi
  echo "Erforderliches Kommando nicht gefunden: $1" >&2
  exit 1
}

# Hier gesammelt statt ueber einen RETURN-Trap pro Aufruf, damit Temp-Verzeichnisse auch entfernt werden, wenn set -e das Skript abbricht.
CLEANUP_DIRS=()
cleanup_temp_dirs() {
  local dir
  for dir in "${CLEANUP_DIRS[@]:-}"; do
    [[ -n "$dir" && -d "$dir" ]] && rm -rf "$dir"
  done
  return 0
}
trap cleanup_temp_dirs EXIT
trap 'echo "FEHLER: $SCRIPT_NAME abgebrochen (Exit-Code $?) in Zeile $LINENO: $BASH_COMMAND" >&2' ERR

act() {
  if ((DRY_RUN)); then
    printf 'TESTLAUF: %s\n' "$*"
  else
    "$@"
  fi
}

as_root() {
  if ((EUID == 0)); then
    act "$@"
  elif have sudo; then
    if ((DRY_RUN)); then
      printf 'TESTLAUF: sudo %s\n' "$*"
    else
      sudo "$@"
    fi
  else
    echo "Root-Rechte oder sudo erforderlich fuer: $*" >&2
    exit 1
  fi
}

arch_tag() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) echo "Nicht unterstuetzte Architektur: $(uname -m)" >&2; exit 1 ;;
  esac
}

# bsdextrautils ersetzte bsdmainutils ab Debian 11; es wird verwendet, was der lokale APT-Cache anbietet.
column_package() {
  if apt-cache show bsdextrautils >/dev/null 2>&1; then
    printf 'bsdextrautils'
  else
    printf 'bsdmainutils'
  fi
}

install_apt_packages() {
  local column_pkg
  column_pkg=$(column_package)
  local pairs=(jq:jq git:git curl:curl iproute2:ss lsof:lsof "${column_pkg}:column"
    lynis:lynis shellcheck:shellcheck yamllint:yamllint apparmor-utils:aa-status auditd:auditctl)
  local package command_name missing=()
  for pair in "${pairs[@]}"; do
    package="${pair%%:*}"
    command_name="${pair##*:}"
    have "$command_name" || missing+=("$package")
  done
  if ((${#missing[@]} == 0)); then
    log "APT-Pakete bereits vorhanden"
    return 0
  fi
  log "Installiere APT-Pakete: ${missing[*]}"
  as_root apt-get update
  as_root apt-get install -y "${missing[@]}"
}

install_vendor_script() {
  local name="$1" url="$2"
  if have "$name"; then
    log "$name bereits installiert"
    return 0
  fi
  log "Installiere $name ueber Upstream-Installskript nach $BIN_DIR"
  if ((DRY_RUN)); then
    printf 'TESTLAUF: curl -sfL %s | sh -s -- -b %s\n' "$url" "$BIN_DIR"
    return 0
  fi
  curl -sfL "$url" | as_root sh -s -- -b "$BIN_DIR"
}

github_asset_url() {
  local repo="$1" pattern="$2"
  curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
    | jq -r --arg pattern "$pattern" '.assets[] | select(.name | test($pattern)) | .browser_download_url' \
    | head -n1
}

install_binary_release() {
  local name="$1" repo="$2" pattern="$3" archive="$4"
  if have "$name"; then
    log "$name bereits installiert"
    return 0
  fi
  if ((DRY_RUN)); then
    printf 'TESTLAUF: neuestes Release von %s aufloesen (Muster: %s) und nach %s installieren\n' "$repo" "$pattern" "$BIN_DIR"
    return 0
  fi
  local url
  url=$(github_asset_url "$repo" "$pattern")
  if [[ -z "$url" ]]; then
    echo "Kein Release-Asset fuer $name gefunden ($repo, Muster: $pattern)" >&2
    return 1
  fi
  log "Installiere $name von $url"
  local tmp_dir
  tmp_dir=$(mktemp -d)
  CLEANUP_DIRS+=("$tmp_dir")
  if [[ "$archive" == "tar.gz" ]]; then
    curl -fsSL "$url" -o "$tmp_dir/asset.tar.gz"
    tar -xzf "$tmp_dir/asset.tar.gz" -C "$tmp_dir"
    as_root install -m 0755 "$tmp_dir/$name" "$BIN_DIR/$name"
  else
    curl -fsSL "$url" -o "$tmp_dir/$name"
    as_root install -m 0755 "$tmp_dir/$name" "$BIN_DIR/$name"
  fi
}

install_binaries() {
  require_command curl
  require_command jq
  require_command tar
  as_root mkdir -p "$BIN_DIR"
  local arch
  arch=$(arch_tag)
  install_vendor_script trivy 'https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh'
  install_vendor_script syft 'https://raw.githubusercontent.com/anchore/syft/main/install.sh'
  install_vendor_script grype 'https://raw.githubusercontent.com/anchore/grype/main/install.sh'
  install_binary_release hadolint hadolint/hadolint "hadolint-linux-${arch/amd64/x86_64}\$" bin
  install_binary_release cosign sigstore/cosign "cosign-linux-${arch}$" bin
  install_binary_release crane google/go-containerregistry "go-containerregistry_Linux_${arch/amd64/x86_64}\.tar\.gz$" tar.gz
  install_binary_release notation notaryproject/notation "notation_.*_linux_${arch}\.tar\.gz$" tar.gz
}

install_falco() {
  if have falco; then
    log "falco bereits installiert"
    return 0
  fi
  log "Fuege das Falco-APT-Repository hinzu und installiere falco"
  as_root bash -c '
    set -e
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
    apt-get update
    apt-get install -y falco
  '
}

install_docker_scout() {
  if docker scout version >/dev/null 2>&1; then
    log "Docker-Scout-CLI-Plugin bereits installiert"
    return 0
  fi
  log "Installiere das Docker-Scout-CLI-Plugin fuer den aktuellen Benutzer"
  act bash -c 'curl -fsSL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --'
}

uninstall_apt_packages() {
  local pairs=(jq:jq git:git curl:curl iproute2:ss lsof:lsof
    lynis:lynis shellcheck:shellcheck yamllint:yamllint apparmor-utils:aa-status auditd:auditctl)
  local package command_name present=()
  for pair in "${pairs[@]}"; do
    package="${pair%%:*}"
    command_name="${pair##*:}"
    have "$command_name" && present+=("$package")
  done
  if have column; then
    local column_pkg
    column_pkg=$(dpkg -S "$(command -v column)" 2>/dev/null | cut -d: -f1 | head -n1)
    [[ -n "$column_pkg" ]] && present+=("$column_pkg")
  fi
  if ((${#present[@]} == 0)); then
    log "APT-Pakete bereits entfernt"
    return 0
  fi
  log "Entferne APT-Pakete: ${present[*]}"
  as_root apt-get purge -y "${present[@]}"
  as_root apt-get autoremove -y
}

# Loescht Binaerdateien nur unterhalb von BIN_DIR; per Paketmanager installierte Versionen an anderer Stelle bleiben unangetastet.
uninstall_binary() {
  local name="$1" path
  path=$(command -v "$name" 2>/dev/null || true)
  if [[ -z "$path" ]]; then
    log "$name bereits nicht vorhanden"
    return 0
  fi
  case "$path" in
    "$BIN_DIR"/*)
      log "Entferne $path"
      as_root rm -f "$path"
      ;;
    *) log "Ueberspringe $name: ausserhalb von $BIN_DIR installiert ($path); bei Bedarf manuell entfernen" ;;
  esac
}

uninstall_binaries() {
  for name in trivy syft grype hadolint cosign crane notation; do
    uninstall_binary "$name"
  done
}

uninstall_falco() {
  if ! have falco && [[ ! -f /etc/apt/sources.list.d/falcosecurity.list ]]; then
    log "falco bereits nicht vorhanden"
    return 0
  fi
  log "Entferne falco und dessen APT-Repository"
  as_root apt-get purge -y falco || true
  as_root rm -f /etc/apt/sources.list.d/falcosecurity.list /usr/share/keyrings/falco-archive-keyring.gpg
  as_root apt-get update
}

uninstall_docker_scout() {
  local plugin_path="$HOME/.docker/cli-plugins/docker-scout"
  if [[ ! -e "$plugin_path" ]]; then
    log "Docker-Scout-CLI-Plugin bereits nicht vorhanden"
    return 0
  fi
  log "Entferne Docker-Scout-CLI-Plugin"
  act rm -f "$plugin_path"
}

if ((UNINSTALL)); then
  ((DO_APT)) && uninstall_apt_packages
  ((DO_BINARIES)) && uninstall_binaries
  ((DO_FALCO)) && uninstall_falco
  ((DO_DOCKER_SCOUT)) && uninstall_docker_scout
else
  ((DO_APT)) && install_apt_packages
  ((DO_BINARIES)) && install_binaries
  ((DO_FALCO)) && install_falco
  ((DO_DOCKER_SCOUT)) && install_docker_scout
fi

log "Verfuegbarkeit der Tools:"
for command_name in jq git curl ss lsof column lynis shellcheck yamllint skopeo trivy syft grype hadolint cosign crane notation aa-status auditctl falco; do
  printf '%-24s ' "$command_name"
  have "$command_name" && command -v "$command_name" || echo "nicht gefunden"
done
if have docker; then
  printf '%-24s ' "docker scout"
  docker scout version >/dev/null 2>&1 && echo "installiert" || echo "nicht gefunden"
fi
