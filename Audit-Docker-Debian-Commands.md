# Audit-Docker-Debian.sh — Referenz fuer die manuelle Kommandoausfuehrung

Alle vom Skript ausgefuehrten Pruefungen, aufgelistet zur manuellen bzw. punktuellen
Ausfuehrung ausserhalb des Skripts (z. B. zur erneuten Pruefung eines einzelnen Punkts
oder auf einem Host, auf dem das Skript selbst nicht laufen kann). Die Befehle sind
nach Abschnitten in derselben Reihenfolge gruppiert, in der das Skript sie ausfuehrt.

Die unten referenzierten Variablen entsprechen den Umgebungsvariablen des Skripts
(siehe `.Audit-Docker-Debian.env`). Vor der Ausfuehrung mit echten Werten belegen
oder zuvor exportieren:

```bash
AUDIT_ROOT=.                        # repository/Compose root
COMPOSE_FILE=docker-compose.yml     # Compose file
IMAGE_NAME=myapp:1.2.3              # local image reference
IMAGE_REF=registry.example.com/myapp:1.2.3
CONTAINER_NAME=myapp
REGISTRY_FQDN=registry.example.com
REPOSITORY=myapp
```

Jeder Befehl unten leitet seine Ausgabe in `$RESULTS_DIR` um, eine Datei pro
Pruefung (dasselbe Prinzip wie `commands/*.txt` im Skript). Das Verzeichnis einmalig
vor der ersten Ausfuehrung anlegen:

```bash
RESULTS_DIR=./manual-results
mkdir -p "$RESULTS_DIR"
```

Mit **(root)** markierte Befehle benoetigen `sudo` bzw. muessen als root laufen.

## 0. Tool-Inventar

**Available commands** — prueft, welche der referenzierten CLIs installiert sind
```bash
{
  for command_name in docker jq git curl ss lsof column lynis shellcheck yamllint skopeo trivy syft grype hadolint cosign crane aa-status auditctl; do
    printf "%-12s " "$command_name"; command -v "$command_name" || true
  done
} > "$RESULTS_DIR/available-commands.txt" 2>&1
```

**Docker version** — CIS 1.1.2
```bash
docker version > "$RESULTS_DIR/docker-version.txt" 2>&1
```

**Docker info**
```bash
docker info > "$RESULTS_DIR/docker-info.txt" 2>&1
```

**Compose version**
```bash
docker compose version > "$RESULTS_DIR/compose-version.txt" 2>&1
```

**Buildx version**
```bash
docker buildx version > "$RESULTS_DIR/buildx-version.txt" 2>&1
```

**containerd version**
```bash
containerd --version > "$RESULTS_DIR/containerd-version.txt" 2>&1
```

**runc version**
```bash
runc --version > "$RESULTS_DIR/runc-version.txt" 2>&1
```

## 1. Host und Inventar

**Hostname** — CIS 1 (Asset-Identifikation)
```bash
hostnamectl > "$RESULTS_DIR/hostname.txt" 2>&1
```

**OS release** — CIS 1.1.1
```bash
cat /etc/os-release > "$RESULTS_DIR/os-release.txt" 2>&1
```

**Kernel** — CIS 1.1.1
```bash
uname -a > "$RESULTS_DIR/kernel.txt" 2>&1
```

**Container inventory** — CIS 1
```bash
{
  docker ps --no-trunc
  docker ps -a --no-trunc
  docker images --digests
  docker volume ls
  docker network ls
  docker system df -v
  docker compose ls
} > "$RESULTS_DIR/container-inventory.txt" 2>&1
```

**Docker configuration files** — CIS 3
```bash
{
  find /etc/docker -maxdepth 2 -type f -print 2>/dev/null
  find /opt /srv /home -maxdepth 5 \( -name "docker-compose*.yml" -o -name "compose*.yaml" -o -name "Dockerfile*" \) -print 2>/dev/null
} > "$RESULTS_DIR/docker-configuration-files.txt" 2>&1
```

## 2. Debian-Host-Grundhaertung

**Upgradeable packages** — CIS 1.1.2
```bash
apt list --upgradable > "$RESULTS_DIR/upgradeable-packages.txt" 2>&1
```

**Docker package policy** — CIS 1.1.2
```bash
apt-cache policy docker-ce docker-ce-cli docker.io containerd.io docker-buildx-plugin docker-compose-plugin > "$RESULTS_DIR/docker-package-policy.txt" 2>&1
```

**Unattended upgrades service** — CIS 1.1.2
```bash
systemctl status unattended-upgrades --no-pager > "$RESULTS_DIR/unattended-upgrades-service.txt" 2>&1
```

**APT unattended-upgrade configuration** — CIS 1.1.2
```bash
grep -R "Unattended-Upgrade" /etc/apt/apt.conf.d/ > "$RESULTS_DIR/apt-unattended-upgrade-configuration.txt" 2>&1
```

**Running services** — CIS 1.1.3
```bash
systemctl --type=service --state=running --no-pager > "$RESULTS_DIR/running-services.txt" 2>&1
```

**Listening ports** — CIS 1.1.3 **(root)**
```bash
sudo ss -tulpen > "$RESULTS_DIR/listening-ports.txt" 2>&1
```

**Open network files** — CIS 1.1.3 **(root)**
```bash
sudo lsof -i -P -n > "$RESULTS_DIR/open-network-files.txt" 2>&1
```

**Firewall rules** — CIS 1.1.3
```bash
{ nft list ruleset 2>/dev/null || iptables -S; } > "$RESULTS_DIR/firewall-rules.txt" 2>&1
```

**Kernel sysctls** — CIS 1.1.1 / 5.1
```bash
sysctl kernel.unprivileged_userns_clone kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv6.conf.all.disable_ipv6 > "$RESULTS_DIR/kernel-sysctls.txt" 2>&1
```

**AppArmor status** — CIS 5.1 **(root)**
```bash
sudo aa-status > "$RESULTS_DIR/apparmor-status.txt" 2>&1
```

**Seccomp and cgroups** — CIS 5.21 / 5.29
```bash
{
  grep Seccomp /proc/self/status
  docker info --format "{{json .SecurityOptions}}"
  docker info --format "Cgroup Driver: {{.CgroupDriver}} | Cgroup Version: {{.CgroupVersion}}"
  mount | grep cgroup || true
} > "$RESULTS_DIR/seccomp-and-cgroups.txt" 2>&1
```

## 3. Docker-Installation und Daemon

**Docker package sources** — CIS 1.1.2
```bash
{
  apt-cache policy docker-ce docker.io containerd.io
  grep -R "download.docker.com\|docker" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true
  dpkg -l | grep -E "docker|containerd|runc" || true
} > "$RESULTS_DIR/docker-package-sources.txt" 2>&1
```

**Docker service**
```bash
systemctl status docker --no-pager > "$RESULTS_DIR/docker-service.txt" 2>&1
```

**Docker enabled state**
```bash
systemctl is-enabled docker > "$RESULTS_DIR/docker-enabled-state.txt" 2>&1
```

**Docker unit** — CIS 3.1 / 3.2
```bash
systemctl cat docker > "$RESULTS_DIR/docker-unit.txt" 2>&1
```

**Docker journal** — CIS 6.1
```bash
journalctl -u docker -n 200 --no-pager > "$RESULTS_DIR/docker-journal.txt" 2>&1
```

**Daemon configuration** — CIS 2.11 / 2.12
```bash
{
  test -f /etc/docker/daemon.json && jq . /etc/docker/daemon.json || echo "no daemon.json found"
  docker info --format "{{json .SecurityOptions}}"
  docker info --format "Logging Driver: {{.LoggingDriver}}"
  docker info --format "Live Restore: {{.LiveRestoreEnabled}}"
} > "$RESULTS_DIR/daemon-configuration.txt" 2>&1
```

**Daemon baseline fields** — CIS 2.5 / 2.6 / 2.14 / 2.15
```bash
jq '{log_driver: .["log-driver"], log_opts: .["log-opts"], userns_remap: .["userns-remap"], no_new_privileges: .["no-new-privileges"], live_restore: .["live-restore"], icc: .icc, iptables: .iptables, hosts: .hosts}' /etc/docker/daemon.json > "$RESULTS_DIR/daemon-baseline-fields.txt" 2>&1
```

**Docker socket and API** — CIS 2.1
```bash
{
  ss -tulpen | grep -E ":(2375|2376)\b" || true
  ls -l /var/run/docker.sock
  getent group docker
  find /etc/systemd/system /lib/systemd/system -type f -name "*docker*" -exec grep -H "tcp://" {} \; 2>/dev/null || true
} > "$RESULTS_DIR/docker-socket-and-api.txt" 2>&1
```

**Docker config permissions** — CIS 3.1-3.9
```bash
{
  stat -c "%A %a %U:%G %n" /etc/docker /etc/docker/daemon.json /lib/systemd/system/docker.service /lib/systemd/system/docker.socket /etc/systemd/system/docker.service.d/* /etc/docker/*.json /etc/docker/*.pem /etc/docker/*.key 2>/dev/null || true
  find /etc/docker /etc/systemd/system/docker.service.d /lib/systemd/system -maxdepth 2 -type f \( -name "*docker*" -o -name "daemon.json" -o -name "*.key" -o -name "*.pem" \) -perm /022 -ls 2>/dev/null || true
} > "$RESULTS_DIR/docker-config-permissions.txt" 2>&1
```

**Docker socket permissions** — CIS 3.3 **(root)**
```bash
sudo stat -c '%A %a %U:%G %n' /etc/docker /var/run/docker.sock > "$RESULTS_DIR/docker-socket-permissions.txt" 2>&1
```

**TLS and authorization** — CIS 2.7 / 2.8
```bash
{
  systemctl show docker -p ExecStart --value
  jq '{hosts, tls, tlsverify, tlscacert, tlscert, tlskey, authorization_plugins: .["authorization-plugins"]}' /etc/docker/daemon.json 2>/dev/null || true
  docker info --format "{{json .SecurityOptions}}"
} > "$RESULTS_DIR/tls-and-authorization.txt" 2>&1
```

## 4. Zugriff und Laufzeitsicherheit

**Docker access** — vertrauenswuerdige Benutzer mit Kontrolle ueber den Daemon
```bash
{
  getent group docker
  for user_name in $(getent group docker | awk -F: '{print $4}' | tr ',' ' '); do id "$user_name"; done
  grep -R "docker" /etc/sudoers /etc/sudoers.d 2>/dev/null || true
} > "$RESULTS_DIR/docker-access.txt" 2>&1
```

**Rootless and user namespaces** — CIS 2.6 / 5.29
```bash
{
  docker info --format "{{json .SecurityOptions}}" | grep -i rootless || true
  dockerd-rootless-setuptool.sh check 2>/dev/null || true
  grep "$(whoami)" /etc/subuid /etc/subgid 2>/dev/null || true
  sysctl kernel.unprivileged_userns_clone
} > "$RESULTS_DIR/rootless-and-user-namespaces.txt" 2>&1
```

**Container runtime settings** — CIS 5.3-5.31
```bash
{
  for id in $(docker ps -q); do
    docker inspect "$id" --format "{{.Name}} User={{.Config.User}} Privileged={{.HostConfig.Privileged}} CapAdd={{.HostConfig.CapAdd}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} Tmpfs={{.HostConfig.Tmpfs}} Memory={{.HostConfig.Memory}} NanoCPUs={{.HostConfig.NanoCpus}} PidsLimit={{.HostConfig.PidsLimit}} Restart={{.HostConfig.RestartPolicy.Name}} Healthcheck={{json .Config.Healthcheck}} NetworkMode={{.HostConfig.NetworkMode}} PidMode={{.HostConfig.PidMode}} IpcMode={{.HostConfig.IpcMode}} Devices={{json .HostConfig.Devices}}"
  done
} > "$RESULTS_DIR/container-runtime-settings.txt" 2>&1
```

**Compose security patterns** — CIS 5.5 / 5.9 / 5.19
```bash
grep -RInE "privileged:|network_mode:\s*host|pid:\s*host|ipc:\s*host|/var/run/docker.sock|/proc:|/sys:|/etc:|/var/lib/docker|devices:|/dev:" "$AUDIT_ROOT" > "$RESULTS_DIR/compose-security-patterns.txt" 2>&1
```

**Docker networks** — CIS 5.29
```bash
{
  docker network ls
  docker network inspect bridge
  for network in $(docker network ls -q); do
    docker network inspect "$network" --format "{{.Name}} Driver={{.Driver}} Internal={{.Internal}} Attachable={{.Attachable}} Containers={{json .Containers}}"
  done
} > "$RESULTS_DIR/docker-networks.txt" 2>&1
```

**Docker mounts and resources** — CIS 5.5 / 5.10 / 5.11
```bash
{
  docker ps -q | xargs -r docker inspect --format "{{.Name}} {{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Mode}}) {{end}}"
  docker stats --no-stream
} > "$RESULTS_DIR/docker-mounts-and-resources.txt" 2>&1
```

**Ulimits** — CIS 5.28
```bash
{
  jq ".ulimits // {}" /etc/docker/daemon.json 2>/dev/null || true
  for id in $(docker ps -q); do
    docker inspect "$id" --format "{{.Name}} Ulimits={{json .HostConfig.Ulimits}} PidsLimit={{.HostConfig.PidsLimit}}"
  done
} > "$RESULTS_DIR/ulimits.txt" 2>&1
```

## 5. Compose, Secrets und Storage

**Compose config** (erfordert vorhandene `$COMPOSE_FILE`)
```bash
{
  docker compose -f "$COMPOSE_FILE" config
  docker compose -f "$COMPOSE_FILE" config --services
} > "$RESULTS_DIR/compose-config.txt" 2>&1
```

**Environment and secret patterns** — CIS 4.10
```bash
{
  find "$AUDIT_ROOT" -maxdepth 4 -type f \( -name ".env*" -o -name "*compose*.yml" -o -name "*compose*.yaml" \) -print
  grep -RInE "PASSWORD=|PASS=|TOKEN=|SECRET=|KEY=|PRIVATE_KEY|AWS_ACCESS_KEY|AZURE_CLIENT_SECRET" "$AUDIT_ROOT" --exclude-dir=.git 2>/dev/null || true
} > "$RESULTS_DIR/environment-and-secret-patterns.txt" 2>&1
```

**Volume and filesystem state** — CIS 1.2 / 5.12
```bash
{
  docker volume ls
  docker volume inspect $(docker volume ls -q) 2>/dev/null || true
  du -sh /var/lib/docker/volumes/* 2>/dev/null | sort -h
  findmnt -T /var/lib/docker
  lsblk -f
  df -h /var/lib/docker
  mount | grep -E "/var/lib/docker|/tmp|/var/tmp" || true
} > "$RESULTS_DIR/volume-and-filesystem-state.txt" 2>&1
```

**Sensitive file permissions** — CIS 3.1-3.9
```bash
{
  find /opt /srv /etc/docker -type f \( -name "*.env" -o -name "*secret*" -o -name "*key*" -o -name "*.pem" -o -name "*.crt" \) -exec ls -l {} \; 2>/dev/null
  find /opt /srv /etc/docker -type f -perm -004 -print 2>/dev/null
} > "$RESULTS_DIR/sensitive-file-permissions.txt" 2>&1
```

## 6. Images und Builds

**Image inventory and identities**
```bash
{
  docker images --digests --no-trunc
  docker ps --format "{{.Names}} {{.Image}}"
  docker inspect $(docker ps -q) --format "{{.Name}} Image={{.Config.Image}} ImageID={{.Image}}" 2>/dev/null || true
} > "$RESULTS_DIR/image-inventory-and-identities.txt" 2>&1
```

**Dockerfile review** — CIS 4.1 / 4.6 / 4.9 / 4.10
```bash
{
  find "$AUDIT_ROOT" -name "Dockerfile*" -print -exec sed -n "1,220p" {} \; 2>/dev/null
  find "$AUDIT_ROOT" -name ".dockerignore" -print -exec sed -n "1,220p" {} \; 2>/dev/null
  grep -RInE "FROM .*:latest|USER root|ADD http|curl .*\|.*sh|wget .*\|.*sh|--privileged|PASSWORD|TOKEN|SECRET" "$AUDIT_ROOT" --exclude-dir=.git 2>/dev/null || true
} > "$RESULTS_DIR/dockerfile-review.txt" 2>&1
```

**Trivy image** — CIS 4.4 (erfordert `$IMAGE_NAME`)
```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed "$IMAGE_NAME" > "$RESULTS_DIR/trivy-image.txt" 2>&1
```

**Grype image** — CIS 4.4 (erfordert `$IMAGE_NAME`)
```bash
grype "$IMAGE_NAME" > "$RESULTS_DIR/grype-image.txt" 2>&1
```

**Syft SBOM** (erfordert `$IMAGE_NAME`)
```bash
syft "$IMAGE_NAME" -o cyclonedx-json > "$RESULTS_DIR/sbom.cyclonedx.json" 2> "$RESULTS_DIR/syft-cyclonedx-sbom.txt"
syft "$IMAGE_NAME" -o spdx-json > "$RESULTS_DIR/sbom.spdx.json" 2> "$RESULTS_DIR/syft-spdx-sbom.txt"
```

**Docker image healthcheck** — CIS 4.6 (erfordert `$IMAGE_NAME`)
```bash
docker image inspect "$IMAGE_NAME" --format 'Healthcheck={{json .Config.Healthcheck}}' > "$RESULTS_DIR/docker-image-healthcheck.txt" 2>&1
```

**Trivy config / filesystem**
```bash
trivy config "$AUDIT_ROOT" > "$RESULTS_DIR/trivy-config.txt" 2>&1
trivy fs --scanners vuln,secret,misconfig "$AUDIT_ROOT" > "$RESULTS_DIR/trivy-filesystem.txt" 2>&1
```

## 7. Registry und Signaturen

**Cosign signature / tree / provenance** — CIS 4.5 (erfordert `$IMAGE_REF`)
```bash
cosign verify "$IMAGE_REF" > "$RESULTS_DIR/cosign-signature.txt" 2>&1
cosign tree "$IMAGE_REF" > "$RESULTS_DIR/cosign-tree.txt" 2>&1
cosign verify-attestation --type slsaprovenance "$IMAGE_REF" > "$RESULTS_DIR/cosign-provenance.txt" 2>&1
```

**Notation inspect / verify** — CIS 4.5 (erfordert `$IMAGE_REF`)
```bash
notation inspect "$IMAGE_REF" > "$RESULTS_DIR/notation-inspect.txt" 2>&1
notation verify "$IMAGE_REF" > "$RESULTS_DIR/notation-verify.txt" 2>&1
```

**Buildx manifest inspection** (erfordert `$IMAGE_REF`)
```bash
docker buildx imagetools inspect "$IMAGE_REF" > "$RESULTS_DIR/buildx-manifest-inspection.txt" 2>&1
```

**Registry configuration** (erfordert `$REGISTRY_FQDN`)
```bash
{
  docker info --format '{{json .RegistryConfig}}'
  jq ".insecure-registries // []" /etc/docker/daemon.json 2>/dev/null || true
  grep -RIn "insecure-registries\|registry-mirrors" /etc/docker "$AUDIT_ROOT" 2>/dev/null || true
} > "$RESULTS_DIR/registry-configuration.txt" 2>&1
```

**Crane repository listing** (erfordert `$REPOSITORY`)
```bash
crane ls "$REPOSITORY" > "$RESULTS_DIR/crane-repository-listing.txt" 2>&1
```

**Skopeo image inspection** (erfordert `$IMAGE_REF`)
```bash
skopeo inspect "docker://$IMAGE_REF" > "$RESULTS_DIR/skopeo-image-inspection.txt" 2>&1
```

## 8. Logging, Audit und Betrieb

**Docker event history** — CIS 6.2
```bash
docker events --since '1h' --until '0s' > "$RESULTS_DIR/docker-event-history.txt" 2>&1
```

**Docker daemon journal** — CIS 6.1
```bash
journalctl -u docker --since '7 days ago' --no-pager > "$RESULTS_DIR/docker-daemon-journal.txt" 2>&1
```

**Auditd status** — CIS 1.1.4 **(root)**
```bash
sudo auditctl -s > "$RESULTS_DIR/auditd-status.txt" 2>&1
```

**Auditd rules** — CIS 1.1.4
```bash
auditctl -l 2>/dev/null | grep -E "/etc/docker|/var/lib/docker|docker\.service|docker\.socket" > "$RESULTS_DIR/auditd-rules.txt" 2>&1
```

**Sudo journal** **(root)**
```bash
sudo journalctl _COMM=sudo --since '7 days ago' --no-pager > "$RESULTS_DIR/sudo-journal.txt" 2>&1
```

**Timers and cron**
```bash
systemctl list-timers --all --no-pager > "$RESULTS_DIR/timers-and-cron.txt" 2>&1
```

**Cron entries**
```bash
{
  crontab -l 2>/dev/null || true
  ls -l /etc/cron.* /var/spool/cron/crontabs 2>/dev/null || true
} > "$RESULTS_DIR/cron-entries.txt" 2>&1
```

## 9. Linter und optionale Pruefungen

**Compose validation**
```bash
docker compose -f "$COMPOSE_FILE" config --quiet > "$RESULTS_DIR/compose-validation.txt" 2>&1
```

**Hadolint Dockerfiles**
```bash
find "$AUDIT_ROOT" -name "Dockerfile*" -print0 | xargs -0 -r -n1 hadolint > "$RESULTS_DIR/hadolint-dockerfiles.txt" 2>&1
```

**Shellcheck scripts**
```bash
find "$AUDIT_ROOT" -type f \( -name "*.sh" -o -name "*.bash" \) -print0 | xargs -0 -r -n1 shellcheck > "$RESULTS_DIR/shellcheck-scripts.txt" 2>&1
```

**Yamllint YAML files**
```bash
find "$AUDIT_ROOT" -type f \( -name "*.yml" -o -name "*.yaml" \) -print0 | xargs -0 -r -n1 yamllint > "$RESULTS_DIR/yamllint-yaml-files.txt" 2>&1
```

**Falco version / service** (nur mit `--optional`)
```bash
falco --version > "$RESULTS_DIR/falco-version.txt" 2>&1
systemctl status falco --no-pager > "$RESULTS_DIR/falco-service.txt" 2>&1
```

**Docker Scout quickview** (nur mit `--optional`, erfordert `$IMAGE_NAME`)
```bash
docker scout quickview "$IMAGE_NAME" > "$RESULTS_DIR/docker-scout-quickview.txt" 2>&1
```
