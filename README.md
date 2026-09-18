## CIS-Audit Container Platform Debian
#### https://www.cisecurity.org/cis-benchmarks
```
# mkdir -p ~/tools

# git clone https://github.com/git67/audit.git

# cd ~/tools/audit/
```

- Inhalte exemplarisch
```
# vi .Audit-Docker-Debian.env
...
export AUDIT_ROOT="."
export COMPOSE_FILE="/srv/app/docker-compose.yml"
export IMAGE_NAME="alpine:latest"
export IMAGE_REF="hub.docker.com/_/alpine"
export CONTAINER_NAME="alpine"
export REGISTRY_FQDN="hub.docker.com"
export REPOSITORY="alpine"
...
```

```
# ./Install-Audit-Optional-Tools.sh --dry-run
# ./Audit-Docker-Debian.sh
```

- optional
```
# ./Install-Audit-Optional-Tools.sh --all
# ./Audit-Docker-Debian.sh --optional
```
