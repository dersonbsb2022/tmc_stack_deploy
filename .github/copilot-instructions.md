# Copilot Instructions for Docker Swarm & Portainer Installer Codebase

This repository contains shell scripts for automating the deployment of services (like RabbitMQ, Supabase) into a Docker Swarm environment managed by Portainer.

## Architecture & Infrastructure
- **Orchestration:** Docker Swarm is the target runtime.
- **Management:** Portainer is used for stack deployment via its API.
- **Networking:** Services use Docker Overlay networks. Scripts typically list available overlay networks and ask the user to select one.
- **Routing:** Traefik is the reverse proxy. Service labels (`traefik.*`) are used for configuration.
- **State & Config:**
  - Base directory: `/srv/<service_name>` (e.g., `/srv/rabbitmq`, `/srv/supabase`).
  - Configuration persistence: `dados_vps` (env vars) and `dados_vps.json` (JSON format) in the base directory.
  - Docker volumes: Mapped to subdirectories under `/srv/<service_name>/<repo>/docker/volumes`.

## Code Patterns & Conventions

### Shell Script Structure
- **Shebang & Safety:** Always use `#!/usr/bin/env bash` and `set -Eeuo pipefail`.
- **Logging:**
  - Log to `/tmp/<service>_installer_<date>.log`.
  - Use `tee` to show output in console and save to file.
  - Define helper functions for colored output: `step`, `info`, `ok`, `fail`.
- **Error Handling:** Use `trap cleanup_and_report ERR` to catch errors and log context.
- **Root Check:** Scripts enforce execution as root (`EUID -ne 0`).
- **Dependency Check:** Verify tools (`docker`, `curl`, `jq`, `openssl`) exist before running.

### Deployment Workflow
1.  **Context Gathering:** Load existing config from `dados_vps` or prompt user interactively.
2.  **Preparation:** Create directories, generate secrets (openssl), and prepare config files (YAML, JSON).
3.  **Portainer Interaction:**
    - Authenticate to Portainer API to get a JWT.
    - Auto-detect `endpointId` (usually local).
    - Get `SwarmID`.
    - Check for existing stack and remove if necessary.
    - Deploy new stack using `POST /api/stacks/create/swarm/file` (multipart/form-data).
4.  **Verification:** Wait for services to start and check `docker service ls` for `Replicas` count.

### Configuration Management
- **Idempotency:** Scripts should be re-runnable. Check if files/stacks exist before creating.
- **Secrets:** Generate strong random secrets using `openssl rand -hex 16` if not provided.
- **Dynamic YAML:** Generate `docker-compose` style YAML files dynamically within the script using `cat <<EOF`.

## Critical Files
- `install_*.sh`: Standalone installer scripts for specific services.
- `TMCStackDeploy`: Master menu-driven installer script. This is the "Base Model" for the project.
- `/srv/`: Target directory for all persistent data and configurations.

## TMCStackDeploy Architecture (Base Model)
The `TMCStackDeploy` script is the central orchestrator. Any new development should align with its patterns:

1.  **Core Functions:**
    - `stack_editavel`: The primary deployment function. It handles Portainer authentication (JWT), Swarm ID retrieval, and stack creation via `POST /api/stacks/create/swarm/file`.
    - `ferramenta_<service>`: Standard naming convention for service installation functions (e.g., `ferramenta_postgres`, `ferramenta_n8n`).
    - `wait_stack`: Custom health check function that waits for services to become active.

2.  **Credential Management:**
    - Credentials and config are stored in `/root/dados_vps/`.
    - `dados_portainer`: Stores Portainer URL, user, password, and current JWT token.
    - `dados_<service>`: Stores service-specific credentials (generated via `openssl rand -hex 16`).

3.  **Bootstrap Flow (`ferramenta_traefik_e_portainer`):**
    - Installs Docker & Swarm.
    - Creates Overlay Network.
    - Deploys Traefik & Portainer.
    - Initializes Portainer Admin User via API (`/api/users/admin/init`).
    - Generates initial JWT Token.

## Development Tips
- **Dry Run:** Respect `DRY_RUN=1` to validate configuration generation without performing the actual deployment.
- **Portainer API:** When modifying deployment logic, refer to Portainer API endpoints for stack management.
- **JSON/JQ:** Use `jq` for parsing API responses and creating JSON configuration files.


## Language & Tools
- Responda sempre em portugues BR.

## Git & Version Control
- **Ignored Files:** Never push `.yaml` files (like `portainer.yaml`, `traefik.yaml`, `*-stack.yaml`) to the GitHub repository. These files are generated dynamically or contain sensitive information and should remain local.
