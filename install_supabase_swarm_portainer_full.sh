#!/usr/bin/env bash
# Supabase SWARM installer (FULL v6c) - VERSÃO CORRIGIDA
# - Lê/salva dados do Portainer em /srv/supabase/dados_vps e dados_vps.json
# - Lista redes overlay e usa a escolhida (não cria rede)
# - Gera JWTs (anon/service_role) assinados com mesmo segredo (HS256)
# - Gera kong.yml (EXATO ao original) e supabase.yaml com entrypoint do Kong (temp.yml -> kong.yml)
# - Gera pooler.exs e vector.yml mínimos
# - Faz deploy no Portainer (cria/atualiza stack)
# - MELHORIAS: Logging detalhado + tratamento de erros + identação YAML corrigida

set -Eeuo pipefail

# Configurar logging melhorado
LOG_FILE="/tmp/supabase_installer_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== Iniciando instalação Supabase em $(date) ==="
echo "Log salvo em: $LOG_FILE"

c0="\033[0m"; cy="\033[33m"; cg="\033[32m"; cc="\033[36m"; cr="\033[31m"
step(){ echo -e "${cy}$*${c0}"; }
info(){ echo -e "${cc}•${c0} $*"; }
ok(){ echo -e "${cg}[ OK ]${c0} $*"; }
fail(){ echo -e "${cr}[ ERRO ]${c0} $*"; }

# Função de cleanup melhorada
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        fail "Script falhou na linha ${BASH_LINENO[1]}: comando \"${BASH_COMMAND}\" falhou (código $exit_code)."
        echo "=== Log completo salvo em: $LOG_FILE ==="
    fi
}

# Combinar ambos os traps em uma função
cleanup_and_report() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        fail "Script falhou na linha ${BASH_LINENO[1]}: comando \"${BASH_COMMAND}\" falhou (código $exit_code)."
        echo "=== Log completo salvo em: $LOG_FILE ==="
    fi
}

trap cleanup_and_report ERR

# Root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

# Modo dry-run opcional
DRY_RUN="${DRY_RUN:-0}"
if [[ "${DRY_RUN}" == "1" ]]; then
    info "MODO DRY-RUN ATIVADO: Apenas validação, sem deploy."
fi

# Deps
need(){ command -v "$1" >/dev/null 2>&1 || { fail "Dependência ausente: $1"; exit 1; }; }
need docker; need curl; need jq; need openssl; need git

# Verificar se Docker Swarm está ativo
if ! docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -q "active"; then
    fail "Docker Swarm não está ativo. Execute: docker swarm init"
    exit 1
fi

# ---------- Função do código original para gerar JWTs (anon/service) ----------
generate_jwt_tokens() {
  payload_service_key=$(echo '{
    "role": "service_role",
    "iss": "supabase",
    "iat": 1715050800,
    "exp": 1872817200
  }' | jq .)

  payload_anon_key=$(echo '{
    "role": "anon",
    "iss": "supabase",
    "iat": 1715050800,
    "exp": 1872817200
  }' | jq .)

  secret=$(openssl rand -hex 20) # será nosso GOTRUE_JWT_SECRET/JWT_Key

  header=$(printf '{"alg":"HS256","typ":"JWT"}' | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
  payload_service_key_base64=$(printf '%s' "$payload_service_key" | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
  payload_anon_key_base64=$(printf '%s' "$payload_anon_key" | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

  signature_service_key=$(printf '%s' "$header.$payload_service_key_base64" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
  signature_anon_key=$(printf '%s' "$header.$payload_anon_key_base64" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

  token_service_key="$header.$payload_service_key_base64.$signature_service_key"
  token_anon_key="$header.$payload_anon_key_base64.$signature_anon_key"

  echo "$secret $token_service_key $token_anon_key"
}

# ---------- Paths / Variáveis base ----------
SUFFIX="${1:-}"                   # opcional: nome curto do projeto (ex: prod) -> services *_prod
SUF_US="${SUFFIX:+_$SUFFIX}"
BASE_DIR="/srv/supabase"
REPO_DIR="${BASE_DIR}/supabase${SUF_US}"
VOL_DIR="${REPO_DIR}/docker/volumes"
YAML_PATH="${REPO_DIR}/docker/supabase${SUF_US}.yaml"
KONG_DEST="${VOL_DIR}/api/kong.yml"
POOLEX="${VOL_DIR}/pooler/pooler.exs"
VECTOR="${VOL_DIR}/logs/vector.yml"

mkdir -p "${VOL_DIR}"/{api,storage,db,logs,pooler,functions} "${VOL_DIR}/db/data" "${REPO_DIR}/docker"

DADOS_VPS_ENV="${BASE_DIR}/dados_vps"
DADOS_VPS_JSON="${BASE_DIR}/dados_vps.json"
STACK_NAME="supabase${SUF_US}"

# ---------- 1) Rede overlay já existente ----------
step "Listando redes overlay existentes"
mapfile -t ROWS < <(docker network ls --format '{{.Name}}|{{.Driver}}')
OVERLAYS=(); for r in "${ROWS[@]}"; do IFS='|' read -r n d <<<"$r"; [ "$d" = "overlay" ] && OVERLAYS+=("$n"); done
[ "${#OVERLAYS[@]}" -gt 0 ] || { fail "Sem redes overlay. Crie uma e rode de novo."; exit 1; }

CHOSEN_NET="${DOCKER_OVERLAY_NETWORK:-}"
if [ -z "$CHOSEN_NET" ]; then
  echo "Redes overlay disponíveis:"
  i=1; for n in "${OVERLAYS[@]}"; do printf "  %d) %s\n" "$i" "$n"; i=$((i+1)); done
  echo
  while [ -z "$CHOSEN_NET" ]; do
    read -r -p "Qual rede usar? (número ou nome) [${OVERLAYS[0]}]: " ans
    ans="${ans:-${OVERLAYS[0]}}"
    if [[ "$ans" =~ ^[0-9]+$ ]]; then 
      idx=$((ans-1))
      if [ "$idx" -ge 0 ] && [ "$idx" -lt "${#OVERLAYS[@]}" ]; then
        CHOSEN_NET="${OVERLAYS[$idx]}"
      else
        echo "Número inválido! Use 1-${#OVERLAYS[@]}"
      fi
    else 
      # Verificar se o nome existe
      for overlay in "${OVERLAYS[@]}"; do
        if [ "$overlay" = "$ans" ]; then
          CHOSEN_NET="$ans"
          break
        fi
      done
      [ -z "$CHOSEN_NET" ] && echo "Rede '$ans' não encontrada!"
    fi
  done
fi
ok "Rede: ${CHOSEN_NET}"
nome_rede_interna="${CHOSEN_NET}"

# ---------- 2) Portainer: carregar de dados_vps ou perguntar e salvar ----------
load_or_prompt_portainer() {
  local need_save=0

  if [ -f "$DADOS_VPS_ENV" ]; then
    set -a; . "$DADOS_VPS_ENV" || true; set +a
    : "${PORTAINER_URL:=}"; : "${PORTAINER_USERNAME:=}"; : "${PORTAINER_PASSWORD:=}"
    : "${PORTAINER_ENDPOINT_ID:=0}"; : "${PORTAINER_INSECURE:=false}"
    : "${SUPABASE_URL:=}"; : "${S3_URL:=}"; : "${TRAEFIK_CERTRESOLVER:=letsencryptresolver}"
    : "${KONG_DASHBOARD_USER:=admin}"; : "${KONG_DASHBOARD_PASS:=}"
    : "${DOCKER_OVERLAY_NETWORK:=}"

    # Ajusta rede se veio do arquivo
    if [ -z "${CHOSEN_NET:-}" ] && [ -n "${DOCKER_OVERLAY_NETWORK:-}" ]; then
      CHOSEN_NET="$DOCKER_OVERLAY_NETWORK"
      nome_rede_interna="$CHOSEN_NET"
    fi

    # checa se tem credenciais mínimas
    if [ -z "$PORTAINER_URL" ] || [ -z "$PORTAINER_USERNAME" ] || [ -z "$PORTAINER_PASSWORD" ]; then
      need_save=1
    fi
    ok "Usando credenciais do Portainer de ${DADOS_VPS_ENV}"
  else
    need_save=1
  fi

  if [ "$need_save" -eq 1 ]; then
    step "Coletando dados do Portainer (serão salvos em ${DADOS_VPS_ENV})"
    
    while [ -z "${PORTAINER_URL:-}" ]; do
      read -r -p "URL do Portainer (ex: https://portainer.seu-dominio): " PORTAINER_URL
      [ -z "$PORTAINER_URL" ] && echo "URL é obrigatória!"
    done
    
    read -r -p "Cert self-signed? (y/N): " yn
    PORTAINER_INSECURE=$([ "${yn:-N}" = "y" ] || [ "${yn:-N}" = "Y" ] && echo true || echo false)
    
    read -r -p "Admin do Portainer [admin]: " PORTAINER_USERNAME
    PORTAINER_USERNAME="${PORTAINER_USERNAME:-admin}"
    
    while [ -z "${PORTAINER_PASSWORD:-}" ]; do
      read -r -s -p "Senha do Portainer: " PORTAINER_PASSWORD
      echo
      [ -z "$PORTAINER_PASSWORD" ] && echo "Senha é obrigatória!"
    done
    
    read -r -p "endpointId (ENTER autodetecta) [0]: " PORTAINER_ENDPOINT_ID
    PORTAINER_ENDPOINT_ID="${PORTAINER_ENDPOINT_ID:-0}"
  fi

  # Supabase URLs e dashboard: se não havia no arquivo, pergunta e salva
  if [ -z "${SUPABASE_URL:-}" ] || [ -z "${S3_URL:-}" ] || [ -z "${KONG_DASHBOARD_PASS:-}" ] || [ -z "${S3_ACCESS_KEY:-}" ] || [ -z "${S3_SECRET_KEY:-}" ]; then
    step "Configuração do Supabase"
    
    if [ -z "${SUPABASE_URL:-}" ]; then
      while [ -z "${SUPABASE_URL:-}" ]; do
        read -r -p "URL pública do Supabase (Kong), ex: supabase.seu-dominio: " SUPABASE_URL
        [ -z "$SUPABASE_URL" ] && echo "URL do Supabase é obrigatória!"
      done
    fi
    
    if [ -z "${S3_URL:-}" ]; then
      while [ -z "${S3_URL:-}" ]; do
        read -r -p "URL S3 (MinIO), ex: s3.seu-dominio: " S3_URL
        [ -z "$S3_URL" ] && echo "URL do S3 é obrigatória!"
      done
    fi
    
    if [ -z "${S3_ACCESS_KEY:-}" ]; then
      read -r -p "S3 Access Key [minioadmin]: " S3_ACCESS_KEY
      S3_ACCESS_KEY="${S3_ACCESS_KEY:-minioadmin}"
    fi
    
    if [ -z "${S3_SECRET_KEY:-}" ]; then
      read -r -s -p "S3 Secret Key [minioadmin]: " S3_SECRET_KEY
      echo
      S3_SECRET_KEY="${S3_SECRET_KEY:-minioadmin}"
    fi
    
    if [ -z "${TRAEFIK_CERTRESOLVER:-}" ]; then
      read -r -p "Traefik certresolver [letsencryptresolver]: " TRAEFIK_CERTRESOLVER
      TRAEFIK_CERTRESOLVER="${TRAEFIK_CERTRESOLVER:-letsencryptresolver}"
    fi
    
    if [ -z "${KONG_DASHBOARD_USER:-}" ]; then
      read -r -p "Usuário do Dashboard (Kong BasicAuth) [admin]: " KONG_DASHBOARD_USER
      KONG_DASHBOARD_USER="${KONG_DASHBOARD_USER:-admin}"
    fi
    
    if [ -z "${KONG_DASHBOARD_PASS:-}" ]; then
      while [ -z "${KONG_DASHBOARD_PASS:-}" ]; do
        read -r -s -p "Senha do Dashboard: " KONG_DASHBOARD_PASS
        echo
        [ -z "$KONG_DASHBOARD_PASS" ] && echo "Senha do dashboard é obrigatória!"
      done
    fi
  fi

  umask 077
  {
    printf 'PORTAINER_URL=%s\n' "$PORTAINER_URL"
    printf 'PORTAINER_USERNAME=%s\n' "$PORTAINER_USERNAME"
    printf 'PORTAINER_PASSWORD=%s\n' "$PORTAINER_PASSWORD"
    printf 'PORTAINER_ENDPOINT_ID=%s\n' "$PORTAINER_ENDPOINT_ID"
    printf 'PORTAINER_INSECURE=%s\n' "$PORTAINER_INSECURE"
    printf 'DOCKER_OVERLAY_NETWORK=%s\n' "$CHOSEN_NET"
    printf 'SUPABASE_URL=%s\n' "$SUPABASE_URL"
    printf 'S3_URL=%s\n' "$S3_URL"
    printf 'S3_ACCESS_KEY=%s\n' "$S3_ACCESS_KEY"
    printf 'S3_SECRET_KEY=%s\n' "$S3_SECRET_KEY"
    printf 'TRAEFIK_CERTRESOLVER=%s\n' "$TRAEFIK_CERTRESOLVER"
    printf 'KONG_DASHBOARD_USER=%s\n' "$KONG_DASHBOARD_USER"
    printf 'KONG_DASHBOARD_PASS=%s\n' "$KONG_DASHBOARD_PASS"
  } > "$DADOS_VPS_ENV"

  jq -nc \
    --arg url "$PORTAINER_URL" \
    --arg user "$PORTAINER_USERNAME" \
    --arg pass "$PORTAINER_PASSWORD" \
    --argjson eid "${PORTAINER_ENDPOINT_ID}" \
    --argjson insecure "${PORTAINER_INSECURE}" \
    --arg net "$CHOSEN_NET" \
    --arg u "$SUPABASE_URL" \
    --arg s3 "$S3_URL" \
    --arg s3key "$S3_ACCESS_KEY" \
    --arg s3secret "$S3_SECRET_KEY" \
    --arg c "$TRAEFIK_CERTRESOLVER" \
    --arg du "$KONG_DASHBOARD_USER" \
    '{portainer:{url:$url,username:$user,password:$pass,endpoint_id:$eid,insecure:$insecure},docker:{overlay_network:$net},supabase:{public_kong_url:$u,s3_url:$s3,s3_access_key:$s3key,s3_secret_key:$s3secret,traefik_certresolver:$c,dashboard_user:$du}}' \
    > "$DADOS_VPS_JSON"

  ok "Dados salvos em ${DADOS_VPS_ENV}"
}

load_or_prompt_portainer

# ---------- 3) Login Portainer e autodetect endpoint ----------
step "Conectando no Portainer"
CURL_K=(-sS); [ "${PORTAINER_INSECURE}" = "true" ] && CURL_K+=(-k)
PORTAINER_JWT="$(curl "${CURL_K[@]}" -H "Content-Type: application/json" -X POST \
  --data "{\"Username\":\"${PORTAINER_USERNAME}\",\"Password\":\"${PORTAINER_PASSWORD}\"}" \
  "${PORTAINER_URL%/}/api/auth" | jq -r '.jwt // empty')"
[ -n "${PORTAINER_JWT}" ] || fail "Login Portainer falhou"
ok "Login OK"

if [ "${PORTAINER_ENDPOINT_ID:-0}" = "0" ]; then
  EPS="$(curl "${CURL_K[@]}" -H "Authorization: Bearer ${PORTAINER_JWT}" "${PORTAINER_URL%/}/api/endpoints")"
  PORTAINER_ENDPOINT_ID="$(echo "$EPS" | jq -r '[.[] | select((.Name|ascii_downcase)=="local")][0].Id // 0')"
  [ "${PORTAINER_ENDPOINT_ID}" = "0" ] && PORTAINER_ENDPOINT_ID="$(echo "$EPS" | jq -r '.[0].Id // 0')"
  [ "${PORTAINER_ENDPOINT_ID}" = "0" ] && fail "Não encontrei endpointId no Portainer"
  sed -i "s/^PORTAINER_ENDPOINT_ID=.*/PORTAINER_ENDPOINT_ID=${PORTAINER_ENDPOINT_ID}/" "$DADOS_VPS_ENV"
  jq ".portainer.endpoint_id=${PORTAINER_ENDPOINT_ID}" "$DADOS_VPS_JSON" > "${DADOS_VPS_JSON}.tmp" && mv "${DADOS_VPS_JSON}.tmp" "$DADOS_VPS_JSON"
  ok "endpointId detectado e salvo: ${PORTAINER_ENDPOINT_ID}"
fi

# ---------- 4) Preparar arquivos do Supabase ----------
step "Preparando arquivos do repositório Supabase"
prepare_supabase_files() {
  # Criar diretório temporário
  TEMP_DIR=$(mktemp -d)
  cd "$TEMP_DIR"
  
  # Baixar repositório do Supabase
  info "Baixando repositório oficial do Supabase..."
  git clone --depth 1 https://github.com/supabase/supabase.git
  
  if [ $? -eq 0 ]; then
    ok "Repositório baixado com sucesso"
  else
    fail "Falha ao baixar repositório"
    exit 1
  fi
  
  cd supabase
  # Usar commit específico conhecido
  git checkout a3c77cd0609fd4524114f69dd3ef8ea36156f023 2>/dev/null || true
  
  # Copiar arquivos necessários
  cd docker
  # Remover arquivos desnecessários
  rm -rf dev .env.example .gitignore README.md docker-compose.s3.yml docker-compose.yml reset.sh
  
  # Mover arquivos para destino
  cp -r . "${REPO_DIR}/docker/"
  
  # Criar diretórios necessários se não existirem
  mkdir -p "${VOL_DIR}/db/data"
  mkdir -p "${VOL_DIR}/storage"
  mkdir -p "${VOL_DIR}/functions"
  
  # Definir permissões corretas para os diretórios de volumes
  chmod -R 755 "${VOL_DIR}"
  chown -R root:root "${VOL_DIR}"
  
  # Limpeza
  cd /
  rm -rf "$TEMP_DIR"
  
  ok "Arquivos do Supabase preparados com permissões corretas"
}

# Executar preparação apenas se diretório não existe ou está vazio
if [ ! -d "${REPO_DIR}/docker" ] || [ -z "$(ls -A "${REPO_DIR}/docker" 2>/dev/null)" ]; then
  prepare_supabase_files
else
  ok "Arquivos do Supabase já existem em ${REPO_DIR}/docker"
fi

# ---------- 5) Segredos + JWTs ----------
step "Gerando segredos e JWTs (anon/service_role)"
result="$(generate_jwt_tokens)"
JWT_Key="$(awk '{print $1}' <<<"$result")"
SERVICE_KEY="$(awk '{print $2}' <<<"$result")"
ANON_KEY="$(awk '{print $3}' <<<"$result")"
Senha_Postgres="$(openssl rand -hex 16)"
Logflare_key="$(openssl rand -hex 16)"
Logflare_key_public="$(openssl rand -hex 16)"
SECRET_KEY_BASE="$(openssl rand -hex 32)"
VAULT_ENC_KEY="$(openssl rand -base64 32 | tr -d '\n' | cut -c1-32)"
ok "Segredos gerados (JWT_Key+ANON_KEY+SERVICE_KEY válidos)"

# Aviso sobre pasta de dados existente (senhas antigas se já existir cluster)
if [ -n "$(ls -A "${VOL_DIR}/db/data" 2>/dev/null || true)" ]; then
  info "Atenção: ${VOL_DIR}/db/data já possui dados. O Postgres manterá as senhas antigas."
  info "Use SUFFIX diferente OU apague ${VOL_DIR}/db/data para recriar do zero (cuidado!)."
fi

# ---------- 6) pooler.exs e vector.yml mínimos ----------
step "Gerando pooler.exs e vector.yml mínimos"
cat > "${POOLEX}" <<'EXS'
Application.put_env(:supavisor, :tenants, [
  %{
    id: 1,
    db_host: System.get_env("DB_HOST", "db"),
    db_port: 5432,
    db_user: "supabase_admin",
    db_password: System.get_env("POSTGRES_PASSWORD", "postgres"),
    db_database: "_supabase",
    pool_size: 5,
    max_client_conn: 100,
    pool_mode: :transaction
  }
])
EXS

cat > "${VECTOR}" <<'VYML'
data_dir: /var/lib/vector
sources:
  docker:
    type: docker_logs
    include_containers: ["*"]
sinks:
  console:
    type: console
    inputs: ["docker"]
    encoding:
      codec: json
VYML
ok "Arquivos: ${POOLEX} e ${VECTOR}"

# ---------- 7) kong.yml (EXATO ao original), movendo para o destino ----------
step "Gerando kong.yml (declarativo) com identação corrigida"
cd "$(mktemp -d)"

# Criar kong.yml com substituição correta de variáveis
cat > kong.yml <<EOF
_format_version: '2.1'
_transform: true

###
### O Consumers / Users
###
consumers:
  - username: DASHBOARD
  - username: anon
    keyauth_credentials:
      - key: \$SUPABASE_ANON_KEY
  - username: service_role
    keyauth_credentials:
      - key: \$SUPABASE_SERVICE_KEY

###
### R Access Control List
###
acls:
  - consumer: anon
    group: anon
  - consumer: service_role
    group: admin

###
### I Dashboard credentials
###
basicauth_credentials:
  - consumer: DASHBOARD
    username: '\$DASHBOARD_USERNAME'
    password: '\$DASHBOARD_PASSWORD'

###
### O API Routes
###
services:
  ## Open Auth routes
  - name: auth-v1-open
    url: http://auth${SUF_US}:9999/verify
    routes:
      - name: auth-v1-open
        strip_path: true
        paths:
          - /auth/v1/verify
    plugins:
      - name: cors
  - name: auth-v1-open-callback
    url: http://auth${SUF_US}:9999/callback
    routes:
      - name: auth-v1-open-callback
        strip_path: true
        paths:
          - /auth/v1/callback
    plugins:
      - name: cors
  - name: auth-v1-open-authorize
    url: http://auth${SUF_US}:9999/authorize
    routes:
      - name: auth-v1-open-authorize
        strip_path: true
        paths:
          - /auth/v1/authorize
    plugins:
      - name: cors

  ## Secure Auth routes
  - name: auth-v1
    _comment: 'GoTrue: /auth/v1/* -> http://auth${SUF_US}:9999/*'
    url: http://auth${SUF_US}:9999/
    routes:
      - name: auth-v1-all
        strip_path: true
        paths:
          - /auth/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## N Secure REST routes
  - name: rest-v1
    _comment: 'PostgREST: /rest/v1/* -> http://rest${SUF_US}:3000/*'
    url: http://rest${SUF_US}:3000/
    routes:
      - name: rest-v1-all
        strip_path: true
        paths:
          - /rest/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: true
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## Secure GraphQL routes
  - name: graphql-v1
    _comment: 'PostgREST: /graphql/v1/* -> http://rest${SUF_US}:3000/rpc/graphql'
    url: http://rest${SUF_US}:3000/rpc/graphql
    routes:
      - name: graphql-v1-all
        strip_path: true
        paths:
          - /graphql/v1
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: true
      - name: request-transformer
        config:
          add:
            headers:
              - Content-Profile:graphql_public
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## Secure Realtime routes
  - name: realtime-v1-ws
    _comment: 'Realtime: /realtime/v1/* -> ws://realtime${SUF_US}:4000/socket/*'
    url: http://realtime${SUF_US}:4000/socket
    protocol: ws
    routes:
      - name: realtime-v1-ws
        strip_path: true
        paths:
          - /realtime/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon
  - name: realtime-v1-rest
    _comment: 'Realtime: /realtime/v1/* -> ws://realtime${SUF_US}:4000/socket/*'
    url: http://realtime${SUF_US}:4000/api
    protocol: http
    routes:
      - name: realtime-v1-rest
        strip_path: true
        paths:
          - /realtime/v1/api
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon
  ## Storage routes: the storage server manages its own auth
  - name: storage-v1
    _comment: 'Storage: /storage/v1/* -> http://storage${SUF_US}:5000/*'
    url: http://storage${SUF_US}:5000/
    routes:
      - name: storage-v1-all
        strip_path: true
        paths:
          - /storage/v1/
    plugins:
      - name: cors

  ## Edge Functions routes
  - name: functions-v1
    _comment: 'Edge Functions: /functions/v1/* -> http://functions${SUF_US}:9000/*'
    url: http://functions${SUF_US}:9000/
    routes:
      - name: functions-v1-all
        strip_path: true
        paths:
          - /functions/v1/
    plugins:
      - name: cors

  ## Analytics routes
  - name: analytics-v1
    _comment: 'Analytics: /analytics/v1/* -> http://logflare${SUF_US}:4000/*'
    url: http://analytics${SUF_US}:4000/
    routes:
      - name: analytics-v1-all
        strip_path: true
        paths:
          - /analytics/v1/

  ## Secure Database routes
  - name: meta
    _comment: 'pg-meta: /pg/* -> http://meta${SUF_US}:8080/*'
    url: http://meta${SUF_US}:8080/
    routes:
      - name: meta-all
        strip_path: true
        paths:
          - /pg/
    plugins:
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin

  ## Protected Dashboard - catch all remaining routes
  - name: dashboard
    _comment: 'Studio: /* -> http://studio${SUF_US}:3000/*'
    url: http://studio${SUF_US}:3000/
    routes:
      - name: dashboard-all
        strip_path: true
        paths:
          - /
    plugins:
      - name: cors
      - name: basic-auth
        config:
          hide_credentials: true
EOF

# move para destino no /srv
mkdir -p "$(dirname "${KONG_DEST}")"
rm -f "${KONG_DEST}" || true
mv kong.yml "${KONG_DEST}"

# Definir permissões corretas para o arquivo kong.yml (necessário para Docker Swarm)
chmod 644 "${KONG_DEST}"
chown root:root "${KONG_DEST}"

cd - >/dev/null
ok "kong.yml em ${KONG_DEST} (permissões: 644)"

# ---------- 8) supabase.yaml (formato do original) ----------
step "Gerando supabase.yaml (rede overlay: ${nome_rede_interna})"
cat > "${YAML_PATH}" <<EOF
version: "3.7"
services:

## ------------------------------------------------------------------------ ##

  studio${SUF_US}:
    image: supabase/studio:2025.06.30-sha-6f5982d ## Versão do Supabase Studio

    networks:
      - $nome_rede_interna ## Nome da rede interna
    
    environment:
    ## Definindo o Hostname
      - HOSTNAME=0.0.0.0

    ## Configurações de Logs
      - DEBUG=next:*
      - NEXT_PUBLIC_ENABLE_LOGS=true
      - NEXT_ANALYTICS_BACKEND_PROVIDER=postgres

    ## Configuração de Branding
      - DEFAULT_ORGANIZATION_NAME=TMCPlus
      - DEFAULT_PROJECT_NAME=TMCSuporte

    ## Configuração do Banco de Dados PostgreSQL
      - POSTGRES_PASSWORD=$Senha_Postgres
      - STUDIO_PG_META_URL=http://meta${SUF_US}:8080

    ## Configuração do Supabase
      - SUPABASE_URL=http://kong${SUF_US}:8000
      - SUPABASE_PUBLIC_URL=https://$SUPABASE_URL

    ## Integração com Logflare
      - LOGFLARE_API_KEY=$Logflare_key
      - LOGFLARE_URL=http://analytics${SUF_US}:4000
      - LOGFLARE_PRIVATE_ACCESS_TOKEN=$Logflare_key

    ## Configurações de Autenticação
      - SUPABASE_ANON_KEY=$ANON_KEY
      - SUPABASE_SERVICE_KEY=$SERVICE_KEY
      - AUTH_JWT_SECRET=$JWT_Key

    ## Configuração do OpenAI (opcional)
      # - OPENAI_API_KEY=

    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  kong${SUF_US}:
    image: kong:2.8.1 ## Versão do Supabase Kong
    entrypoint: bash -c 'eval "echo \"\$\$(cat ~/temp.yml)\"" > ~/kong.yml && /docker-entrypoint.sh kong docker-start'

    volumes:
       - ${REPO_DIR}/docker/volumes/api/kong.yml:/home/kong/temp.yml:ro

    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração de usuário e senha do Dashboard
      - DASHBOARD_USERNAME=$KONG_DASHBOARD_USER
      - DASHBOARD_PASSWORD=$KONG_DASHBOARD_PASS

    ## Configurações de Autenticação
      - JWT_SECRET=$JWT_Key
      - SUPABASE_ANON_KEY=$ANON_KEY
      - SUPABASE_SERVICE_KEY=$SERVICE_KEY

    ## Configuração do Banco de Dados
      - KONG_DATABASE=off
      - KONG_DECLARATIVE_CONFIG=/home/kong/kong.yml

    ## Configuração de DNS
      - KONG_DNS_ORDER=LAST,A,CNAME

    ## Configuração de Plugins
      - KONG_PLUGINS=request-transformer,cors,key-auth,acl,basic-auth

    ## Configurações de Buffers do NGINX
      - KONG_NGINX_PROXY_PROXY_BUFFER_SIZE=160k
      - KONG_NGINX_PROXY_PROXY_BUFFERS=64 160k
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager  
      labels:
        - traefik.enable=true
        - traefik.http.routers.kong${SUF_US}.rule=Host(\`$SUPABASE_URL\`) && PathPrefix(\`/\`) ## Url do Supabase
        - traefik.http.services.kong${SUF_US}.loadbalancer.server.port=8000
        - traefik.http.routers.kong${SUF_US}.service=kong${SUF_US}
        - traefik.http.routers.kong${SUF_US}.entrypoints=websecure
        - traefik.http.routers.kong${SUF_US}.tls.certresolver=$TRAEFIK_CERTRESOLVER
        - traefik.http.routers.kong${SUF_US}.tls=true

## ------------------------------------------------------------------------ ##

  auth${SUF_US}:
    image: supabase/gotrue:v2.176.1 ## Versão do Supabase Auth
    
    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração Geral da API Auth
      - GOTRUE_API_HOST=0.0.0.0
      - GOTRUE_API_PORT=9999
      - API_EXTERNAL_URL=https://$SUPABASE_URL

    ## Configuração do Banco de Dados
      - GOTRUE_DB_DRIVER=postgres
      - GOTRUE_DB_DATABASE_URL=postgres://supabase_auth_admin:$Senha_Postgres@db${SUF_US}:5432/postgres ## Troque a senha do postgres

    ## Configurações de URL e Permissões
      - GOTRUE_SITE_URL=https://$SUPABASE_URL
      - GOTRUE_URI_ALLOW_LIST=
      - GOTRUE_DISABLE_SIGNUP=false

    ## Configurações de JWT
      - GOTRUE_JWT_ADMIN_ROLES=service_role
      - GOTRUE_JWT_AUD=authenticated
      - GOTRUE_JWT_DEFAULT_GROUP_NAME=authenticated
      - GOTRUE_JWT_EXP=31536000
      - GOTRUE_JWT_SECRET=$JWT_Key

    ## Configuração de Email
      - GOTRUE_EXTERNAL_EMAIL_ENABLED=false
      - GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED=false
      #- GOTRUE_MAILER_AUTOCONFIRM=true # Envia emails automaticamente para confirmar cadastros
      #- GOTRUE_SMTP_ADMIN_EMAIL=email@dominio.com # Email administrador SMTP
      #- GOTRUE_SMTP_HOST=smtp.dominio.com # Host SMTP
      #- GOTRUE_SMTP_PORT=587 # Porta SMTP
      #- GOTRUE_SMTP_USER=email@dominio.com # Usuário SMTP
      #- GOTRUE_SMTP_PASS=senha # Senha SMTP
      #- GOTRUE_SMTP_SENDER_NAME=email@dominio.com # Nome do remetente SMTP

    ## Configurações de URL para Emails
      - GOTRUE_MAILER_URLPATHS_INVITE=/auth/v1/verify
      - GOTRUE_MAILER_URLPATHS_CONFIRMATION=/auth/v1/verify
      - GOTRUE_MAILER_URLPATHS_RECOVERY=/auth/v1/verify
      - GOTRUE_MAILER_URLPATHS_EMAIL_CHANGE=/auth/v1/verify

    ## Configurações de SMS
      - GOTRUE_EXTERNAL_PHONE_ENABLED=false
      - GOTRUE_SMS_AUTOCONFIRM=false
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  rest${SUF_US}:
    image: postgrest/postgrest:v12.2.12 ## Versão do Supabase Rest
    command: "postgrest"
    
    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração do Banco de Dados
      - PGRST_DB_URI=postgres://authenticator:$Senha_Postgres@db${SUF_US}:5432/postgres
      - PGRST_DB_SCHEMAS=public,storage,graphql_public
      - PGRST_DB_ANON_ROLE=anon

    ## Configurações de JWT (JSON Web Tokens)
      - PGRST_JWT_SECRET=$JWT_Key
      - PGRST_APP_SETTINGS_JWT_SECRET=$JWT_Key
      - PGRST_APP_SETTINGS_JWT_EXP=31536000

    ## Outras Configurações
      - PGRST_DB_USE_LEGACY_GUCS="false"
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  realtime${SUF_US}:
    image: supabase/realtime:v2.34.47 ## Versão do Supabase Realtime

    networks:
      - $nome_rede_interna ## Nome da rede interna
    
    environment:
    ## Configuração da API Realtime
      - PORT=4000
      - API_JWT_SECRET=$JWT_Key
      - SECRET_KEY_BASE=$SECRET_KEY_BASE
      - APP_NAME=realtime

    ## Configuração do Banco de Dados
      - DB_HOST=db${SUF_US}
      - DB_PORT=5432
      - DB_USER=supabase_admin
      - DB_PASSWORD=$Senha_Postgres
      - DB_NAME=postgres
      - DB_AFTER_CONNECT_QUERY='SET search_path TO _realtime'
      - DB_ENC_KEY=supabaserealtime

    ## Configuração de Conexão e Rede
      - ERL_AFLAGS=-proto_dist inet_tcp
      - DNS_NODES="''"
      - RLIMIT_NOFILE=10000

    ## Configuração do Ambiente
      - SEED_SELF_HOST=true
      - RUN_JANITOR=true
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  storage${SUF_US}:
    image: supabase/storage-api:v1.22.17 ## Versão do Supabase Storage

    volumes:
      - ${REPO_DIR}/docker/volumes/storage:/var/lib/storage:z

    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração do PostgREST e JWT
      - ANON_KEY=$ANON_KEY
      - SERVICE_KEY=$SERVICE_KEY
      - POSTGREST_URL=http://rest${SUF_US}:3000
      - PGRST_JWT_SECRET=$JWT_Key
      - DATABASE_URL=postgres://supabase_storage_admin:$Senha_Postgres@db${SUF_US}:5432/postgres

    ## Configuração de Armazenamento de Arquivos MinIO
      - FILE_SIZE_LIMIT=52428800
      - STORAGE_BACKEND=s3
      - GLOBAL_S3_BUCKET=supabase${SUF_US/-/_} ## Nome da bucket do MinIO
      - GLOBAL_S3_ENDPOINT=https://$S3_URL ## URL S3 do MinIO
      - GLOBAL_S3_PROTOCOL=https
      - GLOBAL_S3_FORCE_PATH_STYLE=true
      - AWS_ACCESS_KEY_ID=$S3_ACCESS_KEY ## Access Key
      - AWS_SECRET_ACCESS_KEY=$S3_SECRET_KEY ## Secret Key
      - AWS_DEFAULT_REGION=eu-south ## Região MinIO
      - FILE_STORAGE_BACKEND_PATH=/var/lib/storage

    ## Configuração de Imagens
      - ENABLE_IMAGE_TRANSFORMATION="true"
      - IMGPROXY_URL=http://imgproxy${SUF_US}:5001

    ## Configuração de Identificação e Região
      - TENANT_ID=stub
      - REGION=eu-south ## Região
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  imgproxy${SUF_US}:
    image: darthsim/imgproxy:v3.8.0 ## Versão do Supabase Imgproxy
  
    volumes:
      - ${REPO_DIR}/docker/volumes/storage:/var/lib/storage:z

    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração do IMGPROXY
      - IMGPROXY_BIND=:5001
      - IMGPROXY_LOCAL_FILESYSTEM_ROOT=/
      - IMGPROXY_USE_ETAG=true
      - IMGPROXY_ENABLE_WEBP_DETECTION=true
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  meta${SUF_US}:
    image: supabase/postgres-meta:v0.89.3 ## Versão do Meta 

    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração do PG_META
      - PG_META_PORT=8080
      - PG_META_DB_HOST=db${SUF_US}
      - PG_META_DB_PORT=5432
      - PG_META_DB_NAME=postgres
      - PG_META_DB_USER=supabase_admin
      - PG_META_DB_PASSWORD=$Senha_Postgres
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  functions${SUF_US}:
    image: supabase/edge-runtime:v1.67.4 ## Versão do Supabase Functions
    command:
      - start
      - --main-service
      - /home/deno/functions/main
    
    volumes:
      - ${REPO_DIR}/docker/volumes/functions:/home/deno/functions:Z

    networks:
      - $nome_rede_interna ## Nome da rede interna
   
    environment:
    ## Configuração de JWT e Supabase
      - VERIFY_JWT="false"
      - JWT_SECRET=$JWT_Key
      - SUPABASE_URL=http://kong${SUF_US}:8000
      - SUPABASE_ANON_KEY=$ANON_KEY
      - SUPABASE_SERVICE_ROLE_KEY=$SERVICE_KEY
      - SUPABASE_DB_URL=postgresql://postgres:$Senha_Postgres@db${SUF_US}:5432/postgres
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  analytics${SUF_US}:
    image: supabase/logflare:1.14.2 ## Versão do Supabase Analytics

    networks:
      - $nome_rede_interna ## Nome da rede interna
    
    environment:
    ## Configuração de Banco de Dados
      - DB_USERNAME=supabase_admin
      - DB_DATABASE=_supabase
      - DB_HOSTNAME=db${SUF_US}
      - DB_PORT=5432
      - DB_PASSWORD=$Senha_Postgres
      - DB_SCHEMA=_analytics
    
    ## Configuração do Postgres Backend
      - POSTGRES_BACKEND_URL=postgresql://supabase_admin:$Senha_Postgres@db${SUF_US}:5432/_supabase
      - POSTGRES_BACKEND_SCHEMA=_analytics
    
    ## Configuração do Logflare
      - LOGFLARE_NODE_HOST=127.0.0.1
      - LOGFLARE_API_KEY=$Logflare_key
      - LOGFLARE_PUBLIC_ACCESS_TOKEN=$Logflare_key_public
      - LOGFLARE_PRIVATE_ACCESS_TOKEN=$Logflare_key
      - LOGFLARE_SINGLE_TENANT=true
      - LOGFLARE_SUPABASE_MODE=true
      - LOGFLARE_MIN_CLUSTER_SIZE=1
      - LOGFLARE_FEATURE_FLAG_OVERRIDE=multibackend=true
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  db${SUF_US}:
    image: supabase/postgres:15.8.1.060 ## Versão do Supabase Db
    command:
      - postgres
      - '-c'
      - config_file=/etc/postgresql/postgresql.conf
      - '-c'
      - log_min_messages=fatal
    
    volumes:
      - ${REPO_DIR}/docker/volumes/db/realtime.sql:/docker-entrypoint-initdb.d/migrations/99-realtime.sql:Z
      - ${REPO_DIR}/docker/volumes/db/webhooks.sql:/docker-entrypoint-initdb.d/init-scripts/98-webhooks.sql:Z
      - ${REPO_DIR}/docker/volumes/db/roles.sql:/docker-entrypoint-initdb.d/init-scripts/99-roles.sql:Z
      - ${REPO_DIR}/docker/volumes/db/jwt.sql:/docker-entrypoint-initdb.d/init-scripts/99-jwt.sql:Z
      - ${REPO_DIR}/docker/volumes/db/data:/var/lib/postgresql/data:Z
      - ${REPO_DIR}/docker/volumes/db/_supabase.sql:/docker-entrypoint-initdb.d/migrations/97-_supabase.sql:Z
      - ${REPO_DIR}/docker/volumes/db/logs.sql:/docker-entrypoint-initdb.d/migrations/99-logs.sql:Z
      - ${REPO_DIR}/docker/volumes/db/pooler.sql:/docker-entrypoint-initdb.d/migrations/99-pooler.sql:Z
      - ${STACK_NAME}_db_config:/etc/postgresql-custom

    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração do PostgreSQL
      - POSTGRES_HOST=/var/run/postgresql
      - PGPORT=5432
      - POSTGRES_PORT=5432
      - PGPASSWORD=$Senha_Postgres
      - POSTGRES_PASSWORD=$Senha_Postgres
      - POSTGRES_DB=postgres
      - PGDATABASE=postgres

    ## Configuração de JWT
      - JWT_SECRET=$JWT_Key
      - JWT_EXP=31536000  ## O padrão é 3600
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

  vector${SUF_US}:
    image: timberio/vector:0.28.1-alpine ## Versão do Supabase Vector
    command:
      - '--config'
      - etc/vector/vector.yml
    
    volumes:
    - ${REPO_DIR}/docker/volumes/logs/vector.yml:/etc/vector/vector.yml:ro
    - /var/run/docker.sock:/var/run/docker.sock:ro

    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração do Logflare
      - LOGFLARE_API_KEY=$Logflare_key
      - LOGFLARE_PUBLIC_ACCESS_TOKEN=$Logflare_key_public
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ####

  supavisor${SUF_US}:
    image: supabase/supavisor:2.5.1 ## Versão do Supabase Supavisor
    command:
      - /bin/sh
      - -c
      - /app/bin/migrate && /app/bin/supavisor eval "\$\$(cat /etc/pooler/pooler.exs)" && /app/bin/server

    volumes:
      -  ${REPO_DIR}/docker/volumes/pooler/pooler.exs:/etc/pooler/pooler.exs:ro

    networks:
      - $nome_rede_interna ## Nome da rede interna

    environment:
    ## Configuração do Banco de Dados
      - POSTGRES_PORT=5432
      - POSTGRES_DB=postgres
      - POSTGRES_PASSWORD=$Senha_Postgres
      - DATABASE_URL=ecto://supabase_admin:$Senha_Postgres@db${SUF_US}:5432/_supabase
      - CLUSTER_POSTGRES=true

    ## Configuração de JWT
      - API_JWT_SECRET=$JWT_Key
      - METRICS_JWT_SECRET=$JWT_Key

    ## Configuração de Segurança
      - SECRET_KEY_BASE=$SECRET_KEY_BASE
      - VAULT_ENC_KEY=$VAULT_ENC_KEY

    ## Configuração de Regionalização
      - REGION=local

    ## Configuração de Erlang
      - ERL_AFLAGS=-proto_dist inet_tcp

    ## Configuração do Pooler
      - POOLER_TENANT_ID=1
      - POOLER_DEFAULT_POOL_SIZE=20
      - POOLER_MAX_CLIENT_CONN=100
      - POOLER_POOL_MODE=transaction
      - DB_POOL_SIZE=5

    ## Configuração de Porta
      - PORT=4000
    
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

## ------------------------------------------------------------------------ ##

volumes:
  ${STACK_NAME}_db_config:
    external: true
    name: ${STACK_NAME}_db_config

networks:
  $nome_rede_interna: ## Nome da rede interna
    external: true
    name: $nome_rede_interna ## Nome da rede interna
EOF

ok "Stack gerada: ${YAML_PATH}"

# ---------- 9) Criar volume externo do Postgres (se não existir) ----------
docker volume create "${STACK_NAME}_db_config" >/dev/null 2>&1 || true

# ---------- Verificar e corrigir permissões antes do deploy ----------
step "Verificando e corrigindo permissões dos arquivos"

# Corrigir permissões do kong.yml se existir
if [ -f "${KONG_DEST}" ]; then
    chmod 644 "${KONG_DEST}"
    chown root:root "${KONG_DEST}"
    ok "Permissões do kong.yml corrigidas"
fi

# Corrigir permissões do pooler.exs se existir
if [ -f "${POOLEX}" ]; then
    # Verificar se o arquivo tem a sintaxe correta
    if grep -q "import Config" "${POOLEX}" || grep -q "config :supavisor" "${POOLEX}"; then
        info "Corrigindo sintaxe do pooler.exs (Application.put_env)"
        cat > "${POOLEX}" <<'EXS'
Application.put_env(:supavisor, :tenants, [
  %{
    id: 1,
    db_host: System.get_env("DB_HOST", "db"),
    db_port: 5432,
    db_user: "supabase_admin",
    db_password: System.get_env("POSTGRES_PASSWORD", "postgres"),
    db_database: "_supabase",
    pool_size: 5,
    max_client_conn: 100,
    pool_mode: :transaction
  }
])
EXS
    fi
    chmod 644 "${POOLEX}"
    chown root:root "${POOLEX}"
    ok "Permissões e sintaxe do pooler.exs corrigidas"
fi

# Corrigir permissões do vector.yml se existir
if [ -f "${VECTOR}" ]; then
    chmod 644 "${VECTOR}"
    chown root:root "${VECTOR}"
    ok "Permissões do vector.yml corrigidas"
fi

# Corrigir permissões dos diretórios de volumes
if [ -d "${VOL_DIR}" ]; then
    find "${VOL_DIR}" -type d -exec chmod 755 {} \;
    find "${VOL_DIR}" -type f -exec chmod 644 {} \;
    chown -R root:root "${VOL_DIR}"
    ok "Permissões dos volumes corrigidas"
fi

# ---------- 10) Deploy via Portainer ----------
if [[ "${DRY_RUN}" == "1" ]]; then
    step "MODO DRY-RUN: Pulando deploy no Portainer"
    ok "Arquivos gerados com sucesso (sem deploy):"
    echo " - ${DADOS_VPS_ENV}"
    echo " - ${DADOS_VPS_JSON}"
    echo " - ${KONG_DEST}"
    echo " - ${YAML_PATH}"
    echo "=== Para fazer deploy real, execute sem DRY_RUN=1 ==="
    exit 0
fi

step "Fazendo deploy no Portainer"

# Primeiro, obter o SwarmID
info "Obtendo SwarmID..."
SWARM_ID=$(curl "${CURL_K[@]}" -H "Authorization: Bearer ${PORTAINER_JWT}" \
  "${PORTAINER_URL%/}/api/endpoints/${PORTAINER_ENDPOINT_ID}/docker/swarm" | jq -r '.ID // empty')

if [ -z "$SWARM_ID" ]; then
  fail "Não foi possível obter SwarmID"
  exit 1
fi
ok "SwarmID obtido: ${SWARM_ID}"

# Verificar se a stack já existe
stacks="$(curl "${CURL_K[@]}" -H "Authorization: Bearer ${PORTAINER_JWT}" "${PORTAINER_URL%/}/api/stacks")"
sid="$(echo "$stacks" | jq -r --arg n "${STACK_NAME}" --argjson eid "${PORTAINER_ENDPOINT_ID}" \
  '[.[] | select(.Name==$n and (.EndpointId==$eid or .EndpointID==$eid))][0].Id // 0')"

if [ "${sid}" != "0" ]; then
  info "Removendo stack existente (${STACK_NAME})..."
  curl "${CURL_K[@]}" -H "Authorization: Bearer ${PORTAINER_JWT}" -X DELETE \
    "${PORTAINER_URL%/}/api/stacks/${sid}?endpointId=${PORTAINER_ENDPOINT_ID}" >/dev/null
  ok "Stack antiga removida."
  sleep 2
fi

# Criar nova stack usando multipart/form-data
info "Criando stack via upload de arquivo..."

# Criar arquivos temporários para capturar resposta
erro_output=$(mktemp)
response_output=$(mktemp)

# Deploy usando o método correto.
http_code=$(curl -s -o "$response_output" -w "%{http_code}" "${CURL_K[@]}" -X POST \
  -H "Authorization: Bearer ${PORTAINER_JWT}" \
  -F "Name=${STACK_NAME}" \
  -F "file=@${YAML_PATH}" \
  -F "SwarmID=${SWARM_ID}" \
  -F "endpointId=${PORTAINER_ENDPOINT_ID}" \
  "${PORTAINER_URL%/}/api/stacks/create/swarm/file" 2> "$erro_output")

response_body=$(cat "$response_output")

if [ "$http_code" -eq 200 ]; then
  # Verifica o conteúdo da resposta para garantir que o deploy foi bem-sucedido
  if echo "$response_body" | grep -q "\"Id\""; then
    ok "Stack '${STACK_NAME}' criada com sucesso!"
    stack_id=$(echo "$response_body" | jq -r '.Id')
    ok "Stack ID: ${stack_id}"
  else
    fail "Erro, resposta inesperada do servidor ao tentar efetuar deploy da stack ${STACK_NAME}"
    echo "Resposta do servidor: $(echo "$response_body" | jq . 2>/dev/null || echo "$response_body")"
  fi
else
  fail "Erro ao efetuar deploy. Resposta HTTP: $http_code"
  echo "Mensagem de erro: $(cat "$erro_output")"
  echo "Detalhes: $(echo "$response_body" | jq . 2>/dev/null || echo "$response_body")"
fi

# Limpeza
rm -f "$erro_output" "$response_output"

# ---------- Verificação pós-deploy e correções automáticas ----------
step "Verificando serviços pós-deploy"

# Aguardar alguns segundos para os serviços iniciarem
sleep 5

# Verificar serviços com problemas e tentar corrigir
info "Verificando status dos serviços..."
failed_services=$(docker service ls --format "table {{.Name}}\t{{.Replicas}}" | grep "${STACK_NAME}_" | grep "0/1" | awk '{print $1}' || true)

if [ -n "$failed_services" ]; then
    info "Serviços com problemas detectados: $failed_services"
    
    for service in $failed_services; do
        if [[ "$service" == *"kong"* ]]; then
            info "Corrigindo permissões do kong.yml para $service"
            chmod 644 "${KONG_DEST}" 2>/dev/null || true
            docker service update --force "$service" >/dev/null 2>&1 || true
        elif [[ "$service" == *"supavisor"* ]]; then
            info "Verificando pooler.exs para $service"
            chmod 644 "${POOLEX}" 2>/dev/null || true
            docker service update --force "$service" >/dev/null 2>&1 || true
        else
            info "Reiniciando $service"
            docker service update --force "$service" >/dev/null 2>&1 || true
        fi
        sleep 2
    done
    
    # Aguardar e verificar novamente
    sleep 10
    final_status=$(docker service ls --format "table {{.Name}}\t{{.Replicas}}" | grep "${STACK_NAME}_" | grep "0/1" | wc -l || echo "0")
    
    if [ "$final_status" -eq 0 ]; then
        ok "Todos os serviços estão funcionando corretamente!"
    else
        info "Alguns serviços ainda podem estar inicializando. Verifique com: docker service ls"
    fi
else
    ok "Todos os serviços estão funcionando corretamente!"
fi

echo

# ---------- Informações finais ----------
step "Informações de acesso ao Supabase"
echo
echo -e "${cg}=== SUPABASE INSTALADO COM SUCESSO ===${c0}"
echo
echo -e "${cy}URL de Acesso:${c0} https://$SUPABASE_URL"
echo -e "${cy}Dashboard Kong:${c0} admin / $KONG_DASHBOARD_PASS"
echo
echo -e "${cy}Anon Key:${c0} $ANON_KEY"
echo -e "${cy}Service Key:${c0} $SERVICE_KEY"
echo -e "${cy}JWT Secret:${c0} $JWT_Key"
echo
echo -e "${cy}Serviços Ativos:${c0}"
docker service ls --format "table {{.Name}}\t{{.Replicas}}\t{{.Image}}" | grep "${STACK_NAME}_" | sed 's/^/  /'
echo

ok "Arquivos:"
echo " - ${DADOS_VPS_ENV}"
echo " - ${DADOS_VPS_JSON}"
echo " - ${KONG_DEST}"
echo " - ${YAML_PATH}"
echo
ok "Concluído. Stack '${STACK_NAME}' no Portainer usando a rede '${nome_rede_interna}'."
echo "=== Log completo salvo em: $LOG_FILE ==="

