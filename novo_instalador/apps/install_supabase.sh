#!/usr/bin/env bash
set -Eeuo pipefail

# Cores
VERDE='\033[0;32m'
AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'
NC='\033[0m'

info() { echo -e "${AMARELO}[INFO]${NC} $1"; }
ok() { echo -e "${VERDE}[OK]${NC} $1"; }
erro() { echo -e "${VERMELHO}[ERRO]${NC} $1"; }

# Função de espera
wait_stack() {
    local service_name="$1"
    info "Aguardando serviço $service_name iniciar..."
    local retries=0
    local max_retries=60
    
    while [ $retries -lt $max_retries ]; do
        if docker service ls --format "{{.Name}} {{.Replicas}}" | grep -q "$service_name"; then
            local replicas=$(docker service ls --format "{{.Name}} {{.Replicas}}" | grep "$service_name" | awk '{print $2}')
            local current=$(echo $replicas | cut -d/ -f1)
            local target=$(echo $replicas | cut -d/ -f2)
            
            if [ "$current" == "$target" ] && [ "$target" != "0" ]; then
                ok "Serviço $service_name está online ($replicas)."
                return 0
            fi
        fi
        sleep 5
        retries=$((retries+1))
        echo -n "."
    done
    erro "Timeout aguardando serviço $service_name."
    return 1
}

# Função de Spinner (Indicador de Progresso)
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -n " "
    while ps -p $pid > /dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Função para gerar JWTs
generate_jwt_tokens() {
    # Verificar dependências
    if ! command -v openssl &> /dev/null; then
        apt-get update && apt-get install -y openssl
    fi
    if ! command -v jq &> /dev/null; then
        apt-get update && apt-get install -y jq
    fi

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

    secret=$(openssl rand -hex 20)

    header=$(echo -n '{"alg":"HS256","typ":"JWT"}' | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
    
    payload_service_key_base64=$(echo -n "$payload_service_key" | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
    payload_anon_key_base64=$(echo -n "$payload_anon_key" | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

    signature_service_key=$(echo -n "$header.$payload_service_key_base64" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
    signature_anon_key=$(echo -n "$header.$payload_anon_key_base64" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

    token_service_key="$header.$payload_service_key_base64.$signature_service_key"
    token_anon_key="$header.$payload_anon_key_base64.$signature_anon_key"

    echo "$secret $token_service_key $token_anon_key"
}

# 1. Carregar Dados do Ambiente
clear
echo -e "${VERDE}=== Instalação Supabase (Docker Swarm) ===${NC}"
echo ""

DADOS_FILE="/root/dados_vps/dados_portainer"

if [ -f "$DADOS_FILE" ]; then
    info "Carregando configurações salvas..."
    PORTAINER_URL=$(grep "URL:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_USER=$(grep "User:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_PASS=$(grep "Pass:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_TOKEN=$(grep "Token:" "$DADOS_FILE" | awk '{print $2}')
    NOME_REDE=$(grep "Network:" "$DADOS_FILE" | awk '{print $2}')
    
    # Extrair domínio base
    BASE_DOMAIN=$(echo "$PORTAINER_URL" | sed -e 's|^[^/]*//||' -e 's|^[^.]*\.||')
    
    ok "Rede: $NOME_REDE"
    ok "Domínio Base: $BASE_DOMAIN"
else
    erro "Arquivo de configuração base não encontrado ($DADOS_FILE)."
    exit 1
fi

# 2. Coleta de Dados
echo ""
read -p "Subdomínio para o Supabase [padrão: supabase.$BASE_DOMAIN]: " INPUT_DOMAIN
SUPABASE_DOMAIN=${INPUT_DOMAIN:-supabase.$BASE_DOMAIN}

read -p "Usuário Dashboard [padrão: admin]: " INPUT_USER
SUPABASE_USER=${INPUT_USER:-admin}

read -p "Senha Dashboard [padrão: admin123]: " INPUT_PASS
SUPABASE_PASS=${INPUT_PASS:-admin123}

# 3. Preparação do Ambiente
info "Preparando diretórios e arquivos..."

BASE_DIR="/root/supabase"
if [ -d "$BASE_DIR" ]; then
    rm -r "$BASE_DIR"
fi
mkdir -p "$BASE_DIR"

# Clonar repositório oficial para obter os scripts de inicialização
info "Baixando scripts de inicialização do Supabase (isso pode demorar um pouco)..."
TEMP_DIR=$(mktemp -d)
# Usar filter=blob:none para reduzir o tamanho do download
git clone --filter=blob:none https://github.com/supabase/supabase.git "$TEMP_DIR/supabase" > /dev/null 2>&1 &
PID_GIT=$!
show_spinner $PID_GIT
wait $PID_GIT

if [ $? -eq 0 ]; then
    ok "Download concluído."
else
    erro "Falha no download do repositório."
    exit 1
fi

cd "$TEMP_DIR/supabase"
# Checkout no commit específico usado na referência para garantir compatibilidade
git checkout a3c77cd0609fd4524114f69dd3ef8ea36156f023 > /dev/null 2>&1

# Mover a pasta docker para o destino
mv docker "$BASE_DIR/docker"
cd "$BASE_DIR"
rm -rf "$TEMP_DIR"

# Limpar arquivos desnecessários
rm -rf "$BASE_DIR/docker/dev" "$BASE_DIR/docker/.env.example" "$BASE_DIR/docker/.gitignore" "$BASE_DIR/docker/README.md" "$BASE_DIR/docker/docker-compose.s3.yml" "$BASE_DIR/docker/docker-compose.yml" "$BASE_DIR/docker/reset.sh"

# Criar diretórios de dados
mkdir -p "$BASE_DIR/docker/volumes/db/data"
mkdir -p "$BASE_DIR/docker/volumes/storage"

# 4. Gerar Tokens e Senhas
info "Gerando chaves e tokens..."
read SECRET_KEY SERVICE_KEY ANON_KEY <<< $(generate_jwt_tokens)
DB_PASSWORD=$(openssl rand -hex 16)
LOGFLARE_KEY=$(openssl rand -hex 16)
SECRET_KEY_BASE=$(openssl rand -hex 32)
VAULT_ENC_KEY=$(openssl rand -base64 32 | tr -d '\n' | cut -c1-32)

# 5. Criar Configuração do Kong (kong.yml)
info "Criando configuração do Kong..."
cat > "$BASE_DIR/docker/volumes/api/kong.yml" <<EOL
_format_version: '2.1'
_transform: true

consumers:
  - username: DASHBOARD
  - username: anon
    keyauth_credentials:
      - key: $ANON_KEY
  - username: service_role
    keyauth_credentials:
      - key: $SERVICE_KEY

acls:
  - consumer: anon
    group: anon
  - consumer: service_role
    group: admin

basicauth_credentials:
  - consumer: DASHBOARD
    username: '$SUPABASE_USER'
    password: '$SUPABASE_PASS'

services:
  - name: auth-v1-open
    url: http://auth:9999/verify
    routes:
      - name: auth-v1-open
        strip_path: true
        paths:
          - /auth/v1/verify
    plugins:
      - name: cors
  - name: auth-v1-open-callback
    url: http://auth:9999/callback
    routes:
      - name: auth-v1-open-callback
        strip_path: true
        paths:
          - /auth/v1/callback
    plugins:
      - name: cors
  - name: auth-v1-open-authorize
    url: http://auth:9999/authorize
    routes:
      - name: auth-v1-open-authorize
        strip_path: true
        paths:
          - /auth/v1/authorize
    plugins:
      - name: cors

  - name: auth-v1
    url: http://auth:9999/
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

  - name: rest-v1
    url: http://rest:3000/
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

  - name: graphql-v1
    url: http://rest:3000/rpc/graphql
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

  - name: realtime-v1-ws
    url: http://realtime:4000/socket
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
    url: http://realtime:4000/api
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

  - name: storage-v1
    url: http://storage:5000/
    routes:
      - name: storage-v1-all
        strip_path: true
        paths:
          - /storage/v1/
    plugins:
      - name: cors

  - name: functions-v1
    url: http://functions:9000/
    routes:
      - name: functions-v1-all
        strip_path: true
        paths:
          - /functions/v1/
    plugins:
      - name: cors

  - name: analytics-v1
    url: http://analytics:4000/
    routes:
      - name: analytics-v1-all
        strip_path: true
        paths:
          - /analytics/v1/

  - name: meta
    url: http://meta:8080/
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

  - name: dashboard
    url: http://studio:3000/
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
EOL

# 6. Criar Stack Docker (docker-compose.yml)
info "Criando arquivo de stack..."
cat > "$BASE_DIR/docker-compose.yml" <<EOL
version: "3.7"
services:

  studio:
    image: supabase/studio:2025.06.30-sha-6f5982d
    networks:
      - $NOME_REDE
    environment:
      - HOSTNAME=0.0.0.0
      - DEBUG=next:*
      - NEXT_PUBLIC_ENABLE_LOGS=true
      - NEXT_ANALYTICS_BACKEND_PROVIDER=postgres
      - DEFAULT_ORGANIZATION_NAME=MinhaOrganizacao
      - DEFAULT_PROJECT_NAME=MeuProjeto
      - POSTGRES_PASSWORD=$DB_PASSWORD
      - STUDIO_PG_META_URL=http://meta:8080
      - SUPABASE_URL=http://kong:8000
      - SUPABASE_PUBLIC_URL=https://$SUPABASE_DOMAIN
      - LOGFLARE_API_KEY=$LOGFLARE_KEY
      - LOGFLARE_URL=http://analytics:4000
      - LOGFLARE_PRIVATE_ACCESS_TOKEN=$LOGFLARE_KEY
      - SUPABASE_ANON_KEY=$ANON_KEY
      - SUPABASE_SERVICE_KEY=$SERVICE_KEY
      - AUTH_JWT_SECRET=$SECRET_KEY
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  kong:
    image: kong:2.8.1
    entrypoint: bash -c 'eval "echo \"\$\$(cat ~/temp.yml)\"" > ~/kong.yml && /docker-entrypoint.sh kong docker-start'
    volumes:
       - $BASE_DIR/docker/volumes/api/kong.yml:/home/kong/temp.yml:ro
    networks:
      - $NOME_REDE
    environment:
      - DASHBOARD_USERNAME=$SUPABASE_USER
      - DASHBOARD_PASSWORD=$SUPABASE_PASS
      - JWT_SECRET=$SECRET_KEY
      - SUPABASE_ANON_KEY=$ANON_KEY
      - SUPABASE_SERVICE_KEY=$SERVICE_KEY
      - KONG_DATABASE=off
      - KONG_DECLARATIVE_CONFIG=/home/kong/kong.yml
      - KONG_DNS_ORDER=LAST,A,CNAME
      - KONG_PLUGINS=request-transformer,cors,key-auth,acl,basic-auth
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
        - traefik.http.routers.supabase.rule=Host(\`$SUPABASE_DOMAIN\`) && PathPrefix(\`/\`)
        - traefik.http.services.supabase.loadbalancer.server.port=8000
        - traefik.http.routers.supabase.service=supabase
        - traefik.http.routers.supabase.entrypoints=websecure
        - traefik.http.routers.supabase.tls.certresolver=letsencryptresolver
        - traefik.http.routers.supabase.tls=true

  auth:
    image: supabase/gotrue:v2.176.1
    networks:
      - $NOME_REDE
    environment:
      - GOTRUE_API_HOST=0.0.0.0
      - GOTRUE_API_PORT=9999
      - API_EXTERNAL_URL=https://$SUPABASE_DOMAIN
      - GOTRUE_DB_DRIVER=postgres
      - GOTRUE_DB_DATABASE_URL=postgres://supabase_auth_admin:$DB_PASSWORD@db:5432/postgres
      - GOTRUE_SITE_URL=https://$SUPABASE_DOMAIN
      - GOTRUE_URI_ALLOW_LIST=
      - GOTRUE_DISABLE_SIGNUP=false
      - GOTRUE_JWT_ADMIN_ROLES=service_role
      - GOTRUE_JWT_AUD=authenticated
      - GOTRUE_JWT_DEFAULT_GROUP_NAME=authenticated
      - GOTRUE_JWT_EXP=31536000
      - GOTRUE_JWT_SECRET=$SECRET_KEY
      - GOTRUE_EXTERNAL_EMAIL_ENABLED=false
      - GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED=false
      - GOTRUE_MAILER_URLPATHS_INVITE=/auth/v1/verify
      - GOTRUE_MAILER_URLPATHS_CONFIRMATION=/auth/v1/verify
      - GOTRUE_MAILER_URLPATHS_RECOVERY=/auth/v1/verify
      - GOTRUE_MAILER_URLPATHS_EMAIL_CHANGE=/auth/v1/verify
      - GOTRUE_EXTERNAL_PHONE_ENABLED=false
      - GOTRUE_SMS_AUTOCONFIRM=false
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  rest:
    image: postgrest/postgrest:v12.2.12
    command: "postgrest"
    networks:
      - $NOME_REDE
    environment:
      - PGRST_DB_URI=postgres://authenticator:$DB_PASSWORD@db:5432/postgres
      - PGRST_DB_SCHEMAS=public,storage,graphql_public
      - PGRST_DB_ANON_ROLE=anon
      - PGRST_JWT_SECRET=$SECRET_KEY
      - PGRST_APP_SETTINGS_JWT_SECRET=$SECRET_KEY
      - PGRST_APP_SETTINGS_JWT_EXP=31536000
      - PGRST_DB_USE_LEGACY_GUCS="false"
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  realtime:
    image: supabase/realtime:v2.34.47
    networks:
      - $NOME_REDE
    environment:
      - PORT=4000
      - API_JWT_SECRET=$SECRET_KEY
      - SECRET_KEY_BASE=$SECRET_KEY_BASE
      - APP_NAME=realtime
      - DB_HOST=db
      - DB_PORT=5432
      - DB_USER=supabase_admin
      - DB_PASSWORD=$DB_PASSWORD
      - DB_NAME=postgres
      - DB_AFTER_CONNECT_QUERY='SET search_path TO _realtime'
      - DB_ENC_KEY=supabaserealtime
      - ERL_AFLAGS=-proto_dist inet_tcp
      - DNS_NODES="''"
      - RLIMIT_NOFILE=10000
      - SEED_SELF_HOST=true
      - RUN_JANITOR=true
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  storage:
    image: supabase/storage-api:v1.22.17
    volumes:
      - $BASE_DIR/docker/volumes/storage:/var/lib/storage:z
    networks:
      - $NOME_REDE
    environment:
      - ANON_KEY=$ANON_KEY
      - SERVICE_KEY=$SERVICE_KEY
      - POSTGREST_URL=http://rest:3000
      - PGRST_JWT_SECRET=$SECRET_KEY
      - DATABASE_URL=postgres://supabase_storage_admin:$DB_PASSWORD@db:5432/postgres
      - FILE_SIZE_LIMIT=52428800
      - STORAGE_BACKEND=file
      - FILE_STORAGE_BACKEND_PATH=/var/lib/storage
      - ENABLE_IMAGE_TRANSFORMATION="true"
      - IMGPROXY_URL=http://imgproxy:5001
      - TENANT_ID=stub
      - REGION=local
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  imgproxy:
    image: darthsim/imgproxy:v3.8.0
    volumes:
      - $BASE_DIR/docker/volumes/storage:/var/lib/storage:z
    networks:
      - $NOME_REDE
    environment:
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

  meta:
    image: supabase/postgres-meta:v0.89.3
    networks:
      - $NOME_REDE
    environment:
      - PG_META_PORT=8080
      - PG_META_DB_HOST=db
      - PG_META_DB_PORT=5432
      - PG_META_DB_NAME=postgres
      - PG_META_DB_USER=supabase_admin
      - PG_META_DB_PASSWORD=$DB_PASSWORD
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  functions:
    image: supabase/edge-runtime:v1.67.4
    command:
      - start
      - --main-service
      - /home/deno/functions/main
    volumes:
      - $BASE_DIR/docker/volumes/functions:/home/deno/functions:Z
    networks:
      - $NOME_REDE
    environment:
      - VERIFY_JWT="false"
      - JWT_SECRET=$SECRET_KEY
      - SUPABASE_URL=http://kong:8000
      - SUPABASE_ANON_KEY=$ANON_KEY
      - SUPABASE_SERVICE_ROLE_KEY=$SERVICE_KEY
      - SUPABASE_DB_URL=postgresql://postgres:$DB_PASSWORD@db:5432/postgres
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  analytics:
    image: supabase/logflare:1.14.2
    networks:
      - $NOME_REDE
    environment:
      - DB_USERNAME=supabase_admin
      - DB_DATABASE=_supabase
      - DB_HOSTNAME=db
      - DB_PORT=5432
      - DB_PASSWORD=$DB_PASSWORD
      - DB_SCHEMA=_analytics
      - POSTGRES_BACKEND_URL=postgresql://supabase_admin:$DB_PASSWORD@db:5432/_supabase
      - POSTGRES_BACKEND_SCHEMA=_analytics
      - LOGFLARE_NODE_HOST=127.0.0.1
      - LOGFLARE_API_KEY=$LOGFLARE_KEY
      - LOGFLARE_PUBLIC_ACCESS_TOKEN=$LOGFLARE_KEY
      - LOGFLARE_PRIVATE_ACCESS_TOKEN=$LOGFLARE_KEY
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

  db:
    image: supabase/postgres:15.8.1.060
    command:
      - postgres
      - '-c'
      - config_file=/etc/postgresql/postgresql.conf
      - '-c'
      - log_min_messages=fatal
    volumes:
      - $BASE_DIR/docker/volumes/db/realtime.sql:/docker-entrypoint-initdb.d/migrations/99-realtime.sql:Z
      - $BASE_DIR/docker/volumes/db/webhooks.sql:/docker-entrypoint-initdb.d/init-scripts/98-webhooks.sql:Z
      - $BASE_DIR/docker/volumes/db/roles.sql:/docker-entrypoint-initdb.d/init-scripts/99-roles.sql:Z
      - $BASE_DIR/docker/volumes/db/jwt.sql:/docker-entrypoint-initdb.d/init-scripts/99-jwt.sql:Z
      - $BASE_DIR/docker/volumes/db/data:/var/lib/postgresql/data:Z
      - $BASE_DIR/docker/volumes/db/_supabase.sql:/docker-entrypoint-initdb.d/migrations/97-_supabase.sql:Z
      - $BASE_DIR/docker/volumes/db/logs.sql:/docker-entrypoint-initdb.d/migrations/99-logs.sql:Z
      - $BASE_DIR/docker/volumes/db/pooler.sql:/docker-entrypoint-initdb.d/migrations/99-pooler.sql:Z
      - supabase_db_config:/etc/postgresql-custom
    networks:
      - $NOME_REDE
    environment:
      - POSTGRES_HOST=/var/run/postgresql
      - PGPORT=5432
      - POSTGRES_PORT=5432
      - PGPASSWORD=$DB_PASSWORD
      - POSTGRES_PASSWORD=$DB_PASSWORD
      - POSTGRES_DB=postgres
      - PGDATABASE=postgres
      - JWT_SECRET=$SECRET_KEY
      - JWT_EXP=31536000
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  vector:
    image: timberio/vector:0.28.1-alpine
    command:
      - '--config'
      - etc/vector/vector.yml
    volumes:
    - $BASE_DIR/docker/volumes/logs/vector.yml:/etc/vector/vector.yml:ro
    - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - $NOME_REDE
    environment:
      - LOGFLARE_API_KEY=$LOGFLARE_KEY
      - LOGFLARE_PUBLIC_ACCESS_TOKEN=$LOGFLARE_KEY
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

  supavisor:
    image: supabase/supavisor:2.5.1
    command:
      - /bin/sh
      - -c
      - /app/bin/migrate && /app/bin/supavisor eval "\$\$(cat /etc/pooler/pooler.exs)" && /app/bin/server
    volumes:
      -  $BASE_DIR/docker/volumes/pooler/pooler.exs:/etc/pooler/pooler.exs:ro
    networks:
      - $NOME_REDE
    environment:
      - POSTGRES_PORT=5432
      - POSTGRES_DB=postgres
      - POSTGRES_PASSWORD=$DB_PASSWORD
      - DATABASE_URL=ecto://supabase_admin:$DB_PASSWORD@db:5432/_supabase
      - CLUSTER_POSTGRES=true
      - API_JWT_SECRET=$SECRET_KEY
      - METRICS_JWT_SECRET=$SECRET_KEY
      - SECRET_KEY_BASE=$SECRET_KEY_BASE
      - VAULT_ENC_KEY=$VAULT_ENC_KEY
      - REGION=local
      - ERL_AFLAGS=-proto_dist inet_tcp
      - POOLER_TENANT_ID=1
      - POOLER_DEFAULT_POOL_SIZE=20
      - POOLER_MAX_CLIENT_CONN=100
      - POOLER_POOL_MODE=transaction
      - DB_POOL_SIZE=5
      - PORT=4000
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

volumes:
  supabase_db_config:
    external: true
    name: supabase_db_config

networks:
  $NOME_REDE:
    external: true
    name: $NOME_REDE
EOL

# 7. Criar Volume Externo
info "Criando volume externo para configuração do DB..."
docker volume create supabase_db_config > /dev/null 2>&1 || true

# 8. Deploy via Portainer API
info "Enviando stack para o Portainer..."

# Função para renovar token se expirado
refresh_token_if_needed() {
    local check_status=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $PORTAINER_TOKEN" "$PORTAINER_URL/api/endpoints")
    
    if [[ "$check_status" == "401" || "$check_status" == "403" ]]; then
        info "Token do Portainer expirado ou inválido (HTTP $check_status). Tentando renovar..."
        
        local auth_resp=$(curl -k -s -X POST "$PORTAINER_URL/api/auth" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$PORTAINER_USER\",\"password\":\"$PORTAINER_PASS\"}")
            
        local new_token=$(echo "$auth_resp" | jq -r .jwt)
        
        if [[ "$new_token" != "null" && -n "$new_token" ]]; then
            ok "Token renovado com sucesso."
            PORTAINER_TOKEN="$new_token"
            sed -i "s|Token: .*|Token: $new_token|" "$DADOS_FILE"
        else
            erro "Falha ao renovar token. Verifique usuário/senha em $DADOS_FILE."
            exit 1
        fi
    fi
}

refresh_token_if_needed

# Função auxiliar para buscar Swarm ID localmente
get_swarm_id() {
    docker info --format '{{.Swarm.Cluster.ID}}'
}

SWARM_ID=$(get_swarm_id)

if [ -z "$SWARM_ID" ]; then
    erro "Não foi possível obter o Swarm ID localmente."
    exit 1
fi

# Verificar se stack já existe
STACKS_RESP=$(curl -k -s -H "Authorization: Bearer $PORTAINER_TOKEN" "$PORTAINER_URL/api/stacks")
STACK_ID=""

if echo "$STACKS_RESP" | jq -e 'type == "array"' >/dev/null 2>&1; then
    STACK_ID=$(echo "$STACKS_RESP" | jq -r '.[] | select(.Name == "supabase") | .Id' 2>/dev/null || true)
fi

STACK_CONTENT=$(cat "$BASE_DIR/docker-compose.yml")

if [ -n "$STACK_ID" ]; then
    info "Atualizando stack existente (ID: $STACK_ID) via API..."
    
    UPDATE_PAYLOAD=$(jq -n \
        --arg stackFileContent "$STACK_CONTENT" \
        --arg envVar "[]" \
        '{
            StackFileContent: $stackFileContent,
            Env: [],
            Prune: true
        }')

    HTTP_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" -X PUT "$PORTAINER_URL/api/stacks/$STACK_ID?endpointId=1" \
        -H "Authorization: Bearer $PORTAINER_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$UPDATE_PAYLOAD")

    if [[ "$HTTP_CODE" == "200" ]]; then
        ok "Stack atualizada com sucesso via Portainer API."
    else
        erro "Falha ao atualizar stack via API (HTTP $HTTP_CODE)."
        docker stack deploy -c "$BASE_DIR/docker-compose.yml" supabase
    fi

else
    info "Criando nova stack via Portainer API..."
    
    CREATE_PAYLOAD=$(jq -n \
        --arg name "supabase" \
        --arg swarmID "$SWARM_ID" \
        --arg stackFileContent "$STACK_CONTENT" \
        '{
            Name: $name,
            SwarmID: $swarmID,
            StackFileContent: $stackFileContent,
            Env: []
        }')

    # Endpoint específico para criação de Swarm Stacks via String (Portainer 2.19+)
    RESP=$(curl -k -s -X POST "$PORTAINER_URL/api/stacks/create/swarm/string?endpointId=1" \
        -H "Authorization: Bearer $PORTAINER_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$CREATE_PAYLOAD")

    NEW_ID=$(echo "$RESP" | jq -r .Id)
    
    if [[ "$NEW_ID" != "null" && -n "$NEW_ID" ]]; then
        ok "Stack criada com sucesso no Portainer (ID: $NEW_ID)."
    else
        erro "Falha ao criar stack via API."
        echo "Resposta: $RESP"
        docker stack deploy -c "$BASE_DIR/docker-compose.yml" supabase
    fi
fi

# 9. Verificação
wait_stack "supabase_studio"
wait_stack "supabase_kong"
wait_stack "supabase_db"

# 10. Salvar Credenciais
info "Salvando credenciais..."
cat > "$BASE_DIR/credenciais.txt" <<EOL
[ SUPABASE ]
URL: https://$SUPABASE_DOMAIN
Dashboard User: $SUPABASE_USER
Dashboard Pass: $SUPABASE_PASS

JWT Secret: $SECRET_KEY
Anon Key: $ANON_KEY
Service Key: $SERVICE_KEY
DB Password: $DB_PASSWORD
EOL

ok "Instalação concluída!"
echo -e "${VERDE}Acesse: https://$SUPABASE_DOMAIN${NC}"
echo -e "Credenciais salvas em: $BASE_DIR/credenciais.txt"
