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

# Função para gerar JWTs (Mantida do original)
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

  secret=$(openssl rand -hex 20)

  header=$(printf '{"alg":"HS256","typ":"JWT"}' | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
  payload_service_key_base64=$(printf '%s' "$payload_service_key" | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
  payload_anon_key_base64=$(printf '%s' "$payload_anon_key" | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

  signature_service_key=$(printf '%s' "$header.$payload_service_key_base64" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')
  signature_anon_key=$(printf '%s' "$header.$payload_anon_key_base64" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 | tr -d '=' | tr '+/' '-_' | tr -d '\n')

  token_service_key="$header.$payload_service_key_base64.$signature_service_key"
  token_anon_key="$header.$payload_anon_key_base64.$signature_anon_key"

  echo "$secret $token_service_key $token_anon_key"
}

# 1. Carregar Dados do Ambiente
clear
echo -e "${VERDE}=== TMC Stack Deploy: Supabase ===${NC}"
echo ""

DADOS_FILE="/root/dados_vps/dados_portainer"

if [ -f "$DADOS_FILE" ]; then
    info "Carregando configurações salvas..."
    PORTAINER_URL=$(grep "URL:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_USER=$(grep "User:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_PASS=$(grep "Pass:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_TOKEN=$(grep "Token:" "$DADOS_FILE" | awk '{print $2}')
    NOME_REDE=$(grep "Network:" "$DADOS_FILE" | awk '{print $2}')
    
    # Extrair domínio base do Portainer URL (ex: https://portainer.dominio.com -> dominio.com)
    BASE_DOMAIN=$(echo "$PORTAINER_URL" | sed -e 's|^[^/]*//||' -e 's|^[^.]*\.||')
    
    ok "Rede: $NOME_REDE"
    ok "Domínio Base: $BASE_DOMAIN"
else
    erro "Arquivo de configuração base não encontrado ($DADOS_FILE)."
    erro "Por favor, execute a instalação BASE primeiro."
    exit 1
fi

# 2. Coleta de Dados Específicos
echo ""
read -p "Subdomínio para o Supabase [padrão: supabase.$BASE_DOMAIN]: " INPUT_DOMAIN
if [ -z "$INPUT_DOMAIN" ]; then
    SUPABASE_DOMAIN="supabase.$BASE_DOMAIN"
else
    SUPABASE_DOMAIN="$INPUT_DOMAIN"
fi

read -s -p "Senha do Banco de Dados (Postgres) [Enter para gerar aleatória]: " DB_PASSWORD
echo ""
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD=$(openssl rand -hex 16)
    info "Senha gerada: $DB_PASSWORD"
fi

# 3. Preparação
BASE_DIR="/srv/supabase"
mkdir -p "$BASE_DIR/volumes/db" "$BASE_DIR/volumes/storage" "$BASE_DIR/config"

# Gerar Segredos
info "Gerando chaves JWT..."
read -r JWT_SECRET SERVICE_ROLE_KEY ANON_KEY <<< $(generate_jwt_tokens)
DASHBOARD_USER="admin"
DASHBOARD_PASSWORD=$(openssl rand -hex 12)

# Salvar Credenciais
cat > "$BASE_DIR/dados_supabase.txt" <<EOF
[ SUPABASE ]
URL: https://$SUPABASE_DOMAIN
DB Password: $DB_PASSWORD
JWT Secret: $JWT_SECRET
Anon Key: $ANON_KEY
Service Role Key: $SERVICE_ROLE_KEY
Dashboard User: $DASHBOARD_USER
Dashboard Pass: $DASHBOARD_PASSWORD
EOF
chmod 600 "$BASE_DIR/dados_supabase.txt"
ok "Credenciais salvas em $BASE_DIR/dados_supabase.txt"

# 4. Configuração Kong (API Gateway)
cat > "$BASE_DIR/config/kong.yml" <<EOF
_format_version: "2.1"
services:
  - name: auth-v1
    url: http://auth:9999
    routes:
      - name: auth-v1-route
        paths:
          - /auth/v1/
        strip_path: false
  - name: rest-v1
    url: http://rest:3000
    routes:
      - name: rest-v1-route
        paths:
          - /rest/v1/
        strip_path: false
  - name: realtime-v1
    url: http://realtime:4000
    routes:
      - name: realtime-v1-route
        paths:
          - /realtime/v1/
        strip_path: false
  - name: storage-v1
    url: http://storage:5000
    routes:
      - name: storage-v1-route
        paths:
          - /storage/v1/
        strip_path: false
  - name: meta
    url: http://meta:8080
    routes:
      - name: meta-route
        paths:
          - /pg/
        strip_path: false
EOF

# 5. Stack Supabase
info "Gerando arquivo da stack..."
cat > "$BASE_DIR/supabase-stack.yaml" <<EOF
version: "3.8"

services:
  studio:
    image: supabase/studio:20240101-8e2d666
    environment:
      STUDIO_PG_META_URL: http://meta:8080
      POSTGRES_PASSWORD: $DB_PASSWORD
      SUPABASE_URL: http://kong:8000
      SUPABASE_PUBLIC_URL: https://$SUPABASE_DOMAIN
      SUPABASE_ANON_KEY: $ANON_KEY
      SUPABASE_SERVICE_KEY: $SERVICE_ROLE_KEY
    networks:
      - $NOME_REDE
    deploy:
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.supabase-studio.rule=Host(\`$SUPABASE_DOMAIN\`)"
        - "traefik.http.routers.supabase-studio.entrypoints=websecure"
        - "traefik.http.routers.supabase-studio.tls.certresolver=letsencryptresolver"
        - "traefik.http.services.supabase-studio.loadbalancer.server.port=3000"

  kong:
    image: kong:2.8.1
    environment:
      KONG_DATABASE: "off"
      KONG_DECLARATIVE_CONFIG: /var/lib/kong/kong.yml
      KONG_DNS_ORDER: LAST,A,CNAME
      KONG_PLUGINS: request-transformer,cors,key-auth,acl
    volumes:
      - $BASE_DIR/config/kong.yml:/var/lib/kong/kong.yml
    networks:
      - $NOME_REDE
    deploy:
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.supabase-api.rule=Host(\`$SUPABASE_DOMAIN\`) && PathPrefix(\`/auth/v1\`, \`/rest/v1\`, \`/realtime/v1\`, \`/storage/v1\`, \`/pg/\`)"
        - "traefik.http.routers.supabase-api.entrypoints=websecure"
        - "traefik.http.routers.supabase-api.tls.certresolver=letsencryptresolver"
        - "traefik.http.services.supabase-api.loadbalancer.server.port=8000"

  auth:
    image: supabase/gotrue:v2.132.3
    environment:
      GOTRUE_API_HOST: 0.0.0.0
      GOTRUE_API_PORT: 9999
      GOTRUE_DB_DRIVER: postgres
      GOTRUE_DB_DATABASE_URL: postgres://supabase_auth_admin:$DB_PASSWORD@db:5432/postgres
      GOTRUE_SITE_URL: https://$SUPABASE_DOMAIN
      GOTRUE_JWT_SECRET: $JWT_SECRET
      GOTRUE_JWT_EXP: 3600
      GOTRUE_JWT_DEFAULT_GROUP_NAME: authenticated
      GOTRUE_EXTERNAL_EMAIL_ENABLED: "true"
      GOTRUE_MAILER_AUTOCONFIRM: "true"
    networks:
      - $NOME_REDE

  rest:
    image: postgrest/postgrest:v12.0.1
    environment:
      PGRST_DB_URI: postgres://authenticator:$DB_PASSWORD@db:5432/postgres
      PGRST_DB_SCHEMAS: public,storage,graphql_public
      PGRST_DB_ANON_ROLE: anon
      PGRST_JWT_SECRET: $JWT_SECRET
    networks:
      - $NOME_REDE

  realtime:
    image: supabase/realtime:v2.25.22
    environment:
      PORT: 4000
      DB_HOST: db
      DB_PORT: 5432
      DB_USER: supabase_admin
      DB_PASSWORD: $DB_PASSWORD
      DB_NAME: postgres
      DB_AFTER_CONNECT_QUERY: 'SET search_path TO _realtime'
      DB_ENC_KEY: $(openssl rand -hex 16)
      API_JWT_SECRET: $JWT_SECRET
      REPLICATION_MODE: RLS
      REPLICATION_POLL_INTERVAL: 100
      SECURE_CHANNELS: "true"
      SLOT_NAME: supabase_realtime_rls
      TEMPORARY_SLOT: "true"
    networks:
      - $NOME_REDE

  storage:
    image: supabase/storage-api:v0.43.10
    environment:
      ANON_KEY: $ANON_KEY
      SERVICE_KEY: $SERVICE_ROLE_KEY
      POSTGREST_URL: http://rest:3000
      PGRST_JWT_SECRET: $JWT_SECRET
      DATABASE_URL: postgres://supabase_storage_admin:$DB_PASSWORD@db:5432/postgres
      FILE_SIZE_LIMIT: 52428800
      STORAGE_BACKEND: file
      FILE_STORAGE_BACKEND_PATH: /var/lib/storage
      TENANT_ID: stub
      REGION: stub
      GLOBAL_S3_BUCKET: stub
    volumes:
      - $BASE_DIR/volumes/storage:/var/lib/storage
    networks:
      - $NOME_REDE

  meta:
    image: supabase/postgres-meta:v0.80.0
    environment:
      PG_META_PORT: 8080
      PG_META_DB_HOST: db
      PG_META_DB_PASSWORD: $DB_PASSWORD
    networks:
      - $NOME_REDE

  db:
    image: supabase/postgres:15.1.1.44
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    environment:
      POSTGRES_PASSWORD: $DB_PASSWORD
    volumes:
      - $BASE_DIR/volumes/db:/var/lib/postgresql/data
    networks:
      - $NOME_REDE
    deploy:
      placement:
        constraints:
          - node.role == manager

networks:
  $NOME_REDE:
    external: true
EOF

# 6. Deploy via Portainer API
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
            # Atualiza o arquivo para futuras execuções
            sed -i "s|Token: .*|Token: $new_token|" "$DADOS_FILE"
        else
            erro "Falha ao renovar token. Verifique usuário/senha em $DADOS_FILE."
            erro "Resposta Auth: $auth_resp"
            exit 1
        fi
    fi
}

# Verifica/Renova token antes de prosseguir
refresh_token_if_needed

# Função auxiliar para buscar Swarm ID com tratamento de erro
get_swarm_id() {
    local ep_id=$1
    local resp=$(curl -k -s -H "Authorization: Bearer $PORTAINER_TOKEN" "$PORTAINER_URL/api/endpoints/$ep_id/docker/swarms")
    
    # Verifica se a resposta é um array e tem o campo Id no primeiro elemento
    if echo "$resp" | jq -e 'type == "array" and .[0].Id != null' >/dev/null 2>&1; then
        echo "$resp" | jq -r '.[0].Id'
    else
        # Retorna vazio em caso de erro (objeto de erro ou array vazio)
        echo ""
    fi
}

# Tenta obter ID do endpoint 1, se falhar tenta o 2
SWARM_ID=$(get_swarm_id 1)
if [ -z "$SWARM_ID" ]; then
    SWARM_ID=$(get_swarm_id 2)
fi

if [ -z "$SWARM_ID" ]; then
    erro "Não foi possível obter o Swarm ID do Portainer."
    erro "Verifique se o Portainer está conectado ao Docker Swarm local (Endpoints 1 ou 2)."
    
    # DEBUG INFO
    info "--- DEBUG INFO ---"
    info "URL: $PORTAINER_URL"
    info "Token (parcial): ${PORTAINER_TOKEN:0:10}..."
    info "Tentando listar endpoints disponíveis:"
    curl -k -s -H "Authorization: Bearer $PORTAINER_TOKEN" "$PORTAINER_URL/api/endpoints" | jq -r '.[] | "ID: \(.Id) Name: \(.Name) Type: \(.Type)"' || echo "Falha ao listar endpoints"
    
    echo ""
    info "Resposta bruta Endpoint 1:"
    curl -k -s -H "Authorization: Bearer $PORTAINER_TOKEN" "$PORTAINER_URL/api/endpoints/1/docker/swarms"
    echo ""
    info "------------------"
    
    exit 1
fi

# Verificar se stack já existe
STACKS_RESP=$(curl -k -s -H "Authorization: Bearer $PORTAINER_TOKEN" "$PORTAINER_URL/api/stacks")
STACK_ID=""

# Verifica se a resposta é um array antes de processar
if echo "$STACKS_RESP" | jq -e 'type == "array"' >/dev/null 2>&1; then
    STACK_ID=$(echo "$STACKS_RESP" | jq -r '.[] | select(.Name == "supabase") | .Id' 2>/dev/null || true)
fi

if [ -n "$STACK_ID" ]; then
    info "Atualizando stack existente (ID: $STACK_ID)..."
    URL_DEPLOY="$PORTAINER_URL/api/stacks/$STACK_ID?endpointId=1"
    METHOD="PUT"
    # Para update, o payload é diferente, geralmente enviamos o conteúdo do arquivo
    # Simplificação: Vamos usar docker stack deploy localmente já que estamos no manager
    # Isso evita complexidade de upload de arquivo via API bash puro
    info "Usando docker stack deploy local..."
    docker stack deploy -c "$BASE_DIR/supabase-stack.yaml" supabase
else
    info "Criando nova stack..."
    # Fallback para deploy local também, mais robusto via CLI quando já estamos no servidor
    docker stack deploy -c "$BASE_DIR/supabase-stack.yaml" supabase
fi

wait_stack "supabase_kong"
wait_stack "supabase_studio"

echo ""
echo -e "${VERDE}Instalação do Supabase Concluída!${NC}"
echo "Studio URL: https://$SUPABASE_DOMAIN"
echo "Credenciais salvas em: $BASE_DIR/dados_supabase.txt"
