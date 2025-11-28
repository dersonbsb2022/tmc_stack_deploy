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

# 1. Carregar Dados do Ambiente
clear
echo -e "${VERDE}=== TMC Stack Deploy: RabbitMQ ===${NC}"
echo ""

DADOS_FILE="/root/dados_vps/dados_portainer"

if [ -f "$DADOS_FILE" ]; then
    info "Carregando configurações salvas..."
    PORTAINER_URL=$(grep "URL:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_USER=$(grep "User:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_PASS=$(grep "Pass:" "$DADOS_FILE" | awk '{print $2}')
    PORTAINER_TOKEN=$(grep "Token:" "$DADOS_FILE" | awk '{print $2}')
    NOME_REDE=$(grep "Network:" "$DADOS_FILE" | awk '{print $2}')
    
    BASE_DOMAIN=$(echo "$PORTAINER_URL" | sed -e 's|^[^/]*//||' -e 's|^[^.]*\.||')
    
    ok "Rede: $NOME_REDE"
    ok "Domínio Base: $BASE_DOMAIN"
else
    erro "Arquivo de configuração base não encontrado ($DADOS_FILE)."
    erro "Por favor, execute a instalação BASE primeiro."
    exit 1
fi

# 2. Coleta de Dados
echo ""
read -p "Subdomínio para o RabbitMQ [padrão: rabbitmq.$BASE_DOMAIN]: " INPUT_DOMAIN
if [ -z "$INPUT_DOMAIN" ]; then
    RABBIT_DOMAIN="rabbitmq.$BASE_DOMAIN"
else
    RABBIT_DOMAIN="$INPUT_DOMAIN"
fi

read -p "Usuário Admin do RabbitMQ [padrão: admin]: " RABBIT_USER
if [ -z "$RABBIT_USER" ]; then
    RABBIT_USER="admin"
fi

read -s -p "Senha Admin do RabbitMQ [padrão: admin]: " RABBIT_PASS
echo ""
if [ -z "$RABBIT_PASS" ]; then
    RABBIT_PASS="admin"
fi

# 3. Preparação
BASE_DIR="/srv/rabbitmq"
mkdir -p "$BASE_DIR/data"

# Salvar Credenciais
cat > "$BASE_DIR/dados_rabbitmq.txt" <<EOF
[ RABBITMQ ]
URL: https://$RABBIT_DOMAIN
User: $RABBIT_USER
Pass: $RABBIT_PASS
EOF
chmod 600 "$BASE_DIR/dados_rabbitmq.txt"
ok "Credenciais salvas em $BASE_DIR/dados_rabbitmq.txt"

# 4. Gerar Stack
cat > "$BASE_DIR/rabbitmq-stack.yaml" <<EOF
version: '3.8'

services:
  rabbitmq:
    image: rabbitmq:3-management
    environment:
      RABBITMQ_DEFAULT_USER: $RABBIT_USER
      RABBITMQ_DEFAULT_PASS: $RABBIT_PASS
    volumes:
      - $BASE_DIR/data:/var/lib/rabbitmq
    networks:
      - $NOME_REDE
    deploy:
      mode: replicated
      replicas: 1
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.rabbitmq.rule=Host(\`$RABBIT_DOMAIN\`)"
        - "traefik.http.routers.rabbitmq.entrypoints=websecure"
        - "traefik.http.routers.rabbitmq.tls.certresolver=letsencryptresolver"
        - "traefik.http.services.rabbitmq.loadbalancer.server.port=15672"

networks:
  $NOME_REDE:
    external: true
EOF

# 5. Deploy via Portainer API
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
    STACK_ID=$(echo "$STACKS_RESP" | jq -r '.[] | select(.Name == "rabbitmq") | .Id' 2>/dev/null || true)
fi

STACK_CONTENT=$(cat "$BASE_DIR/rabbitmq-stack.yaml")

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
        docker stack deploy -c "$BASE_DIR/rabbitmq-stack.yaml" rabbitmq
    fi

else
    info "Criando nova stack via Portainer API..."
    
    CREATE_PAYLOAD=$(jq -n \
        --arg name "rabbitmq" \
        --arg swarmID "$SWARM_ID" \
        --arg stackFileContent "$STACK_CONTENT" \
        '{
            Name: $name,
            SwarmID: $swarmID,
            StackFileContent: $stackFileContent,
            Env: []
        }')

    RESP=$(curl -k -s -X POST "$PORTAINER_URL/api/stacks?type=1&method=string&endpointId=1" \
        -H "Authorization: Bearer $PORTAINER_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$CREATE_PAYLOAD")

    NEW_ID=$(echo "$RESP" | jq -r .Id)
    
    if [[ "$NEW_ID" != "null" && -n "$NEW_ID" ]]; then
        ok "Stack criada com sucesso no Portainer (ID: $NEW_ID)."
    else
        erro "Falha ao criar stack via API."
        echo "Resposta: $RESP"
        docker stack deploy -c "$BASE_DIR/rabbitmq-stack.yaml" rabbitmq
    fi
fi

wait_stack "rabbitmq_rabbitmq"

echo ""
echo -e "${VERDE}Instalação do RabbitMQ Concluída!${NC}"
echo "URL: https://$RABBIT_DOMAIN"
echo "Credenciais salvas em: $BASE_DIR/dados_rabbitmq.txt"
