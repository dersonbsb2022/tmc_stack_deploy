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

# Função para testar conexão com Postgres (via docker run na rede overlay)
test_db_connection() {
    local host=$1
    local port=$2
    local user=$3
    local pass=$4
    local db=$5

    info "Testando conexão com Postgres ($host:$port)..."

    # Verifica se a rede é attachable
    if [ "$(docker network inspect "$NOME_REDE" --format '{{.Attachable}}')" != "true" ]; then
        erro "A rede '$NOME_REDE' não é 'attachable'. Não é possível testar a conexão via docker run."
        return 1
    fi

    # 1. Teste de Rede (pg_isready)
    info "Verificando disponibilidade do host (pg_isready)..."
    
    if ! docker run --rm --network "$NOME_REDE" postgres:16-alpine pg_isready -h "$host" -p "$port" -t 5 >/dev/null 2>&1; then
        erro "O host '$host' não está respondendo na porta $port."
        return 1
    fi

    # 2. Teste de Autenticação e Criação do Banco
    info "Verificando acesso ao banco de dados..."
    
    # Tenta conectar diretamente ao banco alvo
    if docker run --rm --network "$NOME_REDE" -e PGPASSWORD="$pass" postgres:16-alpine psql -h "$host" -p "$port" -U "$user" -d "$db" -c '\q' >/dev/null 2>&1; then
        ok "Banco de dados '$db' já existe e a conexão foi bem-sucedida!"
        return 0
    fi

    # Se falhar, tenta conectar no 'postgres' para criar o banco
    info "Banco '$db' não acessível. Tentando criar..."
    
    if docker run --rm --network "$NOME_REDE" -e PGPASSWORD="$pass" postgres:16-alpine psql -h "$host" -p "$port" -U "$user" -d "postgres" -c "CREATE DATABASE $db;" >/dev/null 2>&1; then
        ok "Banco de dados '$db' criado com sucesso!"
        return 0
    else
        # Se falhar a criação, verifica se é erro de senha ou permissão
        if ! docker run --rm --network "$NOME_REDE" -e PGPASSWORD="$pass" postgres:16-alpine psql -h "$host" -p "$port" -U "$user" -d "postgres" -c '\q' >/dev/null 2>&1; then
            erro "Falha na autenticação com o usuário '$user'. Verifique a senha."
            return 1
        else
            erro "Falha ao criar o banco '$db'. O usuário '$user' pode não ter permissão ou o banco já existe com outro dono."
            # Tenta listar os bancos para debug
            docker run --rm --network "$NOME_REDE" -e PGPASSWORD="$pass" postgres:16-alpine psql -h "$host" -p "$port" -U "$user" -d "postgres" -c '\l'
            return 1
        fi
    fi
}

# Função para testar conexão com Redis (via docker run na rede overlay)
test_redis_connection() {
    local host=$1
    local port=$2
    local pass=$3

    info "Testando conexão com Redis ($host:$port)..."
    
    if docker run --rm --network "$NOME_REDE" redis:7-alpine redis-cli -h "$host" -p "$port" -a "$pass" ping | grep -q "PONG"; then
        ok "Conexão com Redis bem-sucedida!"
        return 0
    else
        erro "Falha na conexão com Redis. Verifique Host, Porta e Senha."
        return 1
    fi
}

# 1. Carregar Dados do Ambiente
clear
echo -e "${VERDE}=== TMC Stack Deploy: n8n ===${NC}"
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
read -p "Subdomínio para o Editor n8n [padrão: n8n.$BASE_DOMAIN]: " INPUT_DOMAIN_EDITOR
N8N_DOMAIN_EDITOR=${INPUT_DOMAIN_EDITOR:-n8n.$BASE_DOMAIN}

read -p "Subdomínio para o Webhook n8n [padrão: webhook.$BASE_DOMAIN]: " INPUT_DOMAIN_WEBHOOK
N8N_DOMAIN_WEBHOOK=${INPUT_DOMAIN_WEBHOOK:-webhook.$BASE_DOMAIN}

echo ""
info "Configuração do Banco de Dados (Postgres)"
while true; do
    read -p "Já possui um banco de dados Postgres rodando na rede '$NOME_REDE'? (s/n): " HAS_DB
    if [[ "$HAS_DB" =~ ^[Ss]$ ]]; then
        read -p "Host do Postgres [padrão: postgres]: " POSTGRES_HOST
        POSTGRES_HOST=${POSTGRES_HOST:-postgres}
        
        read -p "Porta do Postgres [padrão: 5432]: " POSTGRES_PORT
        POSTGRES_PORT=${POSTGRES_PORT:-5432}
        
        read -p "Usuário do Postgres: " POSTGRES_USER
        read -s -p "Senha do Postgres: " POSTGRES_PASSWORD
        echo ""
        
        read -p "Nome do Banco de Dados [padrão: n8n]: " POSTGRES_DB
        POSTGRES_DB=${POSTGRES_DB:-n8n}
        
        if test_db_connection "$POSTGRES_HOST" "$POSTGRES_PORT" "$POSTGRES_USER" "$POSTGRES_PASSWORD" "$POSTGRES_DB"; then
            break
        else
            erro "Falha no teste de conexão."
            read -p "Deseja tentar novamente (s) ou prosseguir mesmo com erro (n)? (s/n): " RETRY_DB
            if [[ "$RETRY_DB" =~ ^[Nn]$ ]]; then
                echo -e "${AMARELO}[AVISO]${NC} Prosseguindo sem validar a conexão com o banco de dados."
                echo -e "${AMARELO}[AVISO]${NC} Se as credenciais estiverem erradas, o n8n não iniciará corretamente."
                break
            fi
        fi
    else
        info "Iniciando instalação do Postgres..."
        
        # Tenta localizar o script de instalação do Postgres
        # 1. Caminho de Desenvolvimento Local (Prioridade)
        DEV_PATH="/scritps/novo_instalador/apps/install_postgres.sh"
        # 2. Caminho relativo ao script atual (caso esteja tudo na mesma pasta ou em /tmp baixado junto)
        CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
        RELATIVE_PATH="$CURRENT_DIR/install_postgres.sh"
        
        POSTGRES_SCRIPT=""
        
        if [ -f "$DEV_PATH" ]; then
            POSTGRES_SCRIPT="$DEV_PATH"
        elif [ -f "$RELATIVE_PATH" ]; then
            POSTGRES_SCRIPT="$RELATIVE_PATH"
        fi
        
        if [ -n "$POSTGRES_SCRIPT" ]; then
            # Tornar executável se não for
            chmod +x "$POSTGRES_SCRIPT"
            
            # Executar instalador do Postgres
            "$POSTGRES_SCRIPT"
            
            if [ $? -eq 0 ]; then
                ok "Instalação do Postgres finalizada."
                info "Por favor, agora informe os dados de conexão do banco criado."
                # O loop continua, permitindo que o usuário preencha os dados agora
            else
                erro "Falha ao executar a instalação do Postgres."
                exit 1
            fi
        else
            erro "Script de instalação do Postgres não encontrado."
            erro "Procurado em: $DEV_PATH e $RELATIVE_PATH"
            exit 1
        fi
    fi
done

echo ""
info "Configuração do Redis"
while true; do
    read -p "Já possui um Redis rodando na rede '$NOME_REDE'? (s/n): " HAS_REDIS
    if [[ "$HAS_REDIS" =~ ^[Ss]$ ]]; then
        read -p "Host do Redis [padrão: redis]: " REDIS_HOST
        REDIS_HOST=${REDIS_HOST:-redis}
        
        read -p "Porta do Redis [padrão: 6379]: " REDIS_PORT
        REDIS_PORT=${REDIS_PORT:-6379}
        
        read -s -p "Senha do Redis: " REDIS_PASSWORD
        echo ""
        
        if test_redis_connection "$REDIS_HOST" "$REDIS_PORT" "$REDIS_PASSWORD"; then
            break
        else
            erro "Falha no teste de conexão com Redis."
            read -p "Deseja tentar novamente (s) ou prosseguir mesmo com erro (n)? (s/n): " RETRY_REDIS
            if [[ "$RETRY_REDIS" =~ ^[Nn]$ ]]; then
                echo -e "${AMARELO}[AVISO]${NC} Prosseguindo sem validar a conexão com o Redis."
                break
            fi
        fi
    else
        info "Iniciando instalação do Redis..."
        
        DEV_PATH="/scritps/novo_instalador/apps/install_redis.sh"
        CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
        RELATIVE_PATH="$CURRENT_DIR/install_redis.sh"
        
        REDIS_SCRIPT=""
        
        if [ -f "$DEV_PATH" ]; then
            REDIS_SCRIPT="$DEV_PATH"
        elif [ -f "$RELATIVE_PATH" ]; then
            REDIS_SCRIPT="$RELATIVE_PATH"
        fi
        
        if [ -n "$REDIS_SCRIPT" ]; then
            chmod +x "$REDIS_SCRIPT"
            "$REDIS_SCRIPT"
            
            if [ $? -eq 0 ]; then
                ok "Instalação do Redis finalizada."
                info "Por favor, agora informe os dados de conexão do Redis criado."
            else
                erro "Falha ao executar a instalação do Redis."
                exit 1
            fi
        else
            erro "Script de instalação do Redis não encontrado."
            exit 1
        fi
    fi
done

echo ""
info "Configuração SMTP (Opcional - Pressione Enter para pular)"
read -p "Email SMTP: " SMTP_EMAIL
read -p "Usuário SMTP: " SMTP_USER
read -s -p "Senha SMTP: " SMTP_PASS
echo ""
read -p "Host SMTP: " SMTP_HOST
read -p "Porta SMTP: " SMTP_PORT

# 3. Preparação
BASE_DIR="/srv/n8n"
mkdir -p "$BASE_DIR/data"

# Gerar Chaves
ENCRYPTION_KEY=$(openssl rand -hex 16)

# Salvar Credenciais
cat > "$BASE_DIR/dados_n8n.txt" <<EOF
[ N8N ]
Editor URL: https://$N8N_DOMAIN_EDITOR
Webhook URL: https://$N8N_DOMAIN_WEBHOOK
Encryption Key: $ENCRYPTION_KEY

[ DATABASE ]
Host: $POSTGRES_HOST
Port: $POSTGRES_PORT
User: $POSTGRES_USER
DB: $POSTGRES_DB

[ REDIS ]
Host: $REDIS_HOST
Port: $REDIS_PORT
EOF
chmod 600 "$BASE_DIR/dados_n8n.txt"
ok "Credenciais salvas em $BASE_DIR/dados_n8n.txt"

# 4. Gerar Stack
cat > "$BASE_DIR/n8n-stack.yaml" <<EOF
version: "3.8"

services:
  editor:
    image: n8nio/n8n:latest
    command: start
    environment:
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_DATABASE=$POSTGRES_DB
      - DB_POSTGRESDB_HOST=$POSTGRES_HOST
      - DB_POSTGRESDB_PORT=$POSTGRES_PORT
      - DB_POSTGRESDB_USER=$POSTGRES_USER
      - DB_POSTGRESDB_PASSWORD=$POSTGRES_PASSWORD
      - N8N_ENCRYPTION_KEY=$ENCRYPTION_KEY
      - N8N_HOST=$N8N_DOMAIN_EDITOR
      - N8N_EDITOR_BASE_URL=https://$N8N_DOMAIN_EDITOR/
      - WEBHOOK_URL=https://$N8N_DOMAIN_WEBHOOK/
      - N8N_PROTOCOL=https
      - NODE_ENV=production
      - EXECUTIONS_MODE=queue
      - EXECUTIONS_PROCESS=main
      - N8N_SMTP_SENDER=$SMTP_EMAIL
      - N8N_SMTP_USER=$SMTP_USER
      - N8N_SMTP_PASS=$SMTP_PASS
      - N8N_SMTP_HOST=$SMTP_HOST
      - N8N_SMTP_PORT=$SMTP_PORT
      - N8N_SMTP_SSL=$(if [ "$SMTP_PORT" == "465" ]; then echo "true"; else echo "false"; fi)
      - QUEUE_BULL_REDIS_HOST=$REDIS_HOST
      - QUEUE_BULL_REDIS_PORT=$REDIS_PORT
      - QUEUE_BULL_REDIS_PASSWORD=$REDIS_PASSWORD
      - GENERIC_TIMEZONE=America/Sao_Paulo
      - TZ=America/Sao_Paulo
    networks:
      - $NOME_REDE
    deploy:
      mode: replicated
      replicas: 1
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.n8n_editor.rule=Host(\`$N8N_DOMAIN_EDITOR\`)"
        - "traefik.http.routers.n8n_editor.entrypoints=websecure"
        - "traefik.http.routers.n8n_editor.tls.certresolver=letsencryptresolver"
        - "traefik.http.routers.n8n_editor.service=n8n_editor"
        - "traefik.http.services.n8n_editor.loadbalancer.server.port=5678"
      placement:
        constraints:
          - node.role == manager

  webhook:
    image: n8nio/n8n:latest
    command: webhook
    environment:
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_DATABASE=$POSTGRES_DB
      - DB_POSTGRESDB_HOST=$POSTGRES_HOST
      - DB_POSTGRESDB_PORT=$POSTGRES_PORT
      - DB_POSTGRESDB_USER=$POSTGRES_USER
      - DB_POSTGRESDB_PASSWORD=$POSTGRES_PASSWORD
      - N8N_ENCRYPTION_KEY=$ENCRYPTION_KEY
      - N8N_HOST=$N8N_DOMAIN_EDITOR
      - N8N_EDITOR_BASE_URL=https://$N8N_DOMAIN_EDITOR/
      - WEBHOOK_URL=https://$N8N_DOMAIN_WEBHOOK/
      - N8N_PROTOCOL=https
      - NODE_ENV=production
      - EXECUTIONS_MODE=queue
      - EXECUTIONS_PROCESS=main
      - N8N_SMTP_SENDER=$SMTP_EMAIL
      - N8N_SMTP_USER=$SMTP_USER
      - N8N_SMTP_PASS=$SMTP_PASS
      - N8N_SMTP_HOST=$SMTP_HOST
      - N8N_SMTP_PORT=$SMTP_PORT
      - N8N_SMTP_SSL=$(if [ "$SMTP_PORT" == "465" ]; then echo "true"; else echo "false"; fi)
      - QUEUE_BULL_REDIS_HOST=$REDIS_HOST
      - QUEUE_BULL_REDIS_PORT=$REDIS_PORT
      - QUEUE_BULL_REDIS_PASSWORD=$REDIS_PASSWORD
      - GENERIC_TIMEZONE=America/Sao_Paulo
      - TZ=America/Sao_Paulo
    networks:
      - $NOME_REDE
    deploy:
      mode: replicated
      replicas: 1
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.n8n_webhook.rule=Host(\`$N8N_DOMAIN_WEBHOOK\`) && PathPrefix(\`/webhook\`)"
        - "traefik.http.routers.n8n_webhook.entrypoints=websecure"
        - "traefik.http.routers.n8n_webhook.tls.certresolver=letsencryptresolver"
        - "traefik.http.routers.n8n_webhook.service=n8n_webhook"
        - "traefik.http.services.n8n_webhook.loadbalancer.server.port=5678"
      placement:
        constraints:
          - node.role == manager

  worker:
    image: n8nio/n8n:latest
    command: worker --concurrency=10
    environment:
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_DATABASE=$POSTGRES_DB
      - DB_POSTGRESDB_HOST=$POSTGRES_HOST
      - DB_POSTGRESDB_PORT=$POSTGRES_PORT
      - DB_POSTGRESDB_USER=$POSTGRES_USER
      - DB_POSTGRESDB_PASSWORD=$POSTGRES_PASSWORD
      - N8N_ENCRYPTION_KEY=$ENCRYPTION_KEY
      - N8N_HOST=$N8N_DOMAIN_EDITOR
      - N8N_EDITOR_BASE_URL=https://$N8N_DOMAIN_EDITOR/
      - WEBHOOK_URL=https://$N8N_DOMAIN_WEBHOOK/
      - N8N_PROTOCOL=https
      - NODE_ENV=production
      - EXECUTIONS_MODE=queue
      - EXECUTIONS_PROCESS=main
      - N8N_SMTP_SENDER=$SMTP_EMAIL
      - N8N_SMTP_USER=$SMTP_USER
      - N8N_SMTP_PASS=$SMTP_PASS
      - N8N_SMTP_HOST=$SMTP_HOST
      - N8N_SMTP_PORT=$SMTP_PORT
      - N8N_SMTP_SSL=$(if [ "$SMTP_PORT" == "465" ]; then echo "true"; else echo "false"; fi)
      - QUEUE_BULL_REDIS_HOST=$REDIS_HOST
      - QUEUE_BULL_REDIS_PORT=$REDIS_PORT
      - QUEUE_BULL_REDIS_PASSWORD=$REDIS_PASSWORD
      - GENERIC_TIMEZONE=America/Sao_Paulo
      - TZ=America/Sao_Paulo
    networks:
      - $NOME_REDE
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager

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
    STACK_ID=$(echo "$STACKS_RESP" | jq -r '.[] | select(.Name == "n8n") | .Id' 2>/dev/null || true)
fi

STACK_CONTENT=$(cat "$BASE_DIR/n8n-stack.yaml")

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
        docker stack deploy -c "$BASE_DIR/n8n-stack.yaml" n8n
    fi

else
    info "Criando nova stack via Portainer API..."
    
    CREATE_PAYLOAD=$(jq -n \
        --arg name "n8n" \
        --arg swarmID "$SWARM_ID" \
        --arg stackFileContent "$STACK_CONTENT" \
        '{
            Name: $name,
            SwarmID: $swarmID,
            StackFileContent: $stackFileContent,
            Env: []
        }')

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
        docker stack deploy -c "$BASE_DIR/n8n-stack.yaml" n8n
    fi
fi

wait_stack "n8n_editor"
wait_stack "n8n_webhook"

echo ""
echo -e "${VERDE}Instalação do n8n Concluída!${NC}"
echo "Editor: https://$N8N_DOMAIN_EDITOR"
echo "Webhook: https://$N8N_DOMAIN_WEBHOOK"
echo "Credenciais salvas em: $BASE_DIR/dados_n8n.txt"
