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

# Função de espera (Healthcheck simples)
wait_stack() {
    local service_name="$1"
    info "Aguardando serviço $service_name iniciar..."
    local retries=0
    local max_retries=30
    
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

# 0. Verificação Inicial de Segurança (Antes de tudo)
if command -v docker &> /dev/null; then
    if docker info 2>/dev/null | grep -q "Swarm: active"; then
        if docker stack ls > /dev/null 2>&1; then
            if docker stack ls | grep -qE "traefik|portainer"; then
                clear
                echo -e "${VERMELHO}!!! ATENÇÃO - SISTEMA JÁ EM USO !!!${NC}"
                echo -e "${AMARELO}Detectamos que já existem stacks do Traefik ou Portainer rodando neste Swarm.${NC}"
                echo -e "Prosseguir irá ${VERMELHO}REMOVER${NC} as instalações atuais e recriá-las do zero."
                echo -e "Isso pode causar interrupção nos serviços e perda de configurações não persistidas."
                echo ""
                echo -e "Para continuar e SOBRESCREVER a instalação atual, digite: ${VERDE}CONFIRMO${NC}"
                echo -e "Para cancelar, pressione ENTER ou digite qualquer outra coisa."
                echo ""
                read -p "Sua escolha: " CONFIRMACAO

                if [ "$CONFIRMACAO" == "CONFIRMO" ]; then
                    info "Removendo instalações antigas..."
                    docker stack rm traefik portainer 2>/dev/null || true
                    info "Aguardando limpeza dos serviços (20s)..."
                    sleep 20
                    ok "Stacks removidas. Iniciando nova instalação..."
                else
                    erro "Instalação cancelada pelo usuário."
                    exit 0
                fi
            fi
        fi
    fi
fi

# 1. Coleta de Dados
clear
echo -e "${VERDE}=== TMC Stack Deploy: Base (Swarm + Traefik + Portainer) ===${NC}"
echo ""

read -p "Nome do Servidor (Hostname) [ex: vps-01]: " NOME_SERVIDOR
read -p "Nome da Rede Overlay [ex: tmc_net]: " NOME_REDE
read -p "Email para SSL (Let's Encrypt) [ex: admin@dominio.com]: " EMAIL_SSL
read -p "Domínio do Portainer [ex: portainer.dominio.com]: " URL_PORTAINER
read -p "Usuário Admin do Portainer [ex: admin]: " USER_PORTAINER
read -s -p "Senha Admin do Portainer (min 12 chars): " PASS_PORTAINER
echo ""

if [[ -z "$NOME_SERVIDOR" || -z "$NOME_REDE" || -z "$EMAIL_SSL" || -z "$URL_PORTAINER" || -z "$USER_PORTAINER" || -z "$PASS_PORTAINER" ]]; then
    erro "Todos os campos são obrigatórios."
    exit 1
fi

# 2. Configuração do Sistema
info "Configurando Hostname e Timezone..."
hostnamectl set-hostname "$NOME_SERVIDOR"
timedatectl set-timezone America/Sao_Paulo
sed -i "s/127.0.0.1[[:space:]]localhost/127.0.0.1 localhost $NOME_SERVIDOR/g" /etc/hosts

# 3. Instalação do Docker
info "Instalando Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | bash
    systemctl enable docker
    systemctl start docker
else
    ok "Docker já instalado."
fi

# 4. Inicialização do Swarm
info "Inicializando Docker Swarm..."
if ! docker info | grep -q "Swarm: active"; then
    IP_ADDR=$(hostname -I | awk '{print $1}')
    docker swarm init --advertise-addr "$IP_ADDR"
    ok "Swarm inicializado no IP $IP_ADDR."
else
    ok "Swarm já ativo."
fi



# 5. Rede Overlay
info "Criando rede $NOME_REDE..."
if ! docker network ls | grep -q "$NOME_REDE"; then
    docker network create --driver=overlay "$NOME_REDE"
    ok "Rede criada."
else
    ok "Rede já existe."
fi

# 6. Traefik
info "Deploy do Traefik..."
cat > traefik.yaml <<EOF
version: "3.7"
services:
  traefik:
    image: traefik:v3.4.0
    command:
      - "--api.dashboard=true"
      - "--providers.swarm=true"
      - "--providers.docker.endpoint=unix:///var/run/docker.sock"
      - "--providers.docker.exposedbydefault=false"
      - "--providers.docker.network=$NOME_REDE"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencryptresolver.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencryptresolver.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencryptresolver.acme.storage=/etc/traefik/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencryptresolver.acme.email=$EMAIL_SSL"
      - "--log.level=INFO"
    volumes:
      - "vol_certificates:/etc/traefik/letsencrypt"
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
    networks:
      - $NOME_REDE
    ports:
      - target: 80
        published: 80
        mode: host
      - target: 443
        published: 443
        mode: host
    deploy:
      placement:
        constraints:
          - node.role == manager
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.dashboard.rule=Host(\`traefik.$URL_PORTAINER\`)"
        - "traefik.http.routers.dashboard.service=api@internal"
        - "traefik.http.routers.dashboard.entrypoints=websecure"
        - "traefik.http.routers.dashboard.tls.certresolver=letsencryptresolver"
        - "traefik.http.services.dummy.loadbalancer.server.port=9999"

volumes:
  vol_certificates:
    external: true
    name: volume_swarm_certificates

networks:
  $NOME_REDE:
    external: true
EOF

# Cria volumes externos se não existirem
docker volume create volume_swarm_certificates || true

docker stack deploy --prune --resolve-image always -c traefik.yaml traefik
wait_stack "traefik_traefik"

# 7. Portainer
info "Deploy do Portainer..."
cat > portainer.yaml <<EOF
version: "3.7"
services:
  agent:
    image: portainer/agent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/lib/docker/volumes:/var/lib/docker/volumes
    networks:
      - $NOME_REDE
    deploy:
      mode: global
      placement:
        constraints: [node.platform.os == linux]

  portainer:
    image: portainer/portainer-ce:latest
    command: -H tcp://tasks.agent:9001 --tlsskipverify
    volumes:
      - portainer_data:/data
    networks:
      - $NOME_REDE
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints: [node.role == manager]
      labels:
        - "traefik.enable=true"
        - "traefik.http.routers.portainer.rule=Host(\`$URL_PORTAINER\`)"
        - "traefik.http.services.portainer.loadbalancer.server.port=9000"
        - "traefik.http.routers.portainer.tls.certresolver=letsencryptresolver"
        - "traefik.http.routers.portainer.entrypoints=websecure"

volumes:
  portainer_data:
    external: true
    name: portainer_data

networks:
  $NOME_REDE:
    external: true
EOF

docker volume create portainer_data || true
docker stack deploy --prune --resolve-image always -c portainer.yaml portainer
wait_stack "portainer_portainer"

# 8. Configuração Inicial do Portainer (API)
info "Configurando usuário Admin no Portainer..."
sleep 10 # Aguarda Portainer estar pronto para receber requisições

# Tenta criar o usuário
RESPONSE=$(curl -k -s -X POST "https://$URL_PORTAINER/api/users/admin/init" \
    -H "Content-Type: application/json" \
    -d "{\"Username\": \"$USER_PORTAINER\", \"Password\": \"$PASS_PORTAINER\"}")

if echo "$RESPONSE" | grep -q "Username"; then
    ok "Usuário admin criado."
else
    # Se falhar, pode ser que já exista ou erro de conexão. Tenta autenticar para ver se já existe.
    info "Não foi possível inicializar admin (talvez já exista). Tentando autenticar..."
fi

# Gera Token
info "Gerando Token de Acesso..."
TOKEN=$(curl -k -s -X POST "https://$URL_PORTAINER/api/auth" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER_PORTAINER\",\"password\":\"$PASS_PORTAINER\"}" | jq -r .jwt)

if [[ "$TOKEN" != "null" && -n "$TOKEN" ]]; then
    ok "Token gerado com sucesso."
    
    # Salva Credenciais
    mkdir -p /root/dados_vps
    cat > /root/dados_vps/dados_portainer <<EOF
[ PORTAINER ]
URL: https://$URL_PORTAINER
User: $USER_PORTAINER
Pass: $PASS_PORTAINER
Token: $TOKEN
Network: $NOME_REDE
EOF
    chmod 600 /root/dados_vps/dados_portainer
    ok "Credenciais salvas em /root/dados_vps/dados_portainer"
else
    erro "Falha ao gerar token. Verifique as credenciais ou se o Portainer subiu corretamente."
    exit 1
fi

echo ""
echo -e "${VERDE}TMC Stack Deploy Base Concluído!${NC}"
echo "Acesse: https://$URL_PORTAINER"
