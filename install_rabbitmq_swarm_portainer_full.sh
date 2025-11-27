#!/usr/bin/env bash
# RabbitMQ SWARM installer (FULL v1.0) - Baseado no instalador Supabase
# - Lê/salva dados do Portainer em /srv/rabbitmq/dados_vps e dados_vps.json
# - Lista redes overlay e usa a escolhida (não cria rede)
# - Gera credenciais aleatórias para RabbitMQ
# - Faz deploy no Portainer (cria/atualiza stack)
# - MELHORIAS: Logging detalhado + tratamento de erros + integração Portainer

set -Eeuo pipefail

# Configurar logging melhorado
LOG_FILE="/tmp/rabbitmq_installer_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== Iniciando instalação RabbitMQ em $(date) ==="
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
need docker; need curl; need jq; need openssl

# Verificar se Docker Swarm está ativo
if ! docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -q "active"; then
    fail "Docker Swarm não está ativo. Execute: docker swarm init"
    exit 1
fi

# ---------- Paths / Variáveis base ----------
SUFFIX="${1:-}"                   # opcional: nome curto do projeto (ex: prod) -> services *_prod
SUF_US="${SUFFIX:+_$SUFFIX}"
BASE_DIR="/srv/rabbitmq"
REPO_DIR="${BASE_DIR}/rabbitmq${SUF_US}"
VOL_DIR="${REPO_DIR}/docker/volumes"
YAML_PATH="${REPO_DIR}/docker/rabbitmq${SUF_US}.yaml"

mkdir -p "${VOL_DIR}" "${REPO_DIR}/docker"

DADOS_VPS_ENV="${BASE_DIR}/dados_vps"
DADOS_VPS_JSON="${BASE_DIR}/dados_vps.json"
STACK_NAME="rabbitmq${SUF_US}"

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
    ans="${ans:-${OVERLAYS[0]}"
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
    : "${RABBITMQ_URL:=}"; : "${TRAEFIK_CERTRESOLVER:=letsencryptresolver}"
    : "${RABBITMQ_USER:=}"; : "${RABBITMQ_PASS:=}"
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

  # RabbitMQ URLs: se não havia no arquivo, pergunta e salva
  if [ -z "${RABBITMQ_URL:-}" ] || [ -z "${RABBITMQ_USER:-}" ] || [ -z "${RABBITMQ_PASS:-}" ]; then
    step "Configuração do RabbitMQ"
    
    if [ -z "${RABBITMQ_URL:-}" ]; then
      while [ -z "${RABBITMQ_URL:-}" ]; do
        read -r -p "URL pública do RabbitMQ, ex: rabbitmq.seu-dominio: " RABBITMQ_URL
        [ -z "$RABBITMQ_URL" ] && echo "URL do RabbitMQ é obrigatória!"
      done
    fi
    
    if [ -z "${RABBITMQ_USER:-}" ]; then
      read -r -p "Usuário do RabbitMQ [admin]: " RABBITMQ_USER
      RABBITMQ_USER="${RABBITMQ_USER:-admin}"
    fi
    
    if [ -z "${RABBITMQ_PASS:-}" ]; then
      RABBITMQ_PASS=$(openssl rand -hex 16)
      info "Senha gerada automaticamente: $RABBITMQ_PASS"
    fi
    
    if [ -z "${TRAEFIK_CERTRESOLVER:-}" ]; then
      read -r -p "Traefik certresolver [letsencryptresolver]: " TRAEFIK_CERTRESOLVER
      TRAEFIK_CERTRESOLVER="${TRAEFIK_CERTRESOLVER:-letsencryptresolver}"
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
    printf 'RABBITMQ_URL=%s\n' "$RABBITMQ_URL"
    printf 'RABBITMQ_USER=%s\n' "$RABBITMQ_USER"
    printf 'RABBITMQ_PASS=%s\n' "$RABBITMQ_PASS"
    printf 'TRAEFIK_CERTRESOLVER=%s\n' "$TRAEFIK_CERTRESOLVER"
  } > "$DADOS_VPS_ENV"

  jq -nc \
    --arg url "$PORTAINER_URL" \
    --arg user "$PORTAINER_USERNAME" \
    --arg pass "$PORTAINER_PASSWORD" \
    --argjson eid "${PORTAINER_ENDPOINT_ID}" \
    --argjson insecure "${PORTAINER_INSECURE}" \
    --arg net "$CHOSEN_NET" \
    --arg u "$RABBITMQ_URL" \
    --arg ru "$RABBITMQ_USER" \
    --arg rp "$RABBITMQ_PASS" \
    --arg c "$TRAEFIK_CERTRESOLVER" \
    '{portainer:{url:$url,username:$user,password:$pass,endpoint_id:$eid,insecure:$insecure},docker:{overlay_network:$net},rabbitmq:{public_url:$u,user:$ru,password:$rp,traefik_certresolver:$c}}' \
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

# ---------- 4) Gerar credenciais RabbitMQ ----------
step "Gerando credenciais RabbitMQ"
RABBITMQ_ERLANG_COOKIE="$(openssl rand -hex 16)"
ok "Credenciais geradas"

# ---------- 5) rabbitmq.yaml (formato do original) ----------
step "Gerando rabbitmq.yaml (rede overlay: ${nome_rede_interna})"
cat > "${YAML_PATH}" <<EOF
version: "3.7"
services:

## ------------------------------------------------------------------------ ##

  rabbitmq${SUF_US}:
    image: rabbitmq:management
    command: rabbitmq-server

    hostname: rabbitmq

    volumes:
      - rabbitmq${SUF_US}_data:/var/lib/rabbitmq

    networks:
      - $nome_rede_interna

    environment:
    ## Dados de acesso
      - RABBITMQ_DEFAULT_USER=$RABBITMQ_USER
      - RABBITMQ_DEFAULT_PASS=$RABBITMQ_PASS
      - RABBITMQ_ERLANG_COOKIE=$RABBITMQ_ERLANG_COOKIE
      - RABBITMQ_DEFAULT_VHOST=/

    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager
      resources:
        limits:
          cpus: "1"
          memory: 1024M
      labels:
        - traefik.enable=true
        - traefik.http.routers.rabbitmq${SUF_US}.rule=Host(\`$RABBITMQ_URL\`)
        - traefik.http.routers.rabbitmq${SUF_US}.entrypoints=websecure
        - traefik.http.routers.rabbitmq${SUF_US}.tls.certresolver=$TRAEFIK_CERTRESOLVER
        - traefik.http.routers.rabbitmq${SUF_US}.service=rabbitmq${SUF_US}
        - traefik.http.services.rabbitmq${SUF_US}.loadbalancer.server.port=15672

## ------------------------------------------------------------------------ ##

volumes:
  rabbitmq${SUF_US}_data:
    external: true

networks:
  $nome_rede_interna:
    external: true
EOF

ok "Stack gerada: ${YAML_PATH}"

# ---------- 6) Criar volume externo do RabbitMQ (se não existir) ----------
docker volume create "rabbitmq${SUF_US}_data" >/dev/null 2>&1 || true

# ---------- 7) Deploy via Portainer ----------
if [[ "${DRY_RUN}" == "1" ]]; then
    step "MODO DRY-RUN: Pulando deploy no Portainer"
    ok "Arquivos gerados com sucesso (sem deploy):"
    echo " - ${DADOS_VPS_ENV}"
    echo " - ${DADOS_VPS_JSON}"
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

# ---------- Verificação pós-deploy ----------
step "Verificando serviços pós-deploy"

# Aguardar alguns segundos para os serviços iniciarem
sleep 5

# Verificar serviços com problemas e tentar corrigir
info "Verificando status dos serviços..."
failed_services=$(docker service ls --format "table {{.Name}}\t{{.Replicas}}" | grep "${STACK_NAME}_" | grep "0/1" | awk '{print $1}' || true)

if [ -n "$failed_services" ]; then
    info "Serviços com problemas detectados: $failed_services"
    
    for service in $failed_services; do
        info "Reiniciando $service"
        docker service update --force "$service" >/dev/null 2>&1 || true
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
step "Informações de acesso ao RabbitMQ"
echo
echo -e "${cg}=== RABBITMQ INSTALADO COM SUCESSO ===${c0}"
echo
echo -e "${cy}URL de Acesso:${c0} https://$RABBITMQ_URL"
echo -e "${cy}Usuário:${c0} $RABBITMQ_USER"
echo -e "${cy}Senha:${c0} $RABBITMQ_PASS"
echo
echo -e "${cy}Serviços Ativos:${c0}"
docker service ls --format "table {{.Name}}\t{{.Replicas}}\t{{.Image}}" | grep "${STACK_NAME}_" | sed 's/^/  /'
echo

ok "Arquivos:"
echo " - ${DADOS_VPS_ENV}"
echo " - ${DADOS_VPS_JSON}"
echo " - ${YAML_PATH}"
echo
ok "Concluído. Stack '${STACK_NAME}' no Portainer usando a rede '${nome_rede_interna}'."
echo "=== Log completo salvo em: $LOG_FILE ==="

