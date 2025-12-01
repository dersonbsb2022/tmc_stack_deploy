#!/bin/bash
set -e

echo "=== INICIANDO LIMPEZA COMPLETA ==="
echo "ATENÇÃO: Isso removerá TODOS os containers, volumes, redes e dados em /srv."
echo "Esta ação é IRREVERSÍVEL."
read -p "Tem certeza que deseja continuar? (digite 'sim' para confirmar): " confirm

if [ "$confirm" != "sim" ]; then
    echo "Operação cancelada."
    exit 1
fi

echo "[1/5] Removendo Serviços do Swarm..."
# Remove todos os serviços
if [ "$(docker service ls -q)" ]; then
    docker service rm $(docker service ls -q)
fi

echo "[2/5] Removendo Stacks..."
# Remove todas as stacks (pode falhar se não tiver o binário do docker stack ou se não tiver stacks, ignorar erro)
docker stack rm $(docker stack ls --format "{{.Name}}") 2>/dev/null || true

echo "[3/5] Limpando Containers, Volumes e Redes..."
# Força remoção de tudo
docker system prune -a -f --volumes

# Remove redes overlay que podem ter sobrado
docker network prune -f

echo "[4/5] Removendo Diretórios de Dados..."
rm -rf /srv/*
rm -rf /etc/traefik
rm -rf /root/dados_vps

echo "[5/5] Desinstalando Docker..."
systemctl stop docker || true
apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras || true
apt-get autoremove -y || true
rm -rf /var/lib/docker
rm -rf /var/lib/containerd
rm -rf /etc/docker

echo "=== Limpeza Concluída! ==="
echo "O sistema foi resetado. Para iniciar do zero, rode o install_base.sh novamente."
