#!/usr/bin/env bash
set -Eeuo pipefail

echo "--> Iniciando instalador do Postgres..."
echo "--> Verificando se o Docker Swarm está ativo..."

if ! docker info | grep -q "Swarm: active"; then
    echo "ERRO: Docker Swarm não está ativo. Execute a instalação base primeiro."
    exit 1
fi

echo "--> Simulando instalação do Postgres..."
sleep 2
echo "--> Criando volumes..."
sleep 1
echo "--> Deploy da stack via Portainer API (Simulado)..."
sleep 1

echo "--> Postgres instalado com sucesso!"
