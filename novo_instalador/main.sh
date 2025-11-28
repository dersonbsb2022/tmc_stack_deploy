#!/usr/bin/env bash
set -Eeuo pipefail

# Configurações Globais
REPO_BASE_URL="https://raw.githubusercontent.com/dersonbsb2022/tmc_stack_deploy/main/novo_instalador/apps"
# Para testes locais, você pode descomentar a linha abaixo:
# REPO_BASE_URL="file://$(pwd)/apps"

# Cores
VERDE='\033[0;32m'
AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'
NC='\033[0m' # No Color

# Funções de Log
info() { echo -e "${AMARELO}[INFO]${NC} $1"; }
ok() { echo -e "${VERDE}[OK]${NC} $1"; }
erro() { echo -e "${VERMELHO}[ERRO]${NC} $1"; }

# 1. Verificação do Sistema Operacional (Debian 13 - Trixie)
verificar_os() {
    info "Verificando Sistema Operacional..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "debian" ]]; then
            # Debian 13 é "trixie" (testing atualmente)
            # A versão pode não estar numerada como 13 ainda em algumas builds, então checamos o codename
            if [[ "$VERSION_ID" == "13" ]] || [[ "$VERSION_CODENAME" == "trixie" ]]; then
                ok "Sistema detectado: Debian 13 (Trixie) - Experimental"
            else
                erro "Este script foi projetado para Debian 13 (Trixie)."
                erro "Sistema atual: $PRETTY_NAME"
                read -p "Deseja continuar mesmo assim? (s/n): " continuar
                if [[ "$continuar" != "s" ]]; then
                    exit 1
                fi
            fi
        else
            erro "Este script requer Debian. Sistema atual: $ID"
            exit 1
        fi
    else
        erro "Não foi possível identificar o sistema operacional."
        exit 1
    fi
}

# 2. Verificação de Dependências Básicas
verificar_dependencias() {
    info "Verificando dependências..."
    local deps=("curl" "wget" "jq" "git")
    local faltantes=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            faltantes+=("$dep")
        fi
    done

    if [ ${#faltantes[@]} -gt 0 ]; then
        info "Instalando dependências faltantes: ${faltantes[*]}"
        apt-get update -qq
        apt-get install -y -qq "${faltantes[@]}"
        ok "Dependências instaladas."
    else
        ok "Todas as dependências estão satisfeitas."
    fi
}

# 3. Função para Baixar e Executar Scripts
baixar_e_executar() {
    local script_name="$1"
    local temp_file="/tmp/$script_name"
    
    # Detecta diretório local de apps (assumindo estrutura do repo)
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local local_app_path="$script_dir/apps/$script_name"

    # Lógica Híbrida:
    # 1. Se o arquivo existir localmente (Ambiente de Dev/Repo clonado), usa ele.
    # 2. Se não existir, baixa do GitHub (Ambiente de Produção/Curl).
    
    if [ -f "$local_app_path" ]; then
        info "Modo DEV: Usando script local ($local_app_path)..."
        cp "$local_app_path" "$temp_file"
    else
        info "Baixando $script_name do GitHub..."
        # Adiciona timestamp para evitar cache do GitHub Raw
        local url="$REPO_BASE_URL/$script_name?t=$(date +%s)"
        
        if ! curl -fsSL "$url" -o "$temp_file"; then
            erro "Falha ao baixar o script: $url"
            return 1
        fi
    fi

    chmod +x "$temp_file"
    
    info "Executando $script_name..."
    echo "---------------------------------------------------"
    # Executa o script e passa o controle para ele
    # O script filho deve herdar as variáveis de ambiente se necessário
    bash "$temp_file"
    local status=$?
    echo "---------------------------------------------------"
    
    if [ $status -eq 0 ]; then
        ok "Instalação de $script_name concluída com sucesso."
    else
        erro "Falha na execução de $script_name."
    fi
    
    # Limpeza
    rm -f "$temp_file"
    
    echo ""
    read -p "Pressione ENTER para voltar ao menu..."
}

# 4. Menu Principal
menu_principal() {
    while true; do
        clear
        echo -e "${VERDE}===================================================${NC}"
        echo -e "${VERDE}           TMC STACK DEPLOY V2 (MODULAR)           ${NC}"
        echo -e "${VERDE}===================================================${NC}"
        echo -e "${AMARELO}Base: Debian 13 (Experimental)${NC}"
        echo ""
        echo "1. Instalar Docker Swarm & Portainer (Base)"
        echo "2. Instalar Postgres"
        echo "3. Instalar Redis"
        echo "4. Instalar N8N"
        echo "5. Instalar Supabase"
        echo "0. Sair"
        echo ""
        read -p "Escolha uma opção: " opcao

        case $opcao in
            1) baixar_e_executar "install_base.sh" ;;
            2) baixar_e_executar "install_postgres.sh" ;;
            3) baixar_e_executar "install_redis.sh" ;;
            4) baixar_e_executar "install_n8n.sh" ;;
            5) baixar_e_executar "install_supabase.sh" ;;
            0) exit 0 ;;
            *) erro "Opção inválida!" ; sleep 1 ;;
        esac
    done
}

# Execução
if [[ $EUID -ne 0 ]]; then
   erro "Este script precisa ser executado como root."
   exit 1
fi

verificar_os
verificar_dependencias
menu_principal
