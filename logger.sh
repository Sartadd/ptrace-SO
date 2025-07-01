#!/bin/bash

# --- Configurações ---
# O comando para executar o módulo Python principal do seu logger
PYTHON_LOGGER_CMD="python3 -m syscall_logger.main" 
OUTPUT_DIR="./logs" # Diretório padrão para salvar os arquivos de log
DEFAULT_FORMAT="text"

# --- Cores para melhor visualização ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Variáveis para armazenar os argumentos ---
TARGET_PID=""
TARGET_CMD_ARRAY=()
OUTPUT_FILE=""
OUTPUT_FORMAT=""

# --- Funções Auxiliares ---

# Exibe a mensagem de uso do script
display_usage() {
    echo -e "${BLUE}Uso: sudo $0 [OPÇÕES] (--pid <PID> | --command <COMANDO> [ARGS...])${NC}"
    echo -e "Monitora chamadas de sistema de um PID existente ou de um novo comando usando o logger Python."
    echo -e "\n${YELLOW}Opções:${NC}"
    echo -e "  ${GREEN}-p, --pid <PID>${NC}        : PID do processo a ser monitorado."
    echo -e "  ${GREEN}-c, --command <COMANDO>${NC} : Comando a ser executado e monitorado (ex: /bin/ls -la)."
    echo -e "                             Args para o comando devem vir depois do --command."
    echo -e "  ${GREEN}-o, --output <ARQUIVO>${NC}  : Caminho para o arquivo de saída. Padrão: stdout."
    echo -e "                             Será salvo em '${OUTPUT_DIR}/<ARQUIVO>' se apenas o nome for dado."
    echo -e "  ${GREEN}-f, --format <FORMATO>${NC} : Formato de saída do log (text, csv, json). Padrão: text."
    echo -e "  ${GREEN}-h, --help${NC}             : Exibe esta mensagem de ajuda."
    echo -e "\n${YELLOW}Exemplos:${NC}"
    echo -e "  ${GREEN}sudo $0 --pid 12345 --format text${NC}"
    echo -e "  ${GREEN}sudo $0 -c \"ls -la /tmp\" -o meu_log.csv -f csv${NC}"
    echo -e "  ${GREEN}sudo $0 --command \"python3 my_script.py arg1 arg2\" --output my_app_log.json --format json${NC}"
    exit 1
}

# Garante que o diretório de logs exista
ensure_output_dir() {
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR"
        echo -e "${YELLOW}Diretório de logs '$OUTPUT_DIR' criado.${NC}"
    fi
}

# Valida um PID (verifica se é numérico e se o processo existe)
is_valid_pid() {
    local pid="$1"
    [[ "$pid" =~ ^[0-9]+$ ]] && ps -p "$pid" > /dev/null
}

# --- Parsing de Argumentos ---

# Opções de short e long
OPTIONS="p:c:o:f:h"
LONG_OPTIONS="pid:,command:,output:,format:,help"

# Analisa os argumentos da linha de comando
PARSED_ARGS=$(getopt -o $OPTIONS --long $LONG_OPTIONS --name "$0" -- "$@")

if [[ $? -ne 0 ]]; then
    # Erro no getopt, exibe uso
    display_usage
fi

# Avalia o comando gerado pelo getopt para setar as variáveis
eval set -- "$PARSED_ARGS"

# Loop para processar cada argumento
while true; do
    case "$1" in
        -p|--pid)
            TARGET_PID="$2"
            shift 2
            ;;
        -c|--command)
            # Todos os argumentos restantes são parte do comando
            shift # Remove -c ou --command
            TARGET_CMD_ARRAY=("$@") # Pega todos os argumentos restantes
            break # Sair do loop de parsing de opções
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -h|--help)
            display_usage
            ;;
        --)
            # Fim das opções
            shift
            break
            ;;
        *)
            # Argumento inesperado ou erro
            echo -e "${RED}ERRO: Argumento inesperado: $1${NC}" >&2
            display_usage
            ;;
    esac
done

# --- Validação e Execução ---

# Verifica se o comando Python do logger pode ser invocado
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERRO: 'python3' não encontrado. Certifique-se de que Python 3 está instalado e no PATH.${NC}" >&2
    exit 1
fi
# Testa se o módulo python consegue ser importado (exemplo de teste)
# O teste abaixo tenta executar um comando básico para verificar se o módulo existe.
if ! python3 -c "import syscall_logger.main" &> /dev/null; then
    echo -e "${RED}ERRO: Não foi possível encontrar o módulo 'syscall_logger.main'.${NC}" >&2
    echo -e "${YELLOW}Certifique-se de que você está executando o script do diretório raiz 'syscall-logger-py/' e que os arquivos Python estão corretos.${NC}" >&2
    exit 1
fi


# Valida o formato de saída
case "$OUTPUT_FORMAT" in
    "text"|"csv"|"json"|"") # Vazio é aceitável, usará o padrão do script Python
        ;;
    *)
        echo -e "${RED}ERRO: Formato de saída inválido: '$OUTPUT_FORMAT'. Use 'text', 'csv' ou 'json'.${NC}" >&2
        display_usage
        ;;
esac

# Verifica se o PID ou o comando foram especificados
if [[ -z "$TARGET_PID" && ${#TARGET_CMD_ARRAY[@]} -eq 0 ]]; then
    echo -e "${RED}ERRO: Você deve especificar um PID (--pid) ou um comando (--command).${NC}" >&2
    display_usage
fi

# Verifica se apenas um dos dois (PID ou Comando) foi especificado
if [[ -n "$TARGET_PID" && ${#TARGET_CMD_ARRAY[@]} -gt 0 ]]; then
    echo -e "${RED}ERRO: Não é possível especificar --pid E --command ao mesmo tempo.${NC}" >&2
    display_usage
fi

# Constrói o comando base para o logger Python
LOGGER_COMMAND="sudo $PYTHON_LOGGER_CMD"

# Adiciona argumentos de saída
if [[ -n "$OUTPUT_FILE" ]]; then
    # Se o caminho de saída não for absoluto, salva no diretório de logs
    if [[ ! "$OUTPUT_FILE" =~ ^/ ]]; then # Não começa com /
        ensure_output_dir
        OUTPUT_FILE="${OUTPUT_DIR}/${OUTPUT_FILE}"
    fi
    LOGGER_COMMAND+=" --output \"$OUTPUT_FILE\""
    echo -e "${BLUE}Log será salvo em: ${OUTPUT_FILE}${NC}"
fi

if [[ -n "$OUTPUT_FORMAT" ]]; then
    LOGGER_COMMAND+=" --format $OUTPUT_FORMAT"
else
    # Se nenhum formato foi especificado, não adiciona --format, deixando o logger Python usar seu padrão
    # Ou, se preferir forçar um padrão via Bash:
    # LOGGER_COMMAND+=" --format $DEFAULT_FORMAT"
    : # Não faz nada, o logger Python já tem um padrão
fi

# Adiciona o PID ou o comando alvo
if [[ -n "$TARGET_PID" ]]; then
    if ! is_valid_pid "$TARGET_PID"; then
        echo -e "${RED}ERRO: O PID '$TARGET_PID' é inválido ou o processo não está em execução.${NC}" >&2
        exit 1
    fi
    LOGGER_COMMAND+=" $TARGET_PID"
    echo -e "${BLUE}Monitorando PID: $TARGET_PID${NC}"
elif [[ ${#TARGET_CMD_ARRAY[@]} -gt 0 ]]; then
    # Converte o array de comando em uma string para passar ao eval
    # Garantir que argumentos com espaços sejam tratados corretamente
    local cmd_str=""
    for arg in "${TARGET_CMD_ARRAY[@]}"; do
        # Envolve cada argumento em aspas duplas para preservar espaços e caracteres especiais
        # Importante para que o logger Python receba args corretamente.
        cmd_str+="\"$arg\" " 
    done
    # Adiciona --command ao comando do Python logger e depois a string do comando/args
    LOGGER_COMMAND+=" --command $cmd_str"
    echo -e "${BLUE}Executando e monitorando comando: ${cmd_str}${NC}"
fi

echo -e "${YELLOW}\nExecutando comando: ${LOGGER_COMMAND}${NC}"
echo -e "${BLUE}Atenção: Pode ser solicitada a senha do sudo.${NC}\n"

# Executa o comando construído
eval $LOGGER_COMMAND

echo -e "${GREEN}\nOperação concluída.${NC}"
exit 0