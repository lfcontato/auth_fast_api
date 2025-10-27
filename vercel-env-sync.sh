#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------
# Vercel ENV Sync (update-or-insert)
# ---------------------------------------
# Uso:
#   ./vercel-env-sync.sh [production|preview|development] [--file .env] [--dry-run]
#
# Regras:
# - Atualiza se já existir (rm -> add); insere se não existir.
# - Ignora linhas em branco e comentários (#).
# - Aceita "export KEY=VAL" e "KEY=VAL".
# - Mantém tudo após o primeiro "=" como valor (inclui "=" no valor).
# - Remove CRLF do fim da linha (compatível com arquivos do Windows).
#
# Exemplo:
#   ./vercel-env-sync.sh production
#   ./vercel-env-sync.sh preview --file .env.preview
#   ./vercel-env-sync.sh development --dry-run

# ---------- cores ----------
BOLD="\033[1m"; DIM="\033[2m"; RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; NC="\033[0m"

# ---------- args ----------
ENVIRONMENT="${1:-production}"
shift || true

FILE_ARG=""
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --file) FILE_ARG="$2"; shift 2;;
    --dry-run) DRY_RUN="true"; shift;;
    *) echo -e "${RED}Argumento desconhecido:${NC} $1"; exit 1;;
  esac
done

# ---------- escolhe arquivo ----------
guess_file() {
  case "$ENVIRONMENT" in
    production)   [[ -f ".env.production" ]] && echo ".env.production" || echo ".env" ;;
    preview)      [[ -f ".env.preview" ]] && echo ".env.preview" || echo ".env" ;;
    development)  [[ -f ".env.development" ]] && echo ".env.development" || echo ".env" ;;
    *)            echo ".env" ;;
  esac
}

FILE="${FILE_ARG:-$(guess_file)}"

if [[ ! -f "$FILE" ]]; then
  echo -e "${RED}Arquivo não encontrado:${NC} $FILE"
  exit 1
fi

# ---------- checagens ----------
if ! command -v vercel >/dev/null 2>&1; then
  echo -e "${RED}Vercel CLI não encontrado.${NC} Instale com: ${BOLD}npm i -g vercel${NC}"
  exit 1
fi

echo -e "${BOLD}Vercel ENV Sync${NC}"
echo -e " Ambiente: ${BLUE}${ENVIRONMENT}${NC}"
echo -e " Arquivo:  ${BLUE}${FILE}${NC}"
[[ "$DRY_RUN" == "true" ]] && echo -e " Modo:     ${YELLOW}DRY-RUN (não aplica)${NC}"
echo

# ---------- loop ----------
updated=0; skipped=0; total=0

while IFS= read -r rawline || [[ -n "$rawline" ]]; do
  # remove CR (Windows)
  line="${rawline%$'\r'}"

  # ignora em branco ou comentário puro
  [[ -z "${line//[[:space:]]/}" ]] && continue
  [[ "$line" =~ ^[[:space:]]*# ]] && continue

  # remove prefixo "export "
  line="${line#export }"
  line="${line#EXPORT }"

  # precisa ter "="
  if [[ "$line" != *"="* ]]; then
    echo -e "${DIM}Ignorando linha sem '=':${NC} $line"
    ((skipped++)); ((total++)); continue
  fi

  key="${line%%=*}"
  value="${line#*=}"

  # trim key
  key="$(echo -n "$key" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

  # ignora se key vazia
  if [[ -z "$key" ]]; then
    echo -e "${DIM}Ignorando chave vazia:${NC} $line"
    ((skipped++)); ((total++)); continue
  fi

  ((total++))

  if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}[DRY]${NC} Atualizaria ${BOLD}$key${NC}"
    continue
  fi

  echo -e "→ ${DIM}Atualizando${NC} ${BOLD}$key${NC}"

  # remove silenciosamente (se não existir, ignora erro)
  vercel env rm "$key" "$ENVIRONMENT" --yes >/dev/null 2>&1 || true

  # adiciona (mantém valor exato, inclusive com '=' no meio)
  # Usamos stdin para evitar eco do valor no terminal
  printf "%s" "$value" | vercel env add "$key" "$ENVIRONMENT" >/dev/null

  echo -e "   ${GREEN}OK${NC} ${DIM}($key)${NC}"
  ((updated++))
done < "$FILE"

echo
echo -e "${BOLD}Resumo:${NC} ${GREEN}${updated} atualizadas${NC}, ${YELLOW}${skipped} ignoradas${NC}, ${BLUE}${total} lidas${NC}"
echo -e "${DIM}Dica:${NC} rode com ${BOLD}--dry-run${NC} para validar antes de aplicar."
