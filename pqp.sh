#!/bin/bash

# --- CONFIGURAÇÃO ---
# 1. Defina o caminho para o arquivo problemático (deve ser o correto)
SECRET_FILE=".env"
# 2. Defina o conteúdo do seu novo commit
NEW_COMMIT_MESSAGE="Corrigido: Removida chave de API do histórico de commits."

# --- AVISO DE SEGURANÇA ---
echo "=========================================="
echo "🚨 ATENÇÃO: ESTE SCRIPT REESCREVE O HISTÓRICO DO GIT!"
echo "Certifique-se de que a chave de API FOI REMOVIDA manualmente do arquivo: $SECRET_FILE"
echo "E que você REVOGOU a chave na plataforma OpenAI!"
echo "Pressione [ENTER] para continuar ou Ctrl+C para cancelar."
read

# --- PASSOS DE CORREÇÃO ---

echo "1. Desfazendo o último commit (soft reset)..."
# O --soft mantém as mudanças no seu diretório de trabalho e área de staging
git reset --soft HEAD^

echo "2. Garantindo que o arquivo de segredo não será commitado (.gitignore e git rm --cached)..."
# Adiciona o arquivo .env ao .gitignore (se já não estiver lá)
if ! grep -q "$SECRET_FILE" .gitignore; then
  echo "$SECRET_FILE" >> .gitignore
fi

# Remove o arquivo do rastreamento do Git (ele continua no disco)
git rm --cached $SECRET_FILE

echo "3. Refazendo o commit com o histórico limpo..."
# Adiciona todos os arquivos restantes ao staging (incluindo o .gitignore atualizado)
git add .
git commit -m "$NEW_COMMIT_MESSAGE"

echo "4. Tentando fazer o push forçado..."
# O push forçado é necessário porque o histórico local foi reescrito.
git push --force

if [ $? -eq 0 ]; then
  echo "✅ Sucesso! O push foi concluído. O histórico foi reescrito."
else
  echo "❌ Erro! O push falhou novamente. A chave ainda pode estar em commits mais antigos."
  echo "Considere usar 'git rebase -i' para remover segredos de commits mais antigos."
fi