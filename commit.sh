#!/bin/bash

# Obtém a data e hora atual no formato ano-mês-dia-hora-minuto-segundo
current_date=$(date '+%Y-%m-%d-%H-%M-%S')

# Obtém o nome do computador
computer_name=$(hostname)

# Se atualizar os ignores
# git rm -r --cached .

# Exibe a data e o nome do computador
# git config --global credential.helper osxkeychain
# git config --global credential.helper 'cache --timeout=3600' # Armazena por 1 hora
git config --global user.name "luis.fernando.pereira@gmail.com"
git config --global user.email "luis.fernando.pereira@gmail.com"
git config --global credential.helper store
git add .
git commit -m "$computer_name $current_date"
git push