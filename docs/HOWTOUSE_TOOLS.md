Arquivo: HOWTOUSE_TOOLS.md
Resumo: Como trabalhar com UsersSpaces e bases das tools.

Manutenção: atualize estes exemplos sempre que houver mudanças nas rotas, parâmetros, respostas ou permissões. Garanta consistência com TOOLS.md e USERS.md. Não inclua checklists ou “próximos passos” aqui — o local canônico é TOOLS.md (para tools) e USERS.md (para usuários).

# UsersSpaces

Pré‑requisitos
- Ter um usuário verificado (`is_verified=true`) e com plano vigente (ex.: `lifetime`).
- Ter `FACIENDUM_DATABASE_URL` configurado (ou usar fallback local). Exemplos:
  - `FACIENDUM_DATABASE_URL=sqlite:///faciendum_test.db`
  - `FACIENDUM_DATABASE_URL=postgres://user:pass@host:5432/dbname`

Autenticar o usuário (obter ACCESS_TOKEN)
```
ACCESS_TOKEN=$(curl -s -X POST http://localhost:8080/user/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"usuario_admin","password":"senha"}' | jq -r .access_token)
echo $ACCESS_TOKEN
```

- Criar espaço (qualquer usuário verificado):
```
ACCESS_TOKEN="<JWT>"
curl -X POST http://localhost:8080/user/spaces \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Meu Espaço"}'
```

- Listar meus espaços:
```
curl -s http://localhost:8080/user/spaces \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Obter rapidamente o hash do primeiro espaço e definir `SPACE_HASH` para usar nas rotas das tools:
```
SPACE_HASH=$(curl -s http://localhost:8080/user/spaces \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -r '.items[0].hash')
echo $SPACE_HASH
```

# Databases das Tools

- Configure por variáveis de ambiente:
  - `FACIENDUM_DATABASE_URL=sqlite:///faciendum_test.db`
  - `AUTOMATA_DATABASE_URL=sqlite:///automata_test.db`

# Referência de roadmap
Consulte TOOLS.md para o checklist e próximos passos das tools.

# Membership (exemplos)

- Adicionar membro ao espaço (owner):
```
ACCESS_TOKEN="<JWT>"
SPACE_ID=1
curl -X POST http://localhost:8080/user/spaces/$SPACE_ID/members \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"login":"usuario2","role":"user"}'
```

- Listar membros do espaço (owner):
```
curl -s http://localhost:8080/user/spaces/$SPACE_ID/members \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Alterar papel do membro:
```
TARGET_USER_ID=42
curl -X PATCH http://localhost:8080/user/spaces/$SPACE_ID/members/$TARGET_USER_ID \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"guest"}'
```

- Remover membro do espaço:
```
curl -X DELETE http://localhost:8080/user/spaces/$SPACE_ID/members/$TARGET_USER_ID \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

# Faciendum (ACL + Persistência Completa)

SPACE_HASH="<hash-do-seu-userspace>"
BASE="http://localhost:8080/user/spaces/$SPACE_HASH/faciendum"

- Listar boards (requer board:read):
```
curl -s "$BASE/boards" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Criar board (requer board:write):
```
curl -X POST "$BASE/boards" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Meu Board"}'
```

- Renomear board (requer board:write):
```
BOARD_ID=1
curl -X PATCH "$BASE/boards/$BOARD_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Board Renomeado"}'
```

- Excluir board (requer board:write):
```
curl -X DELETE "$BASE/boards/$BOARD_ID" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Listar tracks de um board (requer board:read):
```
curl -s "$BASE/tracks?board_id=$BOARD_ID" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Criar track (requer board:write):
```
curl -X POST "$BASE/tracks" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"board_id":1, "name":"Revisão", "position":1}'
```

- Atualizar track (requer board:write):
```
TRACK_ID=2
curl -X PATCH "$BASE/tracks/$TRACK_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"position":2, "is_final":false}'
```

- Excluir track vazia (requer board:write):
```
curl -X DELETE "$BASE/tracks/$TRACK_ID" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Listar tasks (requer task:read):
```
curl -s "$BASE/tasks" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Criar task (requer task:write):
```
curl -X POST "$BASE/tasks" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"board_id":1, "title":"Minha Tarefa", "description":"Detalhes"}'
```
# Checklist e Próximos Passos
Consulte TOOLS.md para o checklist e próximos passos das tools.
Validação de ACL (exemplos de falha)
- Tentar criar board com usuário sem permissão (ex.: `guest` no espaço): deve retornar 403
```
GUEST_TOKEN="<JWT de usuário sem permissão>"
curl -i -X POST "$BASE/boards" \
  -H "Authorization: Bearer $GUEST_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Board Negado"}'
```

Filtro de tasks por board
```
BOARD_ID=1
curl -s "$BASE/tasks?board_id=$BOARD_ID" -H "Authorization: Bearer $ACCESS_TOKEN"
```

# Automata (Stubs com ACL)
Agora com persistência básica.

ABASE="http://localhost:8080/user/spaces/$SPACE_HASH/automata"

- Listar chaves (requires space:read):
```
curl -s "$ABASE/keys" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Cadastrar chave (requires space:write):
  - provider aceito: `openai|gemini|grok`
```
curl -X POST "$ABASE/keys" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"provider":"openai","name":"Minha Key","api_key":"sk-..."}'
```

- Listar prompts (requires space:read):
```
curl -s "$ABASE/prompts" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Cadastrar prompt (requires space:write):
  - provider (opcional) aceito: `openai|gemini|grok`
```
curl -X POST "$ABASE/prompts" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Resuma Texto","description":"Resumir em 5 bullets","provider":"openai","api_key_id":1}'
```

- Listar chats (requires space:read):
```
curl -s "$ABASE/chats" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Criar chat (requires space:write):
```
curl -X POST "$ABASE/chats" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"prompt_id":1, "message":"Explique o SOLID"}'
```
- Remover chave (requires space:write):
```
KEY_ID=1
curl -X DELETE "$ABASE/keys/$KEY_ID" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Atualizar prompt (requires space:write):
```
PROMPT_ID=1
curl -X PATCH "$ABASE/prompts/$PROMPT_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Resuma Curto"}'
```

- Remover prompt (requires space:write):
```
curl -X DELETE "$ABASE/prompts/$PROMPT_ID" -H "Authorization: Bearer $ACCESS_TOKEN"
```
- Atualizar task (requer task:write):
```
TASK_ID=1
curl -X PATCH "$BASE/tasks/$TASK_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Nova task", "description":"Detalhada"}'
```

- Remover task (requer task:write):
```
curl -X DELETE "$BASE/tasks/$TASK_ID" -H "Authorization: Bearer $ACCESS_TOKEN"
```

- Mover task entre trilhas e reordenar (requer task:write):
```
TO_TRACK_ID=3
curl -X PATCH "$BASE/tasks/$TASK_ID/move" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"to_track_id":'"$TO_TRACK_ID"', "position":0}'
```
