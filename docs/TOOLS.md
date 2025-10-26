Arquivo: docs/TOOLS.md
Resumo: Conceito de Tools, UsersSpaces e bancos separados. Checklist do que foi entregue e pendências.

Manutenção: mantenha este documento alinhado com o código sempre que alterar rotas, entidades, regras de ACL ou roadmap. Este arquivo é o local canônico do checklist e “próximos passos” das tools. Os HOWTOUSE não devem conter checklists — apenas exemplos de consumo.

Navegação: [Admins](ADMINS.md) · [Usuários](USERS.md) · [Como usar (Users)](../HOWTOUSE_USERS.md) · [Como usar (Tools)](../HOWTOUSE_TOOLS.md)

# Visão Geral

- Tools são módulos independentes associados a um UsersSpace.
- Cada UsersSpace tem um `hash` único (32 chars) e um dono (`owner_user_id`).
- Usuários com `tools_role=admin` podem criar UsersSpaces via API.
- Exemplos de tools planejadas:
  - faciendum (To‑Do/Kanban) – `FACIENDUM_DATABASE_URL=sqlite:///faciendum_test.db`
  - automata (Estúdio de Agentes) – `AUTOMATA_DATABASE_URL=sqlite:///automata_test.db`

 

# Políticas de Acesso

- tools_role=admin: cria UsersSpaces (é o owner), pode gerenciar conteúdo e permissões do espaço.
- tools_role=user: não cria UsersSpaces; acesso restrito ao que for concedido por membership.
- tools_role=guest: convidado; acesso somente uso, conforme membership.

# Endpoints de Membership

- POST `/user/spaces/{space_id}/members` – adicionar membro (owner apenas). Body: `{ login, role }`.
- GET `/user/spaces/{space_id}/members` – listar membros (owner apenas).
- PATCH `/user/spaces/{space_id}/members/{user_id}` – alterar papel (owner apenas).
- DELETE `/user/spaces/{space_id}/members/{user_id}` – remover membro (owner apenas).

# Notas de Implementação

- O `hash` do UsersSpace é gerado por `generateUsersSpaceHash(32)` (hex de 16 bytes).
- O JWT de usuário inclui `uid`, `email` e `user=true` para diferenciar de admins.
- O clamp de expiração respeita `subscription_plan` do usuário:
  - `lifetime`: sem clamp; demais planos limitam `access`/`refresh` por `expires_at`.

# ACL por UsersSpace (Matriz)

- Papéis: `owner`, `admin`, `user`, `guest`.
- Ações (exemplos usados pelas tools):
  - `space:read`, `space:write`, `member:manage`
  - `board:read`, `board:write`, `task:read`, `task:write`
- Regras padrão:
  - owner: todas as ações permitidas.
  - admin: `board:*`, `task:*`, `space:read`.
  - user: `task:*`, `board:read`, `space:read`.
  - guest: `task:read`, `board:read`, `space:read`.

Observação: gestão de membros continua restrita ao proprietário do espaço.


# Testes (curl)

- Consulte HOWTOUSE_TOOLS.md para um roteiro completo de testes cobrindo UsersSpaces, membership e Faciendum (boards/tasks), incluindo exemplos de falhas de ACL.

# Faciendum (ACL + Persistência Completa)

- Base: `/user/spaces/{space_id}/faciendum`
- Endpoints:
  - Boards:
    - GET `/boards` → lista boards do espaço (ACL: `board:read`).
    - POST `/boards` → cria board e trilhas padrão: "A Fazer", "Em Progresso", "Feito" (final) (ACL: `board:write`).
    - PATCH `/boards/{board_id}` → renomeia board (ACL: `board:write`).
    - DELETE `/boards/{board_id}` → exclui board e seus tracks/tasks (ACL: `board:write`).
  - Tracks:
    - GET `/tracks?board_id=` → lista trilhas do board em ordem (ACL: `board:read`).
    - POST `/tracks` → cria trilha `{board_id,name,position?,is_final?}` (ACL: `board:write`).
    - PATCH `/tracks/{track_id}` → atualiza `{name?,position?,is_final?}` com reordenação (ACL: `board:write`).
    - DELETE `/tracks/{track_id}` → exclui trilha vazia (ACL: `board:write`).
  - Tasks:
    - GET `/tasks?board_id=` → lista tasks do espaço (filtro opcional por board) (ACL: `task:read`).
    - POST `/tasks` → cria task `{board_id,title,description?}` na primeira trilha (ACL: `task:write`).
    - PATCH `/tasks/{task_id}` → atualiza `{title?,description?}` (ACL: `task:write`).
    - DELETE `/tasks/{task_id}` → remove task (ACL: `task:write`).
    - PATCH `/tasks/{task_id}/move` → move task `{to_track_id,position?}` com reordenação (ACL: `task:write`).

Exemplos em HOWTOUSE_TOOLS.md.

# Automata (Stubs com ACL)

- Base: `/user/spaces/{space_id}/automata`
- Endpoints (stubs; valida ACL, sem persistência funcional):
  - GET `/keys` → lista chaves do usuário (ACL: `space:read`).
  - POST `/keys` → cadastra chave (ACL: `space:write`).
  - GET `/prompts` → lista prompts do usuário (ACL: `space:read`).
  - POST `/prompts` → cadastra prompt (ACL: `space:write`).
  - GET `/chats` → lista chats (ACL: `space:read`).
  - POST `/chats` → cria chat (ACL: `space:write`).

# Próximos Passos (Checklist)

- UsersSpaces e ACL
  - [x] UsersSpaces: criação/listagem (POST/GET `/user/spaces`).
  - [x] Membership por espaço (add/list/update/remove).
  - [x] ACL por UsersSpace (owner/admin/user/guest) aplicada às tools.
  - [ ] Convites de membros por link/token (expirável) e aceite.
  - [ ] Transferência de propriedade do espaço e exclusão/arquivamento com salvaguardas.
  - [ ] Auditoria (logs) e limites por rota/usuário/space.
  - [ ] Paginação/filtros em listagens (espaços, membros, entidades das tools).

- Faciendum (Kanban)
  - [x] Stubs com ACL (boards/tasks).
  - [x] Migrações e boot do DB (FACIENDUM_DATABASE_URL).
  - [x] Endpoints completos: boards (listar/criar/renomear/excluir), tracks (listar/criar/editar/excluir), tasks (listar/criar/editar/excluir/mover).
  - [ ] Presets de trilhas personalizáveis por espaço.

- Automata (Agentes)
  - [x] Migrações e boot do DB (AUTOMATA_DATABASE_URL).
  - [x] Chaves de API por usuário (CRUD básico: listar/criar/excluir).
  - [x] CRUD de prompts (nome/descrição/chave) do usuário.
  - [x] Chat: criação e listagem com persistência (execução simulada).
  - [ ] Integração com provedores (OpenAI/Gemini) para execução real do chat.
