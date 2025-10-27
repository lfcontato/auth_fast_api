```bash

ACCESS_TOKEN=$(curl -sS -X POST http://localhost:8080/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"admin","password":"stringst"}' | jq -r .access_token)
echo "Token de Acesso Guardado: $ACCESS_TOKEN"

curl -sS -X PATCH http://localhost:8080/admin/2/system-role -H "Authorization: Bearer ${ACCESS_TOKEN}" -H 'Content-Type: application/json' -d '{"system_role":"admin"}'

curl -sS -X PATCH http://localhost:8080/admin/2/system-role 'Content-Type: application/json' -d '{"system_role":"admin"}'


```
admins: system_role
o campo system_role da tabela admins são opcionais se não passar nenhum tem que por o 'guest', e só aceitam as opções:
'guest', 'user', 'admin', 'root'

admins: subscription_plan
o campo subscription_plan da tabela admins são opcionais se não passar nenhum tem que por o 'trial', e só aceitam as opções: 
'trial', 'monthly', 'semiannual', 'annual', 'lifetime'

users: tools_role
o campo tools_role da tabela users são opcionais se não passar nenhum tem que por o 'guest', e só aceitam as opções:
'guest', 'user', 'admin', 'root'

users: subscription_plan
o campo subscription_plan da tabela users são opcionais se não passar nenhum tem que por o 'guest', e só aceitam as opções:
'trial', 'monthly', 'semiannual', 'annual', 'lifetime'

isso tem que refletir no openapi.json
coloque isso na documentacao em ADMINS.md, USERS.md, HOWTOUSE_ADMINS.md HOWTOUSE_USERS.md, README.md HOWTOUSE.md

-----

# ─────────────────────────────────────────────────────────────────────────────
# Papéis de permissão — Sistema (escopo global)
# Representa o papel do usuário no sistema como um todo (login/conta).
# Ordem de privilégio: guest < user < admin < root.
# Use para gates globais (ex.: acessar painel admin).
# ─────────────────────────────────────────────────────────────────────────────
SystemRole = Annotated[
    str,
    Literal['guest', 'user', 'admin', 'root'],
    LowerStr,
]
SYSTEM_ROLE_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(SystemRole)
SYSTEM_ROLE_DEFAULT: str = 'guest'
SYSTEM_ROLE_PRIORITY: dict[str, int] = {role: idx for idx, role in enumerate(SYSTEM_ROLE_CHOICES)}
SYSTEM_ROLE_SUPERUSER: str = 'root'
# ─────────────────────────────────────────────────────────────────────────────
# Papéis de permissão — Recurso (escopo local/ACL)
# Representa o papel do membro dentro de um recurso específico.
# Ordem de privilégio: viewer < editor < admin < owner.
# ─────────────────────────────────────────────────────────────────────────────
ResourceRole = Annotated[
    str,
    Literal['viewer', 'editor', 'admin', 'owner'],
    LowerStr,
]
RESOURCE_ROLE_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(ResourceRole)
RESOURCE_ROLE_DEFAULT: str = 'viewer'
# ─────────────────────────────────────────────────────────────────────────────
# Planos de assinatura
# Define o ciclo/estado do plano. 'trial' é temporário; os demais são ciclos.
# ─────────────────────────────────────────────────────────────────────────────
SubscriptionPlan = Annotated[
    str,
    Literal['trial', 'monthly', 'semiannual', 'annual', 'lifetime'],
    LowerStr,
]
SUBSCRIPTION_PLAN_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(SubscriptionPlan)
SUBSCRIPTION_PLAN_DEFAULT: str = 'trial'
# ─────────────────────────────────────────────────────────────────────────────
# Status da Conta (escopo global)
# Define o estado de autenticação/uso da conta no sistema (vale para qualquer
# papel, inclusive admin). Apenas 'active' permite login normal.
# locked = bloqueio temporário por segurança; suspended = bloqueio administrativo
# reversível; disabled/archived/deleted = sem acesso (políticas de retenção).
# ─────────────────────────────────────────────────────────────────────────────
AccountStatus = Annotated[
    str,
    Literal[
        'invited',
        'pending_verification',
        'active',
        'password_reset_required',
        'locked',
        'suspended',
        'disabled',
        'archived',
        'deleted',
    ],
    LowerStr,
    Field(description='Estado global da conta; controla se o usuário pode autenticar e operar.'),
]
ACCOUNT_STATUS_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(AccountStatus)
ACCOUNT_STATUS_DEFAULT: str = 'pending_verification'
def managed_system_roles(role: str) -> Sequence[str]:
    """Retorna os papéis que podem ser administrados por alguém com o papel informado."""
    role_key = role.lower()
    if role_key == SYSTEM_ROLE_SUPERUSER:
        return SYSTEM_ROLE_CHOICES
    priority = SYSTEM_ROLE_PRIORITY.get(role_key)
    if priority is None:
        return ()
    return tuple(candidate for candidate, value in SYSTEM_ROLE_PRIORITY.items() if value < priority)
def can_manage_system_role(acting_role: str, target_role: str) -> bool:
    """Determina se o papel `acting_role` pode gerenciar `target_role`."""
    acting = acting_role.lower()
    target = target_role.lower()
    if acting == SYSTEM_ROLE_SUPERUSER:
        return True
    acting_priority = SYSTEM_ROLE_PRIORITY.get(acting)
    target_priority = SYSTEM_ROLE_PRIORITY.get(target)
    if acting_priority is None or target_priority is None:
        return False
    return acting_priority > target_priority