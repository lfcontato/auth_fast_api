```bash

ACCESS_TOKEN=$(curl -sS -X POST http://localhost:8080/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"admin","password":"stringst"}' | jq -r .access_token)
echo "Token de Acesso Guardado: $ACCESS_TOKEN"

curl -sS -X PATCH http://localhost:8080/admin/2/system-role -H "Authorization: Bearer ${ACCESS_TOKEN}" -H 'Content-Type: application/json' -d '{"system_role":"admin"}'

curl -sS -X PATCH http://localhost:8080/admin/2/system-role 'Content-Type: application/json' -d '{"system_role":"admin"}'


```