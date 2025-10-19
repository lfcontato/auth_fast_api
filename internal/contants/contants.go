// Caminho: internal/contants/contants.go
// Resumo: Constantes globais do sistema.

package contants

// Comprimento padrão para senha gerada automaticamente (em dígitos numéricos).
const DefaultGeneratedPasswordLength = 8

// Assunto padrão para e-mail de criação de administrador.
const EmailSubjectAdminCreated = "Bem-vindo(a) – Sua conta de administrador"

// Assunto padrão para e-mail de recuperação de senha.
const EmailSubjectPasswordRecovery = "Recuperação de senha da sua conta"

// Nome padrão do template de e-mail para criação de administrador.
const TemplateAdminCreated = "admin_created.html"

// Tamanho do código de verificação (em caracteres). Ex.: 64 para 32 bytes em hex.
const VerificationCodeLength = 64
