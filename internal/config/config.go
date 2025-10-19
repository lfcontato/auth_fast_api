// Caminho: internal/config/config.go
// Resumo: Carrega e expõe variáveis de configuração do sistema a partir de variáveis de ambiente.
// Inclui defaults seguros para desenvolvimento e centraliza chaves usadas no serviço.

package config

import (
    "os"
    "strconv"
)

// Config representa as configurações necessárias do serviço.
type Config struct {
    DeploymentEnv string
    LogLevel      string

    // Banco de dados (Postgres/SQLite)
    DatabaseURL string

    // Redis (opcional)
    RedisHost string
    RedisPort int
    RedisPass string
    RedisTLS  bool
    RedisURL  string

    // Rate limit / Lockout (configuráveis por env)
    LoginIPLimit            int
    LoginIPWindowMinutes    int
    LoginUserLimit          int
    LoginUserWindowMinutes  int
    LoginFailLockThreshold  int
    LoginFailLockTTLMinutes int
    RecoveryIPLimit         int
    RecoveryIPWindowMinutes int
    RecoveryEmailLimit      int
    RecoveryEmailWindowMinutes int
    VerifyCodeTTLHours      int

    // MFA por e-mail
    MFAEmailEnabled     bool
    MFACodeTTLMinutes   int
    MFACodeLength       int
    MFAMaxAttempts      int

    // JWT / Segurança
    SecretKey       string
    SecretAlgorithm string

    // E-mail (SMTP)
    EmailUsername       string
    EmailServerName     string
    EmailPassword       string
    EmailSMTPHost       string
    EmailSMTPPort       int
    EmailSMTPEncryption string // NONE | STARTTLS | SSL/TLS
    EmailTemplateDir    string
    EmailTemplateName   string
    SecurityTemplate    string
    AdminCreatedTemplate string
    EmailFromAddress    string
    EmailFromName       string
    EmailCCAddresses    string
    EmailBCCAddresses   string

    // Metadados
    ServiceName string
    Version     string

    // URL pública base (frontend) para compor links em e-mails
    PublicBaseURL string
}

// getenv retorna o valor de uma variável de ambiente, ou o default se não definido.
func getenv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

// getenvInt retorna uma variável de ambiente como inteiro, ou o default se ausente/inválido.
func getenvInt(key string, def int) int {
    if v := os.Getenv(key); v != "" {
        if n, err := strconv.Atoi(v); err == nil {
            return n
        }
    }
    return def
}

// getenvBool retorna uma variável de ambiente como bool, ou o default se ausente/inválido.
func getenvBool(key string, def bool) bool {
    if v := os.Getenv(key); v != "" {
        if b, err := strconv.ParseBool(v); err == nil {
            return b
        }
    }
    return def
}

// Load carrega as variáveis de configuração a partir do ambiente e devolve uma instância de Config.
func Load() *Config {
    return &Config{
        DeploymentEnv:   getenv("DEPLOYMENT_ENVIRONMENT", "development"),
        LogLevel:        getenv("LOG_LEVEL", "INFO"),
        DatabaseURL:     getenv("DATABASE_URL", ""),
        RedisHost:       getenv("REDIS_HOST", ""),
        RedisPort:       getenvInt("REDIS_PORT", 0),
        RedisPass:       getenv("REDIS_PASSWORD", ""),
        RedisTLS:        getenvBool("REDIS_USE_TLS", false),
        RedisURL:        getenv("REDIS_URL", ""),

        // Defaults: login IP 20/5min; login user 20/5min; lock >=5 for 15min
        LoginIPLimit:            getenvInt("LOGIN_IP_LIMIT", 20),
        LoginIPWindowMinutes:    getenvInt("LOGIN_IP_WINDOW_MINUTES", 5),
        LoginUserLimit:          getenvInt("LOGIN_USER_LIMIT", 20),
        LoginUserWindowMinutes:  getenvInt("LOGIN_USER_WINDOW_MINUTES", 5),
        LoginFailLockThreshold:  getenvInt("LOGIN_FAIL_LOCK_THRESHOLD", 5),
        LoginFailLockTTLMinutes: getenvInt("LOGIN_FAIL_LOCK_TTL_MINUTES", 15),
        // Recovery: IP 10/h (60min); e-mail 3/15min
        RecoveryIPLimit:         getenvInt("RECOVERY_IP_LIMIT", 10),
        RecoveryIPWindowMinutes: getenvInt("RECOVERY_IP_WINDOW_MINUTES", 60),
        RecoveryEmailLimit:      getenvInt("RECOVERY_EMAIL_LIMIT", 3),
        RecoveryEmailWindowMinutes: getenvInt("RECOVERY_EMAIL_WINDOW_MINUTES", 15),
        // Verification code TTL default 24h
        VerifyCodeTTLHours:      getenvInt("VERIFY_CODE_TTL_HOURS", 24),

        // MFA (e-mail)
        MFAEmailEnabled:   getenvBool("MFA_EMAIL_ENABLED", false),
        MFACodeTTLMinutes: getenvInt("MFA_CODE_TTL_MINUTES", 10),
        MFACodeLength:     getenvInt("MFA_CODE_LENGTH", 6),
        MFAMaxAttempts:    getenvInt("MFA_MAX_ATTEMPTS", 5),
        SecretKey:       getenv("SECRET_KEY", "change-me"),
        SecretAlgorithm: getenv("SECRET_ALGORITHM", "HS256"),
        // E-mail
        EmailUsername:       getenv("EMAIL_SERVER_USERNAME", ""),
        EmailServerName:     getenv("EMAIL_SERVER_NAME", ""),
        EmailPassword:       getenv("EMAIL_SERVER_PASSWORD", ""),
        EmailSMTPHost:       getenv("EMAIL_SERVER_SMTP_HOST", ""),
        EmailSMTPPort:       getenvInt("EMAIL_SERVER_SMTP_PORT", 587),
        EmailSMTPEncryption: getenv("EMAIL_SERVER_SMTP_ENCRYPTION", "STARTTLS"),
        EmailTemplateDir:    getenv("EMAIL_SERVER_TEMPLATE_DIR", "template_email"),
        EmailTemplateName:   getenv("EMAIL_TEMPLATE_NAME", "email_notifications.html"),
        SecurityTemplate:    getenv("SECURITY_TEMPLATE_NAME", "security_notifications.html"),
        AdminCreatedTemplate: getenv("ADMIN_CREATED_TEMPLATE_NAME", "admin_created.html"),
        EmailFromAddress:    getenv("EMAIL_FROM_ADDRESS", getenv("EMAIL_SERVER_USERNAME", "")),
        EmailFromName:       getenv("EMAIL_FROM_NAME", getenv("EMAIL_SERVER_NAME", "")),
        EmailCCAddresses:    getenv("EMAIL_CC_ADDRESSES", ""),
        EmailBCCAddresses:   getenv("EMAIL_BCC_ADDRESSES", ""),
        ServiceName:     getenv("OTEL_SERVICE_NAME", "auth_fast_api"),
        Version:         getenv("SERVICE_VERSION", "0.1.0"),
        PublicBaseURL:   getenv("PUBLIC_BASE_URL", ""),
    }
}
