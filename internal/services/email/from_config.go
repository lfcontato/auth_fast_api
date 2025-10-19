package emailsvc

import "github.com/lfcontato/auth_fast_api/internal/config"

// FromConfig cria Service a partir de internal/config.Config.
// Retorna nil se host SMTP estiver vazio (e-mail desabilitado).
func FromConfig(cfg *config.Config) *Service {
    if cfg.EmailSMTPHost == "" {
        return nil
    }
    return New(
        cfg.EmailSMTPHost,
        cfg.EmailSMTPPort,
        cfg.EmailUsername,
        cfg.EmailPassword,
        cfg.EmailFromAddress,
        cfg.EmailFromName,
        cfg.EmailSMTPEncryption,
        cfg.EmailTemplateDir,
    )
}
