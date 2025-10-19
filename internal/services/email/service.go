// Caminho: internal/services/email/service.go
// Resumo: Serviço SMTP com suporte a SSL/TLS e STARTTLS, renderização de templates HTML
// e envio com To/Cc/Bcc. Compatível com provedores comuns (Gmail, Outlook/Hotmail, etc.).

package emailsvc

import (
    "bytes"
    "context"
    "crypto/tls"
    "fmt"
    "html/template"
    "net"
    "net/smtp"
    "path/filepath"
    "strings"
    "time"

    tplfs "github.com/lfcontato/auth_fast_api/template_email"
)

// EncryptionMode define o tipo de criptografia para SMTP.
type EncryptionMode string

const (
    EncNone     EncryptionMode = "NONE"
    EncStartTLS EncryptionMode = "STARTTLS"
    EncSSLTLS   EncryptionMode = "SSL/TLS"
)

// Service contém as configurações e dependências para envio de e-mails.
type Service struct {
    Host       string
    Port       int
    Username   string
    Password   string
    FromAddr   string
    FromName   string
    Enc        EncryptionMode
    TemplateDir string
}

// New cria um novo serviço de e-mail.
func New(host string, port int, user, pass, fromAddr, fromName, enc, templateDir string) *Service {
    mode := EncryptionMode(strings.ToUpper(strings.TrimSpace(enc)))
    if mode != EncNone && mode != EncStartTLS && mode != EncSSLTLS {
        mode = EncStartTLS
    }
    return &Service{
        Host: host,
        Port: port,
        Username: user,
        Password: pass,
        FromAddr: fromAddr,
        FromName: fromName,
        Enc: mode,
        TemplateDir: templateDir,
    }
}

// Params encapsula os dados de envio.
type Params struct {
    To        []string
    Cc        []string
    Bcc       []string
    Subject   string
    // TemplateName será resolvido dentro de TemplateDir
    TemplateName string
    // Data para renderizar o template (map ou struct)
    Data      any
}

// Send envia um e-mail com base no template informado.
func (s *Service) Send(ctx context.Context, p Params) error {
    if len(p.To) == 0 {
        return fmt.Errorf("email: destinatário ausente")
    }
    htmlBody, err := s.renderTemplate(p.TemplateName, p.Data)
    if err != nil {
        return fmt.Errorf("email: render template: %w", err)
    }
    msg := buildMIMEMessage(s.FromName, s.FromAddr, p.To, p.Cc, p.Bcc, p.Subject, htmlBody)
    // Concatena todos os destinatários (To+Cc+Bcc)
    recipients := make([]string, 0, len(p.To)+len(p.Cc)+len(p.Bcc))
    recipients = append(recipients, p.To...)
    recipients = append(recipients, p.Cc...)
    recipients = append(recipients, p.Bcc...)

    // Deadline do contexto como timeout opcional
    var d net.Dialer
    if deadline, ok := ctx.Deadline(); ok {
        d.Timeout = time.Until(deadline)
        if d.Timeout <= 0 { d.Timeout = 10 * time.Second }
    } else {
        d.Timeout = 15 * time.Second
    }

    address := fmt.Sprintf("%s:%d", s.Host, s.Port)
    auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)

    switch s.Enc {
    case EncSSLTLS:
        tlsCfg := &tls.Config{ServerName: s.Host}
        conn, err := tls.DialWithDialer(&d, "tcp", address, tlsCfg)
        if err != nil { return fmt.Errorf("email: tls dial: %w", err) }
        defer conn.Close()
        c, err := smtp.NewClient(conn, s.Host)
        if err != nil { return fmt.Errorf("email: new client: %w", err) }
        defer c.Quit()
        if s.Username != "" {
            if err := c.Auth(auth); err != nil { return fmt.Errorf("email: auth: %w", err) }
        }
        if err := c.Mail(s.FromAddr); err != nil { return fmt.Errorf("email: MAIL FROM: %w", err) }
        for _, rcpt := range recipients {
            if err := c.Rcpt(strings.TrimSpace(rcpt)); err != nil { return fmt.Errorf("email: RCPT TO %s: %w", rcpt, err) }
        }
        w, err := c.Data()
        if err != nil { return fmt.Errorf("email: DATA: %w", err) }
        if _, err := w.Write(msg); err != nil { _ = w.Close(); return fmt.Errorf("email: write body: %w", err) }
        if err := w.Close(); err != nil { return fmt.Errorf("email: close data: %w", err) }
        return nil

    case EncStartTLS:
        c, err := smtp.Dial(address)
        if err != nil { return fmt.Errorf("email: dial: %w", err) }
        defer c.Quit()
        if err := c.Hello("localhost"); err != nil { return fmt.Errorf("email: hello: %w", err) }
        // STARTTLS se suportado
        if ok, _ := c.Extension("STARTTLS"); ok {
            tlsCfg := &tls.Config{ServerName: s.Host}
            if err := c.StartTLS(tlsCfg); err != nil { return fmt.Errorf("email: starttls: %w", err) }
        }
        if s.Username != "" {
            if err := c.Auth(auth); err != nil { return fmt.Errorf("email: auth: %w", err) }
        }
        if err := c.Mail(s.FromAddr); err != nil { return fmt.Errorf("email: MAIL FROM: %w", err) }
        for _, rcpt := range recipients {
            if err := c.Rcpt(strings.TrimSpace(rcpt)); err != nil { return fmt.Errorf("email: RCPT TO %s: %w", rcpt, err) }
        }
        w, err := c.Data()
        if err != nil { return fmt.Errorf("email: DATA: %w", err) }
        if _, err := w.Write(msg); err != nil { _ = w.Close(); return fmt.Errorf("email: write body: %w", err) }
        if err := w.Close(); err != nil { return fmt.Errorf("email: close data: %w", err) }
        return nil

    case EncNone:
        // Sem TLS (não recomendado) — útil para ambientes locais/relays confiáveis
        if err := smtp.SendMail(address, auth, s.FromAddr, recipients, msg); err != nil {
            return fmt.Errorf("email: sendmail: %w", err)
        }
        return nil
    }
    return fmt.Errorf("email: modo de criptografia inválido")
}

// renderTemplate executa um template HTML com os dados informados.
func (s *Service) renderTemplate(name string, data any) (string, error) {
    if strings.TrimSpace(name) == "" {
        return "", fmt.Errorf("template: nome inválido")
    }
    // 1) Tenta via filesystem, se TemplateDir foi configurado
    if strings.TrimSpace(s.TemplateDir) != "" {
        path := filepath.Join(s.TemplateDir, name)
        if t, err := template.New(filepath.Base(path)).Option("missingkey=zero").ParseFiles(path); err == nil {
            var buf bytes.Buffer
            if execErr := t.Execute(&buf, data); execErr != nil {
                return "", execErr
            }
            return buf.String(), nil
        }
        // Fallthrough para embedded FS se falhar
    }
    // 2) Tenta via embedded FS (templates embutidos no binário)
    if t, err := template.New(name).Option("missingkey=zero").ParseFS(tplfs.FS, name); err == nil {
        var buf bytes.Buffer
        if execErr := t.Execute(&buf, data); execErr != nil {
            return "", execErr
        }
        return buf.String(), nil
    } else {
        return "", fmt.Errorf("template: render failed for %s: %w", name, err)
    }
}

// buildMIMEMessage cria um e-mail simples em HTML (UTF-8).
func buildMIMEMessage(fromName, fromAddr string, to, cc, bcc []string, subject, htmlBody string) []byte {
    addr := fromAddr
    if strings.TrimSpace(fromName) != "" {
        addr = fmt.Sprintf("%s <%s>", encodeHeader(fromName), fromAddr)
    }
    headers := map[string]string{
        "From":          addr,
        "To":            strings.Join(to, ", "),
        "Subject":       encodeHeader(subject),
        "MIME-Version":  "1.0",
        "Content-Type":  "text/html; charset=UTF-8",
        "Content-Transfer-Encoding": "quoted-printable",
    }
    if len(cc) > 0 { headers["Cc"] = strings.Join(cc, ", ") }

    var msg bytes.Buffer
    for k, v := range headers {
        msg.WriteString(k)
        msg.WriteString(": ")
        msg.WriteString(v)
        msg.WriteString("\r\n")
    }
    msg.WriteString("\r\n")
    qp := toQuotedPrintable(htmlBody)
    msg.Write(qp)
    return msg.Bytes()
}

// encodeHeader faz um encoding simples de cabeçalhos UTF-8.
func encodeHeader(s string) string {
    if s == "" { return "" }
    // RFC 2047 encoded-word (Q-encoding simplificado)
    // Para assuntos e nomes com acentuação.
    needs := false
    for _, r := range s {
        if r > 127 { needs = true; break }
    }
    if !needs { return s }
    // Troca espaços por _ e faz quoted-printable-like para bytes > 127
    b := &bytes.Buffer{}
    for i := 0; i < len(s); i++ {
        c := s[i]
        if c == ' ' { b.WriteByte('_'); continue }
        if c < 33 || c > 126 || c == '=' || c == '?' || c == '_' {
            fmt.Fprintf(b, "=%02X", c)
            continue
        }
        b.WriteByte(c)
    }
    return fmt.Sprintf("=?UTF-8?Q?%s?=", b.String())
}

// toQuotedPrintable converte o corpo para quoted-printable mínimo.
func toQuotedPrintable(s string) []byte {
    var out bytes.Buffer
    lineLen := 0
    for i := 0; i < len(s); i++ {
        c := s[i]
        esc := false
        // CRLF
        if c == '\n' {
            out.WriteString("\r\n")
            lineLen = 0
            continue
        }
        if c == '=' || c < 32 || c > 126 { esc = true }
        part := ""
        if esc {
            part = fmt.Sprintf("=%02X", c)
        } else {
            part = string([]byte{c})
        }
        // Quebra de linha soft se ultrapassar 76
        if lineLen+len(part) > 75 {
            out.WriteString("=\r\n")
            lineLen = 0
        }
        out.WriteString(part)
        lineLen += len(part)
    }
    return out.Bytes()
}
