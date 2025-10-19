package template_email

import "embed"

// FS embute os templates HTML desta pasta no binário.
//go:embed *.html
var FS embed.FS

