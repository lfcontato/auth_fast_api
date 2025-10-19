package db

import "strings"

var currentDriver Driver = DriverSQLite

// setCurrentDriver is called by Connect to record which driver is in use.
func setCurrentDriver(d Driver) { currentDriver = d }

// IsPostgres reports whether the active driver is Postgres.
func IsPostgres() bool { return currentDriver == DriverPostgres }

// Rebind converts '?' placeholders to the driver-specific format.
// For Postgres (pgx), it rewrites to $1, $2, ...; for SQLite it returns unchanged.
func Rebind(query string) string {
    if !IsPostgres() {
        return query
    }
    // Replace each '?' with $n in order
    var b strings.Builder
    b.Grow(len(query) + 8)
    n := 0
    for i := 0; i < len(query); i++ {
        c := query[i]
        if c == '?' {
            n++
            b.WriteByte('$')
            b.WriteString(intToString(n))
        } else {
            b.WriteByte(c)
        }
    }
    return b.String()
}

func intToString(n int) string {
    // small, fast itoa for n>0
    if n == 0 { return "0" }
    var buf [16]byte
    i := len(buf)
    for n > 0 {
        i--
        buf[i] = byte('0' + n%10)
        n /= 10
    }
    return string(buf[i:])
}

