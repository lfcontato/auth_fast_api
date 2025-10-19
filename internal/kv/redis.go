// Caminho: internal/kv/redis.go
// Resumo: Cliente Redis (go-redis/v9) com helpers simples para rate limit e lockout.

package kv

import (
    "context"
    "time"

    "github.com/redis/go-redis/v9"
)

var client *redis.Client

// Init inicializa o cliente usando REDIS_URL (URI) ou addr/pass separados.
func Init(redisURL, host string, port int, pass string, useTLS bool) error {
    if redisURL != "" {
        opt, err := redis.ParseURL(redisURL)
        if err != nil { return err }
        client = redis.NewClient(opt)
        return nil
    }
    addr := host
    if port > 0 { addr = host + ":" + itoa(port) }
    // Para simplicidade, não configuramos TLS via opções separadas; prefira REDIS_URL quando TLS for necessário.
    client = redis.NewClient(&redis.Options{Addr: addr, Password: pass, DB: 0})
    return nil
}

// Available informa se o cliente está configurado.
func Available() bool { return client != nil }

// AllowRate executa um rate limit simples (contagem por janela). Retorna true se permitido.
func AllowRate(ctx context.Context, key string, limit int64, window time.Duration) (bool, int64, error) {
    if client == nil { return true, 0, nil }
    pipe := client.Pipeline()
    incr := pipe.Incr(ctx, key)
    pipe.Expire(ctx, key, window)
    if _, err := pipe.Exec(ctx); err != nil { return true, 0, err }
    n := incr.Val()
    return n <= limit, n, nil
}

// SetLock define um lock com TTL.
func SetLock(ctx context.Context, key string, ttl time.Duration) error {
    if client == nil { return nil }
    return client.Set(ctx, key, "1", ttl).Err()
}

// IsLocked retorna true se existe um lock ativo.
func IsLocked(ctx context.Context, key string) (bool, error) {
    if client == nil { return false, nil }
    _, err := client.Get(ctx, key).Result()
    if err == redis.Nil { return false, nil }
    if err != nil { return false, err }
    return true, nil
}

// Del remove chaves (melhor-esforço).
func Del(ctx context.Context, keys ...string) {
    if client == nil { return }
    _ = client.Del(ctx, keys...).Err()
}

// Set grava uma string com TTL.
func Set(ctx context.Context, key, val string, ttl time.Duration) error {
    if client == nil { return nil }
    return client.Set(ctx, key, val, ttl).Err()
}

// Get recupera uma string; retorna "" e nil se não existir.
func Get(ctx context.Context, key string) (string, error) {
    if client == nil { return "", nil }
    v, err := client.Get(ctx, key).Result()
    if err == redis.Nil { return "", nil }
    return v, err
}

// itoa simples
func itoa(n int) string {
    if n == 0 { return "0" }
    b := [12]byte{}
    i := len(b)
    for n > 0 { i--; b[i] = byte('0' + n%10); n/=10 }
    return string(b[i:])
}
