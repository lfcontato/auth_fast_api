package httpapi

import (
    "context"
    crand "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "github.com/lfcontato/auth_fast_api/internal/contants"
    "github.com/lfcontato/auth_fast_api/internal/db"
    "github.com/lfcontato/auth_fast_api/internal/kv"
    emailsvc "github.com/lfcontato/auth_fast_api/internal/services/email"
    "golang.org/x/crypto/bcrypt"
)

func adminAuthTokenHandler(w http.ResponseWriter, r *http.Request)                 { adminAuthTokenHandler_impl(w, r) }
func adminAuthRefreshHandler(w http.ResponseWriter, r *http.Request)               { adminAuthRefreshHandler_impl(w, r) }
func adminAuthMFAVerifyHandler(w http.ResponseWriter, r *http.Request)             { adminAuthMFAVerifyHandler_impl(w, r) }
func adminAuthPasswordRecoveryHandler(w http.ResponseWriter, r *http.Request)      { adminAuthPasswordRecoveryHandler_impl(w, r) }
func adminAuthVerifyHandler(w http.ResponseWriter, r *http.Request)                { adminAuthVerifyHandler_impl(w, r) }
func adminAuthVerifyCodeURLHandler(w http.ResponseWriter, r *http.Request, code string) {
    adminAuthVerifyCodeURLHandler_impl(w, r, code)
}
func adminListHandler(w http.ResponseWriter, r *http.Request)                      { adminListHandler_impl(w, r) }
func adminCreateHandler(w http.ResponseWriter, r *http.Request)                    { adminCreateHandler_impl(w, r) }
func adminUpdateSubscriptionPlanHandler(w http.ResponseWriter, r *http.Request)    { adminUpdateSubscriptionPlanHandler_impl(w, r) }
func adminUpdateSystemRoleHandler(w http.ResponseWriter, r *http.Request)          { adminUpdateSystemRoleHandler_impl(w, r) }
func adminChangeOwnPasswordHandler(w http.ResponseWriter, r *http.Request)         { adminChangeOwnPasswordHandler_impl(w, r) }
func adminCreateAPITokenHandler(w http.ResponseWriter, r *http.Request)            { adminCreateAPITokenHandler_impl(w, r) }

// Implementações (copiadas do httpapi.go)
func adminAuthTokenHandler_impl(w http.ResponseWriter, r *http.Request) { adminAuthTokenHandler_old(w, r) }
func adminAuthRefreshHandler_impl(w http.ResponseWriter, r *http.Request) { adminAuthRefreshHandler_old(w, r) }
func adminAuthMFAVerifyHandler_impl(w http.ResponseWriter, r *http.Request) { adminAuthMFAVerifyHandler_old(w, r) }
func adminAuthPasswordRecoveryHandler_impl(w http.ResponseWriter, r *http.Request) { adminAuthPasswordRecoveryHandler_old(w, r) }
func adminAuthVerifyHandler_impl(w http.ResponseWriter, r *http.Request) { adminAuthVerifyHandler_old(w, r) }
func adminAuthVerifyCodeURLHandler_impl(w http.ResponseWriter, r *http.Request, code string) {
    adminAuthVerifyCodeURLHandler_old(w, r, code)
}
func adminListHandler_impl(w http.ResponseWriter, r *http.Request) { adminListHandler_old(w, r) }
func adminCreateHandler_impl(w http.ResponseWriter, r *http.Request) { adminCreateHandler_old(w, r) }
func adminUpdateSubscriptionPlanHandler_impl(w http.ResponseWriter, r *http.Request) { adminUpdateSubscriptionPlanHandler_old(w, r) }
func adminUpdateSystemRoleHandler_impl(w http.ResponseWriter, r *http.Request) { adminUpdateSystemRoleHandler_old(w, r) }
func adminChangeOwnPasswordHandler_impl(w http.ResponseWriter, r *http.Request) { adminChangeOwnPasswordHandler_old(w, r) }
func adminCreateAPITokenHandler_impl(w http.ResponseWriter, r *http.Request) { adminCreateAPITokenHandler_old(w, r) }
