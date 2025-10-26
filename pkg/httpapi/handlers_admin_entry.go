package httpapi

import "net/http"

func adminHandleAuthToken(w http.ResponseWriter, r *http.Request)                 { adminAuthTokenHandler(w, r) }
func adminHandleAuthRefresh(w http.ResponseWriter, r *http.Request)               { adminAuthRefreshHandler(w, r) }
func adminHandleMFAVerify(w http.ResponseWriter, r *http.Request)                 { adminAuthMFAVerifyHandler(w, r) }
func adminHandlePasswordRecovery(w http.ResponseWriter, r *http.Request)          { adminAuthPasswordRecoveryHandler(w, r) }
func adminHandleVerifyCodeURL(w http.ResponseWriter, r *http.Request, code string){ adminAuthVerifyCodeURLHandler(w, r, code) }
func adminHandleVerify(w http.ResponseWriter, r *http.Request)                    { adminAuthVerifyHandler(w, r) }
func adminHandleCreate(w http.ResponseWriter, r *http.Request)                    { adminCreateHandler(w, r) }
func adminHandleList(w http.ResponseWriter, r *http.Request)                      { adminListHandler(w, r) }
func adminHandleUpdatePlan(w http.ResponseWriter, r *http.Request)                { adminUpdateSubscriptionPlanHandler(w, r) }
func adminHandleUpdateRole(w http.ResponseWriter, r *http.Request)                { adminUpdateSystemRoleHandler(w, r) }
func adminHandleChangeOwnPassword(w http.ResponseWriter, r *http.Request)         { adminChangeOwnPasswordHandler(w, r) }
func adminHandleCreateAPIToken(w http.ResponseWriter, r *http.Request)            { adminCreateAPITokenHandler(w, r) }

