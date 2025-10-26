package httpapi

import "net/http"

func userHandleAuthToken(w http.ResponseWriter, r *http.Request)              { userAuthTokenHandler(w, r) }
func userHandleAuthRefresh(w http.ResponseWriter, r *http.Request)            { userAuthRefreshHandler(w, r) }
func userHandleAuthVerify(w http.ResponseWriter, r *http.Request)             { userAuthVerifyHandler(w, r) }
func userHandleAuthVerifyLink(w http.ResponseWriter, r *http.Request)         { userAuthVerifyLinkHandler(w, r) }
func userHandlePasswordRecovery(w http.ResponseWriter, r *http.Request)       { userAuthPasswordRecoveryHandler(w, r) }
func userHandleVerificationCode(w http.ResponseWriter, r *http.Request)       { userAuthVerificationCodeHandler(w, r) }

