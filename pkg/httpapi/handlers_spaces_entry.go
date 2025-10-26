package httpapi

import "net/http"

func spacesHandleCreate(w http.ResponseWriter, r *http.Request)              { userSpacesCreateHandler(w, r) }
func spacesHandleList(w http.ResponseWriter, r *http.Request)                { userSpacesListHandler(w, r) }
func spacesHandleMembersAdd(w http.ResponseWriter, r *http.Request)          { userSpacesMembersAddHandler(w, r) }
func spacesHandleMembersList(w http.ResponseWriter, r *http.Request)         { userSpacesMembersListHandler(w, r) }
func spacesHandleMembersUpdate(w http.ResponseWriter, r *http.Request)       { userSpacesMembersUpdateRoleHandler(w, r) }
func spacesHandleMembersRemove(w http.ResponseWriter, r *http.Request)       { userSpacesMembersRemoveHandler(w, r) }

