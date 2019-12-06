package main

import (
	"log"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

func checkLogin(w http.ResponseWriter, r *http.Request) (User, bool) {
	var u = User{}
	// check if session
	c, err := r.Cookie("session")
	if err != nil {
		return u, false
	}
	// check session valid
	s, ok := dbSessions[c.Value]
	if !ok {
		clearCookie(w, r)
		return u, false
	}
	// check user valid
	checkU, ok := dbUsers[s.key]
	if !ok {
		clearCookie(w, r)
		return u, false
	}
	u = checkU
	return u, true
}

func clearCookie(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err == nil {
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
}

func checkPassword(hp []byte, p []byte) bool {
	err := bcrypt.CompareHashAndPassword(hp, p)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func createSession(w http.ResponseWriter, r *http.Request, e string) {
	uid, _ := uuid.NewV4()
	dbSessions[uid.String()] = session{e, time.Now()}
	c := &http.Cookie{
		Name:   "session",
		Value:  uid.String(),
		MaxAge: SessionLength,
	}
	http.SetCookie(w, c)
}

func clearSession(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("session")
	delete(dbSessions, c.Value)
}
