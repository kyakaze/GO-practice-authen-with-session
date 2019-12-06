package main

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template

type User struct {
	Name     string
	Email    string
	Password []byte
	Role     string
}

type session struct {
	key     string
	created time.Time
}

type renderHome struct {
	User User
	Su   map[string]User
}

var dbUsers = map[string]User{}
var dbSessions = map[string]session{}
var SessionLength = 60

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func main() {
	http.HandleFunc("/", rhome)
	http.HandleFunc("/register", rregister)
	http.HandleFunc("/login", rlogin)
	http.HandleFunc("/admin", radmin)
	http.HandleFunc("/logout", rlogout)

	http.ListenAndServe(":8080", nil)
}

func rhome(w http.ResponseWriter, r *http.Request) {
	u, check := checkLogin(w, r)
	if !check {
		clearCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	var re = renderHome{u, dbUsers}
	tpl.ExecuteTemplate(w, "home.html", re)
}

func rregister(w http.ResponseWriter, r *http.Request) {
	_, check := checkLogin(w, r)
	if check {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	var u User
	if r.Method == "POST" {
		n := r.FormValue("name")
		e := r.FormValue("email")
		p := []byte(r.FormValue("password"))
		ro := r.FormValue("role")
		hash, err := bcrypt.GenerateFromPassword(p, bcrypt.MinCost)
		if err != nil {
			log.Println(err)
		}

		if _, ok := dbUsers[e]; ok {
			http.Error(w, "email taken", http.StatusForbidden)
			return
		}
		u = User{n, e, hash, ro}
		dbUsers[e] = u

		createSession(w, r, e)

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "register.html", u)
}

func rlogout(w http.ResponseWriter, r *http.Request) {
	log.Println("BEFORE DELETE **********************", dbSessions) //
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusForbidden)
		return
	}
	_, ok := checkLogin(w, r)
	if ok {
		clearSession(w, r)
		clearCookie(w, r)
	}
	log.Println("AFTER DELETE **********************", dbSessions) //

	http.Redirect(w, r, "/", http.StatusSeeOther)
	return
}

func radmin(w http.ResponseWriter, r *http.Request) {
	u, check := checkLogin(w, r)
	if !check {
		clearCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if u.Role != "admin" {
		http.Redirect(w, r, "/", http.StatusForbidden)
		return
	}
	var re = renderHome{u, dbUsers}
	tpl.ExecuteTemplate(w, "admin.html", re)
}

func rlogin(w http.ResponseWriter, r *http.Request) {
	var m string
	_, ok := checkLogin(w, r)
	if ok {
		clearSession(w, r)
		clearCookie(w, r)
	}
	if r.Method == "POST" {
		e := r.FormValue("email")
		p := r.FormValue("password")
		sp := []byte(p)
		u, ok := dbUsers[e]
		if !ok {
			m = "no account"
		} else {
			if checkPassword(u.Password, sp) {
				createSession(w, r, e)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			m = "wrong password"
		}
	}
	tpl.ExecuteTemplate(w, "login.html", m)
}
