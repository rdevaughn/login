package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	DB_USER     = "go_app"
	DB_PASSWORD = "goapppw"
	DB_NAME     = "go_db"
)

var store = sessions.NewCookieStore([]byte("something-very-secret")) // questions about security implications

func main() {
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("js"))))
	http.HandleFunc("/login", handleLoginRequest)
	err := http.ListenAndServe(":9090", context.ClearHandler(http.DefaultServeMux))
	check(err)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func handleLoginRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/favico.ico" {
		return
	}
	if r.Method == "GET" {
		session, err := store.Get(r, "gorilla-session")
		check(err)
		err = checkSession(session)
		// get data, currently just pulls email from cookie
		data := parseCookie(session, err)
		// load template, return
		t := template.New("login")
		t, err = t.ParseFiles("templates/login.html")
		check(err)
		session.Save(r, w)
		t.ExecuteTemplate(w, "login.html", data)
	} else { // should check if post else ?
		session, err := store.Get(r, "gorilla-session")
		check(err)
		r.ParseForm()
		if r.Form["action"][0] == "Login" {
			logUserIn(r, w, session)
		} else {
			createUser(r, w, session)
		}
	}
}

func logUserIn(r *http.Request, w http.ResponseWriter, session *sessions.Session) {
	// lookup hash with email, handle failure
	hash, err := hashLookup(r.Form["email"][0])
	if err == nil {
		test := bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.Form["password"][0]))
		// compare hashes if match, save session, login
		if test == nil {
			session.Values["email"] = r.Form["email"][0]
			session.Values["key"] = r.Form["password"][0]
			session.Save(r, w)
			http.Redirect(w, r, "/login", 301)
		} else { // if hashes don't match redirect, notify user
			t := template.New("login")
			t, err = t.ParseFiles("templates/login.html")
			check(err)
			t.ExecuteTemplate(w, "login.html", map[string]interface{}{"email": r.Form["email"][0], "unfamiliar": true,
				"incorrectPassword": true})
		}
	} else {
		t := template.New("login")
		t, err = t.ParseFiles("templates/login.html")
		check(err)
		t.ExecuteTemplate(w, "login.html", map[string]interface{}{"email": r.Form["email"][0], "unfamiliar": true,
			"unknownUser": true})
	}
}

func createUser(r *http.Request, w http.ResponseWriter, session *sessions.Session) {
	// validate email
	if validateEmail(r.Form["email"][0]) {
		// create hash, save user to db
		hash, err := bcrypt.GenerateFromPassword([]byte(r.Form["password"][0]), bcrypt.DefaultCost)
		check(err)
		err = saveUser(r.Form["email"][0], string(hash))
		if err != nil { // if save fails (because of email pkey) redirect, notify user
			t := template.New("login")
			t, err := t.ParseFiles("templates/login.html")
			check(err)
			session.Save(r, w)
			t.ExecuteTemplate(w, "login.html", map[string]interface{}{"email": r.Form["email"][0], "unfamiliar": true, "emailTaken": true})
		} else { // if save succeeds, set cookie, login
			session.Values["email"] = r.Form["email"][0]
			session.Values["key"] = r.Form["password"][0]
			session.Save(r, w)
			http.Redirect(w, r, "/login", 301)
		}
	} else {
		t := template.New("login")
		t, err := t.ParseFiles("templates/login.html")
		check(err)
		session.Save(r, w)
		t.ExecuteTemplate(w, "login.html", map[string]interface{}{"email": r.Form["email"][0], "unfamiliar": true,
			"emailInvalid": true})
	}
}

func checkSession(session *sessions.Session) error { // add salt
	hash := ""
	if session.Values["email"] != nil && session.Values["email"] != nil {
		hash, _ = hashLookup(session.Values["email"].(string)) // compare cookie + db (necessary? safe? best practice?)
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(session.Values["key"].(string)))
	}
	return errors.New("Error: Missing email or key")
}

func hashLookup(email string) (string, error) {
	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", DB_USER, DB_PASSWORD, DB_NAME)
	db, err := sql.Open("postgres", dbinfo)
	check(err)
	defer db.Close()
	var hash string
	query := strings.Replace("SELECT hash FROM users where email ='%s'", "%s", email, -1)
	err = db.QueryRow(query).Scan(&hash)
	return hash, err
}

func parseCookie(session *sessions.Session, err error) map[string]interface{} {
	if err == nil {
		if session.Values["email"] != nil {
			return map[string]interface{}{"email": session.Values["email"], "unfamiliar": false}
		} else {
			return map[string]interface{}{"unfamiliar": true, "emailInvalid": true}
		}
	} else {
		return map[string]interface{}{"unfamiliar": true}
	}
}

func saveUser(email string, hash string) error {
	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", DB_USER, DB_PASSWORD, DB_NAME)
	db, err := sql.Open("postgres", dbinfo)
	check(err)
	defer db.Close()
	_, err = db.Exec("INSERT INTO users(email, hash) VALUES($1, $2);", email, hash)
	return err
}

func validateEmail(email string) bool {
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return Re.MatchString(email)
}
