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
	"time"
	"math/rand"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	DB_USER     = "login_app"
	DB_PASSWORD = "loginapppw"
	DB_NAME     = "login_db"
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
	hash, salt, err := hashLookup(r.Form["email"][0])
	if err == nil {
		test := bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.Form["password"][0] + salt))
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
		// create salt,hash save user to db
		salt := randomString(24)
		hash, err := bcrypt.GenerateFromPassword([]byte(r.Form["password"][0] + salt), bcrypt.DefaultCost)
		check(err)
		err = saveUser(r.Form["email"][0], string(hash), salt)
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
	var salt string
	if session.Values["email"] != nil && session.Values["email"] != nil {
		hash, salt, _ = hashLookup(session.Values["email"].(string)) // compare cookie + db (necessary? safe? best practice?)
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(session.Values["key"].(string) + salt))
	}
	return errors.New("Error: Missing email or key")
}

func hashLookup(email string) (string, string, error) {
	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", DB_USER, DB_PASSWORD, DB_NAME)
	db, err := sql.Open("postgres", dbinfo)
	check(err)
	defer db.Close()
	var hash string
	var salt string
	query := strings.Replace("SELECT hash, salt FROM users where email ='%s'", "%s", email, -1)
	rows, err := db.Query(query)
	for rows.Next() { // should only ever be one row, is this best practice?
		err = rows.Scan(&hash, &salt)
		check(err)
	}
	return hash, salt, err
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

func saveUser(email string, hash string, salt string) error {
	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", DB_USER, DB_PASSWORD, DB_NAME)
	db, err := sql.Open("postgres", dbinfo)
	check(err)
	defer db.Close()
	_, err = db.Exec("INSERT INTO users(email, hash, salt) VALUES($1, $2, $3);", email, hash, salt)
	return err
}

func validateEmail(email string) bool {
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return Re.MatchString(email)
}

func randomString(n int) string {
	var letters = []rune("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
