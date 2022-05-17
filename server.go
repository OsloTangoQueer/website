package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/mail"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/mattn/go-sqlite3"
)

type server struct {
	router *chi.Mux
	db     *sql.DB
}

func (server *server) subscribe(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		// TODO log
		fmt.Println("err:", err)
		w.Write([]byte("Failed to parse your email form :( contact styret@oslotangoqueer.no for help"))
		return
	}

	addr := r.Form.Get("Email Address")
	_, err = mail.ParseAddress(addr)
	if err != nil {
		// TODO log
		fmt.Println("err:", err)
		w.Write([]byte("invalid email address :( contact styret@oslotangoqueer.no for help"))
		return
	}

	_, err = server.db.Exec(
		`INSERT INTO newsletter(email) VALUES ($1)`,
		addr,
	)
	if err != nil {
		// TODO log
		fmt.Println("err:", err)
		w.Write([]byte("failed to insert email into DB :( contact styret@oslotangoqueer.no for help"))
		return
	}
	// LOG success??
	w.Write([]byte("success! :) welcome to the mailing list"))
}

func main() {
	var server server

	server.router = chi.NewRouter()
	server.router.Use(middleware.Logger)

	var err error
	//FIXME: db connection not concurrency-safe?
	server.db, err = sql.Open("sqlite3", "./otq.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open database: %v\n", err)
		os.Exit(1)
	}
	defer server.db.Close()

	server.router.Post("/subscribe", server.subscribe)

	fs := http.FileServer(http.Dir("frontend"))
	server.router.Handle("/*", fs)

	fmt.Println("Opening server on :8080")
	http.ListenAndServe(":8080", server.router)
}
