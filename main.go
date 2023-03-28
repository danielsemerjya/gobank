package main

import (
	"flag"
	"fmt"
	"log"
)

func seedAccount(store Storage, fname, lname, pw string) *Account {
	acc, err := NewAccount(fname, lname, pw)
	if err != nil {
		log.Fatal(err)
	}

	if err := store.CreateAccount(acc); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Created account:", acc.Number)

	return acc
}

func seedAccounts(s Storage) {
	seedAccount(s, "John", "Doe", "password")
}

func main() {
	seed := flag.Bool("seed", false, "seed the database")
	flag.Parse()

	store, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	// seed stuff
	if *seed {
		fmt.Println("Seeding database...")
		seedAccounts(store)
	}

	server := NewAPIServer(":5000", store)
	server.Run()
}
