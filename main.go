package main

import (
	"log"
	"net/http"
)

func main() {
	log.Fatal(http.ListenAndServeTLS(
		":8000",
		"serverCert.pem",
		"serverKey.pem",
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	))
}
