package main

import (
	"log"
	"net/http"

	"github.com/akhenakh/wisprgo"
)

func main() {
	wproxy := wisprgo.NewWisprProxy()
	wproxy.AddReverseProxyRule("www.google.com", `(?i)yahoo\.com/.*`)
	wproxy.AddFileServer("/tmp", "home.wifi")
	wproxy.AddReverseProxyRule("localhost:8000", `(?i)wikipedia.wifi`)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		wproxy.ServeHTTP(w, r)
	})
	log.Fatal(http.ListenAndServe(":80", nil))
}
