//usr/bin/env go run "$0" "$@"; exit "$?"
//go:build exclude
package main

import (
    "net/http"
    "log"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Request: %s %s", r.Method, r.URL)
        http.FileServer(http.Dir("public")).ServeHTTP(w, r)
    })

    log.Fatal(http.ListenAndServe(":1313", nil))
}
