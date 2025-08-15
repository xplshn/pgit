//usr/bin/env go run "$0" "$@"; exit "$?"
//go:build exclude
package main
import (
    "net/http"
    "log"
    "os"
)
func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Request: %s %s", r.Method, r.URL)
        http.FileServer(http.Dir(T(len(os.Args)>=1, os.Args[1], "public"))).ServeHTTP(w, r)
    })
    log.Fatal(http.ListenAndServe(":1313", nil))
}
func T[T any](c bool, t, f T) T { if c { return t } else { return f } }
