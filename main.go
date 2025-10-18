package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Servidor Go rodando!")
    })
    fmt.Println("Servidor iniciado em :8080")
    http.ListenAndServe(":8080", nil)
}