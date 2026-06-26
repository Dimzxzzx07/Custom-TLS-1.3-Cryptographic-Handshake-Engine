package main

import (
    "fmt"
    "crypto/rand"
)

func main() {
    fmt.Println("Axon Go Binding")
    
    key := make([]byte, 32)
    rand.Read(key)
    fmt.Printf("Generated key: %x\n", key)
}