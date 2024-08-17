package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

type User struct {
	Username string`json:"username"`
	Password string`json:"-"`
}

var (
	users = make(map[string]User)
	mutex sync.Mutex
)

func HashPassword(password string)string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func PostUser(w http.ResponseWriter, r *http.Request) {
	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	newUser.Password = HashPassword(newUser.Password)
	users[newUser.Username] = newUser

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User created successfully"))
}

func VerifyPassword(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Username string`json:"username"`
		Password string`json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	user, exists := users[request.Username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.Password == HashPassword(request.Password) {
		w.Write([]byte("Password is correct"))
	} else {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
	}
}

func main() {
	http.HandleFunc("/user", PostUser)
	http.HandleFunc("/user/verify", VerifyPassword)

	log.Println("Server started on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
