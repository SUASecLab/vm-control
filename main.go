package main

import (
	"flag"
	"html"
	"log"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/gorilla/mux"
	"github.com/kataras/jwt"
)

var (
	jwtKey            *string
	allowedOperations = []string{"start", "restart"}
)

func runVirshCommand(operation, vm string) {
	// Construct command
	cmd := exec.Command("virsh", "-c", "qemu:///system", operation, vm)
	var stdout strings.Builder
	var stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println("Could not run command:", err)
	}
	log.Println("Run operation:", operation, vm)
	log.Println("stdout:", stdout.String())
	log.Println("stderr:", stderr.String())
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Get token
	token := r.URL.Query().Get("token")
	token = html.EscapeString(token)

	// Check if token is valid
	verfiedToken, err := jwt.Verify(jwt.HS256, []byte(*jwtKey), []byte(token))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Get claims
	var claims = struct {
		VMName    string `json:"vm"`
		Operation string `json:"operation"`
	}{}

	err = verfiedToken.Claims(&claims)
	if err != nil || len(claims.VMName) == 0 || len(claims.Operation) == 0 {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if !slices.Contains(allowedOperations, claims.Operation) {
		log.Println("Forbidden operation requested: ", claims.Operation)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if claims.Operation == "restart" {
		runVirshCommand("destroy", claims.VMName)
		runVirshCommand("start", claims.VMName)
		return
	}
	runVirshCommand(claims.Operation, claims.VMName)
}

func init() {
	jwtKey = flag.String("key", "", "JWT key used to sign the exchanged data")
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	if len(*jwtKey) == 0 {
		log.Println("No JWT key provided, aborting.")
		os.Exit(0)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", handler)
	log.Println("VM control listens on port 25000")
	err := http.ListenAndServe(":25000", r)

	if err != nil {
		log.Fatalln("VM control failed: ", err)
	}
}
