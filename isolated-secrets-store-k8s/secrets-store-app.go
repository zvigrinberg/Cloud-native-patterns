package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
)
const urlSecretPrefix = "/client/v1/secret"
const TOKEN_NAME = "TOKEN"
const PASSWORD_NAME = "PASSWORD"
const CERT_NAME = "CERT"


type responseSecret struct {
	SecretName  string  `json:"secretName"`
	SecretValue string `json:"secretValue"`

}
type Endpoint struct {

	Name string `json:"name"`
	URL string `json:"url"`

}

type responseInit struct {
    Endpoints   []Endpoint `json:"endpoints"`

}



func serveSecrets(w http.ResponseWriter, r *http.Request) {
	reqDump, err := httputil.DumpRequest(r,true)
	fmt.Printf("REQUEST:\n%s", string(reqDump))
	var urlComponents []string = strings.Split(r.RequestURI, "/")
	secretPos := len(urlComponents) - 1
	secretName := urlComponents[secretPos]
	secretValue, err := prepareSecret(secretName)
	if err != nil{
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 - Secret not found"))
	}	else
	{

		secret := responseSecret{secretName, secretValue}
		json.NewEncoder(w).Encode(secret)
		data, err := json.Marshal(secret)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(string(data))
		}
	}

}

func prepareSecret(secretName string) (string, error) {
	value := os.Getenv(secretName)
	if strings.TrimSpace(value) != "" {
		return string(value),nil
	} else {
		return "", fmt.Errorf("secret not found")
	}



}

func prepareEndpoints() []Endpoint {
	token := Endpoint{TOKEN_NAME,urlSecretPrefix + "/" + TOKEN_NAME}
	password := Endpoint{PASSWORD_NAME,urlSecretPrefix + "/" + PASSWORD_NAME}
	cert := Endpoint{CERT_NAME,urlSecretPrefix + "/" + CERT_NAME}
	endpoints := []Endpoint{token,password,cert}
	return endpoints
}

func initConnection(w http.ResponseWriter, r *http.Request) {
	log.Println(r)
	endpoints := prepareEndpoints()
    response := responseInit{endpoints}
	json.NewEncoder(w).Encode(response)
	data, err := json.Marshal(response)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(data))
	}
}

func main() {
	// Use the http.NewServeMux() function to create an empty servemux.
	mux := http.NewServeMux()

	// Use the http.RedirectHandler() function to create a handler which 307
	// redirects all requests it receives to http://example.org.
	passwordsHandler := http.HandlerFunc(serveSecrets)

	// Next we use the mux.Handle() function to register this with our new
	// servemux, so it acts as the handler for all incoming requests with the URL
	// path /foo.
	//const urlSecretPrefix = "/client/v1/secret"
	mux.Handle(urlSecretPrefix + "/", passwordsHandler)
	hateoas := http.HandlerFunc(initConnection)
	mux.Handle("/client/init", hateoas )

	// Then we create a new server and start listening for incoming requests
	// with the http.ListenAndServe() function, passing in our servemux for it to
	// match requests against as the second parameter.
	portNumber := os.Getenv("SERVER_PORT")
	log.Print("Listening on port " + portNumber)
	http.ListenAndServe(":" +portNumber, mux)

}


