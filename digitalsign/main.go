package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"

	"github.com/kavirajkv/security/digest"
	"github.com/kavirajkv/security/sign"
)

// to handle /getDigitalsign request body
type message struct {
	Message string `json:"message"`
}

// response body of /getDigitalsign & to handle verifySign requst body
type signature struct {
	Message   string `json:"message"`
	Sign      string `json:"digital_sign"`
	Publickey string `json:"publickey"`
}

// response body of verifySign
type verification struct {
	Status string `json:"status"`
	Valid  bool   `json:"valid"`
}

// gets message as json body and returns sign,publickey,message
func getDigitalsign(w http.ResponseWriter, r *http.Request) {
	var message message

	err := json.NewDecoder(r.Body).Decode(&message)
	if err != nil {
		http.Error(w, "Enter string message", http.StatusBadRequest)
	}

	public, private, _ := sign.GenerateKeypair()
	msgdigest := digest.ShaDigest(message.Message) //SHA256 to create digest

	sign ,_:= sign.Digitalsign(private, msgdigest)

	response := signature{Message: message.Message, Sign: sign, Publickey: public}

	json.NewEncoder(w).Encode(response)

}

// gets sign,publickey and message to verify validity of the signature
func verifySign(w http.ResponseWriter, r *http.Request) {
	var digitalsign signature

	err := json.NewDecoder(r.Body).Decode(&digitalsign)
	if err != nil {
		http.Error(w, "Enter ", http.StatusBadRequest)
	}

	msgdigest := digest.ShaDigest(digitalsign.Message)

	verified ,err:= sign.Verifysign(digitalsign.Publickey, msgdigest, digitalsign.Sign)
	
	// returns staus and validity
	if err!=nil{
		response:=verification{Status: "Invalid key size or key", Valid: false}
		json.NewEncoder(w).Encode(response)
	}else if verified {
		successresponse := verification{Status: "Signature verified successfully - Valid", Valid: true}
		json.NewEncoder(w).Encode(successresponse)
	} else {
		failureresponse := verification{Status: "Signature not verified - Invalid", Valid: false}
		json.NewEncoder(w).Encode(failureresponse)
	}

}

// routes to handle
func route() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/getdigitalsign", getDigitalsign).Methods("POST", "OPTIONS")
	router.HandleFunc("/verifysign", verifySign).Methods("POST", "OPTIONS")

	return router
}

func main() {
	r := route()
	fmt.Println("Server running at port 8000")
	http.ListenAndServe(":8000", r)
}
