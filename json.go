package goauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

func RespondWithJson(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("error marshalling payload to data %v", err)
		w.WriteHeader(500)
	}
	w.WriteHeader(code)
	_, err = w.Write(data)
	if err != nil {
		log.Printf("error writing data to response %v", err)
		w.WriteHeader(500)
	}
}

func RespondWithError(w http.ResponseWriter, code int, message string) {
	RespondWithJson(w, code, map[string]string{"error": message})

}

func RespondWithPdf(w http.ResponseWriter, code int, pdf []byte, invNumber string) {
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pdf", invNumber))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdf)))

	w.WriteHeader(code)

	if _, err := w.Write(pdf); err != nil {
		log.Printf("error writing pdf to response: %v", err)
	}
}
