package api

import (
	"encoding/json"
	"net/http"
)

func JSON(w http.ResponseWriter, body interface{}, status int) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
