package api

import (
	"net/http"

	"github.com/alextanhongpin/pkg/authhdr"
	"github.com/alextanhongpin/pkg/gojwt"

	"github.com/julienschmidt/httprouter"
)

func Protect(signer gojwt.Signer, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		validator := authhdr.New()
		if err := validator.Extract(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := signer.Verify(validator.Token())
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := UserContext.WithValue(r.Context(), claims)
		r = r.WithContext(ctx)

		next(w, r, ps)
	}
}
