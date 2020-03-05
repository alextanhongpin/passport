package main

import (
	"log"
	"net/http"
	"time"

	"github.com/alextanhongpin/passport/examples/api"
	"github.com/alextanhongpin/passport/examples/controller"
	"github.com/alextanhongpin/passport/examples/database"
	"github.com/alextanhongpin/passport/examples/service"

	"github.com/alextanhongpin/pkg/gojwt"

	"github.com/julienschmidt/httprouter"
)

//go:generate packr2
func main() {
	db, err := database.Setup()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	signer := gojwt.New(gojwt.Option{
		Secret:       []byte("secret"),
		ExpiresAfter: 1 * time.Hour,
	})
	svc := service.New(db, signer)
	ctl := controller.New(svc)

	router := httprouter.New()
	router.GET("/", indexHandler)
	router.GET("/private", api.Protect(signer, indexHandler))
	router.POST("/login", ctl.PostLogin)
	router.POST("/register", ctl.PostRegister)
	router.POST("/user/emails", api.Protect(signer, ctl.PostChangeEmail))
	router.PUT("/user/passwords", api.Protect(signer, ctl.PutChangePassword))
	router.PUT("/confirmations", ctl.PutConfirm)
	router.POST("/confirmations", ctl.PostSendConfirmation)
	router.PUT("/passwords", ctl.PutResetPassword)
	router.POST("/passwords", ctl.PostRequestResetPassword)

	log.Println("Listening to port *:8080. Press ctrl + c to cancel.")
	http.ListenAndServe(":8080", router)
}

func indexHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	api.JSON(w, api.M{"ok": true}, http.StatusOK)
}
