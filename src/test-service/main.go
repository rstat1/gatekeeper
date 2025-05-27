package main

import (
	"gktestsvc/common"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/husobee/vestigo"
	"go.alargerobot.dev/gatekeeper/sdk"
)

func main() {
	common.InitLogrus()
	router := vestigo.NewRouter()

	router.Add("GET", "/api/hoplite/current_time", current_time)
	go func() {
		err := http.ListenAndServe(common.GetOutboundIP()+":17003", router)
		if err != nil {
			common.LogError("", err)
		}
	}()

	gkc := sdk.NewGatekeeperClient(sdk.GatekeeperClientConfig{
		EndpointServicesPort:        17002,
		GatekeeperAPIAddress:        "gatekeeper-dev.alargerobot.dev:2000",
		ClientIsRunningOnKubernetes: true,
		CredentialsRenewedHandler: func() {
			common.LogInfo("", "", "this is where credential renewal would be handled, when not running in a k8s cluster.")
		},
	})
	err := gkc.RegisterServiceEndpoint("timeservice", common.GetOutboundIP()+":17003", []string{})
	if err != nil {
		panic(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	os.Exit(0)
}

func current_time(resp http.ResponseWriter, request *http.Request) {
	common.WriteAPIResponseStruct(resp, common.CreateAPIResponse(time.Now().String(), nil, 200))
}
