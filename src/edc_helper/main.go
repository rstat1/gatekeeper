package main

import (
	"edc_helper/common"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"go.alargerobot.dev/gatekeeper/sdk"
	v1 "go.alargerobot.dev/gatekeeper/sdk/rpc/config/v1"
)

type config struct {
	ServerEndpoint string `json:"serverEndpoint"`
}

func main() {
	var clientConfig config
	common.CommonProcessInit(false, false)

	svcName := flag.String("clientProcessName", "", "set to the name of the process connecting to gatekeeper. Cannot be null")
	flag.Parse()

	if *svcName == "" {
		panic(errors.New("clientProcessName MUST BE SET"))
	}

	if _, e := os.Stat(*svcName); os.IsNotExist(e) {
		panic(errors.New("clientProcessName MUST BE SET TO SOMETHING THAT ACTUALLY EXISTS"))
	}

	confFile, err := os.ReadFile("client_config.json")
	if err != nil {
		panic(err)
	}
	json.Unmarshal(confFile, &clientConfig)

	edc := sdk.NewExternalDeviceClient(sdk.ExternalDeviceClientConfig{
		ClientName:           *svcName,
		ServiceURL:           clientConfig.ServerEndpoint,
		EndpointServicesAddr: common.GetOutboundIP() + ":13337",
		CertificateRenewalHandler: func(sc v1.ServiceCredentials) {
			if e := os.WriteFile("gkroot.crt", []byte(sc.CaCert), 0o600); e != nil {
				common.LogWarn("err", e, "failed to write new root")
			}

			if e := os.WriteFile(*svcName+".crt", []byte(sc.Certificate), 0o600); e != nil {
				common.LogWarn("err", e, "failed to write new cert")
			}

			if e := os.WriteFile(*svcName+".key", []byte(sc.PrivateKey), 0o600); e != nil {
				common.LogWarn("err", e, "failed to write new private key")
			}
		},
	}, nil)

	if err := edc.Login(); err != nil {
		panic(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	os.Exit(0)
}
