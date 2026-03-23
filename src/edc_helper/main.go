package main

import (
	"edc_helper/common"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"

	"go.alargerobot.dev/gatekeeper/sdk"
	v1 "go.alargerobot.dev/gatekeeper/sdk/rpc/config/v1"
)

type config struct {
	ServiceName          string `json:"serviceName"`
	ServerEndpoint       string `json:"serverEndpoint"`
}

func main() {
	var clientConfig config
	common.CommonProcessInit(false, false)

	confFile, err := os.ReadFile("client_config.json")
	if err != nil {
		panic(err)
	}
	json.Unmarshal(confFile, &clientConfig)

	edc := sdk.NewExternalDeviceClient(sdk.ExternalDeviceClientConfig{
		ClientName:           clientConfig.ServiceName,
		ServiceURL:           clientConfig.ServerEndpoint,
		EndpointServicesAddr: common.GetOutboundIP() + ":13337",
		CertificateRenewalHandler: func(sc v1.ServiceCredentials) {
			if e := os.WriteFile("gkroot.crt", []byte(sc.CaCert), 0o600); e != nil {
				common.LogWarn("err", e, "failed to write new root")
			} else {
				common.LogInfo("", "", "wrote new root cert")
			}

			if e := os.WriteFile(clientConfig.ServiceName+".crt", []byte(sc.Certificate), 0o600); e != nil {
				common.LogWarn("err", e, "failed to write new cert")
			} else {
				common.LogInfo("", "", "wrote new client cert")
			}

			if e := os.WriteFile(clientConfig.ServiceName+".key", []byte(sc.PrivateKey), 0o600); e != nil {
				common.LogWarn("err", e, "failed to write new private key")
			} else {
				common.LogInfo("", "", "wrote new client key")
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
