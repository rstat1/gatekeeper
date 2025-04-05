package sdk

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const DEVICE_AUTH_CONTENT_TYPE = "application/x-gatekeeper-device-auth"

type ExternalDeviceClient struct {
	gkAddr    string
	epsServer *EndpointServicesServer
}

func NewExternalDeviceClient(gatekeeperAddress string) *ExternalDeviceClient {
	edc := &ExternalDeviceClient{
		gkAddr:    gatekeeperAddress,
		epsServer: NewEndpointServiceServer(true),
	}
	edc.registerExternalClient()
	return edc
}

// # Description
//
// Login authenticates an external device to Gatekeeper
// This is for the case when you have some IoT like device that needs to connect to a Gatekeeper
// service. This functionn requests from the server, some randomly generated message that will
// be signed by the service's certificate, and returned with the provided request ID. If
// verifcation is successful a signed token will be returned by the server that said device can use
// for authtencation.
//
// # Parameters
//   - serviceURL should be a combo of the service's name and the service domain it belongs to
//   - Example: gktest.test.alargerobot.dev
func (edc *ExternalDeviceClient) Login(serviceURL string) (string, error) {
	var dar DeviceAuthRequest
	req, _ := http.NewRequest("GET", "https://"+serviceURL+"/device_auth/begin", http.NoBody)
	req.Header.Add("Content-Type", DEVICE_AUTH_CONTENT_TYPE)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == 200 {
		reqDetails, e := io.ReadAll(resp.Body)
		if e != nil {
			return "", e
		}
		if e := json.Unmarshal(reqDetails, &dar); e != nil {
			return "", e
		}
		privKeyBytes, _ := os.ReadFile(filepath.Base(os.Args[0]) + ".key")
		if privKey, _ := pem.Decode(privKeyBytes); privKey != nil {
			privateKey, err := x509.ParseECPrivateKey(privKey.Bytes)
			if err != nil {
				return "", fmt.Errorf("failed to parse private key type: %s", err)
			}
			hash := sha512.Sum384([]byte(dar.Message))
			sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
			if err != nil {
				return "", err
			}
			dacr, _ := json.Marshal(DeviceAuthClientResponse{
				Message:   base64.StdEncoding.EncodeToString([]byte(dar.Message)),
				RequestID: dar.RequestID,
				Signature: base64.StdEncoding.EncodeToString(sig),
			})
			r, err := http.DefaultClient.Post("https://"+serviceURL+"/device_auth/finish", DEVICE_AUTH_CONTENT_TYPE, bytes.NewReader(dacr))
			if err != nil {
				return "", err
			}
			resp, _ := io.ReadAll(r.Body)
			if r.StatusCode != 200 {
				return "", errors.New(string(resp))
			} else {
				return string(resp), nil
			}
		} else {
			return "", errors.New("failed to find pem block")
		}
	} else {
		return "", errors.New("not allowed")
	}
}

func (edc *ExternalDeviceClient) registerExternalClient() error {
	return nil
}
