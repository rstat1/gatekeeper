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
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const DEVICE_API_CONTENT_TYPE = "application/x-gatekeeper-device-api"

type ExternalDeviceClient struct {
	serviceURL string
	authToken  string
	epsAddr    string
	epsServer  *endpointServicesServer
}

type deviceRegistration struct {
	DeviceID     string `json:"deviceID"`
	ServicesAddr string `json:"servicesAddr"`
}

// # Description
//
// NewExternalDeviceClient creates a client for connecting an external device to Gatekeeper's
// external device manager
//
// # Parameters
//
//   - serviceURL should be the full URL to service this client is connecting to.
//   - endpointServicesAddr should be formated: <ip-address:port> and is the address/port that
//     Gatekeeper will use the contact the client when necessary (currently just used for provisioning
//     new certifcates when they expire).
func NewExternalDeviceClient(serviceURL string, endpointServicesAddr string) *ExternalDeviceClient {
	svcName := strings.Split(serviceURL, ".")[0]
	deviceID := svcName + "-extdev-" + uuid.NewString()

	edc := &ExternalDeviceClient{
		serviceURL: serviceURL,
		epsAddr:    endpointServicesAddr,
		epsServer:  NewEndpointServiceServer(true, deviceID),
	}

	addrParts := strings.Split(endpointServicesAddr, ":")

	if len(addrParts) != 2 {
		panic(errors.New("invalid address specified. address format is: <ip-address:port>"))
	}

	port, _ := strconv.Atoi(addrParts[1])

	go edc.epsServer.ListenAndServe(port)
	return edc
}

// # Description
//
// Login authenticates an external device to Gatekeeper
// This is for the case when you have some IoT like device that needs to connect to a Gatekeeper
// service. This functionn requests from the server, some randomly generated message that will
// be signed by the service's certificate, and returned with the provided request ID. If
// verifcation is successful a signed token will be returned by the server that said device can use
// for authtencation. Registers the device's endpoint services server (created by NewExternalDevice
// client) if successful.
//
// # Parameters
//   - serviceURL should be a combo of the service's name and the service domain it belongs to
//   - Example: gktest.test.alargerobot.dev
func (edc *ExternalDeviceClient) Login() error {
	var dar DeviceAuthRequest
	req, _ := http.NewRequest("GET", "https://"+edc.serviceURL+"/device/auth/begin", http.NoBody)
	req.Header.Add("Content-Type", DEVICE_API_CONTENT_TYPE)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == 200 {
		reqDetails, e := io.ReadAll(resp.Body)
		if e != nil {
			return e
		}
		if e := json.Unmarshal(reqDetails, &dar); e != nil {
			return e
		}
		privKeyBytes, _ := os.ReadFile(filepath.Base(os.Args[0]) + ".key")
		if privKey, _ := pem.Decode(privKeyBytes); privKey != nil {
			privateKey, err := x509.ParseECPrivateKey(privKey.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse private key type: %s", err)
			}
			hash := sha512.Sum384([]byte(dar.Message))
			sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
			if err != nil {
				return err
			}
			dacr, _ := json.Marshal(DeviceAuthClientResponse{
				Message:   base64.StdEncoding.EncodeToString([]byte(dar.Message)),
				RequestID: dar.RequestID,
				Signature: base64.StdEncoding.EncodeToString(sig),
			})
			r, err := http.DefaultClient.Post("https://"+edc.serviceURL+"/device/auth/finish", DEVICE_API_CONTENT_TYPE, bytes.NewReader(dacr))
			if err != nil {
				return err
			}
			resp, _ := io.ReadAll(r.Body)
			if r.StatusCode != 200 {
				return errors.New(string(resp))
			} else {
				edc.authToken = string(resp)
				if err := edc.registerExternalClient(); err != nil {
					return err
				}
				return nil
			}
		} else {
			return errors.New("failed to find pem block")
		}
	} else {
		return errors.New("not allowed")
	}
}

func (edc *ExternalDeviceClient) registerExternalClient() error {
	svcName := strings.Split(edc.serviceURL, ".")[0]

	devReg, _ := json.Marshal(deviceRegistration{
		ServicesAddr: "https://" + edc.epsAddr + "/ping",
		DeviceID:     svcName + "-extdev-" + uuid.NewString(),
	})

	req, _ := http.NewRequest("GET", "https://"+edc.serviceURL+"/device/activate_eps", bytes.NewReader(devReg))
	req.Header.Add("Content-Type", DEVICE_API_CONTENT_TYPE)
	req.Header.Add("Authorization", "Bearer "+edc.authToken)
	resp, err := http.DefaultClient.Do(req)

	if resp.StatusCode != 200 {
		details, e := io.ReadAll(resp.Body)
		if e != nil {
			return e
		}
		return errors.New(string(details))
	}

	return err
}
