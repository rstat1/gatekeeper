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
	"strconv"
	"strings"

	"github.com/google/uuid"
	v1 "go.alargerobot.dev/gatekeeper/sdk/rpc/config/v1"
)

const DEVICE_API_CONTENT_TYPE = "application/x-gatekeeper-device-api"

type ExternalDeviceClient struct {
	serviceURL string
	authToken  string
	epsAddr    string
	clientName string
	epsServer  *endpointServicesServer
}

type ExternalDeviceClientConfig struct {
	//Name of the current process that wants to connect, or if the helper is being used
	//name of the process for which the helper is being used for
	ClientName string
	//The full URL to service this client is connecting to
	ServiceURL string
	//Should be formated: <ip-address:port> and is the address/port that Gatekeeper will use to
	//contact the client when necessary (currently just used for provisioning new certifcates
	//when they expire).
	EndpointServicesAddr string
	//This function will be called when Gatekeepr renews the credentials for a service, with
	//a copy of the new credentials in tow.
	CertificateRenewalHandler func(v1.ServiceCredentials)
	//URL:Port combo that points the the Gatekeeper config service
	GatekeeperAPIAddress string
}

type deviceRegistration struct {
	DeviceID     string `json:"deviceID"`
	ServicesAddr string `json:"servicesAddr"`
}

type renewalCheckRequest struct {
	ServiceName           string `json:"service"`
	CurrentCertExpiryTime uint64 `json:"currentExpireTime"`
}

type renewalCheckResponse struct {
	Result         string
	NewCredentials string
}

// # Description
//
// NewExternalDeviceClient creates a client for connecting an external device to Gatekeeper's
// external device manager
//
// # Parameters
//   - config: An ExternalDeviceClientConfig struct that contains various settings for configuring
//     the connection to Gatekeeper.
func NewExternalDeviceClient(config ExternalDeviceClientConfig, gkc *GatekeeperClient) *ExternalDeviceClient {
	deviceID := config.ClientName + "-extdev-" + uuid.NewString()

	edc := &ExternalDeviceClient{
		clientName: config.ClientName,
		serviceURL: config.ServiceURL,
		epsAddr:    config.EndpointServicesAddr,
		epsServer:  newEndpointServiceServer(true, deviceID, gkc, config.CertificateRenewalHandler, config.ClientName),
	}

	addrParts := strings.Split(config.EndpointServicesAddr, ":")

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
// for authentication. Registers the device's endpoint services server (created by NewExternalDevice
// client) if successful.
func (edc *ExternalDeviceClient) Login() error {
	var dar DeviceAuthRequest

	if _, e := os.Stat(edc.clientName + ".key"); os.IsNotExist(e) {
		return fmt.Errorf("missing key file: %s", edc.clientName+".key")
	}

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
		privKeyBytes, _ := os.ReadFile(edc.clientName + ".key")
		if privKey, _ := pem.Decode(privKeyBytes); privKey != nil {
			privateKey, err := x509.ParseECPrivateKey(privKey.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse private key type: %s", err)
			}
			hash := sha512.Sum384([]byte(dar.Message))
			sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
			if err != nil {
				return fmt.Errorf("failed to sign message hash: %s", err)
			}
			dacr, _ := json.Marshal(DeviceAuthClientResponse{
				Message:   base64.StdEncoding.EncodeToString([]byte(dar.Message)),
				RequestID: dar.RequestID,
				Signature: base64.StdEncoding.EncodeToString(sig),
			})
			r, err := http.DefaultClient.Post("https://"+edc.serviceURL+"/device/auth/finish", DEVICE_API_CONTENT_TYPE, bytes.NewReader(dacr))
			if err != nil {
				return fmt.Errorf("auth finalizer failed: %s", err)
			}
			resp, _ := io.ReadAll(r.Body)
			if r.StatusCode != 200 {
				return errors.New(string(resp))
			} else {
				edc.authToken = string(resp)
				if err := edc.registerExternalClient(); err != nil {
					return err
				}

				return edc.checkForNewCredentials()
			}
		} else {
			return errors.New("failed to find pem block")
		}
	} else {
		return errors.New("not allowed")
	}
}

func (edc *ExternalDeviceClient) checkForNewCredentials() error {
	certBytes, _ := os.ReadFile(edc.clientName + ".crt")
	if cert, err := x509.ParseCertificate(certBytes); err == nil {
		certExpiresAt := cert.NotAfter.UnixMilli()

		devReg, _ := json.Marshal(renewalCheckRequest{
			ServiceName:           edc.clientName,
			CurrentCertExpiryTime: uint64(certExpiresAt),
		})

		req, _ := http.NewRequest("GET", "https://"+edc.serviceURL+"/device/update_credentials", bytes.NewReader(devReg))
		req.Header.Add("Content-Type", DEVICE_API_CONTENT_TYPE)
		req.Header.Add("Authorization", "Bearer "+edc.authToken)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			if resp.StatusCode != 200 {
				details, e := io.ReadAll(resp.Body)
				if e != nil {
					return e
				}
				return errors.New(string(details))
			} else {
				if details, e := io.ReadAll(resp.Body); e == nil {
					var renewalResp renewalCheckResponse
					json.Unmarshal(details, &renewalResp)
					
					if renewalResp.Result != "not expired" {
						sc := v1.ServiceCredentials{}
						json.Unmarshal([]byte(renewalResp.NewCredentials), &sc)
						edc.epsServer.handleCertRenew(sc)
					}
				}
			}
		} else {
			return err
		}
	}

	return nil
}

func (edc *ExternalDeviceClient) registerExternalClient() error {
	svcName := strings.Split(edc.serviceURL, ".")[0]

	devReg, _ := json.Marshal(deviceRegistration{
		ServicesAddr: edc.epsAddr,
		DeviceID:     svcName + "-extdev-" + uuid.NewString(),
	})

	req, _ := http.NewRequest("GET", "https://"+edc.serviceURL+"/device/activate_eps", bytes.NewReader(devReg))
	req.Header.Add("Content-Type", DEVICE_API_CONTENT_TYPE)
	req.Header.Add("Authorization", "Bearer "+edc.authToken)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		if resp.StatusCode != 200 {
			details, e := io.ReadAll(resp.Body)
			if e != nil {
				return e
			}
			return errors.New(string(details))
		} else {
			return nil
		}
	} else {
		return err
	}
}
