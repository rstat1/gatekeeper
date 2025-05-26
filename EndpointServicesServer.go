package sdk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	v1 "go.alargerobot.dev/gatekeeper/sdk/rpc/config/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type endpointServicesServer struct {
	isEDC           bool
	deviceID        string
	epsServer       *http.Server
	gatekeeper      *GatekeeperClient
	handleCertRenew func(v1.ServiceCredentials)
}

func newEndpointServiceServer(forClient bool, deviceID string, gkc *GatekeeperClient, handleCertRenew func(v1.ServiceCredentials)) *endpointServicesServer {
	return &endpointServicesServer{
		gatekeeper:      gkc,
		isEDC:           forClient,
		deviceID:        deviceID,
		handleCertRenew: handleCertRenew,
	}
}

func (ess *endpointServicesServer) ListenAndServe(port int) error {
	var ca = x509.NewCertPool()
	var gkCreds v1.ServiceCredentials
	var cert tls.Certificate

	if ess.isEDC {
		certPair, err := tls.LoadX509KeyPair(filepath.Base(os.Args[0])+".crt", filepath.Base(os.Args[0])+".key")
		if err != nil {
			panic(err)
		}
		cert = certPair
		caFileBytes, _ := os.ReadFile("gkca.pem")
		ca.AppendCertsFromPEM([]byte(caFileBytes))
	} else {
		gkCreds = *ess.gatekeeper.GetCredentials()
		ca.AppendCertsFromPEM([]byte(gkCreds.CaCert))
		certPair, err := tls.X509KeyPair([]byte(gkCreds.Certificate), []byte(gkCreds.PrivateKey))
		if err != nil {
			panic(err)
		}
		cert = certPair
	}

	tlsConf := tls.Config{
		RootCAs:      ca,
		ClientCAs:    ca,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.PeerCertificates[0].Subject.CommonName != "gatekeeper" && cs.ServerName != "gatekeeper" {
				return errors.New("forbidden")
			}
			return nil
		},
	}

	ess.epsServer = &http.Server{
		Addr:      ":" + strconv.Itoa(port),
		Handler:   ess,
		TLSConfig: &tlsConf,
	}
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	err = ess.epsServer.ServeTLS(listener, "", "")
	if err != nil {
		panic(err)
	}
	return nil
}
func (ess *endpointServicesServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ping":
		if ess.isEDC {
			w.Write([]byte(ess.deviceID))
		} else {
			w.Write([]byte("pong"))
		}
	case "/sign_token":
		if !ess.isEDC {
			ess.signToken(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "/verify_token":
		if !ess.isEDC {
			ess.verifyToken(w, r)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case "/cert_renew":
		ess.renewCert(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
func (ess *endpointServicesServer) verifyToken(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
func (ess *endpointServicesServer) signToken(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
func (ess *endpointServicesServer) renewCert(w http.ResponseWriter, r *http.Request) {
	if newCreds, e := io.ReadAll(r.Body); e == nil {
		var nsr v1.ServiceCredentials
		if err := protojson.Unmarshal(newCreds, &nsr); err == nil {
			ess.handleCertRenew(nsr)
			w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(e.Error()))
	}
}
