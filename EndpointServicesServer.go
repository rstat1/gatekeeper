package sdk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
)

type endpointServicesServer struct {
	isEDC    bool
	deviceID string
	gkc      *GatekeeperClient
}

func NewEndpointServiceServer(forClient bool, deviceID string, gkc *GatekeeperClient) *endpointServicesServer {
	return &endpointServicesServer{
		gkc:      gkc,
		isEDC:    forClient,
		deviceID: deviceID,
	}
}

func (ess *endpointServicesServer) ListenAndServe(port int) error {
	gkCreds := ess.gkc.GetCredentials()

	ca := x509.NewCertPool()
	ca.AppendCertsFromPEM([]byte(gkCreds.Cert.CaCert))

	cert, err := tls.X509KeyPair([]byte(gkCreds.Cert.Certificate), []byte(gkCreds.Cert.PrivateKey))
	if err != nil {
		panic(err)
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

	server := http.Server{
		Addr:      ":" + strconv.Itoa(port),
		Handler:   ess,
		TLSConfig: &tlsConf,
	}
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	err = server.ServeTLS(listener, "", "")
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
	w.WriteHeader(http.StatusNotImplemented)
}
