package sdk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

type EndpointServicesServer struct {
	isEDC bool
}

func NewEndpointServiceServer(forClient bool) *EndpointServicesServer {
	return &EndpointServicesServer{
		isEDC: forClient,
	}
}

func (ess *EndpointServicesServer) ListenAndServe(port int) error {
	cert, err := tls.LoadX509KeyPair(filepath.Base(os.Args[0])+".crt", filepath.Base(os.Args[0])+".key")
	if err != nil {
		panic(err)
	}

	ca := x509.NewCertPool()
	caFile, _ := os.ReadFile("gkca.pem")

	ca.AppendCertsFromPEM(caFile)

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
func (ess *EndpointServicesServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ping":
		w.Write([]byte("pong"))
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
func (ess *EndpointServicesServer) verifyToken(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
func (ess *EndpointServicesServer) signToken(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
func (ess *EndpointServicesServer) renewCert(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}
