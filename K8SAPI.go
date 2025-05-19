package sdk

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	tokenFile     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caCertFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type ServiceStatus struct {
	LoadBalancer LoadBalancerStatus `json:"loadBalancer,omitempty"`
}
type LoadBalancerStatus struct {
	Ingress []LoadBalancerIngress `json:"ingress,omitempty"`
}
type LoadBalancerIngress struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}
type Service struct {
	Kind       string         `json:"kind,omitempty"`
	ApiVersion string         `json:"apiVersion,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Spec       map[string]any `json:"spec,omitempty"`
	Status     ServiceStatus  `json:"status,omitempty"`
}

func getCurrentNamespace() (string, error) {
	if nsBytes, err := os.ReadFile(namespaceFile); err == nil {
		return string(nsBytes), nil
	} else {
		return "", fmt.Errorf("could not read namespace file %s: %w. Are you in a K8s pod?", namespaceFile, err)
	}
}

func getHTTPClient() (*http.Client, error) {
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertFile, err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
		Timeout: 10 * time.Second,
	}, nil
}
func GetLoadBalancerIP(serviceName string) (string, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return "", fmt.Errorf("KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT not set. Ensure this runs in-cluster")
	}

	client, err := getHTTPClient()
	if err != nil {
		return "", err
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token from %s: %w", tokenFile, err)
	}
	ns, err := getCurrentNamespace()
	if err != nil {
		return "", fmt.Errorf("failed to get current namespace: %w", err)
	}

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%s/api/v1/namespaces/%s/services/%s", host, port, ns, serviceName), nil)
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/json")

	if resp, err := client.Do(req); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			var serviceObj Service
			if err := json.Unmarshal(bodyBytes, &serviceObj); err == nil {
				return serviceObj.Status.LoadBalancer.Ingress[0].IP, nil
			} else {
				return "", fmt.Errorf("failed to decode JSON response from Kubernetes API: %w", err)
			}
		} else {
			return "", fmt.Errorf("kubernetes API server returned non-OK status: %d %s. URL: %s", resp.StatusCode, http.StatusText(resp.StatusCode), req.URL)
		}
	} else {
		return "", fmt.Errorf("failed to execute HTTP request to %w", err)
	}
}

func ForceExternalSecretSync(name string) error {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return fmt.Errorf("KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT not set. Ensure this runs in-cluster")
	}

	if client, err := getHTTPClient(); err == nil {
		token, err := os.ReadFile(tokenFile)
		if err != nil {
			return fmt.Errorf("failed to read service account token from %s: %w", tokenFile, err)
		}
		ns, err := getCurrentNamespace()
		if err != nil {
			return fmt.Errorf("failed to get current namespace: %w", err)
		}

		annotations := `{
			"annotations": {
				"force-sync": ` + time.Now().String() +
			`}
		}`

		req, _ := http.NewRequest("PATCH", fmt.Sprintf("https://%s:%s/apis/external-secrets.io/v1beta1/namespaces/%s/externalsecret/%s", host, port, ns, name), bytes.NewReader([]byte(annotations)))
		req.Header.Set("Authorization", "Bearer "+string(token))
		req.Header.Set("Accept", "application/merge-patch+json")
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			} else {
				return fmt.Errorf("kubernetes API server returned non-OK status: %d %s. URL: %s", resp.StatusCode, http.StatusText(resp.StatusCode), req.URL)
			}
		}
		return nil

	} else {
		return err
	}
}
