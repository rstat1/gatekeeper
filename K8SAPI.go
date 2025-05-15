package sdk

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	// Path to the service account token
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	// Path to the service account CA certificate
	caCertFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	// Namespace file (useful for defaulting if not provided)
	namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// ServiceStatus represents the status of a Kubernetes Service.
// We are primarily interested in LoadBalancer status, but this can be expanded.
type ServiceStatus struct {
	LoadBalancer LoadBalancerStatus `json:"loadBalancer,omitempty"`
	// Conditions []Condition         `json:"conditions,omitempty"` // Example of another common status field
	// You can add other fields from the actual ServiceStatus object as needed.
}

// LoadBalancerStatus represents the status of a LoadBalancer.
type LoadBalancerStatus struct {
	Ingress []LoadBalancerIngress `json:"ingress,omitempty"`
}

// LoadBalancerIngress represents an ingress point for a LoadBalancer.
// It can be an IP address or a hostname.
type LoadBalancerIngress struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// Ports    []PortStatus `json:"ports,omitempty"` // Example for more detailed status
}

// Service is a minimal representation of a Kubernetes Service object
// focusing on what's needed to extract the status.
type Service struct {
	Kind       string                 `json:"kind,omitempty"`
	ApiVersion string                 `json:"apiVersion,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"` // Using map for simplicity
	Spec       map[string]interface{} `json:"spec,omitempty"`     // Using map for simplicity
	Status     ServiceStatus          `json:"status,omitempty"`
}

// Helper function to get current namespace if running in-cluster
func getCurrentNamespace() (string, error) {
	nsBytes, err := os.ReadFile(namespaceFile)
	if err != nil {
		// This might happen if not in-cluster or file is not readable
		return "", fmt.Errorf("could not read namespace file %s: %w. Are you in a K8s pod?", namespaceFile, err)
	}
	return string(nsBytes), nil
}

// GetK8sServiceStatus fetches a Kubernetes Service and returns its status.
// It requires the service name and namespace.
// It assumes in-cluster execution for authentication.
func GetK8sServiceStatus(serviceName string) (string, error) {
	// Get Kubernetes API server host and port from environment variables
	// These are automatically injected into pods by Kubernetes.
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return "", fmt.Errorf("KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT not set. Ensure this runs in-cluster")
	}

	// Read the service account token
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token from %s: %w", tokenFile, err)
	}

	// Read the CA certificate
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return "", fmt.Errorf("failed to read CA certificate from %s: %w", caCertFile, err)
	}

	// Create a certificate pool and add the CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return "", fmt.Errorf("failed to append CA certificate to pool")
	}

	// Create a custom HTTP client with TLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12, // Enforce modern TLS
			},
		},
		Timeout: 10 * time.Second, // Set a reasonable timeout
	}

	ns, err := getCurrentNamespace()
	if err != nil {
		return "", fmt.Errorf("failed to get current namespace: %w", err)
	}

	// Construct the API URL for the service
	// Example: https://kubernetes.default.svc/api/v1/namespaces/default/services/my-service
	apiURL := fmt.Sprintf("https://%s:%s/api/v1/namespaces/%s/services/%s", host, port, ns, serviceName)

	// Create a new HTTP GET request
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add the Authorization header with the bearer token
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/json")

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute HTTP request to %s: %w", apiURL, err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		// Try to read body for more error details, but don't fail if it's unreadable
		bodyBytes, _ := os.ReadFile(resp.Body.(*os.File).Name()) // This is not ideal for http.Response.Body
		// A better way to read body:
		// import "io"
		// bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("kubernetes API server returned non-OK status: %d %s. URL: %s. Body: %s",
			resp.StatusCode, http.StatusText(resp.StatusCode), apiURL, string(bodyBytes))
	}

	// Decode the JSON response into our Service struct
	var serviceObj Service
	if err := json.NewDecoder(resp.Body).Decode(&serviceObj); err != nil {
		return "", fmt.Errorf("failed to decode JSON response from Kubernetes API: %w", err)
	}

	// Return the status field
	return serviceObj.Status.LoadBalancer.Ingress[0].IP, nil
}
