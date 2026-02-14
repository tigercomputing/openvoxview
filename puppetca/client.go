package puppetca

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/sebastianrakel/openvoxview/config"
	"github.com/sebastianrakel/openvoxview/model"
)

type client struct {
	config *config.Config
}

func NewClient(config *config.Config) *client {
	return &client{config: config}
}

func (c *client) call(httpMethod string, endpoint string, payload any, query url.Values, responseData any) (*http.Response, int, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	uri := fmt.Sprintf("%s/%s", cfg.GetPuppetCAAddress(), endpoint)
	if query != nil {
		uri = fmt.Sprintf("%s?%s", uri, query.Encode())
	}

	var data []byte

	if payload != nil {
		data, err = json.Marshal(&payload)
		if err != nil {
			fmt.Printf("err: %s", err)
		}
		fmt.Printf("Payload:\n%s\n", data)
	}

	fmt.Printf("HTTP: %#v: %#v\n", httpMethod, uri)

	var tlsConfig *tls.Config

	if cfg.PuppetCA.TLS {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: cfg.PuppetCA.TLSIgnore,
		}

		if cfg.PuppetCA.TLS_CA != "" {
			caCert, err := os.ReadFile(cfg.PuppetCA.TLS_CA)
			if err != nil {
				return nil, 0, err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}

		if cfg.PuppetCA.TLS_KEY != "" {
			cer, err := tls.LoadX509KeyPair(cfg.PuppetCA.TLS_CERT, cfg.PuppetCA.TLS_KEY)
			if err != nil {
				return nil, 0, err
			}

			tlsConfig.Certificates = []tls.Certificate{cer}
		}
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	httpClient := &http.Client{
		Transport: tr,
	}

	req, err := http.NewRequest(httpMethod, uri, bytes.NewBuffer(data))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := httpClient.Do(req)
	if err != nil {
		return resp, http.StatusInternalServerError, err
	}

	defer resp.Body.Close()

	responseRaw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, resp.StatusCode, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		if responseData != nil {
			err = json.Unmarshal(responseRaw, responseData)
			if err != nil {
				return resp, resp.StatusCode, err
			}
		}
	}
	return resp, resp.StatusCode, nil
}

func (c *client) GetCertificates(state *model.CertificateState) ([]model.CertificateStatus, error) {
	var resp []model.CertificateStatus

	query := url.Values{}

	if state != nil {
		query.Set("state", state.String())
	}

	_, _, err := c.call(http.MethodGet, "puppet-ca/v1/certificate_statuses/all", nil, query, &resp)

	return resp, err
}

func (c *client) GetCertificate(name string) (*model.CertificateStatus, error) {
	var resp model.CertificateStatus

	_, statusCode, err := c.call(http.MethodGet, fmt.Sprintf("puppet-ca/v1/certificate_status/%s", name), nil, nil, &resp)

	switch statusCode {
	case http.StatusOK:
		return &resp, err
	default:
	}

	return nil, err
}

func (c *client) SignCertificate(name string) error {
	payload := struct {
		DesiredState string `json:"desired_state"`
	}{
		DesiredState: "signed",
	}

	_, statusCode, err := c.call(http.MethodPut, fmt.Sprintf("puppet-ca/v1/certificate_status/%s", name), payload, nil, nil)

	if err != nil {
		log.Printf("Error signing certificate: %s", err)
		return err
	}

	switch statusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	default:
	}

	log.Printf("Unexpected status code while signing certificate: %d", statusCode)
	return fmt.Errorf("unexpected status code: %d", statusCode)
}

func (c *client) RevokeCertificate(name string) error {
	payload := struct {
		DesiredState string `json:"desired_state"`
	}{
		DesiredState: "revoked",
	}

	_, statusCode, err := c.call(http.MethodPut, fmt.Sprintf("puppet-ca/v1/certificate_status/%s", name), payload, nil, nil)

	if err != nil {
		log.Printf("Error revoking certificate: %s", err)
		return err
	}

	switch statusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	default:
	}

	log.Printf("Unexpected status code while revoking certificate: %d", statusCode)
	return fmt.Errorf("unexpected status code: %d", statusCode)
}

func (c *client) CleanCertificate(name string) error {
	// Determine the current certificate status to decide which endpoint to use
	status, err := c.GetCertificate(name)

	if err != nil {
		log.Printf("Error fetching certificate status: %s", err)
		return err
	}

	if status == nil {
		log.Printf("Certificate %s not found, cannot clean", name)
		return fmt.Errorf("certificate %s not found", name)
	}

	var statusCode int

	switch status.State {
	case model.CertificateSigned:
		// If the certificate is signed, we can use the clean endpoint to revoke and clean in one step
		payload := struct {
			Certnames []string `json:"certnames"`
		}{
			Certnames: []string{name},
		}

		_, statusCode, err = c.call(http.MethodPut, "puppet-ca/v1/clean", payload, nil, nil)

	case model.CertificateRequested, model.CertificateRevoked:
		// If the certificate is revoked or requested, we must directly delete it
		_, statusCode, err = c.call(http.MethodDelete, fmt.Sprintf("puppet-ca/v1/certificate_status/%s", name), nil, nil, nil)

	default:
		log.Printf("Certificate %s is in state %s, cannot clean", name, status.State)
		return fmt.Errorf("certificate %s is in state %s, cannot clean", name, status.State)
	}

	if err != nil {
		log.Printf("Error cleaning certificate: %s", err)
		return err
	}

	switch statusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	default:
	}

	log.Printf("Unexpected status code while cleaning certificate: %d", statusCode)
	return fmt.Errorf("unexpected status code: %d", statusCode)
}
