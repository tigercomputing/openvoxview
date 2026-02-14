package puppetca

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
