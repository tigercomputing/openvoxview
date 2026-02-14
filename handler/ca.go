package handler

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sebastianrakel/openvoxview/config"
	"github.com/sebastianrakel/openvoxview/model"
	"github.com/sebastianrakel/openvoxview/puppetca"
)

type CaHandler struct {
	config *config.Config
}

func NewCaHandler(config *config.Config) *CaHandler {
	return &CaHandler{
		config: config,
	}
}

func (h *CaHandler) RegisterRoutes(group *gin.RouterGroup) {
	group.POST("status", h.QueryCertificateStatuses)
	group.POST("status/:name/sign", h.SignCertificate)
	group.POST("status/:name/revoke", h.RevokeCertificate)
	group.DELETE("status/:name", h.CleanCertificate)
}

func (h *CaHandler) QueryCertificateStatuses(c *gin.Context) {
	var query model.CertificateStatusQuery

	if err := c.ShouldBindJSON(&query); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, NewErrorResponse(err))
		return
	}

	caClient := puppetca.NewClient(h.config)
	resultCerts := make([]model.CertificateStatus, 0)

	if query.States != nil {
		for _, state := range *query.States {
			certs, err := caClient.GetCertificates(&state)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, NewErrorResponse(err))
				return
			}
			resultCerts = append(resultCerts, certs...)
		}
	} else {
		certs, err := caClient.GetCertificates(nil)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, NewErrorResponse(err))
			return
		}
		resultCerts = certs
	}

	if query.Filter != nil {
		resultCerts = slices.Collect(func(yield func(model.CertificateStatus) bool) {
			for _, cert := range resultCerts {
				if strings.Contains(cert.Name, *query.Filter) ||
					strings.Contains(cert.Fingerprint, *query.Filter) ||
					slices.Contains(cert.DnsAltNames, *query.Filter) {
					if !yield(cert) {
						return
					}
				}
			}
		})
	}

	response := model.CertificateStatusResponse{
		CertificateStatuses: resultCerts,
	}

	c.JSON(http.StatusOK, NewSuccessResponse(response))
}

func (h *CaHandler) SignCertificate(c *gin.Context) {
	name := c.Param("name")
	caClient := puppetca.NewClient(h.config)

	err := caClient.SignCertificate(name)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, NewErrorResponse(err))
		return
	}

	c.JSON(http.StatusOK, NewSuccessResponse(nil))
}

func (h *CaHandler) RevokeCertificate(c *gin.Context) {
	name := c.Param("name")
	caClient := puppetca.NewClient(h.config)

	err := caClient.RevokeCertificate(name)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, NewErrorResponse(err))
		return
	}

	c.JSON(http.StatusOK, NewSuccessResponse(nil))
}

func (h *CaHandler) CleanCertificate(c *gin.Context) {
	name := c.Param("name")
	caClient := puppetca.NewClient(h.config)

	err := caClient.CleanCertificate(name)

	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, NewErrorResponse(err))
		return
	}

	c.JSON(http.StatusOK, NewSuccessResponse(nil))
}
