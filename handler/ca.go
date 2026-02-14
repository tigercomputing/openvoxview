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
