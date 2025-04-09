package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	dhcp "github.com/krepox/Controller/dhcpserver"
)

type AgfId struct {
	GnbID string `json:"gnbId" binding:"required"`
}

var agfIds []AgfId

// RegisterRoutes agrega las rutas al router principal
func RegisterRoutes(router *gin.Engine) {
	router.GET("/agfs", getAgfs)
	router.POST("/AGF_registration", registerAgf)
	router.GET("/triggerDHCP", triggerDHCP)
}

func getAgfs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"agfs": agfIds})
}

func registerAgf(c *gin.Context) {
	var d AgfId
	if err := c.ShouldBindJSON(&d); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	agfIds = append(agfIds, d)
	c.JSON(http.StatusOK, gin.H{
		"message": "Datos almacenados correctamente",
		"gnbId":   d.GnbID,
	})
}
func triggerDHCP(c *gin.Context) {
	ueIP := c.Query("ue")
	if ueIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Falta parámetro 'ue'"})
		return
	}

	if err := dhcp.TriggerDHCPClient(ueIP); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Cliente DHCP activado correctamente"})
}
