package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AgfId struct {
	GnbID string `json:"gnbId" binding:"required"`
}

var agfIds []AgfId

type Usuario struct {
	Supi        string `json:"supi"`
	AmfUeNgapId int64  `json:"amfuengapid"`
}

//var user Usuario

func main() {
	router := gin.Default()

	router.SetFuncMap(template.FuncMap{
		"toHex": func(s string) string {
			// Convierte cada byte de la cadena a formato hexadecimal
			return fmt.Sprintf("%x", s)
		},
	})

	router.LoadHTMLGlob("templates/*")

	// Ruta para mostrar la plantilla index.html
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "Página Principal",
			"datos": agfIds,
		})
	})

	// Endpoint POST para recibir y almacenar datos
	router.POST("/AGF_registration", func(c *gin.Context) {
		var d AgfId
		// Deserializa el JSON recibido
		if err := c.ShouldBindJSON(&d); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Almacena el dato recibido (podrías usar una base de datos o similar en un caso real)
		agfIds = append(agfIds, d)

		// Devuelve una respuesta de éxito
		c.JSON(http.StatusOK, gin.H{
			"message": "Datos almacenados correctamente",
			"gnbId":   d.GnbID,
		})
	})
	router.Run() // listen and serve on 0.0.0.0:8080
}
