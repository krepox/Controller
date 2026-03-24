// @title Controlador AGF API
// @version 1.0
// @description API REST para gestionar AGFs, UEs y la movilidad.
// @host localhost:8080
// @BasePath /
// @schemes http

package main

import (
	"log"
	"os/exec"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/krepox/Controller/api"
	dhcp "github.com/krepox/Controller/dhcpserver"
	_ "github.com/krepox/Controller/docs"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	//ver si se puede levantar en las 2 interfaces
	go dhcp.StartDHCPServer("enp1s0np0np0") //I-face to attach the server
	go startFrontend()                    //Start WebUI

	router := gin.Default()

	// Cors config
	router.Use(cors.New(cors.Config{
		//cambiar ips luego para luego la movilidad del controlador a la máquina de OpenStack
		AllowOrigins:     []string{"http://localhost:5173", "http://138.4.21.21:5173"}, // Allow Origins
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	router.Static("/assets", "./frontend/dist/assets")
	router.LoadHTMLFiles("./frontend/dist/index.html")

	api.RegisterRoutes(router)

	// Swagger Endpoint
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	log.Println("Servidor escuchando en http://localhost:8080")
	router.Run("0.0.0.0:8080")
}

// Script to start web server
func startFrontend() {

	cmd := exec.Command("npm", "run", "dev", "--", "--host")
	cmd.Dir = "./frontend"

	err := cmd.Run()
	if err != nil {
		log.Fatalf("Error al ejecutar frontend: %v", err)
	}
}
