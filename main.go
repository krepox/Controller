package main

import (
	"log"
	"os/exec"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/krepox/Controller/api"
	dhcp "github.com/krepox/Controller/dhcpserver"
)

func main() {
	go dhcp.StartDHCPServer("enp1s0np0np0")
	// Iniciar el frontend en segundo plano
	go startFrontend()

	router := gin.Default()

	// Configuración CORS para permitir solicitudes desde cualquier origen
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://138.4.21.21:5173"}, // Permitir estos orígenes
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// Servir archivos estáticos desde frontend/dist
	router.Static("/assets", "./frontend/dist/assets")

	// Cargar el index.html generado por React
	router.LoadHTMLFiles("./frontend/dist/index.html")

	// Registrar rutas desde el módulo `api`
	api.RegisterRoutes(router)

	log.Println("Servidor escuchando en http://localhost:8080")
	router.Run("0.0.0.0:8080")
}

// startFrontend ejecuta el comando `npm run dev` para iniciar el frontend
func startFrontend() {
	// Cambia a la carpeta del frontend
	cmd := exec.Command("npm", "run", "dev", "--", "--host")
	cmd.Dir = "./frontend"

	// Ejecutar el frontend y capturar la salida
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Error al ejecutar frontend: %v", err)
	}
}
