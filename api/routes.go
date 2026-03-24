package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	dhcp "github.com/krepox/Controller/dhcpserver"
)

type AgfId struct {
	GnbID string `json:"gnbId" binding:"required"`
}
type User struct {
	Supi  string `json:"supi"  binding:"required"`
	IMSI  string `json:"imsi" binding:"required"`
	GnbID string `json:"gnb_id" binding:"required"`
}

type triggerDHCPPayload struct {
	UeIP        string `json:"ue" 	 binding:"required"`  //User IP
	TargetGnbID string `json:"gnbId" binding:"required"` //To set new IP depending on T-AGF
	Supi        string `json:"supi"  binding:"required"` // UE identifier
}

// HandoverCompletedPayload define la estructura que el servidor DHCP
// le enviará al controlador después de recibir el ACK con la nueva IP.
type HandoverCompleted struct {
	Supi  string `json:"supi"`
	GnbId string `json:"gnbId"` // solo viene el DESTINO
}

// Rrecibe el Supi y el gnbid del target AGF para enviarle la petición de registrar el nuevo usuario
type RegisterNewUserPayload struct {
	Supi  string `json:"supi"  binding:"required"`
	GnbId string `json:"gnbId" binding:"required"`
}

var agfIds []AgfId

var users = make([]User, 0)         // slice to list users
var userMap = make(map[string]User) // key = supi

// API routes
func RegisterRoutes(router *gin.Engine) {
	router.GET("/agfs", getAgfs)
	router.POST("/AGF_registration", registerAgf)
	router.POST("/triggerDHCP", triggerDHCP)
	router.POST("/user_registration", registerUser)
	router.GET("/users", getUsers)
	router.POST("/triggerHandover", triggerHandover) //endpoint to trigger H.O. on S-AGF
	//router.POST("/handoverCompleted", handleHandoverCompleted)

	// Nuevo endpoint para avisar al AGF destino que registre un nuevo usuario
	router.POST("/registerNewUser", handleRegisterNewUser)
}

// @Summary Obtener AGFs registrados
// @Description Lista los AGFs que se han registrado
// @Tags AGF
// @Produce json
// @Success 200 {object} map[string][]AgfId
// @Router /agfs [get]
func getAgfs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"agfs": agfIds})
}

// @Summary Registrar un AGF
// @Description Registra un AGF con su GNB ID
// @Tags AGF
// @Accept json
// @Produce json
// @Param agf body AgfId true "AGF ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /AGF_registration [post]
func registerAgf(c *gin.Context) {
	var d AgfId
	if err := c.ShouldBindJSON(&d); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check whether AGF already exist
	for _, agf := range agfIds {
		if agf.GnbID == d.GnbID {
			c.JSON(http.StatusOK, gin.H{
				"message": "AGF ya estaba registrado",
				"gnbId":   d.GnbID,
			})
			return
		}
	}

	agfIds = append(agfIds, d)
	c.JSON(http.StatusOK, gin.H{
		"message": "AGF registrado correctamente",
		"gnbId":   d.GnbID,
	})
}

// @Summary Registrar un usuario
// @Description Registra un nuevo usuario (UE) en un AGF
// @Tags Usuario
// @Accept json
// @Produce json
// @Param user body User true "Usuario a registrar"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /user_registration [post]
func registerUser(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check whether user already exist
	if _, exists := userMap[u.Supi]; exists {
		c.JSON(http.StatusOK, gin.H{
			"message": "Usuario ya estaba registrado",
			"supi":    u.Supi,
		})
		return
	}

	users = append(users, u)
	userMap[u.Supi] = u

	c.JSON(http.StatusOK, gin.H{
		"message": "Usuario registrado correctamente",
		"supi":    u.Supi,
	})
}

// @Summary Obtener usuarios registrados
// @Description Lista todos los usuarios registrados
// @Tags Usuario
// @Produce json
// @Success 200 {object} map[string][]User
// @Router /users [get]
func getUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// @Summary Lanzar cliente DHCP
// @Description Inicia el cliente DHCP en un UE con IP y destino
// @Tags DHCP
// @Accept json
// @Produce json
// @Param payload body map[string]string true "IP y GNB de destino"
// @Success 200 {object} map[string]string
// @Failure 400,500 {object} map[string]string
// @Router /triggerDHCP [post]
func triggerDHCP(c *gin.Context) {

	var payload triggerDHCPPayload

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing some value"})
		return
	}

	if err := dhcp.TriggerDHCPClient(payload.UeIP, payload.TargetGnbID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "DHCP Client active"})

	//Send petition to AGF to register the user
	var Source_agfIP string
	switch payload.TargetGnbID {
	case "000103":
		Source_agfIP = "10.2.0.24"
	case "000102":
		Source_agfIP = "10.2.0.86"
	}

	url := fmt.Sprintf("http://%s:8082/deregisterUser", Source_agfIP)
	reqBody, _ := json.Marshal(gin.H{"supi": payload.Supi})

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Unreachable AGF"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"error": "AGF rechazó el deregister"})
		return
	}
	log.Printf("SUPI %s deregistered in: %s", payload.Supi, Source_agfIP)
	// ───────────────────────────────────────────────────────────────

	c.JSON(http.StatusOK,
		gin.H{"message": "Deregister send"})
}

// @Summary Activar Handover
// @Description Solicita el Handover de un usuario a un nuevo AGF destino
// @Tags Handover
// @Accept json
// @Produce json
// @Param payload body map[string]string true "SUPI del usuario y GNB destino"
// @Success 200 {object} map[string]string
// @Failure 400,404,502 {object} map[string]string
// @Router /triggerHandover [post]
func triggerHandover(c *gin.Context) {

	type HandoverReq struct {
		Supi  string `json:"supi"  binding:"required"` // User identifier
		GnbId string `json:"gnbId" binding:"required"` // T-AGF
	}

	var req HandoverReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Handover solicitation received - SUPI: %s, Target GNB: %s", req.Supi, req.GnbId)

	user, ok := userMap[req.Supi]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	log.Printf("User SUPI %s registered on Source AGF (GNB ID): %s", user.Supi, user.GnbID)

	//Resolve S-AGF IP
	var agfIP string
	switch user.GnbID {
	// Vlannet I-face IPs
	case "000102":
		agfIP = "10.2.0.24"
	case "000103":
		agfIP = "10.2.0.86"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Source GnbID not found"})
		return
	} //TODO: Extract IP from new AGFs directly in the registration

	log.Printf("Sending HO solicitation al AGF origen con IP: %s", agfIP)

	// Send SUPI + T-GNB to S-AGF
	url := fmt.Sprintf("http://%s:8082/triggerHandover", agfIP)
	jsonData, _ := json.Marshal(req)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error connecting to S-AGF: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "AGF unreachable"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error in S-AGF response: %s", resp.Status)
	} else {
		log.Println("Handover succesfully started in  S-AGF")
		// Update GnbID after HO
		user.GnbID = req.GnbId
		userMap[req.Supi] = user
		for i, u := range users {
			if u.Supi == req.Supi {
				users[i].GnbID = req.GnbId
				break
			}
		}
		log.Printf("SUPI %s move to new AGF %s", req.Supi, req.GnbId)
	} //TODO: Get notification from S-AGF after succesfull H.O. procedure

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Handover requested: SUPI %s ➜ GNB %s", req.Supi, req.GnbId),
	})
}

// handleRegisterNewUser registra un nuevo usuario en un AGF específico.
// @Summary      Registra nuevo usuario
// @Description  Registra un nuevo usuario (UE) y lo vincula a un AGF existente.
// @Tags         Usuarios
// @Accept       json
// @Produce      json
// @Param        payload  body  RegisterNewUserPayload  true  "Datos del usuario"
// @Success      200      {object}  map[string]string
// @Failure      400      {object}  map[string]string
// @Failure      502      {object}  map[string]string
// @Router       /registerNewUser [post]
func handleRegisterNewUser(c *gin.Context) {
	var payload RegisterNewUserPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON inválido: falta supi o gnbId"})
		return
	}
	log.Printf("[Controller] /registerNewUser recibido: SUPI=%s, GNB destino=%s",
		payload.Supi, payload.GnbId)

	// 1) Resuelve IP del AGF destino según payload.GnbId
	var agfDestIP string
	switch payload.GnbId {
	case "000102":
		agfDestIP = "10.2.0.24"
	case "000103":
		agfDestIP = "10.2.0.86"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown GnbId"})
		return
	}

	// 2) Construye y envía POST al AGF destino
	url := fmt.Sprintf("http://%s:8082/registerNewUser", agfDestIP)
	body, _ := json.Marshal(gin.H{"supi": payload.Supi})

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[Controller] error enviando /registerNewUser a %s: %v", agfDestIP, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "AGF destino inalcanzable"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[Controller] registerNewUser returned status %s", resp.Status)
		c.JSON(http.StatusBadGateway, gin.H{"error": "AGF destino rechazó el registro"})
		return
	}

	log.Printf("[Controller] registerNewUser enviado correctamente a %s para SUPI %s",
		agfDestIP, payload.Supi)
	c.JSON(http.StatusOK, gin.H{"message": "Orden de registro enviada al AGF destino"})
}

/*
// handleHandoverCompleted: la lógica que, al recibir esta petición,
// hará internamente un "user deregister" al AGF origen y "user register" al AGF destino.
func handleHandoverCompleted(c *gin.Context) {

	var payload HandoverCompleted

	if err := c.ShouldBindJSON(&payload); err != nil || payload.Supi == "" || payload.GnbId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Faltan parámetros"})
		return
	}

	log.Printf("[Controller] HandoverCompleted: SUPI=%s, GNB destino=%s", payload.Supi, payload.GnbId)

	// Determinar IPs de AGF destino y origen
	// El gNBID es el que llega a esta petición es el del target
	var agfDestIP, agfOriginIP, originGnb string
	switch payload.GnbId {
	case "000102":
		agfDestIP = "10.2.0.24"
		agfOriginIP = "10.2.0.86"
		originGnb = "000103"
	case "000103":
		agfDestIP = "10.2.0.86"
		agfOriginIP = "10.2.0.24"
		originGnb = "000102"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown target GnbId"})
		return
	}

	// Verificar que el usuario existe
	user, exists := userMap[payload.Supi]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Usuario no encontrado"})
		return
	}

	// Deregistrar en AGF origen
	deregURL := fmt.Sprintf("http://%s:8082/user_deregister", agfOriginIP)
	bodyDereg := gin.H{"supi": payload.Supi}
	jsonDereg, _ := json.Marshal(bodyDereg)
	respDereg, err := http.Post(deregURL, "application/json", bytes.NewBuffer(jsonDereg))
	if err != nil || respDereg.StatusCode != http.StatusOK {
		log.Printf("[Controller] Error en deregister de %s: %v", originGnb, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Deregister fallido en AGF origen"})
		return
	}
	defer respDereg.Body.Close()
	log.Printf("[Controller] Usuario %s desregistrado en AGF %s", payload.Supi, originGnb)

	// Registrar en AGF destino
	registerURL := fmt.Sprintf("http://%s:8082/user_registration", agfDestIP)
	bodyReg := gin.H{
		"supi":   payload.Supi,
		"imsi":   user.IMSI,
		"gnb_id": payload.GnbId,
	}
	jsonReg, _ := json.Marshal(bodyReg)
	respReg, err := http.Post(registerURL, "application/json", bytes.NewBuffer(jsonReg))
	if err != nil || respReg.StatusCode != http.StatusOK {
		log.Printf("[Controller] Error en register de %s: %v", payload.GnbId, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Register fallido en AGF destino"})
		return
	}
	defer respReg.Body.Close()
	log.Printf("[Controller] Usuario %s registrado en AGF %s", payload.Supi, payload.GnbId)

	// Actualizar userMap
	user.GnbID = payload.GnbId
	userMap[payload.Supi] = user
	for i, u := range users {
		if u.Supi == payload.Supi {
			users[i].GnbID = payload.GnbId
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("HandoverCompleted para SUPI %s, de %s a %s", payload.Supi, originGnb, payload.GnbId),
	})
}
*/
