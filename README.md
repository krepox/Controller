Controlador para gestionar el despliegue dinámico de una pool de AGFs
Cuenta con tres módulos:
  -Servidor DHCP: se comunica con los clientes y les reasigna el direccionamiento IP en función del AGF al que se deben conectar.
  -Servidor REST: expone una API para establecer comunicacion con los AGFs
  -Servidor HTTP: levanta el frontend de la aplicación, para visualizar gráficamente los AGFs registrados, así como los usuarios correspondientes a cada uno  
