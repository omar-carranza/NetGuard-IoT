#include <WiFi.h>
#include <HTTPClient.h>

// ===============================
// CONFIGURACION WIFI
// ===============================

const char* ssid = "POCO F7";
const char* password = "12345678";

// ===============================
// IP ESTATICA DEL ESP32
// ===============================

IPAddress local_IP(10,129,176,13);
IPAddress gateway(10,129,176,232);
IPAddress subnet(255,255,255,0);

// ===============================
// SERVIDOR NETGUARD
// ===============================

// ENDPOINT HTTP DEL SERVIDOR
const char* serverURL = "http://10.129.176.217:5000/motion";

// ===============================
// SETUP
// ===============================

void setup() {

  Serial.begin(115200);

  // Configurar IP estatica
  if(!WiFi.config(local_IP, gateway, subnet)) {

    Serial.println("Error configurando IP");
  }

  // Conectar WiFi
  WiFi.begin(ssid, password);

  Serial.print("Conectando");

  while(WiFi.status() != WL_CONNECTED){

    delay(500);

    Serial.print(".");
  }

  Serial.println("\nWiFi conectado");

  Serial.print("IP ESP32: ");

  Serial.println(WiFi.localIP());
}

// ===============================
// LOOP PRINCIPAL
// ===============================

void loop() {

  // Simular deteccion de movimiento
  bool movimiento = random(0, 2);

  // Verificar conexion WiFi
  if(WiFi.status() == WL_CONNECTED){

    HTTPClient http;

    // Iniciar conexion HTTP
    http.begin(serverURL);

    // Tipo de contenido
    http.addHeader("Content-Type", "application/json");

    // Crear JSON
    String json = "{";
    json += "\"device\":\"MOTION_SENSOR\",";
    json += "\"ip\":\"192.168.1.13\",";
    json += "\"motion\":" + String(movimiento ? "true" : "false");
    json += "}";

    // Enviar POST
    int httpResponseCode = http.POST(json);

    Serial.println("\nSolicitud HTTP enviada");

    Serial.println(json);

    // Mostrar respuesta
    Serial.print("Codigo HTTP: ");

    Serial.println(httpResponseCode);

    // Leer respuesta del servidor
    String response = http.getString();

    Serial.print("Respuesta servidor: ");

    Serial.println(response);

    // Cerrar conexion
    http.end();
  }

  else {

    Serial.println("WiFi desconectado");
  }

  // Esperar 5 segundos
  delay(5000);
}