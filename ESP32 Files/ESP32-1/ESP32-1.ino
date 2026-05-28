#include <WiFi.h>

const char* ssid = "Megacable_2.4G_D486";
const char* password = "D4Uph4uq";

IPAddress local_IP(192,168,1,10);
IPAddress gateway(192,168,1,1);
IPAddress subnet(255,255,255,0);

// IP DE TU LAPTOP
const char* host = "192.168.1.2";
const uint16_t port = 8080;

void setup() {

  Serial.begin(115200);

  // Configurar IP estatica
  if(!WiFi.config(local_IP, gateway, subnet)){

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

void loop() {

  // Simular temperatura aleatoria
  int temperatura = random(20, 35);

  // Crear cliente TCP
  WiFiClient client;

  // Intentar conexion
  if(client.connect(host, port)) {

    Serial.println("\nConectado al servidor NetGuard");

    // Crear mensaje JSON
    String json = "{";
    json += "\"device\":\"TEMP_SENSOR\",";
    json += "\"ip\":\"192.168.1.11\",";
    json += "\"temperature\":" + String(temperatura);
    json += "}";

    // Enviar datos
    client.println(json);

    Serial.println("Datos enviados:");

    Serial.println(json);

    // Esperar respuesta del servidor
    while(client.connected() && !client.available()){

      delay(10);
    }

    // Leer respuesta
    if(client.available()){

      String response = client.readStringUntil('\n');

      Serial.print("Servidor responde: ");

      Serial.println(response);
    }

    // Cerrar conexion
    client.stop();

    Serial.println("Conexion cerrada");
  }

  else {
    Serial.println("No se pudo conectar al servidor");
  }

  // Esperar 5 segundos
  delay(5000);
}