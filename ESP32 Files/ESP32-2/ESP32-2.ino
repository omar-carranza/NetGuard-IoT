#include <WiFi.h>
#include <WiFiUdp.h>

// ===============================
// CONFIGURACION WIFI
// ===============================

const char* ssid = "Megacable_2.4G_D486";
const char* password = "D4Uph4uq";

// ===============================
// IP ESTATICA DEL ESP32
// ===============================

IPAddress local_IP(192,168,1,12);
IPAddress gateway(192,168,1,1);
IPAddress subnet(255,255,255,0);

// ===============================
// SERVIDOR NETGUARD
// ===============================

// IP DE TU LAPTOP
const char* host = "192.168.1.2";

// PUERTO UDP
const uint16_t udpPort = 9090;

// ===============================
// OBJETO UDP
// ===============================

WiFiUDP udp;

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

  // Simular nivel de luz
  int luz = random(0, 100);

  // Crear JSON
  String json = "{";
  json += "\"device\":\"LIGHT_SENSOR\",";
  json += "\"ip\":\"192.168.1.12\",";
  json += "\"light\":" + String(luz);
  json += "}";

  // Enviar paquete UDP
  udp.beginPacket(host, udpPort);

  udp.print(json);

  udp.endPacket();

  Serial.println("\nPaquete UDP enviado");

  Serial.println(json);

  // Esperar 5 segundos
  delay(5000);
}