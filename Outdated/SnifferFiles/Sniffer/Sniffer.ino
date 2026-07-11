/*CODIGO PARA RODAR NO WIRESHARK NO WINDOWS
#include <dummy.h>

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"

#define CHANNEL 6        // mude para o canal do seu ESP32 transmissor
#define BAUD_RATE 921600

/*void pcap_global_header() {
  uint32_t magic = 0xa1b2c3d4;
  uint16_t major = 2, minor = 4;
  int32_t  thiszone = 0;
  uint32_t sigfigs = 0, snaplen = 2500, network = 105;

  Serial.write((uint8_t*)&magic,    4);
  Serial.write((uint8_t*)&major,    2);
  Serial.write((uint8_t*)&minor,    2);
  Serial.write((uint8_t*)&thiszone, 4);
  Serial.write((uint8_t*)&sigfigs,  4);
  Serial.write((uint8_t*)&snaplen,  4);
  Serial.write((uint8_t*)&network,  4);
} LEMBRA DE COLOCAR o fim do comment aqui quando quiser rodar a versao do windows/wireshark

void pcap_packet_header(uint32_t len) {
  uint32_t ts_sec  = 0, ts_usec = 0;
  uint32_t incl_len = len, orig_len = len;

  Serial.write((uint8_t*)&ts_sec,   4);
  Serial.write((uint8_t*)&ts_usec,  4);
  Serial.write((uint8_t*)&incl_len, 4);
  Serial.write((uint8_t*)&orig_len, 4);
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint32_t len = pkt->rx_ctrl.sig_len;

  if (len == 0 || len > 2500) return;

  // envia tamanho (4 bytes) seguido dos dados
  Serial.write((uint8_t*)&len, 4);
  Serial.write(pkt->payload, len);
}

void setup() {
  Serial.begin(BAUD_RATE);
  delay(200);

  nvs_flash_init();
  // se der erro de compilação, remova as duas linhas abaixo:
  esp_netif_init();
  esp_event_loop_create_default();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  esp_wifi_set_channel(CHANNEL, WIFI_SECOND_CHAN_NONE);

  //pcap_global_header();
}

void loop() {
  // tudo acontece no callback
}
*/

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"

#define CHANNEL 1        // ajuste para o canal do seu transmissor
#define BAUD_RATE 921600

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint32_t len = pkt->rx_ctrl.sig_len;

  if (len == 0 || len > 2500) return;

  // envia tamanho (4 bytes) + payload
  Serial.write((uint8_t*)&len, 4);
  Serial.write(pkt->payload, len);
}

void setup() {
  Serial.begin(BAUD_RATE);
  delay(200);

  nvs_flash_init();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  esp_wifi_set_channel(CHANNEL, WIFI_SECOND_CHAN_NONE);
}

void loop() {
  // varre todos os canais a cada 200ms
  for (int ch = 1; ch <= 13; ch++) {
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    delay(200);
  }
}