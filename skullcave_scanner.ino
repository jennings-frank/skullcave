/*
 * ============================================================================
 * Project: Skullcave AirScanner Pro (ESP32 Wi-Fi Telemetry & Spectrum Analyzer)
 * Author: Frank Jennings
 *
 * MIT License
 *
 * Copyright (c) 2026 Frank Jennings
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ============================================================================
 *
 * OVERVIEW:
 * Skullcave AirScanner Pro is a handheld diagnostic tool and telemetry dashboard 
 * running on an ESP32 microcontroller. It combines passive 2.4 GHz RF promiscuous 
 * packet monitoring, active Wi-Fi environment auditing, an onboard SSD1306 OLED UI, 
 * and a standalone responsive web application served directly from an internal AP.
 *
 * KEY FEATURES:
 * 1. Multi-Page OLED Display Interface (10 Distinct Views):
 *    - Page 0: Strongest Detected Access Point summary.
 *    - Page 1: Scrollable list of nearby APs with RSSI indicators.
 *    - Page 2: In-depth AP Inspector (BSSID, OUI/Vendor, PMF, Ciphers, Distance).
 *    - Page 3: 2.4 GHz Channel Spectrum Congestion Bar Graph.
 *    - Page 4: Security Posture Audit (WPA3, WPA2, WEP, Open, WPS, TKIP stats).
 *    - Page 5: Local Hotspot status and connected client list.
 *    - Page 6: Live RF promiscuous frame rate sniffer and airtime chart.
 *    - Page 7: Monitored channel active transmitting station list.
 *    - Page 8: Client probe request leak monitor.
 *    - Page 9: Uplink router connection health and ping metrics.
 *
 * 2. Promiscuous RF Packet Sniffing:
 *    - Passive promiscuous frame analysis (Management, Control, Data).
 *    - Tracks deauthentication frame bursts, packet retries, and probe requests.
 *    - Extracts OUI vendor information and distinguishes randomized MACs.
 *
 * 3. Mobile-Responsive Web Portal:
 *    - Hosts a dark-mode web console with live JSON polling endpoints.
 *    - Allows channel switching, re-scanning, and initiating an internet uplink bridge.
 *
 * HARDWARE PIN CONNECTIONS (ESP32 DevKit V1):
 * - I2C OLED Display (SSD1306 128x64):
 *     - SDA: GPIO 21
 *     - SCL: GPIO 22
 * - Tactile Buttons (Active LOW with internal pull-ups):
 *     - BTN_UP:    GPIO 19 (Navigate up / Decrement channel)
 *     - BTN_NEXT:  GPIO 18 (Cycle screen pages / Long-press for display sleep)
 *     - BTN_DOWN:  GPIO 23 (Navigate down / Increment channel)
 *     - BTN_RESET: GPIO 5  (Instant interrupt/scan trigger connected to GND)
 * ============================================================================
 */

#include <WiFi.h>
#include <WebServer.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <esp_wifi.h>
#include <esp_random.h>
#include <esp_netif.h>
#include <lwip/inet.h>
#include <lwip/ip_addr.h>
#include <math.h>

// ----------------------------------------------------------------------------
// OLED Display Configuration
// ----------------------------------------------------------------------------
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1          // Reset shared with ESP32 reset line
#define SCREEN_ADDRESS 0x3C    // Standard I2C address for 0.96" SSD1306

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
WebServer server(80);

// ----------------------------------------------------------------------------
// Hotspot Credentials & Network State
// ----------------------------------------------------------------------------
const char* AP_SSID = "Skullcave";
char ap_password[9];           // 8-character randomly generated alphanumeric key + null

// ----------------------------------------------------------------------------
// Hardware Pin Assignments
// ----------------------------------------------------------------------------
const int BTN_UP    = 19;
const int BTN_NEXT  = 18;
const int BTN_DOWN  = 23;
const int BTN_RESET = 5;       // Instant re-scan trigger (D5 to GND)

// ----------------------------------------------------------------------------
// Display & Navigation State Tracking
// ----------------------------------------------------------------------------
int currentPage = 0;
const int TOTAL_PAGES = 10;
bool isDisplayPowered = true;

// Auto-sleep timer: turns off OLED after inactivity to prevent burn-in
const unsigned long DISPLAY_TIMEOUT_MS = 30000;
unsigned long lastActivityTime = 0;

// Pagination and list scrolling offsets
const int VISIBLE_ITEMS = 3;
const int AUDIT_VISIBLE_ITEMS = 4;
int wifiScrollOffset   = 0;
int inspectorIndex     = 0;
int selectedChannel    = 1;
int auditScrollOffset  = 0;
int clientScrollOffset = 0;
int probeScrollOffset  = 0;

// ----------------------------------------------------------------------------
// Tactile Button Debounce & Event Structure
// ----------------------------------------------------------------------------
enum ButtonEvent { NONE, SHORT_PRESS, LONG_PRESS };

struct SmartButton {
  int pin;
  int lastReading;
  int confirmedState;
  unsigned long pressStartTime;
  unsigned long lastDebounceTime;
  bool longPressTriggered;
};

SmartButton btnUp    = {BTN_UP,    HIGH, HIGH, 0, 0, false};
SmartButton btnNext  = {BTN_NEXT,  HIGH, HIGH, 0, 0, false};
SmartButton btnDown  = {BTN_DOWN,  HIGH, HIGH, 0, 0, false};
SmartButton btnReset = {BTN_RESET, HIGH, HIGH, 0, 0, false};

const unsigned long DEBOUNCE_DELAY = 35;     // 35 ms jitter rejection window
const unsigned long LONG_PRESS_TIME = 750;   // 750 ms threshold for long-press actions

// ----------------------------------------------------------------------------
// Telemetry Data Structures
// ----------------------------------------------------------------------------

// Audit record for scanned 802.11 Access Points
struct NetworkEntry {
  char ssid[33];
  char bssidStr[18];
  char vendor[10];
  char country[3];
  char pairwiseCipher[8];
  char groupCipher[8];
  int rssi;
  int channel;
  uint8_t encType;
  bool isEncrypted;
  bool isWps;
  bool isPmfRequired;
  char phyMode[10];
};

// Stations actively connected to the Skullcave SoftAP
struct ConnectedClient {
  char macStr[18];
  char ipStr[16];
  bool isRandomMac;
  int rssi;
};

// Leaked probe request frame captured via promiscuous mode
struct LeakedProbe {
  char ssid[33];
  char clientMac[18];
  int rssi;
  uint8_t channel;
  bool isRandomMac;
  unsigned long lastSeen;
};

// RF transmitter active on the monitored sniffer channel
struct SniffedDevice {
  char macStr[18];
  char vendor[10];
  int rssi;
  bool isRandomMac;
  unsigned long lastSeen;
};

// Fixed buffer bounds for embedded memory safety
const int MAX_NETWORKS = 40;
const int MAX_CLIENTS  = 8;
const int MAX_PROBES   = 32;
const int MAX_SNIFF_DEV = 16;

NetworkEntry wifiList[MAX_NETWORKS];
ConnectedClient clientList[MAX_CLIENTS];
LeakedProbe leakedProbes[MAX_PROBES];
SniffedDevice sniffedDevices[MAX_SNIFF_DEV];

int totalProbesCaptured = 0;
int totalSniffedDevs    = 0;

// Global environment scan aggregations
int totalWifiDetected = 0;
int totalClientsConnected = 0;
int openCount = 0;
int wepCount = 0;
int wpaCount = 0;
int wpa2Count = 0;
int wpa3Count = 0;
int enterpriseCount = 0;
int hiddenCount = 0;
int duplicateSsidCount = 0;
int wpsCount = 0;
int ht40Count = 0;
int tkipCount = 0;
int channelCounts[14] = {0};
unsigned long lastScanTimestamp = 0;

// Promiscuous Sniffer Counters (updated asynchronously from RX callback)
volatile uint32_t mgmtPacketCount = 0;
volatile uint32_t ctrlPacketCount = 0;
volatile uint32_t dataPacketCount = 0;
volatile uint32_t deauthFrameCount = 0;
volatile uint32_t probeReqCount = 0;
volatile uint32_t retryPacketCount = 0;

// Calculated live packets-per-second (PPS) rates
uint32_t liveMgmtPPS = 0;
uint32_t liveCtrlPPS = 0;
uint32_t liveDataPPS = 0;
uint32_t liveDeauthPPS = 0;
uint32_t liveProbePPS = 0;
uint32_t liveRetryPPS = 0;

unsigned long lastPpsTimestamp = 0;
uint8_t ppsHistory[32] = {0};       // Rolling sparkline buffer for OLED sniffer page
bool isSnifferActive = false;

// STA Uplink Bridge State
bool isUplinkConnected = false;
String uplinkSSID = "";
String uplinkStatusMsg = "Not Linked";
int uplinkPingMs = -1;
unsigned long lastPingTimestamp = 0;

const int AUDIT_TOTAL_LINES = 11;

// ----------------------------------------------------------------------------
// Helper Functions: Protocol Decoding & OUI Resolution
// ----------------------------------------------------------------------------

/**
 * Returns human-readable cipher string from ESP-IDF cipher enumeration.
 */
const char* getCipherName(wifi_cipher_type_t c) {
  switch (c) {
    case WIFI_CIPHER_TYPE_NONE: return "NONE";
    case WIFI_CIPHER_TYPE_WEP40: return "WEP40";
    case WIFI_CIPHER_TYPE_WEP104: return "WEP104";
    case WIFI_CIPHER_TYPE_TKIP: return "TKIP";
    case WIFI_CIPHER_TYPE_CCMP: return "CCMP";
    case WIFI_CIPHER_TYPE_TKIP_CCMP: return "TKIP/CC";
    case WIFI_CIPHER_TYPE_AES_CMAC128: return "CMAC128";
    case WIFI_CIPHER_TYPE_SMS4: return "SMS4";
    case WIFI_CIPHER_TYPE_GCMP: return "GCMP";
    case WIFI_CIPHER_TYPE_GCMP256: return "GCMP256";
    default: return "UNKNOWN";
  }
}

/**
 * Parses MAC address OUI (top 3 octets) to identify common hardware vendors
 * or flag locally administered / randomized MAC addresses.
 */
void getVendorFromOUI(const uint8_t* bssid, char* outVendor, size_t maxLen) {
  uint32_t oui = ((uint32_t)bssid[0] << 16) | ((uint32_t)bssid[1] << 8) | bssid[2];

  // Bit 1 of first byte = Locally Administered Address (Randomized MAC)
  if ((bssid[0] & 0x02) != 0) {
    snprintf(outVendor, maxLen, "Random");
    return;
  }

  switch (oui) {
    case 0x18FE34: case 0x240AC4: case 0x246F28: case 0x30AEA4:
    case 0x483FDA: case 0x840D8E: case 0xA4CF12: case 0xD8BFC0:
      snprintf(outVendor, maxLen, "Espressif"); break;
    case 0x001788: case 0x3C0630: case 0x48D705: case 0x7CD95C:
    case 0xACBC32: case 0xB8E856: case 0xDC2B61: case 0xF01898:
      snprintf(outVendor, maxLen, "Apple"); break;
    case 0x0007AB: case 0x002637: case 0x205531: case 0x5001D9:
    case 0x64B853: case 0x946372: case 0xCC07AB:
      snprintf(outVendor, maxLen, "Samsung"); break;
    case 0x000C41: case 0x14D64D: case 0x30B5C2: case 0xC04A00:
    case 0xEC172F: case 0xF4F26D:
      snprintf(outVendor, maxLen, "TP-Link"); break;
    case 0x00184D: case 0x28C68E: case 0x4494FC: case 0x841B5E:
    case 0x9C3DCF: case 0xE0469A:
      snprintf(outVendor, maxLen, "Netgear"); break;
    case 0x00000C: case 0x000142: case 0x001F6C: case 0x0CD996:
    case 0x5897BD: case 0x708105:
      snprintf(outVendor, maxLen, "Cisco"); break;
    case 0x000E8E: case 0x001422: case 0x001B77: case 0x0026C6:
      snprintf(outVendor, maxLen, "Intel"); break;
    case 0x001A2B: case 0x68D79A: case 0x788A20: case 0xB4E62D:
      snprintf(outVendor, maxLen, "Ubiquiti"); break;
    default:
      snprintf(outVendor, maxLen, "OUI:%02X%02X", bssid[0], bssid[1]); break;
  }
}

// ----------------------------------------------------------------------------
// Promiscuous RX Callback (Runs in High-Speed IRAM Context)
// ----------------------------------------------------------------------------
void IRAM_ATTR promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  int rx_len = pkt->rx_ctrl.sig_len;

  // Minimum 802.11 MAC header length is 24 bytes
  if (rx_len < 24) return;

  // Frame Control byte 2: Check retry bit (0x08)
  if (payload[1] & 0x08) {
    retryPacketCount++;
  }

  // Source Address (SA) begins at payload offset 10
  const uint8_t* sa = &payload[10];
  if (!(sa[0] == 0xFF && sa[1] == 0xFF)) { // Filter out broadcast source
    char srcMac[18];
    snprintf(srcMac, sizeof(srcMac), "%02X:%02X:%02X:%02X:%02X:%02X",
             sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);

    bool devExists = false;
    for (int i = 0; i < totalSniffedDevs; i++) {
      if (strcmp(sniffedDevices[i].macStr, srcMac) == 0) {
        sniffedDevices[i].rssi = pkt->rx_ctrl.rssi;
        sniffedDevices[i].lastSeen = millis();
        devExists = true;
        break;
      }
    }

    if (!devExists) {
      int insertIdx = totalSniffedDevs < MAX_SNIFF_DEV ? totalSniffedDevs : (totalSniffedDevs % MAX_SNIFF_DEV);
      strncpy(sniffedDevices[insertIdx].macStr, srcMac, 17);
      sniffedDevices[insertIdx].macStr[17] = '\0';
      sniffedDevices[insertIdx].rssi = pkt->rx_ctrl.rssi;
      sniffedDevices[insertIdx].isRandomMac = (sa[0] & 0x02) != 0;
      sniffedDevices[insertIdx].lastSeen = millis();
      getVendorFromOUI(sa, sniffedDevices[insertIdx].vendor, sizeof(sniffedDevices[insertIdx].vendor));
      if (totalSniffedDevs < MAX_SNIFF_DEV) totalSniffedDevs++;
    }
  }

  // Inspect 802.11 frame categories
  if (type == WIFI_PKT_MGMT) {
    mgmtPacketCount++;
    uint8_t subtype = (payload[0] >> 4) & 0x0F;

    // Subtypes 0x0C (Deauthentication) and 0x0A (Disassociation)
    if (subtype == 0x0C || subtype == 0x0A) {
      deauthFrameCount++;
    } else if (subtype == 0x04) {
      // Subtype 0x04: Probe Request Frame
      probeReqCount++;

      char targetSsid[33] = {0};
      if (rx_len > 25) {
        int pos = 24; // Start of tagged Information Elements (IE)
        uint8_t tagNum = payload[pos];
        uint8_t tagLen = payload[pos + 1];

        // Tag 0 represents requested SSID
        if (tagNum == 0 && (pos + 2 + tagLen <= rx_len)) {
          if (tagLen > 0 && tagLen <= 32) {
            memcpy(targetSsid, &payload[pos + 2], tagLen);
          } else {
            strncpy(targetSsid, "<Wildcard>", sizeof(targetSsid) - 1);
          }
        }
      }

      if (strlen(targetSsid) == 0) {
        strncpy(targetSsid, "<Wildcard>", sizeof(targetSsid) - 1);
      }

      char srcMac[18];
      snprintf(srcMac, sizeof(srcMac), "%02X:%02X:%02X:%02X:%02X:%02X",
               sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);

      bool exists = false;
      for (int i = 0; i < totalProbesCaptured; i++) {
        if (strcmp(leakedProbes[i].ssid, targetSsid) == 0 && strcmp(leakedProbes[i].clientMac, srcMac) == 0) {
          leakedProbes[i].rssi = pkt->rx_ctrl.rssi;
          leakedProbes[i].channel = pkt->rx_ctrl.channel;
          leakedProbes[i].lastSeen = millis();
          exists = true;
          break;
        }
      }

      if (!exists) {
        int idx = (totalProbesCaptured < MAX_PROBES) ? totalProbesCaptured : (totalProbesCaptured % MAX_PROBES);
        strncpy(leakedProbes[idx].ssid, targetSsid, 32);
        leakedProbes[idx].ssid[32] = '\0';
        strncpy(leakedProbes[idx].clientMac, srcMac, 17);
        leakedProbes[idx].clientMac[17] = '\0';
        leakedProbes[idx].rssi = pkt->rx_ctrl.rssi;
        leakedProbes[idx].channel = pkt->rx_ctrl.channel;
        leakedProbes[idx].isRandomMac = (sa[0] & 0x02) != 0;
        leakedProbes[idx].lastSeen = millis();
        if (totalProbesCaptured < MAX_PROBES) totalProbesCaptured++;
      }
    }
  } else if (type == WIFI_PKT_CTRL) {
    ctrlPacketCount++;
  } else if (type == WIFI_PKT_DATA) {
    dataPacketCount++;
  }
}

/**
 * Toggles ESP32 promiscuous reception on a given 2.4 GHz channel.
 */
void setSnifferMode(bool enable, uint8_t channel) {
  if (enable && !isSnifferActive) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_cb);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    isSnifferActive = true;
  } else if (enable && isSnifferActive) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  } else if (!enable && isSnifferActive) {
    esp_wifi_set_promiscuous(false);
    isSnifferActive = false;
  }
}

void setSnifferMode(bool enable) {
  setSnifferMode(enable, selectedChannel);
}

/**
 * Creates an unambiguous 8-character random password for the local AP.
 */
void generateRandomPassword() {
  const char charset[] = "23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ";
  const size_t charsetSize = sizeof(charset) - 1;
  for (int i = 0; i < 8; i++) {
    uint32_t r = esp_random();
    ap_password[i] = charset[r % charsetSize];
  }
  ap_password[8] = '\0';
}

/**
 * Queries the SoftAP station list to build telemetry for connected devices.
 */
void updateConnectedClients() {
  wifi_sta_list_t staList;
  totalClientsConnected = 0;
  if (esp_wifi_ap_get_sta_list(&staList) == ESP_OK) {
    totalClientsConnected = min((int)staList.num, MAX_CLIENTS);

    for (int i = 0; i < totalClientsConnected; i++) {
      snprintf(clientList[i].macStr, sizeof(clientList[i].macStr),
               "%02X:%02X:%02X:%02X:%02X:%02X",
               staList.sta[i].mac[0], staList.sta[i].mac[1],
               staList.sta[i].mac[2], staList.sta[i].mac[3],
               staList.sta[i].mac[4], staList.sta[i].mac[5]);
      clientList[i].rssi = staList.sta[i].rssi;
      clientList[i].isRandomMac = (staList.sta[i].mac[0] & 0x02) != 0;
      snprintf(clientList[i].ipStr, sizeof(clientList[i].ipStr), "192.168.4.%d", i + 2);
    }
  }
}

/**
 * Debounces mechanical switches and identifies SHORT vs LONG press events.
 */
ButtonEvent checkButton(SmartButton &btn) {
  int reading = digitalRead(btn.pin);
  ButtonEvent event = NONE;

  if (reading != btn.lastReading) btn.lastDebounceTime = millis();

  if ((millis() - btn.lastDebounceTime) > DEBOUNCE_DELAY) {
    if (reading != btn.confirmedState) {
      btn.confirmedState = reading;
      if (btn.confirmedState == LOW) {
        btn.pressStartTime = millis();
        btn.longPressTriggered = false;
      } else {
        if (!btn.longPressTriggered) event = SHORT_PRESS;
      }
    } else if (btn.confirmedState == LOW && !btn.longPressTriggered) {
      if ((millis() - btn.pressStartTime) > LONG_PRESS_TIME) {
        btn.longPressTriggered = true;
        event = LONG_PRESS;
      }
    }
  }
  btn.lastReading = reading;
  return event;
}

const char* getSignalLabel(int rssi) {
  if (rssi >= -60) return "Excellent";
  if (rssi >= -70) return "Good";
  if (rssi >= -80) return "Fair";
  return "Weak";
}

const char* getAuthName(uint8_t auth) {
  switch (auth) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA-PSK";
    case WIFI_AUTH_WPA2_PSK: return "WPA2-PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "802.1X";
    case WIFI_AUTH_WPA3_PSK: return "WPA3-SAE";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default: return "UNKNOWN";
  }
}

/**
 * Calculates rough Free Space Path Loss (FSPL) distance estimate.
 */
float estimateDistance(int rssi) {
  int txPower1m = -40; // Reference RSSI at 1 meter in dBm
  float ratio = (float)(txPower1m - rssi) / (10.0f * 2.4f); // 2.4 path-loss exponent
  return pow(10.0f, ratio);
}

/**
 * Draws a 5-bar cellular-style signal indicator on the OLED screen.
 */
void drawSignalBars(int x, int y, int rssi) {
  int filled = 0;
  if (rssi >= -55) filled = 5;
  else if (rssi >= -65) filled = 4;
  else if (rssi >= -75) filled = 3;
  else if (rssi >= -85) filled = 2;
  else if (rssi > -100) filled = 1;

  for (int i = 0; i < 5; i++) {
    int h = (i + 1) * 2 + 1;
    int bx = x + (i * 4);
    int by = y + (12 - h);
    if (i < filled) display.fillRect(bx, by, 3, h, SSD1306_WHITE);
    else display.drawRect(bx, by, 3, h, SSD1306_WHITE);
  }
}

/**
 * Renders a vertical scrollbar thumb indicating list progression.
 */
void drawScrollbar(int totalItems, int currentOffset, int visibleCount, int topY, int trackHeight) {
  if (totalItems <= visibleCount) return;
  display.drawFastVLine(126, topY, trackHeight, SSD1306_WHITE);
  int maxOffset = max(1, totalItems - visibleCount);
  int thumbHeight = max(4, (visibleCount * trackHeight) / totalItems);
  int thumbY = topY + ((currentOffset * (trackHeight - thumbHeight)) / maxOffset);
  display.fillRect(125, thumbY, 3, thumbHeight, SSD1306_WHITE);
}

/**
 * Initiates an active 2.4 GHz channel sweep and tallies security features.
 */
void performScan() {
  if (isDisplayPowered) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(16, 22);
    display.print("Scanning Airwaves...");
    display.drawRect(14, 38, 100, 6, SSD1306_WHITE);
    display.fillRect(16, 40, 50, 2, SSD1306_WHITE);
    display.display();
  }

  // Clear previous metrics
  totalWifiDetected = 0;
  openCount = 0;
  wepCount = 0;
  wpaCount = 0;
  wpa2Count = 0;
  wpa3Count = 0;
  enterpriseCount = 0;
  hiddenCount = 0;
  duplicateSsidCount = 0;
  wpsCount = 0;
  ht40Count = 0;
  tkipCount = 0;
  wifiScrollOffset = 0;
  inspectorIndex = 0;
  selectedChannel = 1;
  auditScrollOffset = 0;
  for (int i = 0; i < 14; i++) channelCounts[i] = 0;

  wifi_scan_config_t scan_config = {};
  scan_config.ssid = nullptr;
  scan_config.bssid = nullptr;
  scan_config.channel = 0;
  scan_config.show_hidden = true;
  scan_config.scan_type = WIFI_SCAN_TYPE_ACTIVE;
  scan_config.scan_time.active.min = 100;
  scan_config.scan_time.active.max = 300;

  esp_err_t err = esp_wifi_scan_start(&scan_config, true);
  if (err == ESP_OK) {
    uint16_t foundCount = 0;
    esp_wifi_scan_get_ap_num(&foundCount);

    if (foundCount > 0) {
      uint16_t limit = min((int)foundCount, MAX_NETWORKS);
      wifi_ap_record_t* ap_records = (wifi_ap_record_t*)malloc(sizeof(wifi_ap_record_t) * limit);

      if (ap_records && esp_wifi_scan_get_ap_records(&limit, ap_records) == ESP_OK) {
        totalWifiDetected = limit;

        for (int i = 0; i < limit; i++) {
          char rawName[33] = {0};
          memcpy(rawName, ap_records[i].ssid, min((size_t)32, strlen((char*)ap_records[i].ssid)));

          if (strlen(rawName) == 0) {
            strncpy(wifiList[i].ssid, "<Hidden>", sizeof(wifiList[i].ssid));
            hiddenCount++;
          } else {
            strncpy(wifiList[i].ssid, rawName, sizeof(wifiList[i].ssid) - 1);
            wifiList[i].ssid[sizeof(wifiList[i].ssid) - 1] = '\0';
          }

          snprintf(wifiList[i].bssidStr, sizeof(wifiList[i].bssidStr),
                   "%02X:%02X:%02X:%02X:%02X:%02X",
                   ap_records[i].bssid[0], ap_records[i].bssid[1],
                   ap_records[i].bssid[2], ap_records[i].bssid[3],
                   ap_records[i].bssid[4], ap_records[i].bssid[5]);

          getVendorFromOUI(ap_records[i].bssid, wifiList[i].vendor, sizeof(wifiList[i].vendor));

          if (strlen(ap_records[i].country.cc) > 0) {
            snprintf(wifiList[i].country, sizeof(wifiList[i].country), "%.2s", ap_records[i].country.cc);
          } else {
            strcpy(wifiList[i].country, "--");
          }

          strncpy(wifiList[i].pairwiseCipher, getCipherName(ap_records[i].pairwise_cipher), sizeof(wifiList[i].pairwiseCipher));
          strncpy(wifiList[i].groupCipher, getCipherName(ap_records[i].group_cipher), sizeof(wifiList[i].groupCipher));

          if (ap_records[i].pairwise_cipher == WIFI_CIPHER_TYPE_TKIP || ap_records[i].group_cipher == WIFI_CIPHER_TYPE_TKIP) {
            tkipCount++;
          }

          wifi_auth_mode_t auth = ap_records[i].authmode;
          wifiList[i].isPmfRequired = (auth == WIFI_AUTH_WPA3_PSK);
          wifiList[i].rssi = ap_records[i].rssi;
          int ch = ap_records[i].primary;
          wifiList[i].channel = ch;

          wifiList[i].encType = auth;
          wifiList[i].isEncrypted = (auth != WIFI_AUTH_OPEN);
          wifiList[i].isWps = ap_records[i].wps;
          if (wifiList[i].isWps) wpsCount++;

          bool is11n = ap_records[i].phy_11n;
          bool is11g = ap_records[i].phy_11g;
          bool isHT40 = (ap_records[i].second != WIFI_SECOND_CHAN_NONE);
          if (isHT40) ht40Count++;

          if (is11n) {
            snprintf(wifiList[i].phyMode, sizeof(wifiList[i].phyMode), "11n%s", isHT40 ? "/40" : "/20");
          } else if (is11g) {
            snprintf(wifiList[i].phyMode, sizeof(wifiList[i].phyMode), "11g/20");
          } else {
            snprintf(wifiList[i].phyMode, sizeof(wifiList[i].phyMode), "11b/20");
          }

          // Security categorization
          switch (auth) {
            case WIFI_AUTH_OPEN: openCount++; break;
            case WIFI_AUTH_WEP: wepCount++; break;
            case WIFI_AUTH_WPA_PSK: wpaCount++; break;
            case WIFI_AUTH_WPA2_PSK:
            case WIFI_AUTH_WPA_WPA2_PSK: wpa2Count++; break;
            case WIFI_AUTH_WPA2_ENTERPRISE: enterpriseCount++; break;
            case WIFI_AUTH_WPA3_PSK:
            case WIFI_AUTH_WPA2_WPA3_PSK: wpa3Count++; break;
            default: wpa2Count++; break;
          }

          if (ch >= 1 && ch <= 14) channelCounts[ch - 1]++;
        }
        free(ap_records);
      }

      // Check for duplicate SSIDs operating on disparate BSSIDs
      for (int i = 0; i < totalWifiDetected; i++) {
        if (strcmp(wifiList[i].ssid, "<Hidden>") == 0) continue;
        for (int j = i + 1; j < totalWifiDetected; j++) {
          if (strcmp(wifiList[i].ssid, wifiList[j].ssid) == 0) {
            duplicateSsidCount++;
            break;
          }
        }
      }
    }
  }

  lastScanTimestamp = millis();
}

/**
 * Standard UI frame: Header bar, page title, and bottom carousel indicator dots.
 */
void drawScaffolding(const char* title, int pageIndex) {
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.print(title);
  display.drawFastHLine(0, 9, 128, SSD1306_WHITE);

  display.drawFastHLine(0, 55, 128, SSD1306_WHITE);
  int startX = (128 - ((TOTAL_PAGES * 8) - 4)) / 2;
  for (int i = 0; i < TOTAL_PAGES; i++) {
    if (i == pageIndex) display.fillRoundRect(startX + (i * 8), 58, 6, 4, 1, SSD1306_WHITE);
    else display.drawCircle(startX + (i * 8) + 2, 59, 1, SSD1306_WHITE);
  }
}

// ----------------------------------------------------------------------------
// OLED Page Renderers
// ----------------------------------------------------------------------------

void renderPage0_BestWifi() {
  drawScaffolding("BEST WI-FI DETECTED", 0);
  if (totalWifiDetected == 0) {
    display.setCursor(0, 24);
    display.print("No Wi-Fi found.");
    return;
  }

  drawSignalBars(106, 12, wifiList[0].rssi);
  display.setCursor(0, 13);
  display.printf("SSID: %.10s", wifiList[0].ssid);
  display.setCursor(0, 24);
  display.printf("Sig : %s (%ddB)", getSignalLabel(wifiList[0].rssi), wifiList[0].rssi);
  display.setCursor(0, 35);
  display.printf("Ch  : %d | %s [%s]", wifiList[0].channel, wifiList[0].isEncrypted ? "Secured" : "OPEN", wifiList[0].country);
  display.setCursor(0, 45);
  display.printf("%.8s | %s", wifiList[0].vendor, wifiList[0].pairwiseCipher);
}

void renderPage1_WifiList() {
  char titleBuf[22];
  int upper = min(wifiScrollOffset + VISIBLE_ITEMS, totalWifiDetected);
  snprintf(titleBuf, sizeof(titleBuf), "LIST (%d-%d/%d)", wifiScrollOffset + 1, upper, totalWifiDetected);
  drawScaffolding(titleBuf, 1);

  if (totalWifiDetected == 0) {
    display.setCursor(0, 26);
    display.print("No Wi-Fi detected.");
    return;
  }

  for (int i = 0; i < VISIBLE_ITEMS; i++) {
    int idx = wifiScrollOffset + i;
    if (idx >= totalWifiDetected) break;

    int y = 13 + (i * 13);
    if (idx == 0) {
      display.fillRect(0, y, 16, 9, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
      display.setCursor(2, y + 1);
      display.print("#1");
      display.setTextColor(SSD1306_WHITE);
    } else {
      display.setCursor(0, y + 1);
      display.printf("#%-2d", idx + 1);
    }

    display.setCursor(19, y + 1);
    char buf[10];
    snprintf(buf, sizeof(buf), "%.9s", wifiList[idx].ssid);
    display.print(buf);

    display.setCursor(80, y + 1);
    display.printf("%3ddB", wifiList[idx].rssi);
    display.setCursor(114, y + 1);
    display.print(wifiList[idx].isEncrypted ? "#" : "o");
  }

  drawScrollbar(totalWifiDetected, wifiScrollOffset, VISIBLE_ITEMS, 13, 39);
}

void renderPage2_Inspector() {
  char header[24];
  snprintf(header, sizeof(header), "INSPECT (#%d/%d)", inspectorIndex + 1, totalWifiDetected);
  drawScaffolding(header, 2);

  if (totalWifiDetected == 0) {
    display.setCursor(0, 24);
    display.print("No APs detected.");
    return;
  }

  NetworkEntry &net = wifiList[inspectorIndex];
  float dist = estimateDistance(net.rssi);

  display.setCursor(0, 12);
  display.printf("AP:%-10.10s %.5s", net.ssid, net.vendor);

  display.setCursor(0, 23);
  display.printf("%s c%-2d", net.bssidStr, net.channel);

  const char* shortAuth = "UNK";
  switch (net.encType) {
    case WIFI_AUTH_OPEN:            shortAuth = "OPEN"; break;
    case WIFI_AUTH_WEP:             shortAuth = "WEP";  break;
    case WIFI_AUTH_WPA_PSK:         shortAuth = "WPA1"; break;
    case WIFI_AUTH_WPA2_PSK:        shortAuth = "WPA2"; break;
    case WIFI_AUTH_WPA_WPA2_PSK:    shortAuth = "W1/2"; break;
    case WIFI_AUTH_WPA2_ENTERPRISE: shortAuth = "802X"; break;
    case WIFI_AUTH_WPA3_PSK:        shortAuth = "WPA3"; break;
    case WIFI_AUTH_WPA2_WPA3_PSK:   shortAuth = "W2/3"; break;
  }
  display.setCursor(0, 34);
  display.printf("%-4s %-.6s/%-.6s", shortAuth, net.pairwiseCipher, net.groupCipher);

  display.setCursor(0, 45);
  display.printf("%-3s %-4s %3ddB ~%.0fm",
                 net.isWps ? "WPS" : "   ",
                 net.isPmfRequired ? "PMF" : "!PMF",
                 net.rssi,
                 dist);

  drawScrollbar(totalWifiDetected, inspectorIndex, 1, 12, 40);
}

void renderPage3_ChannelSpectrum() {
  char header[24];
  int countOnCh = channelCounts[selectedChannel - 1];
  snprintf(header, sizeof(header), "CH %d (%d APs)", selectedChannel, countOnCh);
  drawScaffolding(header, 3);

  int maxLoad = 1;
  for (int i = 0; i < 13; i++) {
    if (channelCounts[i] > maxLoad) maxLoad = channelCounts[i];
  }

  // Draw 2.4 GHz channel occupancy bars
  for (int i = 0; i < 13; i++) {
    int barHeight = (channelCounts[i] * 8) / maxLoad;
    if (barHeight < 1) barHeight = 1;
    int bx = 4 + (i * 9);
    int by = 21 - barHeight;
    display.fillRect(bx, by, 6, barHeight, SSD1306_WHITE);
  }
  display.drawFastHLine(0, 22, 124, SSD1306_WHITE);

  if (selectedChannel >= 1 && selectedChannel <= 13) {
    int markerX = 4 + ((selectedChannel - 1) * 9) + 1;
    display.fillRect(markerX, 23, 4, 2, SSD1306_WHITE);
  }

  int found = 0;
  int yPos = 28;
  for (int i = 0; i < totalWifiDetected && found < 2; i++) {
    if (wifiList[i].channel == selectedChannel) {
      display.setCursor(0, yPos);
      display.printf("%.8s", wifiList[i].ssid);
      display.setCursor(56, yPos);
      display.printf("%s", wifiList[i].phyMode);
      display.setCursor(102, yPos);
      display.printf("%3d", wifiList[i].rssi);

      yPos += 13;
      found++;
    }
  }

  if (found == 0) {
    display.setCursor(0, 32);
    display.print("No active APs here.");
    if (selectedChannel == 1 || selectedChannel == 6 || selectedChannel == 11) {
      display.setCursor(0, 44);
      display.print("Status: Clean Non-Ov");
    }
  } else if (found == 1 && countOnCh == 1) {
    display.setCursor(0, 43);
    display.print("Solo AP / Low noise");
  }

  drawScrollbar(14, selectedChannel - 1, 1, 12, 40);
}

void renderPage4_SecurityAudit() {
  char header[22];
  snprintf(header, sizeof(header), "AUDIT (%d-%d/%d)", auditScrollOffset + 1, 
           min(auditScrollOffset + AUDIT_VISIBLE_ITEMS, AUDIT_TOTAL_LINES), AUDIT_TOTAL_LINES);
  drawScaffolding(header, 4);

  for (int i = 0; i < AUDIT_VISIBLE_ITEMS; i++) {
    int lineIdx = auditScrollOffset + i;
    int y = 12 + (i * 10);

    display.setCursor(0, y);
    switch (lineIdx) {
      case 0: display.printf("Total APs : %d", totalWifiDetected); break;
      case 1: display.printf("Open APs  : %d %s", openCount, openCount > 0 ? "[WARN]" : ""); break;
      case 2: display.printf("WPS Vuln  : %d %s", wpsCount, wpsCount > 0 ? "[REAVER]" : ""); break;
      case 3: display.printf("TKIP Vuln : %d %s", tkipCount, tkipCount > 0 ? "[WEAK]" : ""); break;
      case 4: display.printf("WEP/WPA1  : %d / %d", wepCount, wpaCount); break;
      case 5: display.printf("WPA2-PSK  : %d", wpa2Count); break;
      case 6: display.printf("WPA3/SAE  : %d", wpa3Count); break;
      case 7: display.printf("802.1X Ent: %d", enterpriseCount); break;
      case 8: display.printf("Wide HT40 : %d APs", ht40Count); break;
      case 9: display.printf("Hidden APs: %d", hiddenCount); break;
      case 10: display.printf("Twin SSIDs: %d %s", duplicateSsidCount, duplicateSsidCount > 0 ? "[ROGUE]" : ""); break;
    }
  }

  drawScrollbar(AUDIT_TOTAL_LINES, auditScrollOffset, AUDIT_VISIBLE_ITEMS, 12, 40);
}

void renderPage5_ConnectHelp() {
  updateConnectedClients();

  if (totalClientsConnected == 0) {
    drawScaffolding("HOTSPOT & CLIENTS", 5);
    display.setCursor(0, 12);
    display.printf("AP  : %s", AP_SSID);
    display.setCursor(0, 23);
    display.printf("Pass: %s", ap_password);
    display.setCursor(0, 34);
    display.printf("IP  : %s", WiFi.softAPIP().toString().c_str());
    display.setCursor(0, 45);
    display.printf("Uplink: %s", isUplinkConnected ? uplinkSSID.substring(0, 10).c_str() : "Offline");
    return;
  }

  char titleBuf[22];
  snprintf(titleBuf, sizeof(titleBuf), "CLIENTS (%d/%d)", clientScrollOffset + 1, totalClientsConnected);
  drawScaffolding(titleBuf, 5);

  for (int i = 0; i < 2; i++) {
    int idx = clientScrollOffset + i;
    if (idx >= totalClientsConnected) break;
    int y = 12 + (i * 21);

    display.setCursor(0, y);
    display.printf("#%d %s", idx + 1, clientList[idx].macStr);
    display.setCursor(0, y + 10);
    display.printf("IP:%.12s %s", clientList[idx].ipStr, clientList[idx].isRandomMac ? "[R-MAC]" : "[HW-MAC]");
  }

  drawScrollbar(totalClientsConnected, clientScrollOffset, 2, 12, 40);
}

void renderPage6_PacketSniffer() {
  char header[24];
  uint32_t totalPPS = liveMgmtPPS + liveCtrlPPS + liveDataPPS;
  snprintf(header, sizeof(header), "SNIFF CH%d PPS:%u", selectedChannel, totalPPS);
  drawScaffolding(header, 6);

  display.setCursor(0, 12);
  display.printf("M:%u/s (Deauth:%u)", liveMgmtPPS, liveDeauthPPS);

  display.setCursor(0, 22);
  display.printf("C:%u/s D:%u/s", liveCtrlPPS, liveDataPPS);

  display.setCursor(0, 32);
  display.printf("Devs on Ch: %d", totalSniffedDevs);

  display.drawFastHLine(0, 53, 124, SSD1306_WHITE);
  uint8_t peak = 1;
  for (int i = 0; i < 32; i++) {
    if (ppsHistory[i] > peak) peak = ppsHistory[i];
  }

  // Draw 32-sample PPS historical sparkline
  for (int i = 0; i < 32; i++) {
    int h = (ppsHistory[i] * 9) / peak;
    if (h < 1 && ppsHistory[i] > 0) h = 1;
    display.drawFastVLine(i * 3 + 10, 52 - h, h, SSD1306_WHITE);
  }
}

void renderPage7_SnifferAnalysis() {
  char header[24];
  snprintf(header, sizeof(header), "RF DEVS: CH%d (%d)", selectedChannel, totalSniffedDevs);
  drawScaffolding(header, 7);

  if (totalSniffedDevs == 0) {
    display.setCursor(0, 24);
    display.print("No transmitters on");
    display.setCursor(0, 36);
    display.printf("channel %d currently.", selectedChannel);
    return;
  }

  for (int i = 0; i < 2; i++) {
    int idx = i;
    if (idx >= totalSniffedDevs) break;
    int y = 13 + (i * 20);

    display.setCursor(0, y);
    display.printf("%-10.10s %s", sniffedDevices[idx].vendor, sniffedDevices[idx].isRandomMac ? "[R]" : "[H]");
    display.setCursor(0, y + 10);
    display.printf("%.8s.. %3ddB", sniffedDevices[idx].macStr + 9, sniffedDevices[idx].rssi);
  }

  drawScrollbar(totalSniffedDevs, 0, 2, 13, 38);
}

void renderPage8_ProbeLeakage() {
  char header[24];
  snprintf(header, sizeof(header), "PROBE HUNT (%d)", totalProbesCaptured);
  drawScaffolding(header, 8);

  if (totalProbesCaptured == 0) {
    display.setCursor(0, 24);
    display.print("Listening for client");
    display.setCursor(0, 36);
    display.print("probe hunting...");
    return;
  }

  for (int i = 0; i < 2; i++) {
    int idx = probeScrollOffset + i;
    if (idx >= totalProbesCaptured) break;
    int y = 13 + (i * 20);

    display.setCursor(0, y);
    display.printf(">%-10.10s c%-2d", leakedProbes[idx].ssid, leakedProbes[idx].channel);
    display.setCursor(0, y + 10);
    display.printf(" %.8s.. %3ddB", leakedProbes[idx].clientMac + 9, leakedProbes[idx].rssi);
  }

  drawScrollbar(totalProbesCaptured, probeScrollOffset, 2, 13, 38);
}

void renderPage9_BridgeHealth() {
  drawScaffolding("BRIDGE HEALTH", 9);

  if (!isUplinkConnected) {
    display.setCursor(0, 18);
    display.print("Bridge: OFFLINE");
    display.setCursor(0, 30);
    display.print("Use mobile UI tab 7");
    display.setCursor(0, 42);
    display.print("to link home router.");
    return;
  }

  display.setCursor(0, 12);
  display.printf("Router: %.14s", uplinkSSID.c_str());

  display.setCursor(0, 23);
  display.printf("STA RSSI: %ddB (%s)", WiFi.RSSI(), getSignalLabel(WiFi.RSSI()));

  display.setCursor(0, 34);
  display.printf("Gateway : %s", WiFi.gatewayIP().toString().c_str());

  display.setCursor(0, 45);
  if (uplinkPingMs >= 0) {
    display.printf("Ping 8.8.8.8: %d ms", uplinkPingMs);
  } else {
    display.print("Ping 8.8.8.8: Testing...");
  }
}

/**
 * Top-level screen coordinator: Dispatches to current page or puts OLED to sleep.
 */
void renderDisplay() {
  if (!isDisplayPowered) {
    display.clearDisplay();
    display.display();
    display.ssd1306_command(SSD1306_DISPLAYOFF);
    return;
  }

  display.ssd1306_command(SSD1306_DISPLAYON);
  display.clearDisplay();

  switch (currentPage) {
    case 0: renderPage0_BestWifi(); break;
    case 1: renderPage1_WifiList(); break;
    case 2: renderPage2_Inspector(); break;
    case 3: renderPage3_ChannelSpectrum(); break;
    case 4: renderPage4_SecurityAudit(); break;
    case 5: renderPage5_ConnectHelp(); break;
    case 6: renderPage6_PacketSniffer(); break;
    case 7: renderPage7_SnifferAnalysis(); break;
    case 8: renderPage8_ProbeLeakage(); break;
    case 9: renderPage9_BridgeHealth(); break;
  }

  display.display();
}

/**
 * Establishes a lightweight TCP connection to Google Public DNS to verify latency.
 */
void updateUplinkPing() {
  if (!isUplinkConnected) {
    uplinkPingMs = -1;
    return;
  }

  IPAddress dnsServer(8, 8, 8, 8);
  WiFiClient pingClient;
  
  unsigned long startPing = millis();
  if (pingClient.connect(dnsServer, 53, 600)) {
    uplinkPingMs = (int)(millis() - startPing);
    pingClient.stop();
  } else {
    uplinkPingMs = -1;
  }
}

// ----------------------------------------------------------------------------
// Embedded HTTP Handlers & Web Application
// ----------------------------------------------------------------------------

void handleRoot() {
  updateConnectedClients();

  String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                  "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                  "<title>Skullcave AirScanner Pro</title><style>"
                  "body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;margin:0;padding:12px}"
                  "header{display:flex;justify-content:space-between;align-items:center;padding-bottom:10px;border-bottom:1px solid #30363d}"
                  "h1{font-size:1.15rem;margin:0;color:#58a6ff}"
                  ".btn{background:#238636;color:#fff;border:none;padding:7px 14px;border-radius:6px;font-weight:600;cursor:pointer;text-decoration:none;font-size:0.85rem}"
                  ".btn-danger{background:#da3633}"
                  ".tabs{display:flex;gap:6px;overflow-x:auto;margin:12px 0 16px;padding-bottom:4px}"
                  ".tab-btn{background:#21262d;border:1px solid #30363d;color:#8b949e;padding:8px 12px;border-radius:6px;font-size:0.85rem;white-space:nowrap;cursor:pointer}"
                  ".tab-btn.active{background:#1f6feb;color:#fff;border-color:#58a6ff}"
                  ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;margin-bottom:12px}"
                  ".tab-content{display:none}.tab-content.active{display:block}"
                  "table{width:100%;border-collapse:collapse;font-size:0.82rem;margin-top:8px}"
                  "th,td{padding:8px 6px;text-align:left;border-bottom:1px solid #21262d}"
                  "th{color:#8b949e;font-size:0.75rem;text-transform:uppercase}"
                  ".badge{display:inline-block;padding:2px 5px;border-radius:4px;font-size:0.72rem;font-weight:bold}"
                  ".b-open{background:#da3633;color:#fff}.b-sec{background:#238636;color:#fff}.b-wps{background:#d29922;color:#000}.b-warn{background:#d29922;color:#000}"
                  ".meter{height:8px;background:#21262d;border-radius:4px;overflow:hidden}"
                  ".fill{height:100%;background:#3fb950}"
                  ".grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}"
                  ".stat-box{background:#21262d;padding:10px;border-radius:6px}"
                  ".stat-title{font-size:0.75rem;color:#8b949e}"
                  ".stat-val{font-size:1.1rem;font-weight:bold;margin-top:2px}"
                  "input,select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:8px 10px;border-radius:6px;width:100%;box-sizing:border-box;margin-top:6px;font-size:0.9rem}"
                  ".form-group{margin-bottom:12px}"
                  ".tag-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}"
                  ".ssid-tag{background:#21262d;border:1px solid #30363d;border-radius:4px;padding:3px 8px;font-size:0.75rem;display:inline-flex;align-items:center;gap:5px}"
                  ".ch-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;font-size:0.85rem}"
                  "</style></head><body>"
                  "<header><h1>Skullcave AirScanner Pro</h1><div><a class='btn' href='/rescan'>Re-Scan</a></div></header>"
                  "<div class='tabs'>"
                  "<button class='tab-btn active' onclick='showTab(0)'>Top AP</button>"
                  "<button class='tab-btn' onclick='showTab(1)'>Networks</button>"
                  "<button class='tab-btn' onclick='showTab(2)'>Inspector</button>"
                  "<button class='tab-btn' onclick='showTab(3)'>Spectrum</button>"
                  "<button class='tab-btn' onclick='showTab(4)'>Audit</button>"
                  "<button class='tab-btn' onclick='showTab(5)'>Sniffer</button>"
                  "<button class='tab-btn' onclick='showTab(6)'>Clients</button>"
                  "<button class='tab-btn' onclick='showTab(7)'>Bridge</button>"
                  "</div>");

  html += F("<div id='t0' class='tab-content active'>");
  if (totalWifiDetected > 0) {
    const char* secBadge0 = wifiList[0].isEncrypted ? "b-sec" : "b-open";
    html += "<div class='card'><h2>" + String(wifiList[0].ssid) + "</h2>";
    html += "<p><strong>Vendor & Country:</strong> " + String(wifiList[0].vendor) + " [CC: " + String(wifiList[0].country) + "]</p>";
    html += "<p><strong>Signal:</strong> " + String(wifiList[0].rssi) + " dBm (" + getSignalLabel(wifiList[0].rssi) + ")</p>";
    html += "<p><strong>MAC / BSSID:</strong> " + String(wifiList[0].bssidStr) + "</p>";
    html += "<p><strong>Channel & Standard:</strong> Ch " + String(wifiList[0].channel) + " (" + String(wifiList[0].phyMode) + ")</p>";
    html += "<p><strong>Ciphers:</strong> Pairwise: " + String(wifiList[0].pairwiseCipher) + " | Group: " + String(wifiList[0].groupCipher) + "</p>";
    html += "<p><strong>Security:</strong> <span class='badge " + String(secBadge0) + "'>" + String(getAuthName(wifiList[0].encType)) + "</span>";
    if (wifiList[0].isWps) html += F(" <span class='badge b-wps'>WPS-PIN</span>");
    if (wifiList[0].isPmfRequired) html += F(" <span class='badge b-sec'>802.11w PMF</span>");
    else html += F(" <span class='badge b-warn'>No PMF</span>");
    html += F("</p></div>");
  } else {
    html += F("<div class='card'>No Wi-Fi networks found.</div>");
  }
  html += F("</div>");

  html += F("<div id='t1' class='tab-content'><div class='card'><table>"
            "<tr><th>#</th><th>SSID</th><th>Vendor</th><th>CC</th><th>Ch</th><th>Ciphers</th><th>RSSI</th><th>Auth</th></tr>");
  for (int i = 0; i < totalWifiDetected; i++) {
    const char* encBadge = wifiList[i].isEncrypted ? "b-sec" : "b-open";
    html += "<tr><td>" + String(i + 1) + "</td>";
    html += "<td><strong>" + String(wifiList[i].ssid) + "</strong></td>";
    html += "<td>" + String(wifiList[i].vendor) + "</td>";
    html += "<td>" + String(wifiList[i].country) + "</td>";
    html += "<td>" + String(wifiList[i].channel) + "</td>";
    html += "<td>" + String(wifiList[i].pairwiseCipher) + "</td>";
    html += "<td>" + String(wifiList[i].rssi) + " dBm</td>";
    html += "<td><span class='badge " + String(encBadge) + "'>" + String(getAuthName(wifiList[i].encType)) + "</span></td></tr>";
  }
  html += F("</table></div></div>");

  html += F("<div id='t2' class='tab-content'>");
  for (int i = 0; i < totalWifiDetected; i++) {
    int freq = (wifiList[i].channel == 14) ? 2484 : 2407 + (wifiList[i].channel * 5);
    float dist = estimateDistance(wifiList[i].rssi);
    const char* pmfColor = wifiList[i].isPmfRequired ? "#3fb950" : "#d29922";
    const char* pmfText  = wifiList[i].isPmfRequired ? "ENFORCED" : "VULNERABLE (NONE)";

    html += "<div class='card'>";
    html += "<h3 style='margin:0 0 6px;color:#58a6ff'>#" + String(i + 1) + " " + String(wifiList[i].ssid) + " [" + String(wifiList[i].country) + "]</h3>";
    html += "<div style='font-family:monospace;font-size:0.85rem;color:#8b949e;margin-bottom:8px'>BSSID: " + String(wifiList[i].bssidStr) + " (" + String(wifiList[i].vendor) + ")</div>";
    html += "<div class='grid'>";
    html += "<div class='stat-box'><div class='stat-title'>CIPHER ENCRYPTION</div><div class='stat-val'>" + String(wifiList[i].pairwiseCipher) + "/" + String(wifiList[i].groupCipher) + "</div></div>";
    html += "<div class='stat-box'><div class='stat-title'>DISTANCE EST.</div><div class='stat-val'>~" + String(dist, 1) + " m</div></div>";
    html += "<div class='stat-box'><div class='stat-title'>802.11w PMF STATE</div><div class='stat-val' style='color:" + String(pmfColor) + ";'>" + String(pmfText) + "</div></div>";
    html += "<div class='stat-box'><div class='stat-title'>RSSI / FREQUENCY</div><div class='stat-val'>" + String(wifiList[i].rssi) + " dBm (" + String(freq) + "M)</div></div>";
    html += "</div></div>";
  }
  html += F("</div>");

  html += F("<div id='t3' class='tab-content'><div class='card'><h3>2.4 GHz Congestion & Channel Map</h3>");
  int maxLoad = 1;
  for (int i = 0; i < 14; i++) { if (channelCounts[i] > maxLoad) maxLoad = channelCounts[i]; }

  for (int ch = 1; ch <= 14; ch++) {
    int count = channelCounts[ch - 1];
    int pct = (count * 100) / maxLoad;
    const char* chColor = (count > 0) ? "#58a6ff" : "#8b949e";
    const char* apSuffix = (count == 1) ? "" : "s";

    html += "<div style='margin-bottom:14px;padding:8px 0;border-bottom:1px solid #21262d;'>";
    html += "<div class='ch-header'><strong>Channel " + String(ch) + "</strong>";
    html += "<span style='color:" + String(chColor) + ";font-weight:600;'>" + String(count) + " AP" + String(apSuffix) + "</span></div>";
    html += "<div class='meter'><div class='fill' style='width:" + String(pct) + "%'></div></div>";

    if (count > 0) {
      html += F("<div class='tag-list'>");
      for (int i = 0; i < totalWifiDetected; i++) {
        if (wifiList[i].channel == ch) {
          const char* chBadge = wifiList[i].isEncrypted ? "b-sec" : "b-open";
          const char* chEncTag = wifiList[i].isEncrypted ? "#" : "OPEN";

          html += "<span class='ssid-tag'><strong>" + String(wifiList[i].ssid) + "</strong> (" + String(wifiList[i].phyMode) + " | " + String(wifiList[i].rssi) + "dBm) ";
          html += "<span class='badge " + String(chBadge) + "'>" + String(chEncTag) + "</span></span>";
        }
      }
      html += F("</div>");
    } else {
      html += F("<div style='font-size:0.75rem;color:#8b949e;margin-top:4px;'>Clean / No active transmitters</div>");
    }
    html += "</div>";
  }
  html += F("</div></div>");

  html += F("<div id='t4' class='tab-content'><div class='card'><h3>RF Security & Recon Audit</h3><div class='grid'>");
  html += "<div class='stat-box'><div class='stat-title'>TOTAL DETECTED</div><div class='stat-val'>" + String(totalWifiDetected) + "</div></div>";
  html += "<div class='stat-box'><div class='stat-title'>OPEN / CAPTIVE</div><div class='stat-val' style='color:#da3633'>" + String(openCount) + "</div></div>";
  html += "<div class='stat-box'><div class='stat-title'>WEP / WPA1</div><div class='stat-val' style='color:#f0883e'>" + String(wepCount + wpaCount) + "</div></div>";
  html += "<div class='stat-box'><div class='stat-title'>WPA2-PSK</div><div class='stat-val'>" + String(wpa2Count) + "</div></div>";
  html += "<div class='stat-box'><div class='stat-title'>WPA3 / SAE</div><div class='stat-val' style='color:#8957e5'>" + String(wpa3Count) + "</div></div>";
  html += "<div class='stat-box'><div class='stat-title'>TWIN / ROGUE SSIDs</div><div class='stat-val' style='color:#da3633'>" + String(duplicateSsidCount) + "</div></div>";
  html += "<div class='stat-box'><div class='stat-title'>WPS EXPOSED</div><div class='stat-val' style='color:#d29922'>" + String(wpsCount) + "</div></div>";
  html += "<div class='stat-box'><div class='stat-title'>WEAK TKIP CIPHER</div><div class='stat-val' style='color:#da3633'>" + String(tkipCount) + "</div></div>";
  html += "</div></div></div>";

  html += F("<div id='t5' class='tab-content'><div class='card'>"
            "<div style='display:flex;justify-content:space-between;align-items:center;'>"
            "<h3 style='margin:0'>Live RF Sniffer & Airtime Diagnostics</h3>"
            "<div><label style='font-size:0.85rem;margin-right:6px;'>Tuned Channel:</label>"
            "<select id='sniffCh' onchange='changeSnifferChannel(this.value)' style='width:auto;padding:4px 8px;'>");
  for (int ch = 1; ch <= 14; ch++) {
    const char* selAttr = (ch == selectedChannel) ? " selected" : "";
    html += "<option value='" + String(ch) + "'" + String(selAttr) + ">Channel " + String(ch) + "</option>";
  }
  html += F("</select></div></div>"
            "<div class='grid' style='margin-top:12px;'>"
            "<div class='stat-box'><div class='stat-title'>AIRTIME LOAD (PPS)</div><div class='stat-val' id='sniffTotal' style='color:#58a6ff'>0 /s</div></div>"
            "<div class='stat-box'><div class='stat-title'>RETRY / LOSS RATIO</div><div class='stat-val' id='sniffRetry' style='color:#d29922'>0%</div></div>"
            "<div class='stat-box'><div class='stat-title'>MGMT FRAMES</div><div class='stat-val' id='sniffMgmt'>0 /s</div></div>"
            "<div class='stat-box'><div class='stat-title'>CONTROL (ACK/CTS)</div><div class='stat-val' id='sniffCtrl'>0 /s</div></div>"
            "<div class='stat-box'><div class='stat-title'>DATA FRAMES</div><div class='stat-val' id='sniffData'>0 /s</div></div>"
            "<div class='stat-box'><div class='stat-title'>DEAUTH / DISASSOC</div><div class='stat-val' id='sniffDeauth' style='color:#da3633'>0 /s</div></div>"
            "</div>"
            "<h4 style='margin:14px 0 6px;'>Active Devices Detected on Channel</h4>"
            "<div id='devList' style='font-family:monospace;font-size:0.82rem;background:#0d1117;padding:8px;border-radius:6px;border:1px solid #30363d;max-height:140px;overflow-y:auto;'>Listening for transmitting stations...</div>"
            "<h4 style='margin:16px 0 6px;'>Client Probe Requests (Directed & Wildcard)</h4>"
            "<div id='probeList' style='font-family:monospace;font-size:0.82rem;background:#0d1117;padding:8px;border-radius:6px;border:1px solid #30363d;max-height:160px;overflow-y:auto;'>Listening for client probe requests...</div>"
            "</div></div>");

  html += F("<div id='t6' class='tab-content'><div class='card'><h3>Connected Hotspot Clients</h3>");
  html += "<p><strong>Current AP Password:</strong> <code style='color:#3fb950;font-size:1.1rem;background:#21262d;padding:2px 6px;border-radius:4px;'>" + String(ap_password) + "</code></p>";
  if (totalClientsConnected > 0) {
    html += F("<table><tr><th>#</th><th>Client MAC</th><th>Assigned IP</th><th>MAC Privacy</th><th>RSSI</th></tr>");
    for (int i = 0; i < totalClientsConnected; i++) {
      const char* macBadge = clientList[i].isRandomMac ? "b-warn'>Randomized" : "b-sec'>Permanent HW";

      html += "<tr><td>" + String(i + 1) + "</td>";
      html += "<td style='font-family:monospace;'>" + String(clientList[i].macStr) + "</td>";
      html += "<td>" + String(clientList[i].ipStr) + "</td>";
      html += "<td><span class='badge " + String(macBadge) + "</span></td>";
      html += "<td>" + String(clientList[i].rssi) + " dBm</td></tr>";
    }
    html += F("</table>");
  } else {
    html += F("<p style='color:#8b949e'>No client devices currently attached to Skullcave.</p>");
  }
  html += F("</div></div>");

  html += F("<div id='t7' class='tab-content'><div class='card'><h3>Internet Uplink Bridge</h3>");
  html += "<p><strong>Status:</strong> " + uplinkStatusMsg + "</p>";
  if (isUplinkConnected) {
    html += "<p><strong>Connected To:</strong> " + uplinkSSID + " (IP: " + WiFi.localIP().toString() + ")</p>";
    html += "<p><strong>Gateway / Ping:</strong> " + WiFi.gatewayIP().toString() + " | " + (uplinkPingMs >= 0 ? String(uplinkPingMs) + " ms" : "Measuring...") + "</p>";
    html += F("<p style='color:#3fb950'>Bridge active. Uplink established with DNS forwarding.</p>");
    html += F("<form method='POST' action='/uplink-disconnect'><button class='btn btn-danger' type='submit'>Disconnect Uplink</button></form>");
  } else {
    html += F("<form method='POST' action='/uplink-connect'>"
              "<div class='form-group'><label>Select Target Network:</label><select name='target_ssid'>");
    for (int i = 0; i < totalWifiDetected; i++) {
      html += "<option value='" + String(wifiList[i].ssid) + "'>" + String(wifiList[i].ssid) + " (" + String(wifiList[i].phyMode) + " | " + String(wifiList[i].rssi) + " dBm)</option>";
    }
    html += F("</select></div>"
              "<div class='form-group'><label>Wi-Fi Password:</label><input type='password' name='target_pass' placeholder='Leave blank if OPEN'></div>"
              "<button class='btn' type='submit'>Link Network & Enable Internet</button></form>");
  }
  html += F("</div></div>");

  html += F("<script>"
            "function showTab(n){"
            "document.querySelectorAll('.tab-btn').forEach((b,i)=>b.classList.toggle('active',i===n));"
            "document.querySelectorAll('.tab-content').forEach((c,i)=>c.classList.toggle('active',i===n));"
            "}"
            "function changeSnifferChannel(ch){"
            "fetch('/api/sniffer-channel?ch='+ch,{method:'POST'}).then(()=>updateSnifferUI());"
            "}"
            "function updateSnifferUI(){"
            "fetch('/api/sniffer')"
            ".then(r=>r.json())"
            ".then(data=>{"
            "document.getElementById('sniffTotal').innerText=data.total+' /s';"
            "document.getElementById('sniffMgmt').innerText=data.mgmt+' /s';"
            "document.getElementById('sniffCtrl').innerText=data.ctrl+' /s';"
            "document.getElementById('sniffData').innerText=data.data+' /s';"
            "document.getElementById('sniffDeauth').innerText=data.deauth+' /s';"
            "document.getElementById('sniffRetry').innerText=data.retryPct+'% ('+data.retry+' /s)';"
            "if(data.devices && data.devices.length>0){"
            "let devHtml='';"
            "data.devices.forEach(d=>{"
            "devHtml+='<div style=\"padding:3px 0;border-bottom:1px solid #161b22;\">&bull; <strong style=\"color:#58a6ff;\">'+d.mac+'</strong> ('+d.vendor+') &mdash; '+d.rssi+' dBm '+(d.random?'<span class=\"badge b-warn\">Rand</span>':'<span class=\"badge b-sec\">HW</span>')+'</div>';"
            "});"
            "document.getElementById('devList').innerHTML=devHtml;"
            "} else {"
            "document.getElementById('devList').innerHTML='<span style=\"color:#8b949e;\">No transmitters actively seen on this channel</span>';"
            "}"
            "if(data.probes && data.probes.length>0){"
            "let html='';"
            "data.probes.forEach(p=>{"
            "let tag = (p.ssid==='<Wildcard>') ? '<em style=\"color:#8b949e;\">&lt;Wildcard Broadcast&gt;</em>' : '<strong style=\"color:#3fb950;\">'+p.ssid+'</strong>';"
            "html+='<div style=\"padding:3px 0;border-bottom:1px solid #161b22;\">&bull; '+tag+' &mdash; <code>'+p.mac+'</code> [Ch '+p.ch+'] ('+p.rssi+' dBm) '+(p.random?'[R]':'[HW]')+'</div>';"
            "});"
            "document.getElementById('probeList').innerHTML=html;"
            "} else {"
            "document.getElementById('probeList').innerHTML='<span style=\"color:#8b949e;\">No probe requests recorded yet</span>';"
            "}"
            "}).catch(()=>{});"
            "}"
            "setInterval(updateSnifferUI,1000);"
            "</script></body></html>");

  server.send(200, "text/html", html);
}

void handleRescan() {
  setSnifferMode(false);
  performScan();
  renderDisplay();
  server.sendHeader("Location", "/");
  server.send(303);
}

void handleApiScan() {
  String json = "{\"count\":" + String(totalWifiDetected) + ",\"networks\":[";
  for (int i = 0; i < totalWifiDetected; i++) {
    if (i > 0) json += ",";
    json += "{\"ssid\":\"" + String(wifiList[i].ssid) + "\",";
    json += "\"bssid\":\"" + String(wifiList[i].bssidStr) + "\",";
    json += "\"vendor\":\"" + String(wifiList[i].vendor) + "\",";
    json += "\"country\":\"" + String(wifiList[i].country) + "\",";
    json += "\"pairwise\":\"" + String(wifiList[i].pairwiseCipher) + "\",";
    json += "\"group\":\"" + String(wifiList[i].groupCipher) + "\",";
    json += "\"pmf\":" + String(wifiList[i].isPmfRequired ? "true" : "false") + ",";
    json += "\"phy\":\"" + String(wifiList[i].phyMode) + "\",";
    json += "\"rssi\":" + String(wifiList[i].rssi) + ",";
    json += "\"channel\":" + String(wifiList[i].channel) + ",";
    json += "\"wps\":" + String(wifiList[i].isWps ? "true" : "false") + ",";
    json += "\"encrypted\":" + String(wifiList[i].isEncrypted ? "true" : "false") + "}";
  }
  json += "]}";
  server.send(200, "application/json", json);
}

void handleApiSniffer() {
  if (!isSnifferActive) {
    setSnifferMode(true, selectedChannel);
  }

  uint32_t totalPPS = liveMgmtPPS + liveCtrlPPS + liveDataPPS;
  float contention = (float)liveCtrlPPS / (float)(liveDataPPS > 0 ? liveDataPPS : 1);
  float retryPct = (totalPPS > 0) ? ((float)liveRetryPPS * 100.0f / (float)totalPPS) : 0.0f;

  String diag = "Balanced Traffic";
  if (liveDeauthPPS > 10) diag = "Deauth Flood Detected";
  else if (retryPct > 35.0f && totalPPS > 30) diag = "High RF Collision / Retries";
  else if (totalPPS > 300) diag = "Heavy Airtime Load";
  else if (totalPPS < 15) diag = "Clean / Idle";

  String json = "{";
  json += "\"channel\":" + String(selectedChannel) + ",";
  json += "\"mgmt\":" + String(liveMgmtPPS) + ",";
  json += "\"ctrl\":" + String(liveCtrlPPS) + ",";
  json += "\"data\":" + String(liveDataPPS) + ",";
  json += "\"deauth\":" + String(liveDeauthPPS) + ",";
  json += "\"retry\":" + String(liveRetryPPS) + ",";
  json += "\"retryPct\":" + String(retryPct, 1) + ",";
  json += "\"total\":" + String(totalPPS) + ",";
  json += "\"contention\":" + String(contention, 2) + ",";
  json += "\"diagnosis\":\"" + diag + "\",";

  json += "\"devices\":[";
  for (int i = 0; i < totalSniffedDevs; i++) {
    if (i > 0) json += ",";
    json += "{\"mac\":\"" + String(sniffedDevices[i].macStr) + "\",";
    json += "\"vendor\":\"" + String(sniffedDevices[i].vendor) + "\",";
    json += "\"rssi\":" + String(sniffedDevices[i].rssi) + ",";
    json += "\"random\":" + String(sniffedDevices[i].isRandomMac ? "true" : "false") + "}";
  }
  json += "],";

  json += "\"probes\":[";
  for (int i = 0; i < totalProbesCaptured; i++) {
    if (i > 0) json += ",";
    json += "{\"ssid\":\"" + String(leakedProbes[i].ssid) + "\",";
    json += "\"mac\":\"" + String(leakedProbes[i].clientMac) + "\",";
    json += "\"ch\":" + String(leakedProbes[i].channel) + ",";
    json += "\"random\":" + String(leakedProbes[i].isRandomMac ? "true" : "false") + ",";
    json += "\"rssi\":" + String(leakedProbes[i].rssi) + "}";
  }
  json += "]}";

  server.send(200, "application/json", json);
}

void handleApiSnifferChannel() {
  if (server.hasArg("ch")) {
    int newCh = server.arg("ch").toInt();
    if (newCh >= 1 && newCh <= 14) {
      selectedChannel = newCh;
      totalSniffedDevs = 0;
      if (isSnifferActive) {
        esp_wifi_set_channel(selectedChannel, WIFI_SECOND_CHAN_NONE);
      }
    }
  }
  server.send(200, "text/plain", "OK");
}

void configureHotspotDNS() {
  esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (ap_netif != nullptr) {
    esp_netif_dns_info_t dns;
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    
    // Primary: Google DNS (8.8.8.8)
    dns.ip.u_addr.ip4.addr = ESP_IP4TOADDR(8, 8, 8, 8);
    esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns);

    // Backup: Cloudflare DNS (1.1.1.1)
    dns.ip.u_addr.ip4.addr = ESP_IP4TOADDR(1, 1, 1, 1);
    esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_BACKUP, &dns);
  }
}

/**
 * Associates with an external Wi-Fi router and activates LwIP NAT (NAPT).
 */
void handleUplinkConnect() {
  if (server.hasArg("target_ssid")) {
    uplinkSSID = server.arg("target_ssid");
    String pass = server.hasArg("target_pass") ? server.arg("target_pass") : "";

    uplinkStatusMsg = "Connecting to " + uplinkSSID + "...";

    // Match SoftAP operating channel to target STA channel
    int targetChannel = 1;
    for (int i = 0; i < totalWifiDetected; i++) {
      if (uplinkSSID == wifiList[i].ssid) {
        targetChannel = wifiList[i].channel;
        break;
      }
    }

    WiFi.softAP(AP_SSID, ap_password, targetChannel);
    WiFi.begin(uplinkSSID.c_str(), pass.c_str());

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && (millis() - start < 10000)) {
      delay(100);
    }

    if (WiFi.status() == WL_CONNECTED) {
      isUplinkConnected = true;
      uplinkStatusMsg = "Online (Bridged)";

      // Enable Network Address and Port Translation (NAPT)
      esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
      if (ap_netif != nullptr) esp_netif_napt_enable(ap_netif);

      configureHotspotDNS();
      updateUplinkPing();
    } else {
      isUplinkConnected = false;
      uplinkStatusMsg = "Connection Failed / Timeout";
      WiFi.disconnect(false);
    }
  }
  server.sendHeader("Location", "/");
  server.send(303);
}

void handleUplinkDisconnect() {
  esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (ap_netif != nullptr) esp_netif_napt_disable(ap_netif);

  WiFi.disconnect(false);
  isUplinkConnected = false;
  uplinkSSID = "";
  uplinkStatusMsg = "Disconnected";
  uplinkPingMs = -1;
  server.sendHeader("Location", "/");
  server.send(303);
}

// ----------------------------------------------------------------------------
// Arduino Core Setup
// ----------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);

  // Configure digital button inputs with internal pull-up resistors
  pinMode(BTN_UP,    INPUT_PULLUP);
  pinMode(BTN_NEXT,  INPUT_PULLUP);
  pinMode(BTN_DOWN,  INPUT_PULLUP);
  pinMode(BTN_RESET, INPUT_PULLUP);

  // Fast 400 kHz I2C bus initialization
  Wire.begin();
  Wire.setClock(400000);

  if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println("SSD1306 allocation failed!");
    for (;;);
  }

  // Display initial boot splash
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(16, 28);
  display.print("System Booting...");
  display.display();

  generateRandomPassword();

  // Dual-mode: SoftAP for user control UI, STA for optional internet bridge
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, ap_password);

  // Register WebServer routing endpoints
  server.on("/", handleRoot);
  server.on("/rescan", handleRescan);
  server.on("/api/scan", handleApiScan);
  server.on("/api/sniffer", handleApiSniffer);
  server.on("/api/sniffer-channel", HTTP_POST, handleApiSnifferChannel);
  server.on("/uplink-connect", HTTP_POST, handleUplinkConnect);
  server.on("/uplink-disconnect", HTTP_POST, handleUplinkDisconnect);
  server.begin();

  // Perform initial RF survey on startup
  performScan();
  currentPage = 0;
  isDisplayPowered = true;
  lastActivityTime = millis();
  renderDisplay();
}

// ----------------------------------------------------------------------------
// Main Loop Execution
// ----------------------------------------------------------------------------
void loop() {
  server.handleClient();

  // 1-Second Timer: Compute real-time PPS stats and shift sparkline buffer
  if (millis() - lastPpsTimestamp >= 1000) {
    lastPpsTimestamp = millis();

    liveMgmtPPS   = mgmtPacketCount;
    liveCtrlPPS   = ctrlPacketCount;
    liveDataPPS   = dataPacketCount;
    liveDeauthPPS = deauthFrameCount;
    liveProbePPS  = probeReqCount;
    liveRetryPPS  = retryPacketCount;

    // Reset asynchronous ISR accumulators
    mgmtPacketCount   = 0;
    ctrlPacketCount   = 0;
    dataPacketCount   = 0;
    deauthFrameCount  = 0;
    probeReqCount     = 0;
    retryPacketCount  = 0;

    for (int i = 0; i < 31; i++) {
      ppsHistory[i] = ppsHistory[i + 1];
    }
    uint32_t totalPPS = liveMgmtPPS + liveCtrlPPS + liveDataPPS;
    ppsHistory[31] = (uint8_t)min((uint32_t)255, totalPPS);

    // Auto-refresh sniffer and diagnostic pages while active
    if ((currentPage >= 6 && currentPage <= 8) && isDisplayPowered) {
      renderDisplay();
    }
  }

  // 10-Second Timer: Periodic internet link health checks
  if (isUplinkConnected && (millis() - lastPingTimestamp >= 10000)) {
    lastPingTimestamp = millis();
    updateUplinkPing();
    if (currentPage == 9 && isDisplayPowered) renderDisplay();
  }

  // Read button actions
  ButtonEvent evUp    = checkButton(btnUp);
  ButtonEvent evNext  = checkButton(btnNext);
  ButtonEvent evDown  = checkButton(btnDown);
  ButtonEvent evReset = checkButton(btnReset);

  // --------------------------------------------------------------------------
  // Instant Re-Scan Trigger (D5 / BTN_RESET)
  // Low-latency hardware trigger: instantly wakes screen and starts scan.
  // --------------------------------------------------------------------------
  if (digitalRead(BTN_RESET) == LOW || evReset != NONE) {
    if (!isDisplayPowered) {
      isDisplayPowered = true;
      display.ssd1306_command(SSD1306_DISPLAYON);
    }

    setSnifferMode(false);

    currentPage = 0;
    wifiScrollOffset = 0;
    inspectorIndex = 0;
    auditScrollOffset = 0;
    clientScrollOffset = 0;
    probeScrollOffset = 0;
    lastActivityTime = millis();

    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(16, 22);
    display.print("Scanning Airwaves...");
    display.drawRect(14, 38, 100, 6, SSD1306_WHITE);
    display.fillRect(16, 40, 50, 2, SSD1306_WHITE);
    display.display();

    performScan();
    renderDisplay();

    // Debounce wait until physical switch release
    while (digitalRead(BTN_RESET) == LOW) {
      delay(10);
    }
    btnReset.lastReading = HIGH;
    btnReset.confirmedState = HIGH;
    btnReset.longPressTriggered = false;
    return;
  }

  bool anyButtonPressed = (evUp != NONE || evNext != NONE || evDown != NONE);

  // Power management: Wake screen on button activity
  if (!isDisplayPowered) {
    if (anyButtonPressed) {
      isDisplayPowered = true;
      lastActivityTime = millis();
      renderDisplay();
    }
    return;
  }

  // Check display sleep timeout
  if (anyButtonPressed) {
    lastActivityTime = millis();
  } else if (millis() - lastActivityTime >= DISPLAY_TIMEOUT_MS) {
    isDisplayPowered = false;
    renderDisplay();
    return;
  }

  // Long-press BTN_NEXT: Manually enter display sleep mode
  if (evNext == LONG_PRESS) {
    setSnifferMode(false);
    isDisplayPowered = false;
    renderDisplay();
    return;
  }

  // Long-press BTN_UP on Page 0: Trigger re-scan
  if (evUp == LONG_PRESS && currentPage == 0) {
    setSnifferMode(false);
    performScan();
    renderDisplay();
    return;
  }

  // Fast navigation / jump with Long-press UP
  if (evUp == LONG_PRESS) {
    if (currentPage == 1) wifiScrollOffset = max(0, wifiScrollOffset - 5);
    else if (currentPage == 2) inspectorIndex = max(0, inspectorIndex - 5);
    else if (currentPage == 3) selectedChannel = max(1, selectedChannel - 3);
    else if (currentPage == 4) auditScrollOffset = max(0, auditScrollOffset - 3);
    else if (currentPage == 5) clientScrollOffset = max(0, clientScrollOffset - 2);
    else if (currentPage == 6 || currentPage == 7) {
      selectedChannel = max(1, selectedChannel - 1);
      totalSniffedDevs = 0;
      esp_wifi_set_channel(selectedChannel, WIFI_SECOND_CHAN_NONE);
    } else if (currentPage == 8) {
      probeScrollOffset = max(0, probeScrollOffset - 2);
    }
    renderDisplay();
    return;
  }

  // Fast navigation / jump with Long-press DOWN
  if (evDown == LONG_PRESS) {
    if (currentPage == 1) {
      int maxOff = max(0, totalWifiDetected - VISIBLE_ITEMS);
      wifiScrollOffset = min(maxOff, wifiScrollOffset + 5);
    } else if (currentPage == 2) {
      inspectorIndex = min(max(0, totalWifiDetected - 1), inspectorIndex + 5);
    } else if (currentPage == 3) {
      selectedChannel = min(14, selectedChannel + 3);
    } else if (currentPage == 4) {
      int maxOff = max(0, AUDIT_TOTAL_LINES - AUDIT_VISIBLE_ITEMS);
      auditScrollOffset = min(maxOff, auditScrollOffset + 3);
    } else if (currentPage == 5) {
      int maxOff = max(0, totalClientsConnected - 2);
      clientScrollOffset = min(maxOff, clientScrollOffset + 2);
    } else if (currentPage == 6 || currentPage == 7) {
      selectedChannel = min(14, selectedChannel + 1);
      totalSniffedDevs = 0;
      esp_wifi_set_channel(selectedChannel, WIFI_SECOND_CHAN_NONE);
    } else if (currentPage == 8) {
      int maxOff = max(0, totalProbesCaptured - 2);
      probeScrollOffset = min(maxOff, probeScrollOffset + 2);
    }
    renderDisplay();
    return;
  }

  // Short-press BTN_NEXT: Advance to next screen page
  if (evNext == SHORT_PRESS) {
    if (currentPage >= TOTAL_PAGES - 1) {
      currentPage = 0;
    } else {
      currentPage++;
    }

    // Activate promiscuous mode exclusively on sniffer and probe pages (6, 7, 8)
    setSnifferMode(currentPage == 6 || currentPage == 7 || currentPage == 8, selectedChannel);
    renderDisplay();
    return;
  }

  // Short-press BTN_UP: Scroll up or change parameter
  if (evUp == SHORT_PRESS) {
    if (currentPage == 1) {
      if (wifiScrollOffset > 0) wifiScrollOffset--;
      else currentPage = 0;
    } else if (currentPage == 2) {
      if (inspectorIndex > 0) inspectorIndex--;
      else currentPage = 1;
    } else if (currentPage == 3) {
      if (selectedChannel > 1) selectedChannel--;
      else currentPage = 2;
    } else if (currentPage == 4) {
      if (auditScrollOffset > 0) auditScrollOffset--;
      else currentPage = 3;
    } else if (currentPage == 5) {
      if (clientScrollOffset > 0) clientScrollOffset--;
      else currentPage = 4;
    } else if (currentPage == 6) {
      if (selectedChannel > 1) {
        selectedChannel--;
        totalSniffedDevs = 0;
        esp_wifi_set_channel(selectedChannel, WIFI_SECOND_CHAN_NONE);
      } else {
        setSnifferMode(false);
        currentPage = 5;
      }
    } else if (currentPage == 7) {
      currentPage = 6;
      setSnifferMode(true, selectedChannel);
    } else if (currentPage == 8) {
      if (probeScrollOffset > 0) probeScrollOffset--;
      else {
        currentPage = 7;
        setSnifferMode(true, selectedChannel);
      }
    } else if (currentPage == 9) {
      currentPage = 8;
      setSnifferMode(true, selectedChannel);
    } else {
      if (currentPage > 0) currentPage--;
    }
    renderDisplay();
    return;
  }

  // Short-press BTN_DOWN: Scroll down or change parameter
  if (evDown == SHORT_PRESS) {
    if (currentPage == 1) {
      int maxOff = max(0, totalWifiDetected - VISIBLE_ITEMS);
      if (wifiScrollOffset < maxOff) wifiScrollOffset++;
      else currentPage = 2;
    } else if (currentPage == 2) {
      if (inspectorIndex < totalWifiDetected - 1) inspectorIndex++;
      else currentPage = 3;
    } else if (currentPage == 3) {
      if (selectedChannel < 14) selectedChannel++;
      else currentPage = 4;
    } else if (currentPage == 4) {
      int maxOff = max(0, AUDIT_TOTAL_LINES - AUDIT_VISIBLE_ITEMS);
      if (auditScrollOffset < maxOff) auditScrollOffset++;
      else currentPage = 5;
    } else if (currentPage == 5) {
      int maxOff = max(0, totalClientsConnected - 2);
      if (clientScrollOffset < maxOff) clientScrollOffset++;
      else {
        currentPage = 6;
        setSnifferMode(true, selectedChannel);
      }
    } else if (currentPage == 6) {
      if (selectedChannel < 14) {
        selectedChannel++;
        totalSniffedDevs = 0;
        esp_wifi_set_channel(selectedChannel, WIFI_SECOND_CHAN_NONE);
      } else {
        currentPage = 7;
        setSnifferMode(true, selectedChannel);
      }
    } else if (currentPage == 7) {
      currentPage = 8;
      setSnifferMode(true, selectedChannel);
    } else if (currentPage == 8) {
      int maxOff = max(0, totalProbesCaptured - 2);
      if (probeScrollOffset < maxOff) probeScrollOffset++;
      else {
        setSnifferMode(false);
        currentPage = 9;
      }
    } else if (currentPage == 9) {
      currentPage = 0;
    } else {
      if (currentPage < TOTAL_PAGES - 1) currentPage++;
      else currentPage = 0;
    }
    renderDisplay();
    return;
  }
}
