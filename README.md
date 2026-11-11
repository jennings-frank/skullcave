# Skullcave AirScanner Pro

An open-source, handheld 2.4 GHz Wi-Fi spectrum analyzer, packet telemetry monitor, and security audit tool built for the ESP32. Skullcave AirScanner Pro combines an onboard 0.96-inch SSD1306 OLED display with physical tactile navigation and an embedded, mobile-responsive web dashboard served directly over a local SoftAP.

---

## Overview

Skullcave AirScanner Pro provides real-time visibility into the local 2.4 GHz RF environment. It operates in dual Wi-Fi mode (`WIFI_AP_STA`), broadcasting an administrative portal (`Skullcave`) while simultaneously auditing active access points, sniffing promiscuous frames on tuned channels, and tracking probe request leaks.

### Core Capabilities

- **Active Network Reconnaissance**: Scans and parses up to 40 nearby BSSIDs, identifying SSIDs, signal strengths (RSSI), physical layer modes (802.11b/g/n, HT20/HT40), encryption protocols, pairwise/group ciphers, OUI hardware vendors, and 802.11w Protected Management Frames (PMF) enforcement.
- **Passive Promiscuous Sniffing**: Captures raw 802.11 packets directly from the radio stack without associating to a network. Monitors live Packets-Per-Second (PPS), categorizing Management, Control, Data, and Deauthentication/Disassociation frame bursts.
- **Probe Request Leak Tracker**: Detects unencrypted 802.11 Probe Request frames sent by searching client stations, logging targeted legacy SSIDs, source MACs, and randomized MAC identifiers.
- **RF Spectrum & Channel Congestion**: Generates channel occupancy distribution charts across 2.4 GHz channels (1–14) to locate non-overlapping, low-noise airtime windows.
- **Tactile Multi-Page OLED Interface**: 10 dedicated UI screens navigated via 4 debounced push buttons with fast-scroll, sleep-timeout, and instant-interrupt hardware re-scan support.
- **Standalone Dark-Mode Web Portal**: Embedded WebServer serving real-time telemetry, live JSON APIs, channel controls, and an optional NAT uplink bridge to external access points.

---

## Hardware Requirements

| Component | Specification | Quantity |
| :--- | :--- | :--- |
| **Microcontroller** | ESP32 Development Board (ESP-WROOM-32 / DevKit V1) | 1 |
| **Display** | 0.96-inch I2C Monochrome OLED (SSD1306, 128×64) | 1 |
| **Input Buttons** | Momentary Tactile Push Buttons (Normally Open) | 4 |
| **Prototyping** | Breadboard or Perfboard + Jumper Wires | 1 |
| **Power Supply** | Micro-USB / USB-C cable (5V / 1A) or 3.7V LiPo with regulator | 1 |

---

## Wiring & Pinout

### I2C OLED Display (SSD1306)

| OLED Pin | ESP32 GPIO | Description |
| :--- | :--- | :--- |
| **VCC** | 3V3 / 5V | Power Input |
| **GND** | GND | Ground |
| **SCL** | GPIO 22 | I2C Clock (Clock rate: 400 kHz) |
| **SDA** | GPIO 21 | I2C Data |

### Tactile Navigation Buttons

All push buttons connect between the designated GPIO pin and **GND**. The firmware enables internal pull-ups (`INPUT_PULLUP`), so no external pull-up resistors are required.

| Button | ESP32 GPIO | Functionality |
| :--- | :--- | :--- |
| **UP** | GPIO 19 | Scroll up / Decrement channel / Long-press for fast-jump or re-scan (Page 0) |
| **NEXT** | GPIO 18 | Advance page (0–9) / Long-press to toggle OLED sleep mode |
| **DOWN** | GPIO 23 | Scroll down / Increment channel / Long-press for fast-jump |
| **RESET / SCAN** | GPIO 5 | Instant hardware scan trigger (wakes display and initiates active sweep) |

---

## Dependencies & Software Setup

### Required Libraries

Install the following libraries via the Arduino IDE Library Manager (**Tools > Manage Libraries...**) or PlatformIO:

- **Adafruit SSD1306** (by Adafruit) — `v2.5.7` or higher
- **Adafruit GFX Library** (by Adafruit) — `v1.11.5` or higher

*Note: Core libraries (`WiFi`, `WebServer`, `Wire`, `esp_wifi`, `esp_netif`, `lwip`) are built into the official ESP32 Arduino Core.*

### Arduino IDE Configuration

1. Install the ESP32 board definitions via Board Manager:
   - Board URL: `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
2. Select your board: **Tools > Board > ESP32 Arduino > ESP32 Dev Module**.
3. Configure the following board settings:
   - **Upload Speed**: `921600` (or `115200` if upload fails)
   - **CPU Frequency**: `240MHz (WiFi/BT)`
   - **Flash Frequency**: `80MHz`
   - **Flash Mode**: `QIO`
   - **Flash Size**: `4MB (32Mb)`
   - **Partition Scheme**: `Default 4MB with spiffs (1.2MB APP/1.5MB SPIFFS)` or `Minimal SPIFFS (Large APPS with OTA)`
   - **Core Debug Level**: `None`
4. Connect the ESP32 via USB, select the correct COM port, and click **Upload**.

---

## Display Navigation & Pages

The OLED interface is organized into 10 sequential pages:

```
[Page 0] Best Wi-Fi  ──>  [Page 1] AP List     ──>  [Page 2] AP Inspector ──> [Page 3] Spectrum Map ──> [Page 4] Security Audit
     ▲                                                                                                          │
     │                                                                                                          ▼
[Page 9] Bridge Health <── [Page 8] Probe Hunt <──  [Page 7] RF Transmitters <── [Page 6] Packet Sniffer <── [Page 5] Hotspot Info
```

- **Page 0 — Best Wi-Fi**: Highlights the access point with the strongest RSSI, displaying signal bars, SSID, channel, encryption type, vendor, and cipher.
- **Page 1 — AP List**: Scrollable table of detected access points with live signal dBm and security flags.
- **Page 2 — AP Inspector**: In-depth inspection of individual APs showing MAC/BSSID, OUI-derived vendor, channel, ciphers, 802.11w PMF state, and distance approximation (in meters).
- **Page 3 — Channel Spectrum**: Visual bar chart showing AP distribution across channels 1 to 13.
- **Page 4 — Security Audit**: Aggregated security breakdown highlighting Open networks, WPS exposures, TKIP ciphers, WEP/WPA1 usage, and duplicate SSID anomalies.
- **Page 5 — Hotspot & Clients**: Displays the local SoftAP credentials, IP address, and an active list of connected stations with MAC privacy indicators (`[R-MAC]` vs `[HW-MAC]`).
- **Page 6 — Packet Sniffer**: Activates promiscuous mode on the tuned channel. Displays real-time Management, Control, Data, and Deauthentication frame rates alongside a rolling sparkline.
- **Page 7 — RF Devices**: Lists distinct client and AP hardware addresses transmitting on the currently tuned channel.
- **Page 8 — Probe Hunt**: Logs captured unencrypted probe requests sent by mobile devices searching for saved networks.
- **Page 9 — Bridge Health**: Displays upstream router association details, signal strength, gateway IP, and live ping response latency to `8.8.8.8`.

### Power Management

To protect the SSD1306 panel from burn-in, the display turns off automatically after **30 seconds** of inactivity. Pressing any navigation button wakes the display immediately. Pressing the dedicated hardware switch on **GPIO 5** triggers an instant wake and airwave re-scan.

---

## Web Interface & API Endpoints

Once booted, the device hosts an administrative Wi-Fi access point:

- **SSID**: `Skullcave`
- **Password**: Dynamically generated 8-character random key displayed on boot and visible on **Page 5** of the OLED.
- **Default IP**: `192.168.4.1`

Connect a computer or smartphone to `Skullcave` and navigate to `http://192.168.4.1` in any browser.

### HTTP Endpoints

| Route | Method | Description |
| :--- | :--- | :--- |
| `/` | `GET` | Main responsive multi-tab management console. |
| `/rescan` | `GET` | Stops sniffer mode, triggers a 2.4 GHz active sweep, and redirects to root. |
| `/api/scan` | `GET` | Returns full scan data for all detected APs in JSON format. |
| `/api/sniffer` | `GET` | Returns real-time sniffer telemetry (PPS, retries, deauth count, detected devices, probe leaks). |
| `/api/sniffer-channel` | `POST` | Switches the radio listening channel (query parameter: `?ch=1..14`). |
| `/uplink-connect` | `POST` | Bridges the device to an external Wi-Fi router and activates NAPT. |
| `/uplink-disconnect` | `POST` | Tears down the uplink association and disables NAPT. |

---

## License

This project is licensed under the MIT License. See the header in the source code file for full copyright and permission notices.
