/*
  ESP32 Wi-Fi Defensive Scanner â€” Ultimate Feature Complete Sketch
  - SPI SSD1306 128x64 (7 pins)
  - Automatic scanning (2+ APs), sorted by RSSI (strongest first)
  - Smart loop: cycles networks, 4 timed views per network
  - EMA smoothing for RSSI, SSID scrolling
  - Overlapping-channel congestion metric (2.4GHz)
  - Composite defensive risk score (0-100) + textual category
  - Scan animation, CSV export (send 'c' + Enter), hardware Pause/Resume button
  - Defensive / educational only
*/

#include <WiFi.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <vector>
#include <algorithm>

using std::vector;

// ---------------- Hardware / Display ----------------
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_MOSI   23   // MOSI (Data)
#define OLED_CLK    18   // SCLK
#define OLED_DC     16   // DC
#define OLED_CS     5    // CS
#define OLED_RESET  17   // RST

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &SPI, OLED_DC, OLED_RESET, OLED_CS);

// ---------------- Timing / Config ----------------
const unsigned long SCAN_INTERVAL       = 15000UL; // ms between scans
const unsigned long VIEW_DURATION       = 5000UL;  // ms per view
const unsigned long SSID_SCROLL_INTERVAL= 350UL;   // ms scroll step
const unsigned long BUTTON_DEBOUNCE_MS  = 50UL;    // ms debounce

// ---------------- Button (pause/lock) ----------------
#define BUTTON_PIN 4         // momentary button to GND; internal pullup used
bool paused = false;          // paused flag
bool locked = false;          // if paused while viewing, stays on that AP
unsigned long lastButtonChange = 0;
int lastButtonState = HIGH;

// ---------------- State ----------------
unsigned long lastScanTime = 0;
unsigned long lastViewChangeTime = 0;
unsigned long lastSSIDScrollTime = 0;

int totalNetworks = 0;
int currentNetworkIndex = 0;
int currentViewIndex = 0;
int ssidScrollOffset = 0;

// EMA smoothing for RSSI
float emaRssi = 0.0f;
const float EMA_ALPHA = 0.35f;

// ---------------- Data structure for scans ----------------
struct ScanEntry {
  String ssid;
  int32_t rssi;
  int channel;
  wifi_auth_mode_t enc;
  int signalPercent;
  int riskScore;
};

vector<ScanEntry> lastScanResults;

// ---------------- Utility functions ----------------
int rssiToPercent(int32_t rssi) {
  if (rssi <= -100) return 0;
  if (rssi >= -50) return 100;
  return 2 * (rssi + 100);
}

int estimateSpeedMbps(int32_t rssi) {
  if (rssi >= -50) return 150;
  if (rssi >= -60) return 72;
  if (rssi >= -70) return 36;
  if (rssi >= -80) return 18;
  return 6;
}

String encryptionTypeToString(wifi_auth_mode_t encType) {
  switch (encType) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-E";
    default: return "UNK";
  }
}

int encryptionStrength(wifi_auth_mode_t encType) {
  switch (encType) {
    case WIFI_AUTH_OPEN: return 0;
    case WIFI_AUTH_WEP: return 12;
    case WIFI_AUTH_WPA_PSK: return 45;
    case WIFI_AUTH_WPA2_PSK: return 75;
    case WIFI_AUTH_WPA_WPA2_PSK: return 60;
    case WIFI_AUTH_WPA2_ENTERPRISE: return 90;
    default: return 50;
  }
}

bool isLikelyDefaultSSID(const String& ssid) {
  String s = ssid; s.toLowerCase();
  const char* kws[] = {"linksys","tplink","dlink","netgear","xfinity","att","vodafone",
                       "default","ap","huawei","zte","asus","comcast","android","ssid","guest"};
  for (size_t i=0;i<sizeof(kws)/sizeof(kws[0]);++i) if (s.indexOf(kws[i])>=0) return true;
  return false;
}

bool isHiddenSSID(const String& ssid) { return (ssid == "" || ssid == "<Hidden>"); }
bool is24GHz(int channel) { return (channel >= 1 && channel <= 14); }

float overlapWeight24(int a, int b) {
  int d = abs(a - b);
  if (d == 0) return 1.0f;
  if (d <= 2) return 0.66f;
  if (d <= 4) return 0.33f;
  return 0.0f;
}

float computeChannelCongestionMetric(int targetChannel) {
  if (totalNetworks <= 0) return 0.0f;
  float sum = 0.0f;
  for (int i = 0; i < totalNetworks; ++i) {
    int ch = WiFi.channel(i);
    if (is24GHz(targetChannel) && is24GHz(ch)) sum += overlapWeight24(targetChannel, ch);
    else if (ch == targetChannel) sum += 1.0f;
  }
  float norm = sum / (float)(totalNetworks > 0 ? totalNetworks : 1);
  if (norm > 1.0f) norm = 1.0f;
  return norm;
}

int computeRiskScoreDefensive(wifi_auth_mode_t encType, int signalPercent, int channel, const String& ssid) {
  const float W_ENC  = 0.45f;
  const float W_RSSI = 0.20f;
  const float W_CONG = 0.12f;
  const float W_SSID = 0.13f;
  const float W_BAND = 0.10f;

  float encStrength = encryptionStrength(encType) / 100.0f;
  float encRisk = 1.0f - encStrength;
  float rssiRisk = signalPercent / 100.0f;
  float congMetric = computeChannelCongestionMetric(channel);
  float congRisk = 1.0f - congMetric;
  float ssidRisk = isLikelyDefaultSSID(ssid) ? 1.0f : 0.0f;
  float hiddenPenalty = isHiddenSSID(ssid) ? 0.12f : 0.0f;
  float bandRisk = is24GHz(channel) ? 1.0f : 0.0f;

  float combined = (W_ENC * encRisk) + (W_RSSI * rssiRisk) + (W_CONG * congRisk) + (W_SSID * ssidRisk) + (W_BAND * bandRisk);
  combined += hiddenPenalty * 0.6f;

  int riskPct = (int)roundf(combined * 100.0f);
  riskPct = constrain(riskPct, 0, 100);
  return riskPct;
}

String riskCategory(int risk) {
  if (risk >= 80) return "VERY HIGH";
  if (risk >= 60) return "HIGH";
  if (risk >= 40) return "MEDIUM";
  if (risk >= 20) return "LOW";
  return "VERY LOW";
}

// ---------------- Display helpers ----------------
void displayHeader(const String& title) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(title);
  display.drawLine(0, 10, SCREEN_WIDTH, 10, SSD1306_WHITE);
}

void displayScanProgressFrame(int frame) {
  display.setCursor(96, 0);
  String dots = "";
  for (int i = 0; i < 4; ++i) dots += (i <= frame ? "." : " ");
  display.print(dots);
}

void displaySSIDScrolling(const String& ssid) {
  const int maxChars = 18;
  if (ssid.length() <= maxChars) {
    display.setCursor(0, 14);
    display.print("SSID: ");
    display.println(ssid);
    return;
  }
  unsigned long now = millis();
  if (now - lastSSIDScrollTime > SSID_SCROLL_INTERVAL) {
    lastSSIDScrollTime = now;
    ssidScrollOffset++;
    if (ssidScrollOffset > ssid.length()) ssidScrollOffset = 0;
  }
  String view = ssid.substring(ssidScrollOffset);
  if (view.length() < maxChars) view += "   " + ssid.substring(0, maxChars - view.length());
  display.setCursor(0, 14);
  display.print("SSID: ");
  display.println(view.substring(0, maxChars));
}

void drawRiskBar(int riskPct, int x, int y) {
  int filled = map(riskPct, 0, 100, 0, 10);
  display.setCursor(x, y);
  display.print("[");
  for (int i = 0; i < 10; ++i) display.print(i < filled ? "#" : "-");
  display.print("]");
}

// ---------------- CSV export ----------------
void serialExportCSV() {
  if (lastScanResults.empty()) {
    Serial.println("CSV_EXPORT: no scan data.");
    return;
  }
  Serial.println("CSV_EXPORT: ssid,rssi,channel,encryption,signalPct,riskScore");
  for (auto &e : lastScanResults) {
    String ss = e.ssid; ss.replace("\"", "'");
    Serial.printf("\"%s\",%d,%d,%s,%d,%d\n",
                  ss.c_str(), e.rssi, e.channel, encryptionTypeToString(e.enc).c_str(), e.signalPercent, e.riskScore);
  }
  Serial.println("CSV_EXPORT: done.");
}

// ---------------- Button handling ----------------
void handleButton() {
  int reading = digitalRead(BUTTON_PIN);
  if (reading != lastButtonState) {
    lastButtonChange = millis();
    lastButtonState = reading;
  }
  if ((millis() - lastButtonChange) > BUTTON_DEBOUNCE_MS) {
    // button pressed (to GND) => LOW
    static bool lastStableState = HIGH;
    if (reading != lastStableState) {
      lastStableState = reading;
      if (reading == LOW) { // pressed
        paused = !paused;
        // when pausing, lock current AP view so it doesn't advance (toggle)
        locked = paused ? true : locked;
        Serial.printf("Button pressed: paused=%d locked=%d\n", paused ? 1 : 0, locked ? 1 : 0);
      }
    }
  }
}

// ---------------- Setup / Loop ----------------
void setup() {
  Serial.begin(115200);
  delay(10);

  pinMode(BUTTON_PIN, INPUT_PULLUP);
  lastButtonState = digitalRead(BUTTON_PIN);

  if (!display.begin(SSD1306_SWITCHCAPVCC)) {
    Serial.println("OLED init failed!");
    while (1) delay(100);
  }

  displayHeader("ESP32 Wi-Fi Scanner");
  display.setCursor(0, 14);
  display.println("Defensive only");
  display.setCursor(0, 28);
  display.println("Btn G4: Pause/Lock");
  display.display();
  delay(1200);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);

  lastScanTime = millis() - SCAN_INTERVAL; // immediate first scan

  Serial.println("Starting ESP32 Wi-Fi Defensive Scanner (final).");
  Serial.println("Send 'c' + Enter to export CSV of last scan.");
  Serial.println("Button on GPIO4 toggles Pause/Lock.");
}

void loop() {
  unsigned long now = millis();

  // check serial commands
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.equalsIgnoreCase("c")) serialExportCSV();
  }

  // handle button (pause/resume)
  handleButton();

  // if paused but locked, do not advance networks/views (but still allow CSV)
  // trigger scan if not paused (we still can scan while paused if desired â€” keep scanning only when not paused)
  if (!paused) {
    if ((now - lastScanTime) >= SCAN_INTERVAL || totalNetworks == 0) {
      // small pre-scan animation
      unsigned long animStart = millis();
      int frame = 0;
      while (millis() - animStart < 400) {
        displayHeader("Wi-Fi Scanning...");
        displayScanProgressFrame(frame % 4);
        display.setCursor(0, 14);
        display.println("Please wait...");
        display.display();
        frame++; delay(100);
      }

      Serial.println("Starting Wi-Fi scan...");
      int found = WiFi.scanNetworks(false, true); // synchronous scan, includes hidden
      if (found <= 0) {
        Serial.println("No networks found.");
        totalNetworks = 0;
        lastScanResults.clear();
      } else {
        Serial.printf("Scan found %d networks.\n", found);
        totalNetworks = found;
        lastScanResults.clear();
        lastScanResults.reserve(totalNetworks);

        // Build lastScanResults array
        for (int i = 0; i < totalNetworks; ++i) {
          ScanEntry e;
          e.ssid = WiFi.SSID(i);
          if (e.ssid.length() == 0) e.ssid = "<Hidden>";
          e.rssi = WiFi.RSSI(i);
          e.channel = WiFi.channel(i);
          e.enc = WiFi.encryptionType(i);
          e.signalPercent = rssiToPercent(e.rssi);
          e.riskScore = computeRiskScoreDefensive(e.enc, e.signalPercent, e.channel, e.ssid);
          lastScanResults.push_back(e);
        }

        // sort by RSSI descending (strongest first)
        std::sort(lastScanResults.begin(), lastScanResults.end(), [](const ScanEntry &a, const ScanEntry &b){
          return a.rssi > b.rssi;
        });

        // update totalNetworks to match vector size (should be same)
        totalNetworks = (int)lastScanResults.size();
      }
      lastScanTime = now;
      // reset view indices if needed
      if (currentNetworkIndex >= totalNetworks) currentNetworkIndex = 0;
      if (currentNetworkIndex < 0) currentNetworkIndex = 0;
      // reset indexes
      lastViewChangeTime = now;
      ssidScrollOffset = 0;
      emaRssi = 0.0f;
    }
  } // end if not paused

  // Display current network if exists
  if (totalNetworks > 0 && currentNetworkIndex < totalNetworks) {
    // if we have lastScanResults, use them (sorted snapshot)
    ScanEntry e = lastScanResults[currentNetworkIndex];

    // update live RSSI via WiFi.RSSI(currentNetworkIndex) can be unreliable after sorting,
    // so we keep EMA based on the snapshot value (stable)
    if (emaRssi == 0.0f) emaRssi = (float)e.rssi;
    emaRssi = EMA_ALPHA * (float)e.rssi + (1.0f - EMA_ALPHA) * emaRssi;
    int sigSmoothed = rssiToPercent((int)roundf(emaRssi));
    int speedMbps = estimateSpeedMbps((int)roundf(emaRssi));
    int risk = computeRiskScoreDefensive(e.enc, sigSmoothed, e.channel, e.ssid);
    float congMetric = computeChannelCongestionMetric(e.channel);
    int congPercent = (int)roundf(congMetric * 100.0f);

    Serial.printf("DISPLAY %d/%d: %s | RSSI:%d (EMA %d) | CH:%d | ENC:%s | SIG:%d%% | CONG:%d%% | RISK:%d%%\n",
                  currentNetworkIndex + 1, totalNetworks,
                  e.ssid.c_str(), e.rssi, (int)roundf(emaRssi),
                  e.channel, encryptionTypeToString(e.enc).c_str(), sigSmoothed, congPercent, risk);

    // Render display once
    displayHeader("Wi-Fi Defensive Scanner");
    // show paused status
    display.setCursor(96, 0);
    display.setTextSize(1);
    display.print(paused ? "PAUSE" : "RUN");

    displaySSIDScrolling(e.ssid);

    display.setCursor(0, 28);
    display.print("Risk: ");
    display.print(risk);
    display.print("% ");
    display.setCursor(0, 36);
    drawRiskBar(risk, 0, 36);
    display.setCursor(78, 36);
    display.print(riskCategory(risk));

    // view details
    switch (currentViewIndex) {
      case 0:
        display.setCursor(0, 48);
        display.print("RSSI: ");
        display.print((int)roundf(emaRssi));
        display.print(" dBm (");
        display.print(sigSmoothed);
        display.println("%)");
        break;
      case 1:
        display.setCursor(0, 48);
        display.print("Ch: ");
        display.print(e.channel);
        display.print(" Cong: ");
        display.print(congPercent);
        display.println("%");
        display.setCursor(0, 56);
        display.print("Enc: ");
        display.print(encryptionTypeToString(e.enc));
        break;
      case 2:
        display.setCursor(0, 48);
        display.print("EstSpeed: ");
        display.print(speedMbps);
        display.println(" Mbps");
        display.setCursor(0, 56);
        display.print("Hidden: ");
        display.print(isHiddenSSID(e.ssid) ? "YES" : "NO");
        break;
      case 3:
        display.setCursor(0, 48);
        display.print("Default-SSID: ");
        display.print(isLikelyDefaultSSID(e.ssid) ? "YES" : "NO");
        display.setCursor(0, 56);
        display.print("Band: ");
        display.print(is24GHz(e.channel) ? "2.4GHz" : "5GHz");
        break;
    }

    display.display();

    // Advance view/network depending on pause/locked
    if (!paused) {
      if ((now - lastViewChangeTime) >= VIEW_DURATION) {
        lastViewChangeTime = now;
        currentViewIndex++;
        ssidScrollOffset = 0;
        if (currentViewIndex > 3) {
          currentViewIndex = 0;
          currentNetworkIndex++;
          emaRssi = 0.0f;
        }
        if (currentNetworkIndex >= totalNetworks) currentNetworkIndex = 0;
      }
    } else {
      // paused: if locked==true we keep currentNetworkIndex and currentViewIndex; if not locked, still do not advance
      // nothing to do
    }

  } else {
    // No networks found
    displayHeader("Wi-Fi Defensive Scanner");
    display.setCursor(0, 14);
    display.println("No networks found.");
    display.setCursor(0, 28);
    display.println("Next scan soon...");
    display.display();
  }

  // tiny delay to avoid tight loop CPU hog (still responsive)
  delay(10);
}