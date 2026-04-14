/*
 * tickrmeter-crypto-com-exchange-portfolio.ino
 * Version 0.1
 *
 * MIT License
 * Copyright (c) 2026 Matt Smith
 * See LICENSE file for full terms.
 *
 * Hardware:
 *   MCU:     ESP32 (TickrMeter board)
 *   Display: Good Display GDEY029T94 2.9" BW e-ink, 296x128 px (SSD1680)
 *   LED:     Common-anode RGB LED (GPIO 21=blue/22=green/23=red)
 *
 * Features:
 *   - Web-based WiFi configuration portal (AP mode on first boot)
 *   - HTTPS admin panel (self-signed cert, port 443)
 *   - Fetches total portfolio value from Crypto.com Exchange every 60s
 *   - Sums USD cash + market value of all coin positions
 *   - Displays total on e-ink display with timestamp
 *   - LED color reflects minute-to-minute portfolio change (green=up/red=down/white=stable)
 *   - All settings persisted in NVS across reboots
 *
 * Required libraries (Arduino IDE -> Tools -> Manage Libraries):
 *   - Adafruit GFX Library  by Adafruit  (BSD license)
 *   - ArduinoJson           by Benoit Blanchon  (MIT license)
 *
 * Board: ESP32 Dev Module, Arduino ESP32 core 3.x
 */

#include <SPI.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Fonts/FreeSans9pt7b.h>
#include <Fonts/FreeSansBold18pt7b.h>
#include "SSD1680_EPD.h"
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <time.h>
#include <Preferences.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
#include <esp_wifi.h>
#include <esp_https_server.h>
#include <esp_http_server.h>
#include <Update.h>

// ===========================================================================
//  CONSTANTS
// ===========================================================================
#define FW_VERSION "0.1"
#define DEFAULT_HOSTNAME "tickrmeter-crypto-com"
#define DEFAULT_AP_SSID "tickrmeter-crypto-com"
#define DEFAULT_ADMIN_USER "admin"
#define NVS_NAMESPACE "tickrcfg"

// GPIO pins -- extracted from original TickrMeter firmware binary
#define LED_R 23
#define LED_G 22
#define LED_B 21
#define EPD_CS 15
#define EPD_DC 27
#define EPD_RST 26
#define EPD_BUSY 18
#define EPD_CLK 13
#define EPD_DIN 14
#define EPD_PWR 19

// Timezone: America/Chicago (CST/CDT with automatic DST)
#define TIMEZONE_POSIX "CST6CDT,M3.2.0,M11.1.0"
#define TIMEZONE_NAME "CT"

#define REFRESH_MS 60000UL

// ===========================================================================
//  RUNTIME SELF-SIGNED CERTIFICATE (EC P-256)
// ===========================================================================
// Dynamic buffers — populated by generateSelfSignedCert() or loaded from NVS
char tlsCertPem[1024];
char tlsKeyPem[512];

bool generateSelfSignedCert(const char* cn) {
  Serial.printf("[TLS] Generating self-signed cert for CN=%s...\n", cn);
  unsigned long t0 = millis();

  mbedtls_pk_context key;
  mbedtls_x509write_cert crt;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_pk_init(&key);
  mbedtls_x509write_crt_init(&crt);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  bool ok = false;
  int ret;

  // Seed RNG
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  if (ret != 0) {
    Serial.printf("[TLS] drbg_seed failed: -0x%04X\n", -ret);
    goto cleanup;
  }

  // Generate EC key pair (P-256)
  ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  if (ret != 0) {
    Serial.printf("[TLS] pk_setup failed: -0x%04X\n", -ret);
    goto cleanup;
  }
  ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                            mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.printf("[TLS] ecp_gen_key failed: -0x%04X\n", -ret);
    goto cleanup;
  }

  // Build subject/issuer string
  {
    char subject[128];
    snprintf(subject, sizeof(subject), "CN=%s", cn);

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);

    ret = mbedtls_x509write_crt_set_subject_name(&crt, subject);
    if (ret != 0) {
      Serial.printf("[TLS] set_subject failed: -0x%04X\n", -ret);
      goto cleanup;
    }
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, subject);
    if (ret != 0) {
      Serial.printf("[TLS] set_issuer failed: -0x%04X\n", -ret);
      goto cleanup;
    }

    // Serial number
    ret = mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char*)"\x01", 1);
    if (ret != 0) {
      Serial.printf("[TLS] set_serial failed: -0x%04X\n", -ret);
      goto cleanup;
    }

    // Validity: 2024-01-01 to 2034-01-01
    ret = mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20340101000000");
    if (ret != 0) {
      Serial.printf("[TLS] set_validity failed: -0x%04X\n", -ret);
      goto cleanup;
    }

    ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1);
    if (ret != 0) {
      Serial.printf("[TLS] set_constraints failed: -0x%04X\n", -ret);
      goto cleanup;
    }
  }

  // Write cert PEM
  ret = mbedtls_x509write_crt_pem(&crt, (unsigned char*)tlsCertPem, sizeof(tlsCertPem),
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.printf("[TLS] write_crt_pem failed: -0x%04X\n", -ret);
    goto cleanup;
  }

  // Write key PEM
  ret = mbedtls_pk_write_key_pem(&key, (unsigned char*)tlsKeyPem, sizeof(tlsKeyPem));
  if (ret != 0) {
    Serial.printf("[TLS] write_key_pem failed: -0x%04X\n", -ret);
    goto cleanup;
  }

  ok = true;
  Serial.printf("[TLS] Cert generated in %lums\n", millis() - t0);

cleanup:
  mbedtls_x509write_crt_free(&crt);
  mbedtls_pk_free(&key);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return ok;
}

// ===========================================================================
//  GLOBALS
// ===========================================================================
SSD1680_EPD display(EPD_CS, EPD_DC, EPD_RST, EPD_BUSY);
SPIClass hspi(HSPI);

Preferences prefs;
httpd_handle_t server_handle = NULL;
DNSServer dnsServer;

// Config from NVS
String cfg_wifi_ssid;
String cfg_wifi_pass;
String cfg_hostname;
String cfg_api_key;
String cfg_api_secret;
String cfg_admin_pass;
bool cfg_configured = false;

bool inSetupMode = false;
double currentBalance = 0.0;
double previousBalance = -1.0;  // -1.0 = no previous fetch yet
unsigned long lastRefreshMs = 0;

// Persistent TLS client — reuses session across fetch cycles
WiFiClientSecure tlsClient;

// Simple session token for auth
String sessionToken = "";

// Balance display status
String balanceStatusMsg = "";

// ===========================================================================
//  NVS CONFIG
// ===========================================================================

// Generate a 10-char random alphanumeric password
String generateRandomPassword() {
  const char charset[] = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
  char pwd[11];
  for (int i = 0; i < 10; i++) pwd[i] = charset[esp_random() % (sizeof(charset) - 1)];
  pwd[10] = 0;
  return String(pwd);
}

void loadConfig() {
  prefs.begin(NVS_NAMESPACE, true);
  cfg_configured = prefs.getBool("configured", false);
  cfg_wifi_ssid = prefs.getString("wifi_ssid", "");
  cfg_wifi_pass = prefs.getString("wifi_pass", "");
  cfg_hostname = prefs.getString("hostname", DEFAULT_HOSTNAME);
  cfg_api_key = prefs.getString("api_key", "");
  cfg_api_secret = prefs.getString("api_secret", "");
  cfg_admin_pass = prefs.getString("admin_pass", "");
  prefs.end();

  // Generate and save a random password on first boot
  if (cfg_admin_pass.isEmpty()) {
    cfg_admin_pass = generateRandomPassword();
    saveString("admin_pass", cfg_admin_pass);
    Serial.printf("[Config] Generated random password: %s\n", cfg_admin_pass.c_str());
  }
}

void saveString(const char* key, const String& value) {
  prefs.begin(NVS_NAMESPACE, false);
  prefs.putString(key, value);
  prefs.end();
}

void saveBool(const char* key, bool value) {
  prefs.begin(NVS_NAMESPACE, false);
  prefs.putBool(key, value);
  prefs.end();
}

// Load cert/key from NVS, or generate and save if missing/hostname changed
void loadOrGenerateCert() {
  prefs.begin(NVS_NAMESPACE, true);
  String savedHost = prefs.getString("tls_host", "");
  String savedCert = prefs.getString("tls_cert", "");
  String savedKey = prefs.getString("tls_key", "");
  prefs.end();

  if (savedHost == cfg_hostname && !savedCert.isEmpty() && !savedKey.isEmpty()) {
    strlcpy(tlsCertPem, savedCert.c_str(), sizeof(tlsCertPem));
    strlcpy(tlsKeyPem, savedKey.c_str(), sizeof(tlsKeyPem));
    Serial.printf("[TLS] Loaded cert from NVS (CN=%s)\n", cfg_hostname.c_str());
    return;
  }

  if (generateSelfSignedCert(cfg_hostname.c_str())) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.putString("tls_host", cfg_hostname);
    prefs.putString("tls_cert", String(tlsCertPem));
    prefs.putString("tls_key", String(tlsKeyPem));
    prefs.end();
    Serial.println("[TLS] Saved new cert to NVS");
  } else {
    Serial.println("[TLS] FAILED to generate cert!");
  }
}

// ===========================================================================
//  WIFI HELPERS
// ===========================================================================
String freqFromChannel(int ch) {
  if (ch >= 1 && ch <= 14) return "2.4 GHz";
  if (ch >= 36) return "5 GHz";
  return "Unknown";
}

String getConnectedWifiSpec() {
  wifi_phy_mode_t phymode;
  if (esp_wifi_sta_get_negotiated_phymode(&phymode) == ESP_OK) {
    switch (phymode) {
      case WIFI_PHY_MODE_HE20: return "WiFi 6 (HE20)";
      case WIFI_PHY_MODE_HT40: return "WiFi 4 (HT40)";
      case WIFI_PHY_MODE_HT20: return "WiFi 4 (HT20)";
      default: return "802.11b/g";
    }
  }
  return "N/A";
}

String getConnectedLinkSpeed() {
  wifi_phy_mode_t phymode;
  if (esp_wifi_sta_get_negotiated_phymode(&phymode) == ESP_OK) {
    switch (phymode) {
      case WIFI_PHY_MODE_HE20: return "143 Mbps";
      case WIFI_PHY_MODE_HT40: return "150 Mbps";
      case WIFI_PHY_MODE_HT20: return "72 Mbps";
      default: return "54 Mbps";
    }
  }
  return "N/A";
}

// ===========================================================================
//  HTTPD HELPERS
// ===========================================================================

// URL-decode a string
String urlDecode(const String& text) {
  String decoded;
  decoded.reserve(text.length());
  for (unsigned int i = 0; i < text.length(); i++) {
    char c = text[i];
    if (c == '+') {
      decoded += ' ';
    } else if (c == '%' && i + 2 < text.length()) {
      char h[3] = { text[i + 1], text[i + 2], 0 };
      decoded += (char)strtol(h, NULL, 16);
      i += 2;
    } else {
      decoded += c;
    }
  }
  return decoded;
}

// Parse URL-encoded POST body into key=value pairs
struct FormArg {
  String key;
  String value;
};
struct FormData {
  FormArg args[10];
  int count = 0;
  String get(const char* name) const {
    for (int i = 0; i < count; i++) {
      if (args[i].key == name) return args[i].value;
    }
    return "";
  }
  bool has(const char* name) const {
    for (int i = 0; i < count; i++) {
      if (args[i].key == name) return true;
    }
    return false;
  }
};

FormData _formData;  // global to avoid Arduino prototype issue

void parsePostBody(httpd_req_t* req) {
  _formData = FormData();
  int len = req->content_len;
  if (len <= 0 || len > 2048) return;
  char* buf = (char*)malloc(len + 1);
  if (!buf) return;
  int received = httpd_req_recv(req, buf, len);
  if (received <= 0) {
    free(buf);
    return;
  }
  buf[received] = 0;
  String body = String(buf);
  free(buf);

  int start = 0;
  while (start < (int)body.length() && _formData.count < 10) {
    int amp = body.indexOf('&', start);
    if (amp < 0) amp = body.length();
    String pair = body.substring(start, amp);
    int eq = pair.indexOf('=');
    if (eq > 0) {
      _formData.args[_formData.count].key = urlDecode(pair.substring(0, eq));
      _formData.args[_formData.count].value = urlDecode(pair.substring(eq + 1));
      _formData.count++;
    }
    start = amp + 1;
  }
}

// Get a request header value
String getHeader(httpd_req_t* req, const char* name) {
  size_t len = httpd_req_get_hdr_value_len(req, name);
  if (len == 0) return "";
  char* buf = (char*)malloc(len + 1);
  if (!buf) return "";
  httpd_req_get_hdr_value_str(req, name, buf, len + 1);
  String val(buf);
  free(buf);
  return val;
}

// Check if request has a valid session cookie
bool isRequestAuthenticated(httpd_req_t* req) {
  if (inSetupMode) return true;
  if (sessionToken.isEmpty()) return false;
  String cookie = getHeader(req, "Cookie");
  return cookie.indexOf("SESSION=" + sessionToken) >= 0;
}

// Send a complete response
esp_err_t sendResponse(httpd_req_t* req, int status, const char* type, const String& body) {
  char statusStr[16];
  snprintf(statusStr, sizeof(statusStr), "%d", status);
  httpd_resp_set_status(req, statusStr);
  httpd_resp_set_type(req, type);
  httpd_resp_send(req, body.c_str(), body.length());
  return ESP_OK;
}

// Send a redirect
esp_err_t sendRedirect(httpd_req_t* req, const char* url) {
  httpd_resp_set_status(req, "302");
  httpd_resp_set_hdr(req, "Location", url);
  httpd_resp_send(req, "", 0);
  return ESP_OK;
}

// Generate session token
String generateToken() {
  char buf[17];
  for (int i = 0; i < 16; i++) buf[i] = "0123456789abcdef"[esp_random() % 16];
  buf[16] = 0;
  return String(buf);
}

// ===========================================================================
//  HTML PAGES
// ===========================================================================

const char PAGE_SETUP[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Crypto.com Exchange Portfolio Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f1a;color:#e0e0e0;min-height:100vh}
.wrap{max-width:480px;margin:0 auto;padding:24px 16px}
.logo{text-align:center;padding:30px 0 10px}
.logo h1{font-size:28px;font-weight:700;background:linear-gradient(135deg,#6366f1,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo p{color:#666;font-size:13px;margin-top:4px}
.card{background:#1a1a2e;border:1px solid #2a2a40;border-radius:12px;padding:20px;margin:16px 0}
.card h2{font-size:15px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}
table{width:100%;border-collapse:collapse}
td,th{padding:10px 8px;text-align:left;font-size:14px}
th{color:#6366f1;font-weight:600;border-bottom:2px solid #2a2a40}
td{border-bottom:1px solid #1e1e35}
tr:hover td{background:#22223a;cursor:pointer}
.rssi{font-weight:600}
.rssi.good{color:#22c55e}.rssi.mid{color:#eab308}.rssi.weak{color:#ef4444}
label{display:block;font-size:13px;color:#888;margin:12px 0 4px}
input[type=text],input[type=password]{width:100%;padding:12px;background:#12121f;border:1px solid #2a2a40;color:#e0e0e0;border-radius:8px;font-size:15px;outline:none;transition:border .2s}
input:focus{border-color:#6366f1}
.btn{display:inline-block;background:linear-gradient(135deg,#6366f1,#7c3aed);color:#fff;border:none;padding:12px 28px;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:opacity .2s;width:100%}
.btn:hover{opacity:.9}
.btn-scan{background:linear-gradient(135deg,#374151,#4b5563);width:auto;padding:10px 20px;font-size:13px;margin-bottom:12px}
.msg{padding:12px;margin:12px 0;border-radius:8px;font-size:14px;display:none}
.msg.ok{background:#052e16;border:1px solid #22c55e;color:#22c55e;display:block}
.msg.err{background:#2a0a0a;border:1px solid #ef4444;color:#ef4444;display:block}
.chk-row{display:flex;align-items:center;gap:8px;margin:12px 0 4px}
.chk-row input[type=checkbox]{width:auto;accent-color:#6366f1}
.chk-row label{margin:0;cursor:pointer}
.api-fields{display:none;margin-top:4px}
.hint{color:#555;font-size:12px;margin-top:6px}
</style></head><body>
<div class="wrap">
<div class="logo"><h1>Crypto.com Exchange Portfolio</h1><p>WiFi Setup &middot; v%VERSION%</p></div>
<div class="card">
<h2>Available Networks</h2>
<button class="btn btn-scan" onclick="scan()">Scan for Networks</button>
<table id="nets"><tr><th>Network</th><th>Signal</th><th>Band</th></tr></table>
</div>
<div class="card">
<h2>Connect to WiFi</h2>
<form id="wf">
<label>SSID</label><input type="text" id="ssid" name="ssid" placeholder="Select from scan or type" required>
<label>Password</label><input type="password" id="pass" name="pass" placeholder="WiFi password">
<div style="height:16px"></div>
<div class="chk-row">
<input type="checkbox" id="hasApi" onchange="document.getElementById('apiFields').style.display=this.checked?'block':'none'">
<label for="hasApi">I have my Crypto.com API keys (optional)</label>
</div>
<div id="apiFields" class="api-fields">
<label>API Key</label><input type="text" id="apikey" placeholder="Crypto.com Exchange API Key">
<label>Secret Key</label><input type="password" id="apisec" placeholder="Crypto.com Exchange Secret Key">
</div>
<div style="height:16px"></div>
<button type="submit" class="btn">Save &amp; Reboot</button>
</form>
<div id="msg" class="msg"></div>
</div>
</div>
<script>
function rssiClass(r){return r>-50?'good':r>-70?'mid':'weak'}
function scan(){
  document.querySelector('.btn-scan').textContent='Scanning...';
  fetch('/api/scan').then(r=>r.json()).then(d=>{
    let t=document.getElementById('nets');
    t.innerHTML='<tr><th>Network</th><th>Signal</th><th>Band</th></tr>';
    d.sort((a,b)=>b.rssi-a.rssi);
    d.forEach(n=>{
      let r=document.createElement('tr');
      r.innerHTML='<td>'+n.ssid+(n.open?'':' &#128274;')+'</td><td class="rssi '+rssiClass(n.rssi)+'">'+n.rssi+' dBm</td><td>'+n.freq+'</td>';
      r.onclick=()=>{document.getElementById('ssid').value=n.ssid;document.getElementById('pass').focus()};
      t.appendChild(r);
    });
    document.querySelector('.btn-scan').textContent='Scan for Networks';
  }).catch(()=>{document.querySelector('.btn-scan').textContent='Scan Failed - Retry';});
}
document.getElementById('wf').onsubmit=function(e){
  e.preventDefault();
  let m=document.getElementById('msg');m.style.display='none';
  let body='ssid='+encodeURIComponent(document.getElementById('ssid').value)+'&pass='+encodeURIComponent(document.getElementById('pass').value);
  if(document.getElementById('hasApi').checked){
    body+='&apikey='+encodeURIComponent(document.getElementById('apikey').value)+'&apisec='+encodeURIComponent(document.getElementById('apisec').value);
  }
  fetch('/api/wifi-save',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body
  }).then(r=>r.json()).then(d=>{
    m.className='msg '+(d.success?'ok':'err');m.textContent=d.message;m.style.display='block';
  }).catch(()=>{m.className='msg err';m.textContent='Connection error';m.style.display='block';});
};
scan();
</script></body></html>
)rawliteral";

const char PAGE_LOGIN[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Crypto.com Exchange Portfolio Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f1a;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh}
.login{background:#1a1a2e;border:1px solid #2a2a40;padding:36px;border-radius:16px;width:340px}
.logo{text-align:center;margin-bottom:24px}
.logo h1{font-size:24px;background:linear-gradient(135deg,#6366f1,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo p{color:#666;font-size:12px;margin-top:4px}
label{display:block;font-size:13px;color:#888;margin:14px 0 4px}
input{width:100%;padding:12px;background:#12121f;border:1px solid #2a2a40;color:#e0e0e0;border-radius:8px;font-size:15px;outline:none;transition:border .2s}
input:focus{border-color:#6366f1}
button{width:100%;background:linear-gradient(135deg,#6366f1,#7c3aed);color:#fff;border:none;padding:13px;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;margin-top:20px;transition:opacity .2s}
button:hover{opacity:.9}
.err{color:#ef4444;text-align:center;margin-top:14px;font-size:14px}
</style></head><body>
<div class="login">
<div class="logo"><h1>Crypto.com Exchange Portfolio</h1><p>Admin Panel</p></div>
<form method="POST" action="/login">
<label>Username</label><input type="text" name="user" placeholder="admin" required>
<label>Password</label><input type="password" name="pass" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
%ERROR%
</div></body></html>
)rawliteral";

const char PAGE_ADMIN[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Crypto.com Exchange Portfolio Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f1a;color:#e0e0e0}
.wrap{max-width:780px;margin:0 auto;padding:16px}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #2a2a40;margin-bottom:16px}
.topbar h1{font-size:20px;background:linear-gradient(135deg,#6366f1,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.topbar-r{display:flex;align-items:center;gap:12px}
.ver{color:#555;font-size:12px}
.logout{color:#888;text-decoration:none;font-size:13px;padding:6px 12px;border:1px solid #333;border-radius:6px;transition:all .2s}
.logout:hover{color:#e0e0e0;border-color:#6366f1}
.tabs{display:flex;gap:4px;margin-bottom:0;overflow-x:auto;-webkit-overflow-scrolling:touch}
.tab{padding:10px 16px;background:transparent;border:none;color:#666;cursor:pointer;font-size:13px;font-weight:500;border-bottom:2px solid transparent;white-space:nowrap;transition:all .2s}
.tab:hover{color:#aaa}
.tab.active{color:#6366f1;border-bottom-color:#6366f1}
.panel{display:none;background:#1a1a2e;border:1px solid #2a2a40;border-radius:12px;padding:20px;margin-top:12px}
.panel.active{display:block}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{padding:10px 8px;text-align:left;font-size:14px}
th{color:#6366f1;font-weight:600;border-bottom:2px solid #2a2a40}
td{border-bottom:1px solid #1e1e35}
.info-table th{color:#888;font-weight:400;width:40%;border-bottom:1px solid #3a3a55}
.info-table td{color:#e0e0e0;width:60%;border-bottom:1px solid #3a3a55}
#scan-nets tr:hover td{background:#22223a;cursor:pointer}
.rssi{font-weight:600}
.rssi.good{color:#22c55e}.rssi.mid{color:#eab308}.rssi.weak{color:#ef4444}
label{display:block;font-size:13px;color:#888;margin:14px 0 4px}
input[type=text],input[type=password]{width:100%;padding:12px;background:#12121f;border:1px solid #2a2a40;color:#e0e0e0;border-radius:8px;font-size:14px;outline:none;transition:border .2s}
input:focus{border-color:#6366f1}
.btn{display:inline-block;background:linear-gradient(135deg,#6366f1,#7c3aed);color:#fff;border:none;padding:11px 24px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:opacity .2s;margin-top:12px}
.btn:hover{opacity:.9}
.btn-scan{background:linear-gradient(135deg,#374151,#4b5563);padding:9px 16px;font-size:13px;margin:0 0 12px}
.btn-danger{background:linear-gradient(135deg,#dc2626,#b91c1c)}
.hint{color:#555;font-size:12px;margin-top:6px}
.msg{padding:12px;margin:14px 0 0;border-radius:8px;font-size:14px;display:none}
.msg.ok{background:#052e16;border:1px solid #22c55e;color:#22c55e;display:block}
.msg.err{background:#2a0a0a;border:1px solid #ef4444;color:#ef4444;display:block}
</style></head><body>
<div class="wrap">
<div class="topbar">
<h1>Crypto.com Exchange Portfolio</h1>
<div class="topbar-r"><span class="ver">v%VERSION%</span><a href="/logout" class="logout">Sign Out</a></div>
</div>
<div class="tabs">
<button class="tab active" onclick="showTab('info',this)">Device Info</button>
<button class="tab" onclick="showTab('wifi',this)">WiFi</button>
<button class="tab" onclick="showTab('host',this)">Hostname</button>
<button class="tab" onclick="showTab('api',this)">API Keys</button>
<button class="tab" onclick="showTab('pw',this)">Password</button>
<button class="tab" onclick="showTab('upd',this)">Update</button>
<button class="tab" onclick="showTab('rst',this)">Reset</button>
</div>

<div id="info" class="panel active">
<table class="info-table">
<tr><th>Version</th><td id="i-ver">-</td></tr>
<tr><th>IP Address</th><td id="i-ip">-</td></tr>
<tr><th>Subnet Mask</th><td id="i-sub">-</td></tr>
<tr><th>Gateway</th><td id="i-gw">-</td></tr>
<tr><th>WiFi SSID</th><td id="i-ssid">-</td></tr>
<tr><th>Frequency</th><td id="i-freq">-</td></tr>
<tr><th>WiFi Spec</th><td id="i-spec">-</td></tr>
<tr><th>Link Speed</th><td id="i-speed">-</td></tr>
<tr><th>Signal</th><td id="i-rssi">-</td></tr>
<tr><th>Hostname</th><td id="i-host">-</td></tr>
<tr><th>Free Memory</th><td id="i-heap">-</td></tr>
</table>
</div>

<div id="wifi" class="panel">
<button class="btn btn-scan" onclick="scanNets()">Scan for Networks</button>
<table id="scan-nets"><tr><th>Network</th><th>Signal</th><th>Band</th></tr></table>
<label>SSID</label><input type="text" id="w-ssid">
<label>Password</label><input type="password" id="w-pass">
<button class="btn" onclick="saveWifi()">Save &amp; Reboot</button>
<div id="w-msg" class="msg"></div>
</div>

<div id="host" class="panel">
<label>Hostname</label><input type="text" id="h-name">
<p class="hint">Used as DHCP client name and mDNS address (hostname.local). Device will reboot after saving.</p>
<button class="btn" onclick="saveHost()">Save &amp; Reboot</button>
<div id="h-msg" class="msg"></div>
</div>

<div id="api" class="panel">
<label>API Key</label><input type="text" id="a-key" placeholder="Crypto.com Exchange API Key">
<label>Secret Key</label><input type="password" id="a-sec" placeholder="Crypto.com Exchange Secret Key">
<button class="btn" onclick="saveApi()">Save</button>
<div id="a-msg" class="msg"></div>
</div>

<div id="pw" class="panel">
<label>Current Password</label><input type="password" id="p-cur">
<label>New Password</label><input type="password" id="p-new" placeholder="Min 6 characters">
<label>Confirm New Password</label><input type="password" id="p-cfm">
<button class="btn" onclick="savePw()">Update Password</button>
<div id="p-msg" class="msg"></div>
</div>

<div id="upd" class="panel">
<p style="margin-bottom:8px;color:#888;font-size:14px">Current firmware: <strong>v%VERSION%</strong></p>
<label>Select firmware file (.bin)</label>
<input type="file" id="u-file" accept=".bin" style="padding:10px;background:#12121f;border:1px solid #2a2a40;border-radius:8px;color:#e0e0e0;width:100%">
<button class="btn" onclick="uploadFW()" style="margin-top:14px">Upload &amp; Install</button>
<div id="u-progress" style="display:none;margin-top:14px">
<div style="background:#2a2a40;border-radius:8px;height:24px;overflow:hidden">
<div id="u-bar" style="background:linear-gradient(135deg,#6366f1,#7c3aed);height:100%;width:0%;transition:width .3s;border-radius:8px"></div>
</div>
<p id="u-pct" style="text-align:center;margin-top:6px;font-size:13px;color:#888">0%</p>
</div>
<div id="u-msg" class="msg"></div>
</div>

<div id="rst" class="panel">
<div style="background:#2a0a0a;border:1px solid #dc2626;border-radius:8px;padding:16px;margin-bottom:16px">
<p style="color:#ef4444;font-weight:600;font-size:15px;margin-bottom:8px">&#9888; Factory Reset</p>
<p style="color:#ccc;font-size:13px;line-height:1.5">This will erase all settings including WiFi credentials, API keys, hostname, admin password, and TLS certificate. The device will reboot into setup mode.</p>
</div>
<button class="btn btn-danger" onclick="doReset()">Factory Reset</button>
<div id="r-msg" class="msg"></div>
</div>
</div>

<script>
function showTab(id,el){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  el.classList.add('active');
  if(id==='info')loadInfo();
  if(id==='wifi')scanNets();
}
function loadInfo(){
  fetch('/api/info').then(r=>r.json()).then(d=>{
    document.getElementById('i-ver').textContent=d.version;
    document.getElementById('i-ip').textContent=d.ip;
    document.getElementById('i-sub').textContent=d.subnet;
    document.getElementById('i-gw').textContent=d.gateway;
    document.getElementById('i-ssid').textContent=d.ssid;
    document.getElementById('i-freq').textContent=d.freq;
    document.getElementById('i-spec').textContent=d.wifiSpec;
    document.getElementById('i-speed').textContent=d.linkSpeed;
    document.getElementById('i-rssi').textContent=d.rssi+' dBm';
    document.getElementById('i-host').textContent=d.hostname;
    document.getElementById('i-heap').textContent=Math.round(d.freeHeap/1024)+' KB';
    document.getElementById('h-name').value=d.hostname;
    document.getElementById('a-key').value=d.apiKey||'';
    document.getElementById('a-sec').value=d.apiSecret?'********':'';
  });
}
function rssiClass(r){return r>-50?'good':r>-70?'mid':'weak'}
function scanNets(){
  document.querySelector('.btn-scan').textContent='Scanning...';
  fetch('/api/scan').then(r=>r.json()).then(d=>{
    let t=document.getElementById('scan-nets');
    t.innerHTML='<tr><th>Network</th><th>Signal</th><th>Band</th></tr>';
    d.sort((a,b)=>b.rssi-a.rssi);
    d.forEach(n=>{
      let r=document.createElement('tr');
      r.innerHTML='<td>'+n.ssid+(n.open?'':' &#128274;')+'</td><td class="rssi '+rssiClass(n.rssi)+'">'+n.rssi+' dBm</td><td>'+n.freq+'</td>';
      r.onclick=()=>{document.getElementById('w-ssid').value=n.ssid;document.getElementById('w-pass').focus()};
      t.appendChild(r);
    });
    document.querySelector('.btn-scan').textContent='Scan for Networks';
  });
}
function post(url,data,msgId){
  let m=document.getElementById(msgId);m.style.display='none';
  fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:data})
  .then(r=>r.json()).then(d=>{m.className='msg '+(d.success?'ok':'err');m.textContent=d.message;m.style.display='block';})
  .catch(()=>{m.className='msg err';m.textContent='Connection error';m.style.display='block';});
}
function saveWifi(){post('/api/wifi-save','ssid='+encodeURIComponent(document.getElementById('w-ssid').value)+'&pass='+encodeURIComponent(document.getElementById('w-pass').value),'w-msg');}
function saveHost(){post('/api/hostname-save','hostname='+encodeURIComponent(document.getElementById('h-name').value),'h-msg');}
function saveApi(){post('/api/apikeys-save','key='+encodeURIComponent(document.getElementById('a-key').value)+'&secret='+encodeURIComponent(document.getElementById('a-sec').value),'a-msg');}
function savePw(){
  let n=document.getElementById('p-new').value,c=document.getElementById('p-cfm').value;
  if(n!==c){let m=document.getElementById('p-msg');m.className='msg err';m.textContent='Passwords do not match';m.style.display='block';return;}
  post('/api/password-save','current='+encodeURIComponent(document.getElementById('p-cur').value)+'&new='+encodeURIComponent(n),'p-msg');
}
function uploadFW(){
  var f=document.getElementById('u-file').files[0];
  if(!f){var m=document.getElementById('u-msg');m.className='msg err';m.textContent='Select a .bin file first';m.style.display='block';return;}
  var m=document.getElementById('u-msg');m.style.display='none';
  document.getElementById('u-progress').style.display='block';
  var xhr=new XMLHttpRequest();
  xhr.open('POST','/api/firmware-upload',true);
  xhr.setRequestHeader('Content-Type','application/octet-stream');
  xhr.upload.onprogress=function(e){
    if(e.lengthComputable){var pct=Math.round(e.loaded/e.total*100);
      document.getElementById('u-bar').style.width=pct+'%';
      document.getElementById('u-pct').textContent=pct+'%';}
  };
  xhr.onload=function(){
    try{var d=JSON.parse(xhr.responseText);m.className='msg '+(d.success?'ok':'err');m.textContent=d.message;m.style.display='block';
      if(d.success){document.getElementById('u-pct').textContent='Rebooting...';setTimeout(function(){location.reload()},5000);}
    }catch(e){m.className='msg err';m.textContent='Unexpected response';m.style.display='block';}
  };
  xhr.onerror=function(){m.className='msg err';m.textContent='Upload failed — connection error';m.style.display='block';};
  xhr.send(f);
}
function doReset(){
  if(!confirm('Are you sure? This will erase ALL settings and reboot into setup mode.'))return;
  var m=document.getElementById('r-msg');m.style.display='none';
  fetch('/api/factory-reset',{method:'POST'})
  .then(function(r){return r.json()})
  .then(function(d){m.className='msg '+(d.success?'ok':'err');m.textContent=d.message;m.style.display='block';
    if(d.success)setTimeout(function(){location.reload()},5000);})
  .catch(function(){m.className='msg err';m.textContent='Connection error';m.style.display='block';});
}
loadInfo();
</script></body></html>
)rawliteral";

// ===========================================================================
//  HTTPD HANDLERS
// ===========================================================================

// --- Setup page (HTTP, AP mode) ---
esp_err_t h_setupPage(httpd_req_t* req) {
  String page = FPSTR(PAGE_SETUP);
  page.replace("%VERSION%", FW_VERSION);
  httpd_resp_set_type(req, "text/html");
  httpd_resp_send(req, page.c_str(), page.length());
  return ESP_OK;
}

// --- WiFi scan API ---
esp_err_t h_scanAPI(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) {
    return sendResponse(req, 401, "application/json", "{\"error\":\"auth\"}");
  }
  int n = WiFi.scanNetworks(false, false, false, 300);
  String json = "[";
  for (int i = 0; i < n; i++) {
    if (i > 0) json += ",";
    int ch = WiFi.channel(i);
    bool open = WiFi.encryptionType(i) == WIFI_AUTH_OPEN;
    json += "{\"ssid\":\"" + WiFi.SSID(i) + "\"";
    json += ",\"rssi\":" + String(WiFi.RSSI(i));
    json += ",\"channel\":" + String(ch);
    json += ",\"freq\":\"" + freqFromChannel(ch) + "\"";
    json += ",\"open\":" + String(open ? "true" : "false");
    json += "}";
  }
  json += "]";
  WiFi.scanDelete();
  return sendResponse(req, 200, "application/json", json);
}

// --- WiFi save (also saves optional API keys from setup) ---
esp_err_t h_wifiSave(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) {
    return sendResponse(req, 401, "application/json", "{\"error\":\"auth\"}");
  }
  parsePostBody(req);
  if (!_formData.has("ssid")) {
    return sendResponse(req, 400, "application/json", "{\"success\":false,\"message\":\"Missing SSID\"}");
  }
  saveString("wifi_ssid", _formData.get("ssid"));
  saveString("wifi_pass", _formData.get("pass"));
  saveBool("configured", true);
  // Save API keys if provided during setup
  String ak = _formData.get("apikey");
  String as = _formData.get("apisec");
  if (!ak.isEmpty()) saveString("api_key", ak);
  if (!as.isEmpty()) saveString("api_secret", as);
  sendResponse(req, 200, "application/json", "{\"success\":true,\"message\":\"WiFi saved. Rebooting...\"}");
  delay(1000);
  ESP.restart();
  return ESP_OK;
}

// --- Login page ---
esp_err_t h_loginPage(httpd_req_t* req) {
  String page = FPSTR(PAGE_LOGIN);
  page.replace("%ERROR%", "");
  httpd_resp_set_type(req, "text/html");
  httpd_resp_send(req, page.c_str(), page.length());
  return ESP_OK;
}

// --- Login POST ---
esp_err_t h_loginPost(httpd_req_t* req) {
  parsePostBody(req);
  String user = _formData.get("user");
  String pass = _formData.get("pass");
  if (user == DEFAULT_ADMIN_USER && pass == cfg_admin_pass) {
    sessionToken = generateToken();
    String cookie = "SESSION=" + sessionToken + "; Path=/; HttpOnly; Secure";
    httpd_resp_set_status(req, "302");
    httpd_resp_set_hdr(req, "Set-Cookie", cookie.c_str());
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, "", 0);
  } else {
    String page = FPSTR(PAGE_LOGIN);
    page.replace("%ERROR%", "<p class=\"err\">Invalid username or password</p>");
    httpd_resp_set_status(req, "401");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, page.c_str(), page.length());
  }
  return ESP_OK;
}

// --- Logout ---
esp_err_t h_logout(httpd_req_t* req) {
  sessionToken = "";
  httpd_resp_set_status(req, "302");
  httpd_resp_set_hdr(req, "Set-Cookie", "SESSION=; Path=/; Max-Age=0");
  httpd_resp_set_hdr(req, "Location", "/login");
  httpd_resp_send(req, "", 0);
  return ESP_OK;
}

// --- Admin page ---
esp_err_t h_adminPage(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) return sendRedirect(req, "/login");
  String page = FPSTR(PAGE_ADMIN);
  page.replace("%VERSION%", FW_VERSION);
  httpd_resp_set_type(req, "text/html");
  httpd_resp_send(req, page.c_str(), page.length());
  return ESP_OK;
}

// --- Device info API ---
esp_err_t h_infoAPI(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) {
    return sendResponse(req, 401, "application/json", "{\"error\":\"auth\"}");
  }
  String json = "{";
  json += "\"version\":\"" + String(FW_VERSION) + "\"";
  json += ",\"ip\":\"" + WiFi.localIP().toString() + "\"";
  json += ",\"subnet\":\"" + WiFi.subnetMask().toString() + "\"";
  json += ",\"gateway\":\"" + WiFi.gatewayIP().toString() + "\"";
  json += ",\"ssid\":\"" + WiFi.SSID() + "\"";
  json += ",\"rssi\":" + String(WiFi.RSSI());
  json += ",\"channel\":" + String(WiFi.channel());
  json += ",\"freq\":\"" + freqFromChannel(WiFi.channel()) + "\"";
  json += ",\"wifiSpec\":\"" + getConnectedWifiSpec() + "\"";
  json += ",\"linkSpeed\":\"" + getConnectedLinkSpeed() + "\"";
  json += ",\"hostname\":\"" + cfg_hostname + "\"";
  json += ",\"apiKey\":\"" + cfg_api_key + "\"";
  json += ",\"apiSecret\":" + String(cfg_api_secret.isEmpty() ? "\"\"" : "\"(set)\"");
  json += ",\"freeHeap\":" + String(ESP.getFreeHeap());
  json += "}";
  return sendResponse(req, 200, "application/json", json);
}

// --- Hostname save ---
esp_err_t h_hostnameSave(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) {
    return sendResponse(req, 401, "application/json", "{\"error\":\"auth\"}");
  }
  parsePostBody(req);
  String hostname = _formData.get("hostname");
  if (hostname.length() < 1 || hostname.length() > 32) {
    return sendResponse(req, 400, "application/json", "{\"success\":false,\"message\":\"Hostname must be 1-32 chars\"}");
  }
  cfg_hostname = hostname;
  saveString("hostname", hostname);
  sendResponse(req, 200, "application/json", "{\"success\":true,\"message\":\"Hostname saved. Rebooting...\"}");
  delay(1000);
  ESP.restart();
  return ESP_OK;
}

// --- API keys save ---
esp_err_t h_apiKeysSave(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) {
    return sendResponse(req, 401, "application/json", "{\"error\":\"auth\"}");
  }
  parsePostBody(req);
  String key = _formData.get("key");
  String secret = _formData.get("secret");
  cfg_api_key = key;
  saveString("api_key", key);
  if (secret != "********" && !secret.isEmpty()) {
    cfg_api_secret = secret;
    saveString("api_secret", secret);
  }
  return sendResponse(req, 200, "application/json", "{\"success\":true,\"message\":\"API keys saved\"}");
}

// --- Password save ---
esp_err_t h_passwordSave(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) {
    return sendResponse(req, 401, "application/json", "{\"error\":\"auth\"}");
  }
  parsePostBody(req);
  String current = _formData.get("current");
  String newPass = _formData.get("new");
  if (current != cfg_admin_pass) {
    return sendResponse(req, 403, "application/json", "{\"success\":false,\"message\":\"Current password incorrect\"}");
  }
  if (newPass.length() < 6) {
    return sendResponse(req, 400, "application/json", "{\"success\":false,\"message\":\"Min 6 characters\"}");
  }
  cfg_admin_pass = newPass;
  saveString("admin_pass", newPass);
  sessionToken = "";
  return sendResponse(req, 200, "application/json", "{\"success\":true,\"message\":\"Password changed. Please login again.\"}");
}

// --- Firmware upload (OTA) ---
esp_err_t h_firmwareUpload(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) {
    return sendResponse(req, 401, "application/json", "{\"error\":\"auth\"}");
  }
  int contentLen = req->content_len;
  if (contentLen <= 0) {
    return sendResponse(req, 400, "application/json",
                        "{\"success\":false,\"message\":\"No firmware data received\"}");
  }
  if (!Update.begin(contentLen)) {
    return sendResponse(req, 500, "application/json",
                        "{\"success\":false,\"message\":\"OTA begin failed -- not enough space?\"}");
  }
  const int BUF_SIZE = 4096;
  uint8_t* buf = (uint8_t*)malloc(BUF_SIZE);
  if (!buf) {
    Update.abort();
    return sendResponse(req, 500, "application/json",
                        "{\"success\":false,\"message\":\"Memory allocation failed\"}");
  }
  int remaining = contentLen;
  while (remaining > 0) {
    int toRead = (remaining < BUF_SIZE) ? remaining : BUF_SIZE;
    int received = httpd_req_recv(req, (char*)buf, toRead);
    if (received <= 0) {
      if (received == HTTPD_SOCK_ERR_TIMEOUT) continue;
      free(buf);
      Update.abort();
      return sendResponse(req, 500, "application/json",
                          "{\"success\":false,\"message\":\"Connection lost during upload\"}");
    }
    if (Update.write(buf, received) != (size_t)received) {
      free(buf);
      Update.abort();
      return sendResponse(req, 500, "application/json",
                          "{\"success\":false,\"message\":\"Flash write failed\"}");
    }
    remaining -= received;
  }
  free(buf);
  if (!Update.end(true)) {
    return sendResponse(req, 500, "application/json",
                        "{\"success\":false,\"message\":\"OTA finalize failed\"}");
  }
  sendResponse(req, 200, "application/json",
               "{\"success\":true,\"message\":\"Firmware updated. Rebooting...\"}");
  delay(3000);
  ESP.restart();
  return ESP_OK;
}

// --- Factory reset via web ---
esp_err_t h_factoryReset(httpd_req_t* req) {
  if (!isRequestAuthenticated(req)) {
    return sendResponse(req, 401, "application/json", "{\"error\":\"auth\"}");
  }
  sendResponse(req, 200, "application/json",
               "{\"success\":true,\"message\":\"Factory reset initiated. Rebooting...\"}");
  Serial.println("[Reset] Factory reset triggered via web!");
  setLED(60, 0, 0);
  prefs.begin(NVS_NAMESPACE, false);
  prefs.clear();
  prefs.end();
  display.setFullWindow();
  display.fillScreen(EPD_WHITE);
  display.setFont(&FreeSans9pt7b);
  display.setTextColor(EPD_BLACK);
  display.setCursor(4, 30);
  display.print("FACTORY RESET");
  display.setCursor(4, 55);
  display.print("All settings cleared.");
  display.setCursor(4, 80);
  display.print("Rebooting...");
  display.display(true);
  delay(3000);
  ESP.restart();
  return ESP_OK;
}

// --- Captive portal redirect ---
// Captive portal: redirect any unmatched URI to the setup page
esp_err_t h_captivePortal(httpd_req_t* req, httpd_err_code_t err) {
  char location[64];
  snprintf(location, sizeof(location), "http://%s/", WiFi.softAPIP().toString().c_str());
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", location);
  httpd_resp_send(req, "", 0);
  return ESP_OK;
}

// ===========================================================================
//  SERVER START HELPERS
// ===========================================================================

void registerURI(httpd_handle_t h, const char* uri, httpd_method_t method, esp_err_t (*handler)(httpd_req_t*)) {
  httpd_uri_t u = {};
  u.uri = uri;
  u.method = method;
  u.handler = handler;
  u.user_ctx = NULL;
  httpd_register_uri_handler(h, &u);
}

void startHTTPServer() {
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.server_port = 80;
  config.max_uri_handlers = 16;
  config.stack_size = 8192;
  if (httpd_start(&server_handle, &config) == ESP_OK) {
    Serial.printf("[Web] HTTP server started on port 80\n");
  } else {
    Serial.println("[Web] Failed to start HTTP server");
  }
}

void startHTTPSServer() {
  httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
  config.servercert = (const uint8_t*)tlsCertPem;
  config.servercert_len = strlen(tlsCertPem) + 1;
  config.prvtkey_pem = (const uint8_t*)tlsKeyPem;
  config.prvtkey_len = strlen(tlsKeyPem) + 1;
  config.httpd.max_uri_handlers = 16;
  config.httpd.stack_size = 16384;
  if (httpd_ssl_start(&server_handle, &config) == ESP_OK) {
    Serial.printf("[Web] HTTPS server started on port 443\n");
  } else {
    Serial.println("[Web] Failed to start HTTPS server — falling back to HTTP");
    startHTTPServer();
  }
}

// ===========================================================================
//  HMAC-SHA256
// ===========================================================================
String hmacSHA256(const String& key, const String& payload) {
  uint8_t raw[32];
  mbedtls_md_hmac(
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    (const uint8_t*)key.c_str(), key.length(),
    (const uint8_t*)payload.c_str(), payload.length(),
    raw);
  char hex[65];
  for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", raw[i]);
  return String(hex);
}

// ===========================================================================
//  CRYPTO.COM EXCHANGE API v1
// ===========================================================================
double fetchBalance() {
  if (cfg_api_key.isEmpty() || cfg_api_secret.isEmpty()) {
    Serial.println("[API] No API keys configured");
    return -1.0;
  }

  // Use global tlsClient — reuses TLS session across calls
  if (!tlsClient.connected()) {
    tlsClient.setInsecure();
    tlsClient.setTimeout(10);
  }

  // Single request: private/user-balance returns market_value per coin
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  long long nonce = (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
  char nonceStr[20];
  snprintf(nonceStr, sizeof(nonceStr), "%lld", nonce);

  const char* method = "private/user-balance";
  String sigPayload = String(method) + "1" + cfg_api_key + nonceStr;
  String sig = hmacSHA256(cfg_api_secret, sigPayload);

  char body[512];
  snprintf(body, sizeof(body),
    "{\"id\":1,\"method\":\"%s\",\"api_key\":\"%s\","
    "\"params\":{},\"nonce\":%s,\"sig\":\"%s\"}",
    method, cfg_api_key.c_str(), nonceStr, sig.c_str());

  HTTPClient https;
  if (!https.begin(tlsClient, "https://api.crypto.com/exchange/v1/private/user-balance")) {
    Serial.println("[API] Connection failed");
    return -1.0;
  }
  https.addHeader("Content-Type", "application/json");
  https.setTimeout(10000);

  int httpCode = https.POST(String(body));
  if (httpCode != HTTP_CODE_OK) {
    Serial.printf("[API] HTTP %d\n", httpCode);
    https.end();
    return -1.0;
  }
  String resp = https.getString();
  https.end();

  DynamicJsonDocument doc(16384);
  if (deserializeJson(doc, resp) || doc["code"].as<int>() != 0) {
    Serial.printf("[API] Parse error or code=%d\n", doc["code"].as<int>());
    return -1.0;
  }

  // Sum market_value from position_balances (each entry already has USD value)
  double total = 0.0;
  JsonArray positions = doc["result"]["data"][0]["position_balances"].as<JsonArray>();
  for (JsonObject pos : positions) {
    const char* name = pos["instrument_name"];
    double qty = atof(pos["quantity"] | "0");
    double mktVal = atof(pos["market_value"] | "0");
    if (!name || qty <= 0.0) continue;
    total += mktVal;
    Serial.printf("[Portfolio] %s: qty=%.6f val=$%.2f\n", name, qty, mktVal);
  }

  Serial.printf("[Portfolio] Total: $%.2f\n", total);
  return total;
}

// ===========================================================================
//  SERIAL COMMANDS
// ===========================================================================
void checkSerialCommand() {
  if (!Serial.available()) return;
  String cmd = Serial.readStringUntil('\n');
  cmd.trim();
  if (cmd.equalsIgnoreCase("RESET")) {
    Serial.println("[Reset] Factory reset triggered via serial!");
    setLED(60, 0, 0);

    prefs.begin(NVS_NAMESPACE, false);
    prefs.clear();
    prefs.end();

    display.setFullWindow();
    display.fillScreen(EPD_WHITE);
    display.setFont(&FreeSans9pt7b);
    display.setTextColor(EPD_BLACK);
    display.setCursor(4, 30);
    display.print("FACTORY RESET");
    display.setCursor(4, 55);
    display.print("All settings cleared.");
    display.setCursor(4, 80);
    display.print("Rebooting...");
    display.display(true);

    delay(3000);
    ESP.restart();
  }
}

// ===========================================================================
//  E-INK DISPLAY
// ===========================================================================
void showSetupScreen() {
  display.setRotation(1);
  display.setFullWindow();
  display.fillScreen(EPD_WHITE);
  display.setFont(&FreeSansBold18pt7b);
  display.setTextColor(EPD_BLACK);
  display.setCursor(30, 40);
  display.print("SETUP");
  display.setFont(&FreeSans9pt7b);
  display.setCursor(4, 68);
  display.printf("WiFi: %s", DEFAULT_AP_SSID);
  display.setCursor(4, 88);
  display.printf("Pass: %s", cfg_admin_pass.c_str());
  display.setCursor(4, 108);
  display.printf("Open http://%s", WiFi.softAPIP().toString().c_str());
  display.display(true);
}

// Update the status line on the boot splash (redraws full screen with new status)
void showSplashStatus(const char* line1, const char* line2) {
  display.setRotation(1);
  display.setFullWindow();
  display.fillScreen(EPD_WHITE);
  display.setFont(&FreeSans9pt7b);
  display.setTextColor(EPD_BLACK);
  display.setCursor(4, 30);
  display.print("Crypto.com Exchange Portfolio");
  display.setCursor(4, 60);
  display.print(line1);
  if (line2 && line2[0]) {
    display.setCursor(4, 80);
    display.print(line2);
  }
  display.display(true);
}

void updateDisplay() {
  unsigned long t0 = millis();
  char balStr[32];
  snprintf(balStr, sizeof(balStr), "$%.2f", currentBalance);

  char timeStr[24] = "--:-- --";
  struct tm ti;
  if (getLocalTime(&ti, 1000)) {
    int hour12 = ti.tm_hour % 12;
    if (hour12 == 0) hour12 = 12;
    const char* ampm = ti.tm_hour < 12 ? "AM" : "PM";
    snprintf(timeStr, sizeof(timeStr), "%d:%02d:%02d %s (%s)",
             hour12, ti.tm_min, ti.tm_sec, ampm, TIMEZONE_NAME);
  }

  // Build admin URL
  String adminUrl;
  if (WiFi.status() == WL_CONNECTED) {
    adminUrl = "https://" + WiFi.localIP().toString() + "/";
  } else {
    adminUrl = "https://<unknown>/";
  }

  display.setRotation(1);
  display.setFullWindow();

  // Draw to buffer (full-height buffer = single page, no paging loop needed)
  display.fillScreen(EPD_WHITE);
  display.setFont(&FreeSans9pt7b);
  display.setTextColor(EPD_BLACK);
  display.setCursor(4, 18);
  display.print("Crypto.com Exchange Portfolio");
  display.drawFastHLine(0, 24, display.width(), EPD_BLACK);
  display.setFont(&FreeSansBold18pt7b);
  display.setCursor(4, 68);
  if (cfg_api_key.isEmpty() || cfg_api_secret.isEmpty()) {
    display.setFont(&FreeSans9pt7b);
    display.setCursor(4, 50);
    display.print("API keys not configured.");
    display.setCursor(4, 68);
    display.print("Set them in the admin panel.");
  } else if (!balanceStatusMsg.isEmpty()) {
    display.setFont(&FreeSans9pt7b);
    display.setCursor(4, 58);
    display.print(balanceStatusMsg);
  } else {
    display.print(balStr);
  }
  display.setFont(&FreeSans9pt7b);
  display.setCursor(4, 100);
  display.print("Updated: ");
  display.print(timeStr);
  display.drawFastHLine(0, 106, display.width(), EPD_BLACK);
  display.setFont();
  display.setTextSize(1);
  display.setCursor(4, 112);
  display.print("Admin Panel: ");
  display.print(adminUrl);

  // Partial refresh for flicker-free updates
  display.display(true);

  unsigned long elapsed = millis() - t0;
  Serial.printf("[EPD] updateDisplay() %lums\n", elapsed);
}

// ===========================================================================
//  RGB LED
// ===========================================================================
void setLED(uint8_t r, uint8_t g, uint8_t b) {
  // Common-anode RGB LED: LOW = on, HIGH = off
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  digitalWrite(LED_R, r > 0 ? LOW : HIGH);
  digitalWrite(LED_G, g > 0 ? LOW : HIGH);
  digitalWrite(LED_B, b > 0 ? LOW : HIGH);
}

void updateLED() {
  const double threshold = 0.01;
  Serial.printf("[LED] current=$%.2f previous=$%.2f ", currentBalance, previousBalance);
  if (previousBalance < 0.0) {
    Serial.println("-> white (no data)");
    setLED(1, 1, 1);
  } else if (currentBalance > previousBalance + threshold) {
    Serial.println("-> GREEN (up)");
    setLED(0, 60, 0);
  } else if (currentBalance < previousBalance - threshold) {
    Serial.println("-> RED (down)");
    setLED(60, 0, 0);
  } else {
    Serial.println("-> white (stable)");
    setLED(1, 1, 1);
  }
}

// ===========================================================================
//  SETUP
// ===========================================================================
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.printf("\n=== Crypto.com Exchange Portfolio v%s ===\n", FW_VERSION);

  setLED(1, 1, 1);  // white at boot

  pinMode(EPD_PWR, OUTPUT);
  digitalWrite(EPD_PWR, LOW);
  delay(10);

  hspi.begin(EPD_CLK, -1, EPD_DIN, -1);
  display.begin(hspi, SPISettings(4000000, MSBFIRST, SPI_MODE0));
  display.setRotation(1);
  display.clearScreen();  // one-time full refresh to initialize e-ink particles

  loadConfig();
  Serial.printf("[Config] configured=%d ssid='%s' hostname='%s'\n",
                cfg_configured, cfg_wifi_ssid.c_str(), cfg_hostname.c_str());

  if (!cfg_configured || cfg_wifi_ssid.isEmpty()) {
    // ====== SETUP MODE ======
    inSetupMode = true;
    Serial.println("[Mode] Setup -- creating AP");

    WiFi.mode(WIFI_AP_STA);
    delay(500);
    bool apOk = WiFi.softAP(DEFAULT_AP_SSID, cfg_admin_pass.c_str());
    delay(500);
    Serial.printf("[AP] softAP returned: %s\n", apOk ? "true" : "false");
    Serial.printf("[AP] Actual SSID: '%s'\n", WiFi.softAPSSID().c_str());
    Serial.printf("[AP] Expected SSID: '%s'\n", DEFAULT_AP_SSID);
    Serial.printf("[AP] IP: %s\n", WiFi.softAPIP().toString().c_str());
    dnsServer.start(53, "*", WiFi.softAPIP());

    // HTTP server for setup (no TLS needed on direct AP)
    startHTTPServer();
    registerURI(server_handle, "/", HTTP_GET, h_setupPage);
    registerURI(server_handle, "/api/scan", HTTP_GET, h_scanAPI);
    registerURI(server_handle, "/api/wifi-save", HTTP_POST, h_wifiSave);
    httpd_register_err_handler(server_handle, HTTPD_404_NOT_FOUND, h_captivePortal);

    showSetupScreen();

  } else {
    // ====== NORMAL MODE ======
    inSetupMode = false;
    Serial.printf("[Mode] Normal -- connecting to '%s'\n", cfg_wifi_ssid.c_str());

    // Boot splash
    char connMsg[64];
    snprintf(connMsg, sizeof(connMsg), "Connecting to %s...", cfg_wifi_ssid.c_str());
    showSplashStatus(connMsg, "");

    Serial.printf("[WiFi] SSID='%s'\n", cfg_wifi_ssid.c_str());

    // Try up to 3 connection attempts with full reset each time
    bool connected = false;
    for (int tryNum = 1; tryNum <= 3 && !connected; tryNum++) {
      WiFi.disconnect(true, true);
      WiFi.mode(WIFI_OFF);
      delay(tryNum == 1 ? 100 : 500);
      WiFi.mode(WIFI_STA);
      WiFi.setHostname(cfg_hostname.c_str());
      delay(tryNum == 1 ? 100 : 500);

      Serial.printf("[WiFi] Attempt %d/3: '%s'...", tryNum, cfg_wifi_ssid.c_str());
      WiFi.begin(cfg_wifi_ssid.c_str(), cfg_wifi_pass.c_str());
      int maxWait = (tryNum == 1) ? 1 : 20;
      int attempts = 0;
      while (WiFi.status() != WL_CONNECTED && attempts < maxWait) {
        delay(500);
        attempts++;
      }
      if (WiFi.status() == WL_CONNECTED) {
        connected = true;
        Serial.println(" connected");
      } else {
        const char* reason;
        switch (WiFi.status()) {
          case WL_NO_SSID_AVAIL: reason = "network not found"; break;
          case WL_CONNECT_FAILED: reason = "connection failed"; break;
          case WL_DISCONNECTED: reason = "disconnected"; break;
          case WL_IDLE_STATUS: reason = "idle"; break;
          default: reason = "unknown error"; break;
        }
        Serial.printf(" %s\n", reason);
      }
    }

    if (!connected) {
      Serial.println("[WiFi] All attempts failed -- entering setup mode");
      inSetupMode = true;
      WiFi.disconnect();
      WiFi.mode(WIFI_AP_STA);
      delay(500);
      WiFi.softAP(DEFAULT_AP_SSID, cfg_admin_pass.c_str());
      delay(500);
      Serial.printf("[AP] Fallback SSID: '%s'\n", WiFi.softAPSSID().c_str());
      dnsServer.start(53, "*", WiFi.softAPIP());

      startHTTPServer();
      registerURI(server_handle, "/", HTTP_GET, h_setupPage);
      registerURI(server_handle, "/api/scan", HTTP_GET, h_scanAPI);
      registerURI(server_handle, "/api/wifi-save", HTTP_POST, h_wifiSave);
      httpd_register_err_handler(server_handle, HTTPD_404_NOT_FOUND, h_captivePortal);

      showSetupScreen();
      return;
    }

    Serial.printf("\n[WiFi] Connected. IP: %s\n", WiFi.localIP().toString().c_str());
    showSplashStatus("WiFi connected.", "Syncing time...");
    MDNS.begin(cfg_hostname.c_str());

    // Initialize persistent TLS client
    tlsClient.setInsecure();
    tlsClient.setTimeout(10);

    configTzTime(TIMEZONE_POSIX, "pool.ntp.org", "time.nist.gov");
    Serial.print("[NTP] Syncing");
    struct tm ti;
    for (int i = 0; i < 20 && !getLocalTime(&ti, 1000); i++) Serial.print(".");
    Serial.println(" done");

    // Generate or load TLS certificate, then start HTTPS server
    showSplashStatus("Starting HTTPS server...", "");
    loadOrGenerateCert();
    startHTTPSServer();
    registerURI(server_handle, "/", HTTP_GET, h_adminPage);
    registerURI(server_handle, "/login", HTTP_GET, h_loginPage);
    registerURI(server_handle, "/login", HTTP_POST, h_loginPost);
    registerURI(server_handle, "/logout", HTTP_GET, h_logout);
    registerURI(server_handle, "/api/info", HTTP_GET, h_infoAPI);
    registerURI(server_handle, "/api/scan", HTTP_GET, h_scanAPI);
    registerURI(server_handle, "/api/wifi-save", HTTP_POST, h_wifiSave);
    registerURI(server_handle, "/api/hostname-save", HTTP_POST, h_hostnameSave);
    registerURI(server_handle, "/api/apikeys-save", HTTP_POST, h_apiKeysSave);
    registerURI(server_handle, "/api/password-save", HTTP_POST, h_passwordSave);
    registerURI(server_handle, "/api/firmware-upload", HTTP_POST, h_firmwareUpload);
    registerURI(server_handle, "/api/factory-reset", HTTP_POST, h_factoryReset);

    Serial.printf("[Web] Admin panel at https://%s/ or https://%s.local/\n",
                  WiFi.localIP().toString().c_str(), cfg_hostname.c_str());

    // Initial balance fetch
    showSplashStatus("Fetching portfolio...", "");
    double bal = fetchBalance();
    if (bal >= 0.0) {
      currentBalance = bal;
      previousBalance = bal;  // set baseline so LED works on next fetch
      balanceStatusMsg = "";
      Serial.printf("[Balance] Initial: $%.2f\n", currentBalance);
    } else if (!cfg_api_key.isEmpty() && !cfg_api_secret.isEmpty()) {
      balanceStatusMsg = "API error -- check keys";
    }
    lastRefreshMs = millis();
    updateDisplay();
    updateLED();
  }
}

// ===========================================================================
//  LOOP
// ===========================================================================
void loop() {
  // httpd runs in its own FreeRTOS task -- no handleClient() needed
  checkSerialCommand();

  if (inSetupMode) {
    dnsServer.processNextRequest();
    delay(2);
    return;
  }

  unsigned long now = millis();

  if (now - lastRefreshMs < REFRESH_MS) return;
  lastRefreshMs = now;

  double bal = fetchBalance();
  if (bal >= 0.0) {
    currentBalance = bal;
    balanceStatusMsg = "";
    Serial.printf("[Balance] $%.2f\n", currentBalance);
  } else if (cfg_api_key.isEmpty() || cfg_api_secret.isEmpty()) {
    balanceStatusMsg = "";  // handled in updateDisplay
  } else {
    balanceStatusMsg = "API error -- check keys";
    Serial.println("[Balance] Fetch failed -- keeping last known value");
  }

  updateDisplay();
  updateLED();

  // After LED comparison, move current to previous for next cycle
  if (bal >= 0.0) {
    previousBalance = currentBalance;
  }
}
