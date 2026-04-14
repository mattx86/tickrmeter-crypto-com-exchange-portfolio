# Crypto.com Exchange Portfolio

Custom firmware for the TickrMeter ESP32 e-ink device that displays your Crypto.com Exchange portfolio balance in real-time.

## Features

- **Portfolio tracking** -- fetches total portfolio value from the Crypto.com Exchange API every 60 seconds (single API call returns all positions with USD market values)
- **E-ink display** -- shows portfolio balance, last update time, and admin panel URL on a 2.9" e-ink display with flicker-free partial refresh
- **LED indicator** -- common-anode RGB LED reflects minute-to-minute portfolio change (green = up, red = down, white = stable)
- **HTTPS admin panel** -- self-signed TLS certificate (EC P-256) with session-based authentication, accessible at `https://<device-ip>/`
- **Web-based WiFi setup** -- captive portal on first boot for WiFi configuration, with optional API key entry
- **OTA firmware updates** -- upload new firmware via the admin panel's Update tab
- **Factory reset** -- via admin panel Reset tab or serial console (`RESET` command)
- **Auto-generated credentials** -- random 10-character password generated on first boot, used for both AP mode and admin login
- **Runtime TLS certificates** -- generated on first boot using mbedtls, regenerated when hostname changes, stored in NVS
- **Persistent settings** -- all configuration (WiFi, API keys, hostname, password, TLS cert) stored in ESP32 NVS flash

## Hardware

| Component | Details |
|-----------|---------|
| MCU | ESP32-WROOM (TickrMeter board) |
| Display | Good Display GDEY029T94, 2.9" BW e-ink, 296x128 px, SSD1680 controller |
| LED | Common-anode RGB (GPIO 23=red, 22=green, 21=blue) |
| Display SPI | HSPI bus (CLK=13, MOSI=14, CS=15, DC=27, RST=26, BUSY=18) |
| Display power | GPIO 19 (active LOW) |

## Requirements

### Arduino IDE Board Settings

- **Board**: ESP32 Dev Module
- **Flash Size**: 8MB
- **Partition Scheme**: 8M with spiffs (3MB APP/1.5MB SPIFFS)

### Libraries

Install via Arduino IDE Library Manager:

| Library | License |
|---------|---------|
| Adafruit GFX Library | BSD 3-Clause |
| ArduinoJson | MIT |

### API Keys

Create a **read-only** API key at [Crypto.com Exchange](https://crypto.com/exchange/) under API Management. You can enter the keys during initial WiFi setup or later in the admin panel.

## Hardware Preparation

### Soldering

You will need to solder pin headers to two locations on the TickrMeter board. Insert the pins with the **long side sticking upward** and the **black plastic base resting on the top of the board** (short pins poke through to the bottom).

**Serial header** -- vertical row of 6 pin holes (from bottom to top, as labeled on bottom of board):

| Pin | Function |
|-----|----------|
| 5V  | Power (do not connect to FT232) |
| TX  | Serial transmit |
| RX  | Serial receive |
| GND | Ground |
| RST | Reset (do not connect to FT232) |
| IO0 | Boot mode select (do not connect to FT232) |

**FLASH header** -- separate pair of 2 pin holes labeled FLASH (labeled on the bottom of the board).

### USB-to-Serial Adapter

A **DSD Tech FT232** (or any 3.3V FTDI adapter) is used for serial access and firmware flashing. Connect:

| FT232 Pin | TickrMeter Pin |
|-----------|----------------|
| TX        | TX             |
| RX        | RX             |
| GND       | GND            |

Do **not** connect the FT232's 5V/VCC pin -- the TickrMeter is powered via its own USB port.

## Backing Up Original Firmware

Before flashing custom firmware, back up the original TickrMeter firmware. You only need to do this once.

### Install esptool

```bash
pip install esptool
```

### Read the full flash (8MB)

With the board in **download mode** (see below), run:

```bash
esptool.py --port COM3 --baud 115200 read_flash 0x0 0x800000 tickrmeter_original.bin
```

Replace `COM3` with your serial port (e.g. `/dev/ttyUSB0` on Linux, `/dev/cu.usbserial-*` on macOS). This saves the entire 8MB flash to `tickrmeter_original.bin`.

### Restore original firmware (if needed)

```bash
esptool.py --port COM3 --baud 115200 write_flash 0x0 tickrmeter_original.bin
```

## Flashing the Firmware

### Enter download mode

1. Plug the USB power cable into the TickrMeter (provides power only)
2. Connect the FT232 adapter to the serial header (TX, RX, GND)
3. Keep the TickrMeter's **power switch OFF**
4. **Bridge the FLASH pins** using a jumper or the tip of a screwdriver
5. While holding the FLASH bridge, **flip the power switch ON**
6. The Arduino IDE serial monitor (115200 baud) should display: `waiting for download`
7. You can release the FLASH bridge now

### Arduino IDE settings

- **Tools > Board**: ESP32 Dev Module
- **Tools > Flash Size**: 8MB
- **Tools > Partition Scheme**: 8M with spiffs (3MB APP/1.5MB SPIFFS)
- **Tools > Upload Speed**: 921600 (or 460800 if upload fails)
- **Tools > Port**: select the FT232's serial port

### Compile and upload

1. Open `tickrmeter-crypto-com-exchange-portfolio.ino` in the Arduino IDE
2. Click the **Upload** button (right arrow icon) to compile and flash the firmware
3. Wait for the upload to complete -- the IDE will show "Hard resetting via RTS pin..."
4. Flip the power switch off and back on to boot the new firmware

## Quick Start

1. After flashing, the device boots into **setup mode** -- connect to the `tickrmeter-crypto-com` WiFi network using the password shown on the e-ink display
2. A captive portal should appear automatically; if not, open `http://192.168.4.1/` in your browser
3. Select your WiFi network, enter the password, and optionally enter your Crypto.com API keys
4. The device reboots, connects to WiFi, and begins displaying your portfolio balance
5. Access the admin panel at the HTTPS URL shown on the e-ink display (username: `admin`, password: same as the AP password from step 1)

## Admin Panel

The admin panel is served over HTTPS on port 443 with the following tabs:

| Tab | Function |
|-----|----------|
| Device Info | IP address, WiFi details, signal strength, hostname, free memory |
| WiFi | Scan and connect to a different network |
| Hostname | Change the device hostname (also used for DHCP and mDNS) |
| API Keys | Set or update Crypto.com Exchange API key and secret |
| Password | Change the admin/AP password |
| Update | Upload a new firmware .bin file (OTA) |
| Reset | Factory reset with confirmation (clears all settings) |

## Serial Console

- **Baud rate**: 115200
- **Commands**: Type `RESET` (Press enter to send) to factory reset
- **Logging**: Boot progress, WiFi connection status, portfolio values, LED state, display timing

## E-ink Display

The display uses a custom minimal SSD1680 driver ([SSD1680_EPD.h](SSD1680_EPD.h)). It inherits from Adafruit GFX for text and graphics rendering.

- **Boot**: one full refresh (clears e-ink particles), then all subsequent updates use partial refresh (no flicker)
- **Layout**: title, portfolio balance (or API key status message), last update timestamp, admin panel URL

## Project Structure

```
tickrmeter-crypto-com-exchange-portfolio/
  tickrmeter-crypto-com-exchange-portfolio.ino   Main firmware
  SSD1680_EPD.h                                  Minimal SSD1680 e-ink driver
  LICENSE                                        MIT License
  README.md                                      This file
```

## License

MIT License. See [LICENSE](LICENSE) for details.

Copyright (c) 2026 Matt Smith
