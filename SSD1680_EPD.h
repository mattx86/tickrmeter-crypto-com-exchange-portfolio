/*
 * SSD1680_EPD.h — Minimal SSD1680 e-ink driver for GDEY029T94 (296x128)
 * Inherits from Adafruit_GFX for text/graphics primitives.
 *
 * MIT License
 * Copyright (c) 2026 Matt Smith
 * See LICENSE file for full terms.
 */
#ifndef SSD1680_EPD_H
#define SSD1680_EPD_H

#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_GFX.h>

#define EPD_WIDTH  128
#define EPD_HEIGHT 296
#define EPD_BUF_SIZE (EPD_WIDTH * EPD_HEIGHT / 8)  // 4736 bytes

// Colors
#define EPD_BLACK 0
#define EPD_WHITE 1

class SSD1680_EPD : public Adafruit_GFX {
public:
  SSD1680_EPD(int16_t cs, int16_t dc, int16_t rst, int16_t busy)
    : Adafruit_GFX(EPD_WIDTH, EPD_HEIGHT),
      _cs(cs), _dc(dc), _rst(rst), _busy(busy),
      _spi(NULL), _initialized(false), _partialMode(false) {
    memset(_buffer, 0xFF, sizeof(_buffer));
  }

  void begin(SPIClass &spi, SPISettings settings) {
    _spi = &spi;
    _spiSettings = settings;
    pinMode(_cs, OUTPUT);
    pinMode(_dc, OUTPUT);
    pinMode(_rst, OUTPUT);
    pinMode(_busy, INPUT);
    digitalWrite(_cs, HIGH);
    _hardReset();
    _initDisplay();
  }

  // Required by Adafruit_GFX
  void drawPixel(int16_t x, int16_t y, uint16_t color) override {
    if (x < 0 || y < 0 || x >= width() || y >= height()) return;

    // Map rotated coordinates to physical
    int16_t px, py;
    switch (getRotation()) {
      case 0:  px = x; py = y; break;
      case 1:  px = EPD_WIDTH - 1 - y; py = x; break;
      case 2:  px = EPD_WIDTH - 1 - x; py = EPD_HEIGHT - 1 - y; break;
      case 3:  px = y; py = EPD_HEIGHT - 1 - x; break;
      default: px = x; py = y; break;
    }

    uint16_t idx = px / 8 + py * (EPD_WIDTH / 8);
    uint8_t bit = 7 - (px % 8);
    if (color == EPD_BLACK) {
      _buffer[idx] &= ~(1 << bit);
    } else {
      _buffer[idx] |= (1 << bit);
    }
  }

  void fillScreen(uint16_t color) override {
    memset(_buffer, color == EPD_BLACK ? 0x00 : 0xFF, sizeof(_buffer));
  }

  // Transfer buffer to display and refresh
  void display(bool partial = false) {
    if (!_initialized) _initDisplay();

    if (partial) {
      // Write current buffer only, then partial refresh
      _setRamArea(0, 0, EPD_WIDTH, EPD_HEIGHT);
      _writeBufferToRam(0x24);
      _updatePartial();
      // Write same data to previous buffer for clean next partial update
      _setRamArea(0, 0, EPD_WIDTH, EPD_HEIGHT);
      _writeBufferToRam(0x26);
    } else {
      // Write to both buffers, then full refresh
      _setRamArea(0, 0, EPD_WIDTH, EPD_HEIGHT);
      _writeBufferToRam(0x26);  // previous
      _setRamArea(0, 0, EPD_WIDTH, EPD_HEIGHT);
      _writeBufferToRam(0x24);  // current
      _updateFull();
    }
  }

  // Full refresh clear (initializes both buffers to white)
  void clearScreen() {
    if (!_initialized) _initDisplay();
    _setRamArea(0, 0, EPD_WIDTH, EPD_HEIGHT);
    _writeSolidToRam(0x26, 0xFF);
    _setRamArea(0, 0, EPD_WIDTH, EPD_HEIGHT);
    _writeSolidToRam(0x24, 0xFF);
    _updateFull();
    memset(_buffer, 0xFF, sizeof(_buffer));
  }

  void setFullWindow() {
    // No-op — we always use full window. Kept for API compatibility.
  }

  void powerOff() {
    _writeCommand(0x22);
    _writeData(0x83);
    _writeCommand(0x20);
    _waitBusy();
  }

private:
  int16_t _cs, _dc, _rst, _busy;
  SPIClass *_spi;
  SPISettings _spiSettings;
  bool _initialized;
  bool _partialMode;
  uint8_t _buffer[EPD_BUF_SIZE];

  static const uint8_t _lut_partial[153] PROGMEM;

  void _hardReset() {
    digitalWrite(_rst, HIGH);
    delay(10);
    digitalWrite(_rst, LOW);
    delay(10);
    digitalWrite(_rst, HIGH);
    delay(10);
  }

  void _initDisplay() {
    _writeCommand(0x12);  // Software reset
    delay(10);
    _waitBusy();

    _writeCommand(0x01);  // Driver output control
    _writeData(0x27);     // MUX = 295 (296 lines - 1)
    _writeData(0x01);
    _writeData(0x00);

    _writeCommand(0x11);  // Data entry mode
    _writeData(0x03);     // X increment, Y increment

    _writeCommand(0x3C);  // Border waveform
    _writeData(0x05);

    _writeCommand(0x21);  // Display update control
    _writeData(0x00);
    _writeData(0x80);

    _writeCommand(0x18);  // Temperature sensor
    _writeData(0x80);     // Internal sensor

    _setRamArea(0, 0, EPD_WIDTH, EPD_HEIGHT);
    _initialized = true;
    _partialMode = false;
  }

  void _setRamArea(uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
    _writeCommand(0x11);  // Data entry mode
    _writeData(0x03);

    _writeCommand(0x44);  // RAM X address range
    _writeData(x / 8);
    _writeData((x + w - 1) / 8);

    _writeCommand(0x45);  // RAM Y address range
    _writeData(y & 0xFF);
    _writeData(y >> 8);
    _writeData((y + h - 1) & 0xFF);
    _writeData((y + h - 1) >> 8);

    _writeCommand(0x4E);  // RAM X counter
    _writeData(x / 8);

    _writeCommand(0x4F);  // RAM Y counter
    _writeData(y & 0xFF);
    _writeData(y >> 8);
  }

  void _writeBufferToRam(uint8_t cmd) {
    _writeCommand(cmd);
    _spi->beginTransaction(_spiSettings);
    digitalWrite(_dc, HIGH);
    digitalWrite(_cs, LOW);
    for (uint32_t i = 0; i < EPD_BUF_SIZE; i++) {
      _spi->transfer(_buffer[i]);
    }
    digitalWrite(_cs, HIGH);
    _spi->endTransaction();
  }

  void _writeSolidToRam(uint8_t cmd, uint8_t value) {
    _writeCommand(cmd);
    _spi->beginTransaction(_spiSettings);
    digitalWrite(_dc, HIGH);
    digitalWrite(_cs, LOW);
    for (uint32_t i = 0; i < EPD_BUF_SIZE; i++) {
      _spi->transfer(value);
    }
    digitalWrite(_cs, HIGH);
    _spi->endTransaction();
  }

  void _updateFull() {
    _partialMode = false;
    _writeCommand(0x22);
    _writeData(0xF7);     // Full update sequence (uses OTP LUT)
    _writeCommand(0x20);  // Master activation
    _waitBusy();
  }

  void _updatePartial() {
    if (!_partialMode) _loadPartialLUT();
    _writeCommand(0x22);
    _writeData(0xCC);     // Partial update sequence
    _writeCommand(0x20);  // Master activation
    _waitBusy();
  }

  void _loadPartialLUT() {
    _writeCommand(0x32);
    _spi->beginTransaction(_spiSettings);
    digitalWrite(_dc, HIGH);
    digitalWrite(_cs, LOW);
    for (uint16_t i = 0; i < sizeof(_lut_partial); i++) {
      _spi->transfer(pgm_read_byte(&_lut_partial[i]));
    }
    digitalWrite(_cs, HIGH);
    _spi->endTransaction();
    _partialMode = true;
  }

  void _writeCommand(uint8_t cmd) {
    _spi->beginTransaction(_spiSettings);
    digitalWrite(_dc, LOW);
    digitalWrite(_cs, LOW);
    _spi->transfer(cmd);
    digitalWrite(_cs, HIGH);
    _spi->endTransaction();
  }

  void _writeData(uint8_t data) {
    _spi->beginTransaction(_spiSettings);
    digitalWrite(_dc, HIGH);
    digitalWrite(_cs, LOW);
    _spi->transfer(data);
    digitalWrite(_cs, HIGH);
    _spi->endTransaction();
  }

  void _waitBusy() {
    unsigned long start = millis();
    while (digitalRead(_busy) == HIGH) {  // BUSY = HIGH means busy
      delay(1);
      if (millis() - start > 10000) {
        Serial.println("[EPD] Busy timeout!");
        break;
      }
    }
  }
};

// Partial refresh LUT (from SSD1680 application note)
const uint8_t SSD1680_EPD::_lut_partial[] PROGMEM = {
  0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x80, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x40, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x00, 0x00,
};

#endif // SSD1680_EPD_H
