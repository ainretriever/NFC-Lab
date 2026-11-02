# NFClab Pager — ESP-IDF P0

Independent ESP-IDF target for LilyGO T-LoRa Pager (ESP32-S3 / SX1262 edition).

This initial target only enables NFC power through XL9555 and reads the
ST25R3916 identity register over SPI. It does not transmit RF, read cards,
write cards, or run the STM32 firmware.

Requires ESP-IDF 5.3+ (new I2C master and SPI drivers).

```sh
cd pager
idf.py set-target esp32s3
idf.py build
idf.py -p PORT flash monitor
```

Expected successful identity: `(identity & 0xF8) == 0x30`.
Check raw byte, IRQ pin and actual board revision before expanding features.

Board wiring (LilyGO product documentation): SPI 35/34/33, NFC CS 39,
IRQ 1, XL9555 0x20 bit 5 power enable, I2C SDA 3 / SCL 2.
A separate LilyGoLib document lists IRQ 5 instead of 1: verify on hardware.
Display/SD/LoRa CS are driven inactive before SPI is initialized.
The STM32 Makefile and sources are unchanged.
