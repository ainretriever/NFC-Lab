/* SPDX-License-Identifier: GPL-3.0-or-later
 * NFClab Pager P0: power enable + ST25R3916 identity probe.
 * This does not enable the RF field or alter card contents.
 */
#include <stdint.h>
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/spi_master.h"

#define PIN_SCK 35
#define PIN_MOSI 34
#define PIN_MISO 33
#define PIN_NFC_CS 39
#define PIN_NFC_IRQ 1
#define PIN_DISP_CS 38
#define PIN_SD_CS 21
#define PIN_LORA_CS 36
#define PIN_I2C_SCL 2
#define PIN_I2C_SDA 3
#define XL9555_ADDR 0x20
#define XL9555_NFC_EN (1u << 5)
static const char *TAG = "nfclab_pager";

static esp_err_t enable_nfc_power(i2c_master_bus_handle_t bus)
{
    i2c_master_dev_handle_t dev;
    i2c_device_config_t cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = XL9555_ADDR,
        .scl_speed_hz = 100000,
    };
    ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(bus, &cfg, &dev), TAG, "expander add");
    uint8_t out[2], config[2];
    ESP_RETURN_ON_ERROR(i2c_master_transmit_receive(dev, (uint8_t[]){2}, 1, out, 2, 100), TAG, "read output");
    ESP_RETURN_ON_ERROR(i2c_master_transmit_receive(dev, (uint8_t[]){6}, 1, config, 2, 100), TAG, "read direction");
    out[0] |= XL9555_NFC_EN;
    config[0] &= (uint8_t)~XL9555_NFC_EN;
    ESP_RETURN_ON_ERROR(i2c_master_transmit(dev, (uint8_t[]){2, out[0], out[1]}, 3, 100), TAG, "set output");
    ESP_RETURN_ON_ERROR(i2c_master_transmit(dev, (uint8_t[]){6, config[0], config[1]}, 3, 100), TAG, "set direction");
    return ESP_OK;
}

void app_main(void)
{
    const gpio_num_t inactive_cs[] = {PIN_DISP_CS, PIN_SD_CS, PIN_LORA_CS};
    for (unsigned i = 0; i < sizeof(inactive_cs)/sizeof(inactive_cs[0]); ++i) {
        gpio_set_level(inactive_cs[i], 1);
        gpio_config_t cfg = {.pin_bit_mask = 1ULL << inactive_cs[i], .mode = GPIO_MODE_OUTPUT};
        ESP_ERROR_CHECK(gpio_config(&cfg));
        gpio_set_level(inactive_cs[i], 1);
    }
    i2c_master_bus_handle_t i2c;
    i2c_master_bus_config_t i2c_cfg = {
        .i2c_port = I2C_NUM_0,
        .sda_io_num = PIN_I2C_SDA,
        .scl_io_num = PIN_I2C_SCL,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
    };
    ESP_ERROR_CHECK(i2c_new_master_bus(&i2c_cfg, &i2c));
    ESP_ERROR_CHECK(enable_nfc_power(i2c));
    vTaskDelay(pdMS_TO_TICKS(50));
    gpio_config_t irq_cfg = {.pin_bit_mask = 1ULL << PIN_NFC_IRQ, .mode = GPIO_MODE_INPUT};
    ESP_ERROR_CHECK(gpio_config(&irq_cfg));
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = PIN_MOSI, .miso_io_num = PIN_MISO, .sclk_io_num = PIN_SCK,
        .quadwp_io_num = -1, .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_DISABLED));
    spi_device_interface_config_t dev_cfg = {
        .clock_speed_hz = 500000, .mode = 1, .spics_io_num = PIN_NFC_CS, .queue_size = 1,
    };
    spi_device_handle_t nfc;
    ESP_ERROR_CHECK(spi_bus_add_device(SPI2_HOST, &dev_cfg, &nfc));
    uint8_t rx[2] = {0};
    spi_transaction_t t = {
        .length = 16, .tx_buffer = (uint8_t[]){0x7f, 0x00}, .rx_buffer = rx,
    };
    esp_err_t err = spi_device_polling_transmit(nfc, &t);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "ST25R3916 identity raw: 0x%02x; IRQ=%d", rx[1], gpio_get_level(PIN_NFC_IRQ));
        if ((rx[1] & 0xf8) == 0x30) ESP_LOGI(TAG, "ST25R3916 detected");
        else ESP_LOGW(TAG, "Unexpected identity; check SPI mode, power, and pinout");
    } else ESP_LOGE(TAG, "SPI transaction failed: %s", esp_err_to_name(err));
}
