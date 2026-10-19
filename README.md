# NFClab

基于 WeAct STM32F411 和 ST25R3916B 的 NFC 实验工具，提供 NFC-A / MIFARE
Classic 1K 读取、认证写入、Card Library、被动采集及四字节 UID 模拟。
UID 模拟使用硬件选卡和心跳租约，只模拟 UID，不提供完整 Classic 卡片存储模拟。

## 许可

Copyright (C) 2026 NFClab contributors.
项目代码采用 **GPL-3.0-or-later**，详见 [LICENSE](LICENSE) 与
[第三方声明](NOTICE.md)。软件不提供任何担保。

## 硬件

| ST25R3916B | STM32F411 |
| --- | --- |
| BSS | PA4 |
| SCLK | PA5 |
| MISO | PA6 |
| MOSI | PA7 |
| IRQ | PA0 / EXTI0 |

ST25R 板 I2C_EN 接地以选择 SPI；数字接口使用 3.3 V 电平，并连接公共地。
供电请按所用模块规格接线。PA11/PA12 用于 USB，PA13/PA14 用于 SWD。
当前时钟配置使用 25 MHz HSE，核心时钟 96 MHz。

## 构建

依赖 Python 3.11+、GNU Make、arm-none-eabi-gcc、arm-none-eabi-binutils。
主机离线求解器还需要 GCC、pthread、liblz4 和 libbz2 开发包。

```sh
make
make sniff
```

主固件为 `build/identity.bin`，被动采集启动版本为 `build/sniff.bin`。
使用与你的开发板兼容的刷写工具，刷写前自行备份原 Flash。
USB CDC 是默认通信方式；SWD 调试回退需要 OpenOCD。

离线求解器使用以下固定版本的公开 Proxmark3 源码：

```sh
git clone https://github.com/RfidResearchGroup/proxmark3 reference/proxmark3
git -C reference/proxmark3 checkout --detach dd8bf6c184c3a9e77710e17dcc89d5acf6503617
make host-recovery host-mfkey
```

该外部源码与其完整许可声明需保留。如果分发链接后的二进制，还需同时提供
完整对应源码，包括上游组件及构建脚本。此发布包仅包含项目源代码。

## 使用

```sh
./nfclab --help
./nfclab tag info
./nfclab tag read
./nfclab library list
./nfclab m1 write --help
./nfclab emulate --help
./nfclab tui
```

写入流程支持 Gen1a、Gen2 及普通 Classic 卡，具体参数见各命令帮助。
普通卡不能改写制造商块；整卡写入会展示计划并要求终端确认。
主机运行时应使用与设备固件匹配的 ELF 文件。

## 数据与公开范围

此源码发布不包含开发仓库历史、测试用例、测试记录、验收文档、卡片转储、
认证采集、恢复结果或 Flash 备份。`library/`、`recovery/`、`build/` 及运行时
输出不得随源码公开。请将这些输出保存在单独的私有目录。

随附的默认密钥字典逐项来自公开 Proxmark3 字典；代码中的默认密钥、
已公开的芯片后门常量及协议常量属于功能实现，不是本地实卡密钥样本。
