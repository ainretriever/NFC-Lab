CC = arm-none-eabi-gcc
CFLAGS = -mcpu=cortex-m4 -mthumb -O3 -g3 -ffreestanding -fno-builtin -Wall -Wextra -Werror -ffunction-sections -fdata-sections
FW_DEPS = firmware/sniff_decode.h firmware/uid_sim.inc firmware/m1_auth_write_bulk.inc firmware/m1_gen1a_bulk.inc firmware/m1_nonce_fast.h firmware/board.h firmware/sniff.inc firmware/sniff_codec.h firmware/reader.inc firmware/m1.inc firmware/m1_bulk.inc firmware/m1_keys.inc firmware/m1_recover.inc firmware/m1_magic.inc firmware/m1_fast_select.inc firmware/usb_cdc.inc firmware/usb_proto.inc firmware/m1_timing.h firmware/m1_guard.h firmware/m1_codec.h firmware/crypto1.h firmware/stm32f411.ld
MFKEY_COMMON = reference/proxmark3/common/crapto1/crapto1.c reference/proxmark3/common/crapto1/crypto1.c reference/proxmark3/common/bucketsort.c
HARDNESTED_REF = reference/proxmark3/client/deps/hardnested
.PHONY: all clean sniff host-recovery host-hardnested host-mfkey
all: build/identity.bin
build/identity.elf: firmware/main.c $(FW_DEPS)
	mkdir -p build
	$(CC) $(CFLAGS) -nostdlib -Wl,--gc-sections,-Map=build/identity.map -T firmware/stm32f411.ld $< -o $@
	arm-none-eabi-size $@
build/identity.bin: build/identity.elf
	arm-none-eabi-objcopy -O binary $< $@
sniff: build/sniff.bin
build/sniff.elf: firmware/main.c $(FW_DEPS)
	mkdir -p build
	$(CC) $(CFLAGS) -DNFCLAB_SNIFF_BOOT -nostdlib -Wl,--gc-sections,-Map=build/sniff.map -T firmware/stm32f411.ld $< -o $@
	arm-none-eabi-size $@
build/sniff.bin: build/sniff.elf
	arm-none-eabi-objcopy -O binary $< $@
clean:
	rm -rf build
host-recovery: build/m1-nested build/m1-hardnested
host-hardnested: build/m1-hardnested
host-mfkey: build/mfkey32 build/mfkey32v2 build/mfkey64
build/m1-nested: host/m1-nested.c $(MFKEY_COMMON)
	mkdir -p build
	gcc -O3 -Wall -Wextra -Werror -Ireference/proxmark3/common -Ireference/proxmark3/include $^ -o $@
build/mfkey32 build/mfkey32v2 build/mfkey64: build/%: reference/proxmark3/tools/mfc/card_reader/%.c $(MFKEY_COMMON)
	mkdir -p build
	gcc -O3 -Wall -Wextra -Ireference/proxmark3/common -Ireference/proxmark3/include $^ -o $@
build/m1-hardnested: scripts/build-hardnested.py host/hardnested/main.c host/hardnested/compat.h host/hardnested/ui.h host/hardnested/stream.inc reference/proxmark3/client/src/cmdhfmfhard.c $(wildcard $(HARDNESTED_REF)/*.[ch] reference/proxmark3/common/crapto1/*.[ch] reference/proxmark3/common/bucketsort.[ch] reference/proxmark3/common/parity.h reference/proxmark3/include/common.h reference/proxmark3/include/pm3_cmd.h)
	python3 scripts/build-hardnested.py
