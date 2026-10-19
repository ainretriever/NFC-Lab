# Licensing and third-party notices

Copyright (C) 2026 NFClab contributors.

NFClab project code is licensed under GNU GPL version 3 or, at your option,
any later version (SPDX: GPL-3.0-or-later). See LICENSE. This notice applies
to NFClab-authored code; original third-party copyright and license notices
remain in effect. This software comes WITHOUT ANY WARRANTY.

## Proxmark3

Upstream: https://github.com/RfidResearchGroup/proxmark3
Reference revision: dd8bf6c184c3a9e77710e17dcc89d5acf6503617.

- firmware/crypto1.h adapts common/crapto1/crypto1.c and crapto1.h.
  Copyright (C) 2008-2014 bla <blapost@gmail.com> and Proxmark3 contributors;
  GPL-3.0-or-later. NFClab changes provide bounded, allocation-free operations.
- scripts/m1_fingerprint.py ports the Classic fingerprint rules from
  client/src/cmdhfmf.c. The Fudan recovery helpers in scripts/m1_sen*.py
  adapt the public algorithms in client/src/cmdhfmfsen.c. These adaptations
  are distributed under GPL-3.0-or-later with NFClab's reduced hardware scope.
- resources/mfc_default_keys.dic contains the public upstream default-key
  dictionary, with an NFClab provenance header. It is not a collection of
  private card keys. Proxmark3 contributors; GPL-3.0-or-later.
- host/m1-nested.c links the upstream crapto1 core. host/hardnested contains
  NFClab's GPL-3.0-or-later adapter; see host/hardnested/NOTICE.md for the
  upstream GPL-2.0-or-later, GPL-3.0-or-later and permissive component notices.
- Upstream sources are not bundled in this source release. Build them from
  the pinned upstream checkout, preserving all upstream notices. If you
  distribute linked executables, also provide their complete corresponding
  source, including the upstream components, build scripts and licenses.

## Momentum / Flipper references

https://github.com/Next-Flip/Momentum-Firmware
Reference revision: d3f89dfe2ef6b01839201598e9be1590cba80322.
The default-key dictionary provenance also references Momentum's redistribution.
Protocol and hardware implementation comments reference Flipper's NFC work.
No Momentum source tree or firmware binaries are included in this release.
