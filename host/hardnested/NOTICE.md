# Hardnested attribution

The standalone executable links Proxmark3 code from `reference/proxmark3`:

- `client/src/cmdhfmfhard.c`: Proxmark3 contributors, GPL-3.0-or-later.
- `client/deps/hardnested/*`: piwi and contributors, GPL-2.0-or-later,
  including Aram Verstegen's permissively licensed bitsliced code (full notices
  remain in the upstream sources and generated build copies).
- Crypto1/crapto1 and bucketsort: retain their upstream notices.
- The lookup tables and benchmark fixture are read from the upstream resources.

The combined executable is distributed under GPL-3.0-or-later; a copy is in
[LICENSE.txt](LICENSE.txt). The adapter in this directory and the source
adaptation builder are GPL-3.0-or-later. Upstream sources remain unmodified.
The builder removes client service includes and replaces the hardware acquisition
function with a ciphertext-only streaming adapter; `main.c` exposes file and evidence-stream modes and
passes NULL for both known-key arguments. No algorithm fallback checks a
provided default key. Preserve the upstream source checkout and these build
scripts when distributing the executable's corresponding source.
