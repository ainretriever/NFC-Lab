# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""FM11RF08S seed16 pairing: filter one slot's candidates with its partner slot.

PM3's `fm11_compute_seednt16_nt32` (client/src/cmdhfmfsen.c:990) is an invariant
of a card's key/nonce generation: a sector's two slots derive their nested
nonces from one per-sector seed, so

    seed16(nt_A, K_A) == seed16(nt_B, K_B)

holds even when Key A and Key B differ.  Verified on a laboratory card (three
sectors, three different key pairs).  It lets the counterpart slot's key-free
candidate list filter this slot's ~2^16 candidates and order the survivors so
that "1+1" buckets -- one candidate on each side -- are verified first, where a
failed authentication eliminates both candidates at once.

Read-only, pure computation: nothing here touches the transport.
"""

__all__ = ['seed16', 'pair_candidates']

_SEED_TABLES = None
_SEED_A = (0, 8, 9, 4, 6, 11, 1, 15, 12, 5, 2, 13, 10, 14, 3, 7)
_SEED_B = (0, 13, 1, 14, 4, 10, 15, 7, 5, 3, 8, 6, 9, 2, 12, 11)


def _seed_tables():
    """`fm11_init_lfsr16_table`: 16-bit LFSR predecessor tables (65536 entries)."""
    global _SEED_TABLES
    if _SEED_TABLES is None:
        prev8, prev14, buf = [0] * 65536, [0] * 65536, [0] * 16
        x = 1
        for i in range(65536 + 16):
            prev8[buf[(i + 8) % 16]] = buf[i % 16]
            prev14[buf[(i + 14) % 16]] = buf[i % 16]
            x = ((x >> 1) | ((x ^ (x >> 2) ^ (x >> 3) ^ (x >> 5)) << 15)) & 0xFFFF
            buf[i % 16] = ((x & 0xFF) << 8) | (x >> 8)
        _SEED_TABLES = (prev8, prev14)
    return _SEED_TABLES


def seed16(nt, key):
    """The sector seed behind a (plaintext nonce, key) pair."""
    prev8, prev14 = _seed_tables()
    value = prev14[(nt >> 16) & 0xFFFF]
    odd = True
    for shift in range(0, 48, 8):
        first, second = (_SEED_A, _SEED_B) if odd else (_SEED_B, _SEED_A)
        value ^= first[(key >> shift) & 0xF]
        value ^= second[(key >> (shift + 4)) & 0xF] << 4
        odd = not odd
        value = prev8[value & 0xFFFF]
    return value


def pair_candidates(primary, nt_primary, secondary, nt_secondary):
    """Keep `primary` candidates whose seed also occurs in `secondary`.

    Returns (ordered, stats).  Ordering is by ascending bucket size, so "1+1"
    pairs come first: one on-card authentication then confirms the key or
    eliminates both candidates.  An empty result means the two slots disagree
    (bad evidence, or a card without the invariant), so the caller falls back to
    the untouched list.
    """
    buckets = {}
    for key in secondary:
        value = seed16(nt_secondary, int.from_bytes(key, 'big'))
        buckets[value] = buckets.get(value, 0) + 1
    scored = []
    for key in primary:
        count = buckets.get(seed16(nt_primary, int.from_bytes(key, 'big')), 0)
        if count:
            scored.append((count, key))
    if not scored:
        return list(primary), {'paired': 0, 'primary': len(primary), 'secondary': len(secondary)}
    scored.sort(key=lambda item: item[0])
    stats = {'paired': len(scored), 'primary': len(primary), 'secondary': len(secondary),
             'singleton_buckets': sum(1 for count, _ in scored if count == 1)}
    return [key for _, key in scored], stats


def derive_partner(primary_key, other_candidates, nt_primary, nt_other):
    """The partner key implied by a recovered primary key, when unambiguous.

    In a "1+1" bucket the peer candidate is *provably* the other key: the true
    counterpart also carries the primary key's seed, and it must be in the
    enumerated list.  Returns it only when exactly one candidate matches -- PM3
    does the same in `fm11_derive_pair_key`.
    """
    seed = seed16(nt_primary, int.from_bytes(primary_key, 'big'))
    matches = [key for key in other_candidates
               if seed16(nt_other, int.from_bytes(key, 'big')) == seed]
    return matches[0] if len(matches) == 1 else None
