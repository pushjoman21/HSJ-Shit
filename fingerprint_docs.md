# hCaptcha HSJ Fingerprint 

Event ids are runtime hashes of the internal names; they are stable across
current builds, so this table is reusable. Values come in three classes:
**static** (hardware/version constants), **hashed** (xxHash64 digests of a
browser value), and **dynamic** (regenerated every request).

---

## 1. Envelope

The decrypted fingerprint is a JSON object:

| key | value |
|-----|---------|
| `proof_spec` | echoes the challenge JWT: `difficulty (s)`, `fingerprint_type (f)`, `_type (t)`, `data (d)`, `_location (l)`, `timeout_value` |
| `rand` | `[float 0..1, crc32(enc)*2^-32]` — a self-checksum of the encrypted blob |
| `components` | the structured browser object (see §6) |
| `events` | the 54 `[id, value]` probes (this whole document) |
| `suspicious_events` | `[]` when nothing tripped the anti-tamper traps |
| `messages` | `null` |
| `stack_data` | Error().stack frames, e.g. `["Array.forEach (<anonymous>)", …]` |
| `stamp` | a hashcash PoW over the JWT `d` at difficulty `s` (`1:2:<date>:<d>::<salt>:<counter>`) |
| `href` | the page that hosts the widget |
| `ardata` | `null` |
| `errs` | `{"list":[]}` |
| `perf` | `[[1,navMs],[2,domMs],[3,ttfbMs]]` page-load timing buckets |

---

## 2. Constants & timing-independent flags

### `i3k` — id `2960921106` — value `57`
A fixed browser-family marker: **57** = desktop Chromium, `21` = Firefox, `6` =
mobile. Change only if you switch browser engine.

### `jsw` — id `512466081` — value `true`
A capability boolean (a specific feature-detection result). Stays `true` on
desktop Chrome.

### `82x` — id `227385953` — value `[0,1,2,3,4]`
Indices of the detected browser extensions/content-scripts surface. `[0,1,2,3,4]`
= the clean baseline (no injected extensions). A real extension would perturb it.

### `10he` — id `2227687026` — value `704`
Number of enumerable `CSSStyleDeclaration` properties (`getComputedStyle` length).
**Version-specific** — it grew with each Chrome release; 704 is Chrome 148.

### `gx4` — id `2075271940` — value `1231`
Count of enumerable `window` properties. **Version-specific** and also affected by
how many globals the host page leaks; 1231 matches Chrome 148 on these pages.

### `fl` — id `1785809168` — value `[1,4,5,7,9,12,20,21,24,25,30,32]`
Indices of supported feature flags (a fixed capability bitmap for Chrome 148).

### `3554…`-style feature list — id `1549597269` — value `[16,1024,4096,7,12,120,[23,127,127]]`
`wgp2`, a second WebGL parameter block (see §4).

---

## 3. Identity: navigator, UA-CH, timezone, screen

### `17ud` — id `972286032`
`["5.0 (Windows NT 10.0; Win64; x64) … Chrome/148.0.0.0 Safari/537.36",
"Mozilla/5.0 … Chrome/148.0.0.0 …", 32, 8, "de-DE", ["de-DE"], "Win32", null,
["Chromium 148","Google Chrome 148","Not/A)Brand 99"], false, "Windows", 2, 5,
true, false, 0, false, false, true, "[object Keyboard]", false, false]`
The big `navigator` snapshot: `appVersion`, `userAgent`, **hardwareConcurrency
(32)**, **deviceMemory (8)**, `language`, `languages`, `platform`, brands,
`webdriver=false`, UA-platform, `maxTouchPoints`, etc. Must agree with the
`Accept-Language` header (`de-DE,de;q=0.9`) and every other identity field.

### `7du` — id `2510199053` — value `["Windows","14.0.0",null,"64","x86","148.0.7778.96"]`
`navigator.userAgentData.getHighEntropyValues`: platform, **platformVersion
14.0.0** (Windows 11), bitness `64`, arch `x86`, **full Chrome version
148.0.7778.96**. Bump all three on a Chrome update.

### `504…`/navigator brands appear here too — keep brands order `Chromium, Google Chrome, Not/A)Brand`.

### `27x` — id `928315974` — value `"Europe/Berlin"`
`Intl.DateTimeFormat().resolvedOptions().timeZone`. Must match the proxy/IP
region and `r66`.

### `r66` — id `4056645837` — value `["Europe/Berlin",-60,-60,-3203646808000,"Mitteleuropäische Normalzeit","de"]`
Timezone detail: IANA name, **two −60 UTC offsets** (CET = UTC+1 → −60 min),
a fixed epoch probe, the localized zone name, and the locale. Change all parts
together when you change timezone.

### `r5d` — id `1923420777` — value `[2560,1440,2560,1392,32,32,false,0,1,2560,1392,true,true,true,false]`
Screen geometry: `width, height, availWidth, availHeight, colorDepth,
pixelDepth, touch?, screenX, screenY, innerW, innerH, …flags`. The window inner
size `[2560,1392]` (maximised) must match the motion `wi`/viewport.

---

## 4. GPU & WebGL

### `12ry` — id `1874930862`
`["Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 (0x00001B80)
Direct3D11 vs_5_0 ps_5_0, D3D11)"]` — `UNMASKED_VENDOR_WEBGL` and
`UNMASKED_RENDERER_WEBGL`. The single most identifying GPU string; change it and
you change `1267…`/`3320…` hashes too.

### `wgp1` — id `1003733233` — `[16,4095,30,16,16380,120,12,120,[23,127,127]]`
WebGL limits block 1: max texture units, max texture size, max varying vectors,
max vertex attribs, max viewport dims, point-size range, etc.

### `wgp2` — id `1549597269` — `[16,1024,4096,7,12,120,[23,127,127]]`
WebGL limits block 2 (vertex-shader side).

### `wgm` — id `1121094594` — `[32767,32767,16384,8,8,8]`
`MAX_VIEWPORT_DIMS`, `MAX_TEXTURE_SIZE`, draw-buffer / colour-attachment counts.

### `wgs` — id `1504773159` — `[4294967295,4294967295,4294967295,4294967295]`
Stencil/colour write-mask bits (all-ones = default).

### `wgsh` — id `2156596846` — `[1,1024,1,1,4]`
Shader precision/uniform counts.

### `wgt` — id `2014919491` — `[16384,32,16384,2048,2,2048]`
Texture-related maxima (max combined texture units, etc.).

### `wgpr` — id `3105246452` — `[24,24,65536,212988,200704]`
Renderbuffer / framebuffer precision and size limits.

### `wgv` — id `4067378073` — `[4,120,4]`
Aliased line-width / point range.

### `wgir` — id `729882719` — `[2147483647,2147483647,4294967294]`
Integer range maxima (`getShaderPrecisionFormat` HIGH_INT etc.).

All WebGL blocks are driver/GPU specific — they go together with `12ry`.

---

## 5. Canvas, audio, fonts, media (mostly hashed)

### `195a` — id `1821788771`
`[[195,[195,195,195,255, …]], [[11,0,0,95.96875,15,4,96.765625], …], [0,2,8,…],
[0,0,0,0,14,3,0]]` — a combined **2D-canvas + text-metrics** probe: the first
sub-array is the rendered pixel colour (`195` grey here — driver/AA dependent),
then per-glyph `measureText` boxes, then the set of supported features, then a
small render signature.

### `ct` — id `1893153525`
`[-6.172840118408203, -20.710678100585938, 120.71067810058594, …, 300,150,false]`
The 2D-canvas **transform matrix** readback (sub-pixel float values from
`getTransform` after a known sequence) plus the canvas size `300×150`. The exact
floats are GPU/driver fingerprints.

### `shb` — id `1488184928`
`[[277114314493, 277114314500, …], false]` — the **AudioContext** offline-render
fingerprint: a vector of fixed-point sample sums from an oscillator→compressor
graph, then a boolean. Hardware/OS-audio specific.

### `spv` — id `2046052677`
`[[true,"en-US",true,"Microsoft Zira Desktop - English (United States)", …],
[false,"de-DE",false,"Google Deutsch", …], …]` — `speechSynthesis.getVoices()`:
default flag, lang, localService flag, voice name ×N. The Windows "Zira" + Google
voices set is a strong Windows/Chrome marker. (Excluded on Discord.)

### Hashed digests (xxHash64, seed `5575352424011909552`) — values are 64-bit strings:

| name | id | value | what is hashed |
|------|----|-------|----------------|
| `8s3` | `136692570` | `17157476241021694346` | font-metrics matrix |
| `txj` | `613978715` | `2545642147239152397` | audio render hash |
| `g0z` | `629163118` | `2328426096820180459` | WebGL image (PNG) readback |
| `sh2` | `1002973073` | `7922971862977304831` | WebGL extensions list |
| `sh1` | `1155257292` | `9345374751420407194` | CSS property-name set |
| `6um` | `1164199780` | `10522223096745564852` | font-rendering hash |
| `102q` | `1479662678` | `11357783768420648559` | GPU + WebGL extension combo |
| `h3z` | `1646316944` | `13442721369554225092` | large-canvas PNG |
| `sh3` | `1936889408` | `16927405672252548354` | media-capabilities probe |
| `r0t` | `2051168073` | `756874611071873095` | error-message / canvas string |
| `g18` | `2234310443` | `9549980226303614831` | window-property set |
| `49q` | `3028026278` | `4932383211497360507` | pixel-colour vector |
| `1cp5` | `3205381920` | `8022061930804573802` | small-canvas PNG |
| `lwf` | `3479481863` | `17534494769247407336` | WebGL numeric params |

These are deterministic for one machine; copy them as a set from a real capture
of the GPU/OS you are emulating. They cannot be hand-edited piecemeal.

---

## 6. Storage, browser surface, CSS

### `b48` — id `790389308` — `[5368709120,5368709120,null,null,4294967296,true,true,true,null]`
`navigator.storage.estimate()` quota (5 GiB here) + heap limits + capability
booleans. The quota scales with disk; keep both quota fields equal.

### `tbh` — id `843426934`
`[["loadTimes","csi","app"],35,34,null,false,false,true,37,true,true,true,true,
true,["Raven","_sharedLibs","__wdata","hsj"],[],[2],true]` — the `window.chrome`
surface (`loadTimes/csi/app`), a set of capability flags, and the page-global
key sample (`Raven`, `_sharedLibs`, `__wdata`, `hsj`). The leaked globals depend
on the host page; the rest is Chrome-constant.

---

## 7. Dynamic events (regenerated every request)

These are NOT static — the solver builds them per request and they must stay
mutually consistent in time.

| name | id | example | meaning |
|------|----|---------|---------|
| `vey` | `2345353748` | `9430.0999…` | `performance.now()` at collection |
| `k4h` | `3869360008` | `1778493488641.5` | `Date.now()` style timestamp |
| `2rx` | `2281997539` | `611.0999…` | elapsed-since-load |
| `tmv` | `2276650199` | `20.5` | a sub-timing |
| `ftl` | `2501895723` | `86.19…` | another sub-timing |
| `gsh` | `2272195047` | `[11]` | local hour-of-day |
| `9t3` | `300972553` | `["gJ…","9","8","MCD…"]` | oA-obfuscated timezone |
| `142e` | `2790560789` | `[["Nx…","1a","1c","BV…"],[…]]` | oA-obfuscated GPU strings |
| `qer` | `3770970216` | `["Yd…","19","5","JE…"]` | oA-obfuscated storage quota |
| `ixo` | `3762753378` | `[[["",568893,1],[hsw.js,0,3]],[["*",84,9]]]` | resource-timing entries |
| `perf` | `3456635976` | `[["fetch:…",21.2,103.1],…]` | named performance entries |
| `1bck` | `3439942679` | `[0,10357,10357]` | recursion stack-depth probe |
| `arh` | `2425213868` | `[[0,"<frame>"],…]` | the full interaction recording (== `motionData.vmdata`, see `REVERSE_VMDATA.md`) |

`oA(...)` is hCaptcha's reversible string obfuscation: reverse words, Caesar-shift
by a random key, URL-encode, base64, rotate, case-flip — emitted as
`[payload, shiftHex, offsetHex, keyLetters]`. The shift/offset/key are random per
call, so `9t3`/`142e`/`qer` look different every time while decoding to the same
timezone/GPU/quota.

---

## 8. `components` object

The structured sibling of the events. Key fields and how they must line up:

| field | value | note |
|-------|-------|------|
| `chrome` | `true` | `window.chrome` present |
| `to_string_length` | `33` | `Function.prototype.toString` length probe (anti-hook) |
| `notification_api_permission` | `"Denied"` | matches `Notification.permission` |
| `canvas_hash` | `"6763452924025063800"` | 2D-canvas digest (matches `195a`) |
| `web_gl_hash` / `webrtc_hash` / `audio_hash` | `"-1"` | not separately exposed here |
| `has_touch` | `false` | desktop |
| `has_indexed_db` / `has_local_storage` / `has_session_storage` | `true` | |
| `r_bot_score` / `r_bot_score_2` | `0` | internal heuristic must read clean |
| `r_bot_score_suspicious_keys` | `[]` | no automation globals detected |
| `err_firefox` | `null` | Chrome → null |
| `extensions` | `[false]` | no extension fingerprint |
| `device_pixel_ratio` | `1.0` | matches screen |
| `navigator.*` / `screen.*` | mirror `17ud`/`r5d` | must be identical |
| `parent_win_hash` / `performance_hash` | random 64-bit | per-session |
| `unique_keys` / `inv_unique_keys` / `common_keys_hash` / `common_keys_tail` | per-site | the host page's global-name fingerprint (Steam/Epic/Discord differ) |

---
