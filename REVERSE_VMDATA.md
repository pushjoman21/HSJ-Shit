# hCaptcha `vmdata` — Reverse Engineering

What you need to know to forge `vmdata` (and the `arh` fingerprint event, which
is the same thing). Scope: **only the vmdata VM and its output format** — not the
rest of the motion payload.

Ground truth: a captured **steam_signup** request (checkbox) + a decrypted real
**epicgames_login** fingerprint (invisible), Chrome **148.0.7778.96**.

---

## The "VM"

Each hCaptcha frame (the host page and every captcha iframe) runs a small
recorder — internally a serializer/"VM" that walks the frame's collected state
(geometry, event streams, render-channel hashes) and emits one fixed-shape
array. `vmdata` is the list of those arrays, one per frame, each tagged:

```
vmdata = [[tag, frameJSON], …]            // frameJSON is a JSON *string*
```

- **checkbox** → 3 frames: tag `0` = parent page, `2` = challenge iframe,
  `1` = checkbox iframe.
- **invisible** → 1 frame (parent only).

Two independent things share this exact serialization:
- the `motionData.vmdata` field (plaintext form field), and
- the encrypted-fingerprint event **`2425213868`** ("arh").

They are **byte-identical** — same frames, same signature. Build once, reuse.
(A common mistake is truncating arh to `vmdata[0]`; it is the whole thing.)

The per-frame `signature` (`[21]`, base64 of 96 random bytes) is **the same
across all frames of one capture** — it's the session signature, not per-frame.

---

## Checkbox frame — 22 elements

```
[ 0] session_id   number   (parent: 15-digit random; child iframes: 0)
[ 1] url          document / iframe URL
[ 2] content      [w,h]    (parent content box; checkbox [302,76]; challenge [300,150])
[ 3] outer        [w,h]    window outer size
[ 4] scroll       [0,0]
[ 5] []
[ 6] selectors    parent only — mangled host element ids (≈ first5+last5 of each id)
[ 7] null
[ 8] 0
[ 9] url          == [1]
[10] content      == [2]
[11] events       keyed event streams (below)
[12] wi           [w,h]    widget container size
[13] ws           render signature (below)
[14] star         [] parent / ["*"] child iframes
[15] 1
[16] avail        [availWidth, availHeight]
[17] null
[18] screen       [width, height]
[19] frame_info   [ver, {}, {channelHashes}, ts]   (below)
[20] []
[21] signature    base64(96B) — identical for every frame
```

## Invisible frame — 13 elements

Different envelope, starts with the **document URL**:

```
[href, null, session_id, [], [], 0, href, events,
 selectors1, selectors2, frame_info, null, signature]
```

Here `frame_info` is the richer `[254, {channelEvents 20,21,30,50-53},
{channelHashes}, ts, [], []]`, and `events` adds `120`/`121` focus pairs plus
`172`/`174` invisible markers.

---

## `events` (`[11]`)

Relative timestamps are offsets from this frame's `150` base.

| key | meaning |
|-----|---------|
| `110` / `111` | mousedown / mouseup `[x,y,1,0,relTs]` |
| `112` | mousemove `[x,y,1,0,relTs]` |
| `113` / `131` | mean inter-event period of `112` / parent `pm` |
| `120` / `121` | visibility/focus pairs `[0, relTs]` (invisible) |
| `130` | reserved `[]` |
| `150` | absolute base timestamp (ms) |
| `161` | orientation `"portrait"` |
| `162` | screen object `{availWidth,…,isExtended}` |
| `164` | referrer |
| `165` | widget size `[w,h]` |
| `170` | exec mode `"m"` (checkbox) / `"api"` (invisible) |
| `171` | `pel` — host page's hCaptcha element HTML |
| `172` | `"invisible"` (invisible only) |
| `173` | theme int |
| `174` | invisible flag (bool) |

Parent frame carries the page-level metadata (`161`–`174`); child iframes carry
only the interaction streams (`110`–`113`, `130`, `131`, `150`).

---

## `frame_info` (`[19]`)

- **Parent** (`ver` 62–64): `[ver, {}, {channelHashes}, ts]`, ~13–16 hashes.
- **Child iframes** (`ver+1`): `[ver, {}, {}, null]` — empty.

`channelHashes = { "0": [type, [h,h,h,h,null,null], [], 0,0,0,0], … }`
— WebGL/canvas render-channel digests. `type` mostly `7`, some `0`/`2`;
2–4 non-null uint32 hashes each, occasionally a leading `null`.

## `ws` render signature (`[13]`)

```
[[19,1,2,5,5], [1,1,1,1], N, [d,d,d,d,d]]
```

First two arrays stable per device (draw/buffer counts); `N` (~13–22) and the
five deltas (~15–20) are frame-render timings. The same value is also POSTed as
the top-level `ws` field.

---

## Portability

The hsj.js is identical across current builds (epic / steam / discord — only the
SRI hash differs), so this frame format and the event ids are the same for every
sitekey. Per-site variation lives only in `url`/`host`/`href`, `pel`,
`selectors`, widget sizes, and `exec` mode (checkbox vs invisible).

Implemented in `modules/motiondata.py`: `_build_vmdata` (checkbox 22-element),
`_build_vmdata_invisible` (13-element), `_frame22`, `_channel_hashes`,
`_ws_frame`; consumed as `arh` in `modules/events.py` (`_build_arh`).
```
