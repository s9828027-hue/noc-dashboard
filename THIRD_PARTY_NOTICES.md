# Third-party notices / 第三方元件聲明

`dashboard.html` embeds the following third-party code and data so that the wallboard works without internet access.
`dashboard.html` 內嵌了下列第三方程式與資料,讓大螢幕在不能連外網的環境也能運作。

## d3-geo (ISC License)

A trimmed build of [d3-geo](https://github.com/d3/d3-geo) (orthographic projection and great-arc interpolation only).

```
Copyright 2010-2024 Mike Bostock

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
```

See the upstream repository for the complete license file.

## Map data

- **Natural Earth** (public domain) — land and country outlines. <https://www.naturalearthdata.com/>
- **world-countries** by Mohammed Le Doze (ODbL 1.0) — country coordinates. <https://github.com/mledoze/countries>

## IP geolocation (not included in this repository)

The country map in a real deployment reads an offline IP-to-country database that you download yourself
(see the header of `threat_map_data.py`). When using the free DB-IP Lite database, attribution is required
(CC BY 4.0): "IP Geolocation by [DB-IP](https://db-ip.com)". The wallboard already shows this credit.
