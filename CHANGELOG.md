# Changelog

## 0.1.0 (2026-10-17)


### Features

* **core:** build flows from the inner packets of INT telemetry reports ([#3](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/issues/3)) ([cdfc3ad](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/commit/cdfc3adaa0dbd01728d73dd8fec7de0bc8edecd8))
* **core:** implement pcap analysis prototype ([#1](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/issues/1)) ([4d8604c](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/commit/4d8604c0c75cf0e55c9c21239d95d6bdc68f8c95))
* **gui:** refresh the desktop app's palette and make the overview interactive ([#4](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/issues/4)) ([e8d7264](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/commit/e8d7264d326f0696301554f5266fa0718f885f8a))


### Bug Fixes

* **client:** report an unreachable backend as an ApiError. httpx transport errors are not OSErrors, so they escaped every caller and left the desktop app stuck on Connecting. ([e8d7264](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/commit/e8d7264d326f0696301554f5266fa0718f885f8a))


### Performance Improvements

* **gui:** sort and filter the flow table in Python, and reload history on entry ([#5](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/issues/5)) ([f5b3462](https://github.com/HeriLFIU/ciara-pcap-manager-prototype/commit/f5b34620a0a7058ca564463fa9aed846b26d8473))
