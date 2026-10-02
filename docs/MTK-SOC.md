# MediaTek SoC CCCI Plugin

This branch adds a MediaTek MT6895 CCCI plugin to ModemManager 1.24.2.

## Boundary

The plugin owns the ModemManager control plane:

- primary AT port discovery and initialization;
- SIM slot enumeration and active-slot matching;
- registration and signal-quality parsing;
- SMS bearer selection;
- MIPC direct-IP data activation/deactivation;
- optional MIPC XFRM SPI reservation for the IPsec data path.

It does not load CCCI kernel modules, start the modem, answer CCCI FS/RPC
service requests, or own `/dev/ccci_monitor`. Those responsibilities are in
`MT6895-Mainline/mtk-ccci-userspace`.

## Build

This is an upstream ModemManager fork. Use the normal ModemManager build
instructions and enable the plugin with:

```sh
meson setup build \
  -Dplugin_mtk_soc=enabled \
  -Dqmi=false \
  -Dqrtr=false \
-Dmbim=false
meson compile -C build
meson test -C build
```

The repository's complete build also needs the normal ModemManager development
dependencies, including the GLib D-Bus code-generation tools.

## Hardware contract

The plugin expects:

- a running CCCI owner exposing `ttyCCCI0` and `ccmni*`;
- the MTK MIPC direct-IP endpoint;
- a board-specific, already-validated kernel configuration;
- no vendor Android RIL or Android daemon at runtime.

It is not a generic MT6895 implementation. Board-specific assumptions must be
reviewed before enabling it on another phone.

## Status

The MIPC codec and XFRM reservation code have offline tests. Full data,
SIM, SMS, IMS, voice and long-term reliability are separate acceptance
criteria. A passing build or codec test is not proof of network registration.

The publication source was rebuilt in a separate aarch64 directory with
33/33 Meson tests passing. The MIPC codec also passed 18/18 host ASan/UBSan
tests. The kernel XFRM integration case is opt-in and skips by default;
those counts do not claim a live IMS or VoLTE test.

`QQC_MIPC_SPI_SERVICE=1` enables the experimental same-fd SPI service; it is
off by default. Diagnostic options retain their existing names so a source
publication does not silently change device behavior. Debug logs can contain
identifiers or network configuration; redact before sharing.
