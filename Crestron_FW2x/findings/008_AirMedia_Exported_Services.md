# [REDACTED-ID]_008: AirMedia APK — Unprotected Exported Services

## Severity: MEDIUM (CWE-749: Exposed Dangerous Method or Function)

## Summary

The AirMedia receiver APK (`com.crestron.airmedia.receiver.m360`) exports 4 services without any permission requirements. Any application on the device — or any app that can be installed — can bind to these services and interact with the AirMedia receiver.

## Exported Services (No Permission Required)

| Service | Intent Actions | Risk |
|---------|---------------|------|
| `AirMediaService` | `.BIND`, `.canvas.BIND`, `.observer.BIND`, `.canvas.launcher.BIND` | Full control of AirMedia presentation |
| `AirMediaPerformanceService` | `.performance.BIND` | Performance monitoring data access |
| `CanvasService` | `.canvas.BIND`, `.canvas.window.BIND` | Screen drawing/overlay |
| `SinkApiService` | `.sink.api.BIND` | Miracast wireless display control |

## Additional Issues

- **`usesCleartextTraffic="true"`** — Allows HTTP (not just HTTPS) for all network traffic
- **`allowBackup="true"`** — App data extractable via `adb backup`
- **Splashtop OEM permission** — `com.splashtop.m360.permission.OEM` (undocumented)
- **AirPlay service** — `com.splashtop.airplay.AirPlayService` — Apple AirPlay protocol receiver

## Impact

An attacker with local access (via ADB, sideloaded APK, or exploitation of another vulnerability) can:
1. Control what's displayed on screen via CanvasService
2. Monitor/control active AirMedia sessions
3. Intercept wireless presentation streams (Miracast, AirPlay)
4. Access performance monitoring data

Combined with Development.apk ([REDACTED-ID]_007), an attacker can install a malicious APK that binds to all exported services.

## Remediation

1. Add `android:permission` attributes to all exported services
2. Set `usesCleartextTraffic="false"`
3. Set `allowBackup="false"`
4. Restrict service exports to signed-with-same-key apps only
