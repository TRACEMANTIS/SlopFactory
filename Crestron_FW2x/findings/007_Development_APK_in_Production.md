# [REDACTED-ID]_007: Development Tools APK Shipped in Production Firmware

## Severity: MEDIUM (CWE-489: Active Debug Code)

## Summary

The production firmware (PufVersion 1.5010.00023) includes `Development.apk` (`com.android.development`) — the Android Developer Tools application — with elevated system permissions including REBOOT, DUMP, HARDWARE_TEST, SET_DEBUG_APP, KILL_BACKGROUND_PROCESSES, and Google credential access permissions.

## Evidence

**File:** `/system/app/Development.apk` (116K)

### Dangerous Permissions
| Permission | Impact |
|-----------|--------|
| `android.permission.REBOOT` | Can reboot the device |
| `android.permission.DUMP` | Can dump system state/logs |
| `android.permission.HARDWARE_TEST` | Hardware test access |
| `android.permission.SET_DEBUG_APP` | Enable debugging on apps |
| `android.permission.SET_ACTIVITY_WATCHER` | Monitor all activities |
| `android.permission.SET_PROCESS_LIMIT` | Control process limits |
| `android.permission.KILL_BACKGROUND_PROCESSES` | Kill any process |
| `com.google.android.googleapps.permission.ACCESS_GOOGLE_PASSWORD` | Access stored Google credentials |

### Also Present: `sensor.test.apk`, `TestingCamera.apk`, `SpeechRecorder.apk`
Additional test/development APKs that should not be in production.

## Impact
- Local attacker (via ADB or another app) can use Development tools to debug, dump, or reboot the device
- Expands attack surface with debug functionality not intended for production
- Combined with exported services in other APKs, creates privilege escalation path

## Remediation
Remove all development/test APKs from production firmware builds.
