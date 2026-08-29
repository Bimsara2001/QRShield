# QRShield Credential Rotation Required

## Source remediation status

Source remediation is complete for the credentials identified during the I4 audit:

| Service | Former tracked location | Current configuration | Rotation status |
| --- | --- | --- | --- |
| MongoDB | `Backend/database.py` | `MONGO_URI` environment variable | **Manual rotation required** |
| VirusTotal | `Backend/threat_intel/virustotal.py` | `VIRUSTOTAL_API_KEY` environment variable | **Manual rotation required** |

Actual credential values and fingerprints are intentionally not recorded here.

## Required manual action

Revoke or rotate both previously exposed credentials in their respective provider consoles, provision replacement values through the deployment environment or a secret manager, and verify the deployed service uses only the replacements. Removing values from source does not revoke values already copied, committed, logged, cached, or retained in Git history.

This repository does not rewrite Git history automatically. Rotation must not be marked complete until the service owner independently verifies it.
