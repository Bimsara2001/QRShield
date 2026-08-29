# Final H5 Blocker Closeout

## Decision

H5 remains **OUTSTANDING**. No valid rendered-page/sandbox classification
result exists, so no H5 metrics, confusion matrix, or compliance completion
claim has been created.

## Frozen corpus integrity

The retained benchmark corpus was verified before this final controlled
attempt:

- manifest cases: 50 (25 benign and 25 phishing-like);
- manifest SHA-256: `c0a39dfbbba4b538a61b3f38e61a80d70f90987a661fb25bbe4d63ed67431dfa`;
- manifest hash matches `pre_execution_integrity.json`;
- every fixture SHA-256 matches its frozen manifest value;
- the pre-execution record remains `prediction_started: false`.

The corpus was neither regenerated nor edited.

## Worker and trust investigation

`qrshield-sandbox-worker:latest` is based on Ubuntu 24.04 (Noble), uses
`apt`/`dpkg`, runs `/app/worker.py` as the non-root `qrshield` user, and
contains `update-ca-certificates`. It does not contain `certutil`, an NSS
database, or a cached `libnss3-tools` package. The previous evaluation-only
system-CA overlay did not make Chromium accept the short-lived local CA.

For this final attempt, an evaluation-only Dockerfile was prepared to inherit
the frozen worker and install only Ubuntu's official `libnss3-tools`, allowing
the runtime CA to be imported into a temporary `sql:$HOME/.pki/nssdb` profile.
The Docker build was allowed to use only `archive.ubuntu.com` and
`security.ubuntu.com`. It began downloading official package indexes, but
repeatedly retried index downloads for more than six minutes and did not
complete or produce `qrshield-h5-eval-worker:temporary`. No arbitrary binary,
third-party repository, or test-page download was used.

Without that official NSS tooling, normal Chromium trust cannot be established
in the available worker image. Proceeding would require an impermissible
certificate-ignore flag, an HTTP fallback that changes frozen URL scoring, or
an unsupported trust-store workaround. None was used.

## Benchmark and safety result

No preflight browser success was obtained in this final attempt; therefore no
labelled case was navigated, rendered, scored, or classified. There are no H5
result files under `evaluation/evidence/h5_rendered_benchmark/`.

TLS certificate and hostname validation remained enabled. Production `/scan`,
production SSRF policy, `qrshield-sandbox-worker:latest`, detector code,
thresholds, weights, keywords, VirusTotal behavior, MongoDB behavior, and all
prior frozen evaluation evidence were not modified. No live phishing site was
visited.

## Cleanup and claim boundary

The stalled disposable build was stopped. It produced no evaluation worker
image. Temporary build logs, runtime CA material, evaluation containers,
evaluation networks, and derived evaluation images are removed; production
images and containers are unaffected.

The prepared synthetic corpus remains a pre-execution artifact only. It is not
an H5 accuracy benchmark result and must not be used to claim rendered-page,
real-world, or population-level phishing accuracy.

## Final status

The proposal-compliance matrix is intentionally unchanged: H5 remains
**OUTSTANDING** and the overall proposal status remains **PARTIAL**.
