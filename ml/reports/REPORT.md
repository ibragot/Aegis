# Aegis ML evaluation report

Generated 2026-11-02T23:25:45.373330+00:00 by `aegis train` (seed 7). All numbers are on the held-out **test** split (different days and random seed than training).

## Data

| split | events | malicious |
|---|---:|---:|
| train | 50,426 | 567 |
| validation | 10,800 | 328 |
| test | 14,300 | 458 |

Features per event: 32. Unsupervised thresholds target a 0.5% false-positive rate on benign validation events; XGBoost's threshold maximizes F1 on validation.

## Event-level detection quality

| detector | precision | recall | F1 | FPR | ROC-AUC | PR-AUC | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| isolation_forest | 0.786 | 0.627 | 0.697 | 0.0056 | 0.9932 | 0.8377 | 287 | 78 | 171 |
| autoencoder | 0.885 | 0.758 | 0.817 | 0.0032 | 0.997 | 0.9262 | 347 | 45 | 111 |
| xgboost | 0.996 | 0.996 | 0.996 | 0.0001 | 1.0 | 1.0 | 456 | 2 | 2 |
| markov_sequence | 0.766 | 0.465 | 0.579 | 0.0047 | 0.8475 | 0.4353 | 213 | 65 | 245 |
| ensemble | 0.942 | 0.996 | 0.968 | 0.0020 | 0.9989 | 0.9887 | 456 | 28 | 2 |
| rules_engine | 0.997 | 0.681 | 0.809 | 0.0001 | - | - | 312 | 1 | 146 |
| rules_plus_ml | 0.941 | 1.000 | 0.969 | 0.0021 | - | - | 458 | 29 | 0 |

## Attack-instance detection (caught at least one event of the attack)

| detector | credential_compromise | data_exfiltration | defense_evasion | internal_recon | k8s_compromise | password_spray |
|---|---:|---:|---:|---:|---:|---:|
| isolation_forest | 1/1 | 1/2 | 2/2 | 2/2 | 1/1 | 2/2 |
| autoencoder | 1/1 | 2/2 | 2/2 | 2/2 | 1/1 | 2/2 |
| xgboost | 1/1 | 2/2 | 2/2 | 2/2 | 1/1 | 2/2 |
| markov_sequence | 1/1 | 0/2 | 2/2 | 2/2 | 1/1 | 2/2 |
| ensemble | 1/1 | 2/2 | 2/2 | 2/2 | 1/1 | 2/2 |
| rules_engine | 1/1 | 2/2 | 2/2 | 2/2 | 1/1 | 2/2 |
| rules_plus_ml | 1/1 | 2/2 | 2/2 | 2/2 | 1/1 | 2/2 |

## Inference latency (milliseconds per event, CPU)

| stage / model | batched (500-1000 events) | single event (median) |
|---|---:|---:|
| feature_extraction | 0.0306 | - |
| isolation_forest | 0.0169 | 7.738 |
| autoencoder | 0.0006 | 0.178 |
| xgboost | 0.0016 | 0.158 |
| markov_sequence | 0.0013 | 0.0013 |

## Novel-attack test (event recall per scenario)

`xgboost_unseen` = XGBoost retrained with that scenario removed from its training data.

| scenario | xgboost (seen) | xgboost (unseen) | autoencoder | isolation_forest | ensemble |
|---|---:|---:|---:|---:|---:|
| credential_compromise | 0.991 | 0.948 | 0.948 | 0.914 | 0.991 |
| data_exfiltration | 1.0 | 0.0 | 0.496 | 0.216 | 1.0 |
| defense_evasion | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| internal_recon | 0.992 | 0.0 | 1.0 | 0.967 | 0.992 |
| k8s_compromise | 1.0 | 0.0 | 1.0 | 1.0 | 1.0 |
| password_spray | 1.0 | 0.947 | 0.386 | 0.158 | 1.0 |

## Most important XGBoost features

- `rate_5m` (0.4638)
- `src_hosting` (0.2023)
- `is_failure` (0.0755)
- `rate_ratio` (0.0572)
- `failures_10m` (0.0506)
- `cat_application` (0.0503)
- `log_bytes_out` (0.0374)
- `distinct_resources_10m` (0.011)
- `transition_rarity` (0.0097)
- `cat_resource` (0.0074)

## How to read this

- **Precision**: of the events we flagged, how many were really malicious (analyst time well spent).
- **Recall**: of the malicious events, how many we flagged.
- **FPR**: share of benign events flagged. At SIEM volumes even 0.5% is a lot - this is why the correlator groups alerts into incidents instead of paging on every alert.
- Event-level recall is naturally below 100%: many attacker actions (e.g. a `DescribeInstances`) look exactly like normal work. Attack-instance detection is the number that matters for response.
- XGBoost scores well because it is trained on labels from the *same simulator* - in the real world labels are scarce and attacks evolve, which is why unsupervised models are kept alongside it.
