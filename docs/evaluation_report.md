# Evaluation Report

## Detection Accuracy (Alert Fired vs. Ground Truth, threshold=40)
- Precision: 0.9318
- Recall: 0.9294
- F1 Score: 0.9306

## Confusion Matrix (alert_fired vs. is_attack)

|              | Predicted Normal | Predicted Attack |
|--------------|-------------------|-------------------|
| Actual Normal | 49136 (TN) | 134 (FP) |
| Actual Attack | 139 (FN) | 1831 (TP) |

## False Positive Rate
- FP Rate: 0.0027 (134 false positives out of 49270 true-negative cases)
- Contamination parameter used: 0.06 (matches known injection rate)

## High-Risk Tier Precision (risk_score >= 70)
- Precision: 1.0000 (4 alerts in high tier)

## Per-Class Classification Report (Random Forest attack-type prediction)
```
                   precision    recall  f1-score   support

      brute_force       1.00      1.00      1.00      1052
credential_misuse       0.62      0.96      0.75       131
  device_spoofing       1.00      1.00      1.00        99
impossible_travel       0.10      0.77      0.18       264
 lateral_movement       0.45      0.72      0.55       424
             none       1.00      0.96      0.98     49270

         accuracy                           0.95     51240
        macro avg       0.69      0.90      0.74     51240
     weighted avg       0.99      0.95      0.97     51240

```

## Notes
- Metrics are computed against synthetic ground-truth labels (`is_attack`, `attack_type`) generated alongside the data, not external validation.
- Accuracy alone is misleading on this imbalanced dataset (~6% attack rate); precision/recall/F1 and per-class metrics are reported instead.