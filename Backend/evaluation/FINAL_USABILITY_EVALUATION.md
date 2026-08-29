# QRShield Final Usability Evaluation

## Methodology

This report descriptively analyzes the final Google Forms export, `evaluation/data/usability/QRShield Usability Evaluation (Responses) .xlsx`. The final form contains participant/device information, nine task-completion items, ten Nielsen heuristic items, seven QRShield-specific experience items, and three optional free-text items. Task success means either **Completed easily** or **Completed with difficulty**. Means preserve the original 1–5 response scales; standard deviations are sample standard deviations (N-1). No missing value was imputed and no response was altered.

## Participants and data validation

Five valid, anonymized participants responded: P1, P2, P3, P4, and P5. Three tested on an Android Phone and two on an Android Emulator.

| Validation check | Result |
| --- | --- |
| Total responses | 5 |
| Unique participant IDs | P1, P2, P3, P4, P5 |
| All expected P1–P5 IDs present | Yes |
| Duplicate participant IDs | None |
| Missing required responses | None |
| Invalid task responses | None |
| Invalid Likert values | None |
| Unexpected questions/columns | None; `Timestamp` is Google Forms metadata |
| Optional blank responses | 2 blank improvement comments |

The dataset is valid for the intended N=5 analysis. The two blank improvement comments are optional and were not repaired or imputed.

## Task-completion results

| Task | Easily | With difficulty | Failed | Successful | Success rate | Easy-completion rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| T1 Open application | 3 | 2 | 0 | 5 | 100.00% | 60.00% |
| T2 Scan safe QR code | 5 | 0 | 0 | 5 | 100.00% | 100.00% |
| T3 Identify risk level | 5 | 0 | 0 | 5 | 100.00% | 100.00% |
| T4 View destination preview/screenshot | 5 | 0 | 0 | 5 | 100.00% | 100.00% |
| T5 Analyze safe URL manually | 5 | 0 | 0 | 5 | 100.00% | 100.00% |
| T6 Open and locate a history item | 5 | 0 | 0 | 5 | 100.00% | 100.00% |
| T7 Find Backend Status | 5 | 0 | 0 | 5 | 100.00% | 100.00% |
| T8 Locate Clear History | 5 | 0 | 0 | 5 | 100.00% | 100.00% |
| T9 Submit invalid URL and identify error | 5 | 0 | 0 | 5 | 100.00% | 100.00% |

Across 45 task observations, 45 were successful (100.00% overall task success), 43 were completed easily (95.56% overall easy completion), and there were no failures. T1 had the most difficulty: 2 of 5 participants completed it with difficulty. No task had any failures.

## Nielsen 10-heuristic results

Scale: 1 = Very Poor; 5 = Excellent.

| # | Heuristic | N | Mean | Median | Min | Max | SD |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Visibility of system status | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| 2 | Match between system and the real world | 5 | 4.60 | 5.00 | 4 | 5 | 0.548 |
| 3 | User control and freedom | 5 | 4.60 | 5.00 | 4 | 5 | 0.548 |
| 4 | Consistency and standards | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| 5 | Error prevention | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| 6 | Recognition rather than recall | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| 7 | Flexibility and efficiency of use | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| 8 | Aesthetic and minimalist design | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| 9 | Help users recognize, diagnose, and recover from errors | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| 10 | Help and documentation | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |

The overall Nielsen mean across all 50 ratings is **4.92/5**. The highest-rated heuristics were 1 and 4–10 (all 5.00); the lowest-rated were heuristic 2 and heuristic 3 (both 4.60). These are descriptive observations only and do not establish statistical significance.

## QRShield experience results

Scale: 1 = Strongly Disagree; 5 = Strongly Agree.

| Item | N | Mean | Median | Min | Max | SD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| QR scanning process was easy to understand | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| Low/Medium/High results were clear | 5 | 4.80 | 5.00 | 4 | 5 | 0.447 |
| Risk score was easy to understand | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| Destination screenshot/preview was useful | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| Reasons for detected risks were understandable | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |
| Confidence checking unfamiliar QR codes | 5 | 4.80 | 5.00 | 4 | 5 | 0.447 |
| Overall QRShield was easy to use | 5 | 5.00 | 5.00 | 5 | 5 | 0.000 |

The overall QRShield experience mean across 35 ratings is **4.94/5**. The highest-rated items were QR-scan understanding, risk-score understanding, preview usefulness, understandable reasons, and overall ease of use (all 5.00). The lowest-rated items were clarity of Low/Medium/High results and confidence before opening an unfamiliar QR code (both 4.80).

## Qualitative findings

The qualitative responses are summarized as descriptive counts, not population estimates.

- Three of five participants reported that nothing was confusing. One mentioned initial risk-score interpretation and one described some scan details as technical.
- Two of five participants liked the simple QR-scanning process; two liked the destination/website preview; one liked the clear risk result.
- Two of five participants recommended clearer explanations of the risk score or detected risks, and one recommended faster scanning. Three participants supplied an improvement recommendation; two left that optional item blank.

## Interpretation and limitations

Observed in this controlled N=5 evaluation, every recorded task was successfully completed and ratings were high on the supplied Likert items. The comments indicate that risk-result explanation and some technical details are the main areas participants raised, alongside a single suggestion on scanning speed. These observations support completion of the specified usability-evaluation evidence requirement; they do not justify tuning the application or making broad usability claims.

This is a small usability sample (N=5). Recruitment documentation does not establish random sampling, so it should be treated as a convenience/usability evaluation sample. Ratings are self-reported, task success was measured in a controlled evaluation context, and the results must not be generalized to the whole population or treated as statistically significant.

## Final conclusion

The final response export contains at least five valid participants, the intended T1–T9 completion evaluation, all ten Nielsen heuristic items, and preserved calculated evidence. The proposal requirement **H6 — Nielsen 10-heuristic usability study, >=5 participants** is therefore **COMPLETE**. The overall proposal remains **PARTIAL** because unrelated H5 rendered-page/sandbox accuracy evidence is outstanding and I4 privacy/data-retention evidence remains partial.
