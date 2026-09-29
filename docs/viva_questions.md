# XShield Viva Questions and Answers

## One-Minute Project Explanation

XShield is a defensive Flask prototype that analyzes user-controlled text for
potential XSS-related characteristics. It first validates the submitted
fields, then runs an explainable rule detector and a saved Logistic Regression
model using character-level TF-IDF features. The rule score is normalized and
combined with the ML probability using configurable 0.5 and 0.5 weights. The
hybrid signal is converted into a 0-100 project-defined risk score and
classified as Low, Medium, High, or Critical. The response policy allows,
flags, or blocks the input inside the local demonstration, then stores the
completed event in SQLite for the authenticated dashboard. It is an
experimental testable prototype, not a guarantee of detecting every XSS
attack.

## Complete Algorithm

```text
Input
  |
Validation and field limits
  |
Rule normalization and rule detection
  |
TF-IDF transformation using saved training-fitted vectorizer
  |
Logistic Regression prediction and XSS probability
  |
Hybrid weighted signal
  |
Risk score = signal * 100
  |
Low / Medium / High / Critical
  |
Allow / Flag / Block / Block + Alert marker
  |
SQLite event logging
  |
Authenticated dashboard
```

Validation checks required fields, lengths, and username format. Rule
preprocessing creates bounded, case-folded, one-layer-decoded comparison
views without executing input. The ML stage transforms text with the saved
character TF-IDF vectorizer and asks the saved Logistic Regression classifier
for a label and XSS probability. The hybrid stage combines the normalized rule
score and probability. The risk engine clamps and classifies the result. The
action engine applies the project policy, the logger writes a parameterized
SQLite event, and the dashboard reads and escapes stored values.

## XSS Questions

### 1. What is XSS?

XSS is a vulnerability in which attacker-controlled data is interpreted by a
browser as executable markup or script in an unsafe application context.

### 2. What are common types of XSS?

Common categories are reflected XSS, stored XSS, and DOM-based XSS. XShield
does not claim to model every browser or application context.

### 3. Why is XSS dangerous?

Unsafe script execution can affect users' sessions, page content, actions, or
data. The exact impact depends on application context and browser controls.

### 4. How can XSS be prevented?

Use context-appropriate output encoding, trusted sanitization when HTML is
required, safe DOM APIs, input validation as a supporting control, and secure
application design.

### 5. What is the difference between detection and prevention?

Detection identifies suspicious characteristics. Prevention ensures that data
cannot execute, for example through output encoding. XShield's detectors do
not replace prevention controls.

## Rule-Based Detection

### 6. Why use rules?

Rules are transparent, easy to inspect, and can explain which characteristics
matched. They provide a useful baseline.

### 7. What rule categories are implemented?

Unexpected markup, script-related constructs, event-handler attributes,
suspicious URL schemes, encoded suspicious representations, and combinations
of multiple indicators.

### 8. How does the rule score work?

Each matched rule contributes its configured weight. The sum is capped at 100.
The result also contains matched IDs, details, and reasons.

### 9. Why use multiple rules?

Different indicators capture different characteristics and combinations can
provide more context than a single keyword check.

### 10. What are rule limitations?

Rules can miss new, fragmented, obfuscated, or context-dependent inputs and
can flag legitimate examples. They do not detect every XSS technique.

## Machine Learning

### 11. Why use machine learning?

ML can learn statistical character patterns from examples that are not
explicitly listed as individual rules. It provides a complementary signal.

### 12. Why use TF-IDF?

TF-IDF converts text into numerical feature weights. Character n-grams are
useful here because short security strings often contain meaningful
punctuation, delimiters, and fragments.

### 13. What does TF-IDF do?

It gives higher importance to terms or character sequences that are useful in
the document while reducing the effect of sequences common across many
documents.

### 14. Why Logistic Regression?

It is a simple, fast, probability-producing baseline that works well with
sparse TF-IDF features and is understandable for this project.

### 15. What is the training dataset?

The project uses `HttpParamsDataset`, selecting `attack_type=norm` as benign
and `attack_type=xss` as XSS. Other attack categories are excluded.

### 16. What is the label?

Label `0` means BENIGN and label `1` means XSS for this project.

### 17. Why use a train/test split?

Training data fits the model; held-out test data estimates behavior on
unseen examples. The project uses a reproducible 80/20 per-class split.

### 18. What is data leakage?

Data leakage occurs when information from evaluation data influences training.
XShield fits TF-IDF only on training text and evaluates the saved artifacts on
the held-out test set.

### 19. Why use precision, recall, and F1?

Accuracy can hide poor minority-class behavior. Precision measures the
correctness of positive predictions, recall measures how many positives are
found, and F1 combines the two.

## Hybrid Detection

### 20. Why combine rules and ML?

Rules provide explanations while ML provides learned pattern evidence.
Combining them allows the project to compare complementary signals.

### 21. How are the outputs combined?

The rule score is divided by 100, the ML score is the XSS probability, and
the weighted sum is the hybrid signal:
`rule_weight * normalized_rule_score + ml_weight * ml_score`.

### 22. Why use configurable weights?

Weights make the experiment explicit and allow later evaluation without
hardcoding one unexplained balance into multiple modules.

### 23. Are the weights industry standards?

No. The current 0.5/0.5 values are project-defined experimental parameters.

## Risk Assessment

### 24. How is the risk score calculated?

`risk_score = hybrid_signal * 100`, after defensive clamping to valid ranges.

### 25. Why use a 0-100 score?

It provides an easy-to-explain prototype scale for mapping the normalized
hybrid signal to project-defined levels.

### 26. Why these thresholds?

They were selected as understandable prototype boundaries:
0-29 Low, 30-59 Medium, 60-79 High, and 80-100 Critical.

### 27. Are Low/Medium/High/Critical official standards?

No. They are project-defined experimental thresholds, not universal
cybersecurity standards.

## System

### 28. Why Flask?

Flask is a small Python web framework that fits the project's simple local
web interface and makes routes, templates, and testing easy to understand.

### 29. Why SQLite?

SQLite is built into Python, requires no separate server, and is suitable for
this local college prototype.

### 30. How is data logged?

The completed detector, risk, and action results are converted into an event
record and inserted with parameterized SQL into `security_events`.

### 31. How does the dashboard work?

Authenticated GET routes query SQLite for statistics, recent events, filters,
and event details. The dashboard does not rerun detection.

### 32. What happens when input is blocked?

The local result page suppresses the submitted content, records the event, and
shows the response decision. No network or firewall block occurs.

### 33. What does “block” mean in this prototype?

It means application-level rejection/suppression in the demonstration. It
does not block users, IP addresses, or external traffic.

## Security

### 34. How do you prevent XShield itself from XSS?

Server-side validation is used, Jinja autoescaping remains enabled, stored
values are displayed as text, unsafe HTML/JavaScript sinks are avoided, and
blocked content is not displayed.

### 35. How do you prevent SQL injection?

SQL values use parameterized statements. Dashboard filters use allowlists and
search terms are bound parameters.

### 36. Why is input untrusted?

Clients can submit arbitrary values and bypass browser-side controls.
Therefore the server validates input and treats it as data throughout the
pipeline.

### 37. What are the security limitations?

HTTPS/TLS, credential rotation, production identity/authorization, dependency
pinning, privacy/retention design, and production-scale logging are not
implemented.

## Evaluation

### 38. What is a false positive?

A benign record incorrectly predicted as XSS.

### 39. What is a false negative?

An XSS-labeled record incorrectly predicted as benign.

### 40. Why is accuracy alone insufficient?

The test set is strongly imbalanced toward benign records, so accuracy alone
may hide missed XSS records. Precision, recall, F1, and confusion matrices give
more detail.

### 41. How did you compare Rule, ML, and Hybrid?

All three methods were run on the same 3,967-row held-out test CSV with
documented thresholds. No method was trained on that test data.

### 42. What were the actual results?

Rule F1 was 0.9607843137 with 0 false positives and 8 false negatives. ML F1
was 0.9807692308 with 0 false positives and 4 false negatives. Hybrid F1 was
0.9607843137 with 0 false positives and 8 false negatives. These are
test-split observations, not universal rankings.

## Limitations and Future Scope

### 43. Can XShield detect every XSS attack?

No. It is an experimental prototype whose rules and model depend on the
selected data and do not cover every browser context or attack variation.

### 44. Can ML produce false positives?

Yes. ML can classify unusual legitimate text as suspicious when it differs
from learned examples. The current selected test split happened to record no
ML false positives.

### 45. Can ML produce false negatives?

Yes. The current evaluation recorded four ML false negatives.

### 46. What would you improve in the future?

Use broader data, calibrate thresholds on validation data, evaluate additional
models and robustness, add stronger production identity and HTTPS, centralize
logging, and define privacy/retention policies.
