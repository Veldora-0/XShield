# XShield Final Submission Checklist

## Code

- [ ] Application starts with `.\.venv\Scripts\python.exe -m app`.
- [ ] Dependencies install from `requirements.txt`.
- [ ] Saved vectorizer and classifier artifacts are available under `models/`.
- [ ] Complete unittest suite passes.
- [ ] Evaluation script completes without retraining.

## Security

- [ ] Server-side input validation is enabled.
- [ ] Jinja output escaping remains enabled.
- [ ] SQLite uses parameterized SQL.
- [ ] Dashboard routes require configured authentication.
- [ ] Missing dashboard password fails closed.
- [ ] Model loading uses trusted fixed paths.
- [ ] Request-size and field limits are configured.
- [ ] Debug mode is disabled by default.
- [ ] No real external blocking or alerting is claimed.
- [ ] Security headers are present.

## Machine Learning

- [ ] Dataset source and license information are documented.
- [ ] Label mapping is documented.
- [ ] Preprocessing and split methodology are documented.
- [ ] TF-IDF configuration is documented.
- [ ] Logistic Regression configuration is documented.
- [ ] Evaluation uses the saved model and vectorizer.
- [ ] No metrics were manually fabricated or changed.
- [ ] Limitations and class imbalance are explained.

## Documentation

- [ ] README is current.
- [ ] `docs/XShield_Technical_Documentation.md` is current.
- [ ] `docs/architecture.md` is current.
- [ ] `docs/setup.md` is current.
- [ ] `docs/security.md` is current.
- [ ] `docs/parameters.md` is current.
- [ ] `docs/demo_guide.md` is current.
- [ ] `docs/presentation_outline.md` is ready.
- [ ] `docs/viva_questions.md` is ready.
- [ ] `docs/novelty.md` avoids unsupported research claims.
- [ ] `reports/security_review.md` and evaluation reports are retained.

## Presentation

- [ ] 10-12 slide outline is prepared.
- [ ] Architecture diagram is available.
- [ ] Actual evaluation table and confusion matrices are available.
- [ ] Dashboard screenshot is captured from the local application if required.
- [ ] Demo sequence has been rehearsed locally.
- [ ] Benign and suspicious input examples are understood.
- [ ] The presenter can explain limitations and thresholds.

## Submission

- [ ] `.gitignore` excludes `.venv`, bytecode, SQLite files, logs, and model
      binary artifacts as configured.
- [ ] No source credentials or secrets are committed.
- [ ] No `.env` file containing secrets is present.
- [ ] No unnecessary temporary files are present.
- [ ] The local SQLite database is treated as generated development data.
- [ ] The saved model artifacts are retained locally for demonstration but are
      not treated as source credentials.
- [ ] A clean setup can follow `docs/setup.md`.
