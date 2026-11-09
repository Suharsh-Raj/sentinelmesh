# Phase 1 evaluation

Model `mail-tfidf-v1` was fitted on CPU with CPython 3.13.8 and the [pinned requirements](requirements.txt). The [aggregate run manifest](reports/mail-tfidf-v1.json) records the source hashes, split fingerprints, configuration, metrics, and artifact checksum.

## Data and split

Of 31,332 CSV records, 13,976 Enron spam records were excluded by label and 3 Nazario records were unusable. Of the resulting 17,353 messages, 343 redundant exact copies were removed. There were zero detected conflicting-label groups or conflict removals. There were 581 retained near-duplicate groups covering 1,601 messages and 789 reply-subject keys that linked previously separate groups.

| Split | Total | Legitimate | Phishing | Groups |
|---|---:|---:|---:|---:|
| Train | 10,250 | 9,298 | 952 | 8,834 |
| Validation | 3,421 | 3,128 | 293 | 2,945 |
| Test | 3,339 | 3,041 | 298 | 2,944 |
| Total | 17,010 | 15,467 | 1,543 | 14,723 |

Exact duplicates share normalized text. For near-duplicates, candidate pairs share one of their eight lowest stable word-trigram hashes in a bucket of at most 64 messages. Candidates need at least eight distinct trigrams and a trigram Jaccard similarity of at least 0.82. Trigrams sample the first and last 512 tokens for long messages. Connected near-duplicate groups stay in one split, and groups with conflicting labels are discarded. Detected near-duplicates stay in the benchmark within their group. This approximate method can miss paraphrases, short templates, and pairs lost to the candidate limits. The reply-subject proxy is described in [dataset provenance](DATASET.md).

The split used shuffled five-fold `StratifiedGroupKFold` with seed 42. Fold 0 was test, fold 1 was validation, and folds 2–4 were training. The fixed pipeline used word unigrams and bigrams, a 40,000-feature limit, and logistic regression with `C=1.0`. TF-IDF and the classifier were fitted on the training split only.

## Results

The frozen operating threshold was **0.1080520064**. It gave the highest phishing recall among thresholds with validation false-positive rate at or below 1%. Ties favored lower false-positive rates and then higher thresholds. Validation had 28 false positives and missed 4 phishing messages. At that same threshold the test false-positive rate was **1.15%**, above the validation selection limit.

| Metric | Validation | Held-out test | Held-out dummy prior |
|---|---:|---:|---:|
| Phishing precision | 91.17% | 89.46% | 0.00% |
| Phishing recall | 98.63% | 99.66% | 0.00% |
| Phishing F1 | 94.75% | 94.29% | 0.00% |
| False-positive rate | 0.90% | 1.15% | 0.00% |
| Average precision | 0.9948 | 0.9952 | 0.0892 |
| Accuracy | 99.06% | 98.92% | 91.08% |

The test confusion matrix is **[[3006, 35], [1, 297]]**, with rows actual and columns predicted, both in the order **[legitimate, phishing]**. The dummy uses the training class prior and predicts every test row as legitimate, giving **[[3041, 0], [298, 0]]**. Pipeline fit took **4.90 seconds**. Data preparation, training, and evaluation took **23.67 seconds**, excluding download and artifact serialization.

A separate rerun of the frozen recipe reproduced the split fingerprints, metrics, threshold, fitted vocabulary, IDF values, and regression coefficients and intercept exactly. The serialized Joblib files had different checksums. Each manifest verifies its own artifact.

## Interpretation

The model separated held-out groups from the two selected corpora on this benchmark. Corpus and class are perfectly confounded. Different writing styles, dates, and collection procedures can explain some of the separation. Approximate grouping and the absence of reliable campaign IDs leave possible campaign overlap. These results do not establish performance on a new source, a modern inbox, or generic spam as a separate category. The score has not been calibrated and the validation false-positive limit is not a deployment guarantee.

The model bundle and CLI are ready for experimental score-only integration. Keep the classifier out of automated quarantine decisions until it has been evaluated on independently labeled mail representative of the intended inbox.
