# Phase 4A: Independent evaluation of mail-tfidf-v1

The frozen model marked **641 of 646 legitimate SpaPhish messages** and **55 of 238 SpamAssassin hard-ham messages** as phishing. It detected **498 of 521 SpaPhish phishing messages**. These are transfer results on two particular public sources. They do not estimate production Gmail performance. The model, threshold (`0.10805200643670997`), and application verdicts were preserved.

## Run the offline evaluator

Use the trusted local bundle and its pinned environment described in the [ML setup guide](README.md). From the repository root:

~~~powershell
& .\.ml-venv\Scripts\python.exe -B -m ml.evaluate ml/data/evaluation/examples.jsonl --kind independent --report ml/data/evaluation/aggregate.json --details ml/data/evaluation/private.json
~~~

Use UTF-8 JSON Lines, one object per line. Required fields are `id`, `subject`, `body`, `label`, `source`, and `category`, all strings. IDs must be unique and ID, source, and category must be nonempty. `label` accepts `legitimate`, `phishing`, or `uncertain`. Add optional `group_id` for a campaign, thread, or template and `body_is_html` for a raw HTML body. Use an empty string for a missing subject or body. Keep groups and provenance in nonidentifying form and put local examples and reports under the ignored `ml/data/evaluation/` directory.

~~~json
{"id":"example-001","subject":"Workshop schedule","body":"Classes begin at noon on Saturday.","label":"legitimate","source":"synthetic mechanics fixture","category":"newsletter","group_id":"workshop-series"}
~~~

Ground truth comes from the example's independent annotation. Gmail Spam placement, rule verdicts, and the model prediction do not determine it. Use `--kind diagnostic` for previously inspected data and `--kind synthetic` for mechanics. Uncertain records are counted and excluded from scores. Records without usable text are also counted separately. The report includes class support, excluded rows by reason, false-positive and false-negative counts, precision, recall, F1, false-positive rate (FPR), confusion matrices, and source and category breakdowns. Matrix rows are actual and columns are predicted, both ordered legitimate then phishing. A zero denominator yields JSON `null`. A single-class result cannot measure discrimination across both classes, even when some metrics are numerically defined. Treat small categories as descriptive.

The evaluator verifies the baseline CSV hashes through the existing dataset loader. If the CSVs are unavailable, `--skip-training-overlap` explicitly reports the check as unavailable. Reports are written to new files under `ml/data/evaluation/`. The optional detail file contains local IDs and scores plus top positive and negative contributions for errors. It can reveal text through its feature names and must remain local. Source and category metadata in an aggregate report should also be reviewed before sharing.

## Public sources and overlap

| Source | Provenance and terms | Use in this evaluation |
|---|---|---|
| SpaPhish v5 | CC BY 4.0 dataset by Bustio-Martínez and coauthors, DOI `10.17632/hz2d6gz7pc.5`. The contributors supplied real Spanish-language mail from their own personal and institutional inboxes, collected during 2014–2025 and manually anonymized. Expert consensus assigns `0` to legitimate and `1` to phishing. The release did not reuse a published corpus. [Original deposit and license](https://data.mendeley.com/datasets/hz2d6gz7pc/5) · [Authors' data paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC13273897/) | All 1,395 published rows: 664 legitimate and 731 phishing. The pinned CSV uses commas in practice. The evaluator uses its published subject and body, and stratifies by the published counts of URLs and attachments. |
| Apache SpamAssassin, `20030228_hard_ham.tar.bz2` | The maintainer offers the corpus for offline filter testing and says message text copyright remains with the original senders. The hard-ham subset consists of non-spam deliberately selected to resemble spam. Sources include public forums and newsletters. [Original archive and terms](https://spamassassin.apache.org/old/publiccorpus/readme.html) | 250 non-spam messages as historical legitimate controls. The converter reads MIME in memory, prefers plain text and falls back to HTML. List-related headers provide a mailing-list proxy, not a verified promotion label. The archive's generic spam is excluded. |

The SpaPhish CSV SHA-256 is `656b2245d58da72d640680e5c2a168673a130b38607f2a427c773bbb167e995e`, verified against the deposit's file metadata. The SpamAssassin archive SHA-256 is `ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9`, pinned from the maintainer's download. The prepared JSONL SHA-256 is `46dcd9b90e570f9fb75e68f5d6a7352c5f4b5fed9f70099b696ef216c2ec061a`. The fitted artifact SHA-256 is `339e4d9363f1bfae5de710f399ebfa00717006be86879f9162f80b924952bd3a`.

~~~powershell
New-Item -ItemType Directory -Force ml/data/evaluation | Out-Null
Invoke-WebRequest 'https://data.mendeley.com/public-files/datasets/hz2d6gz7pc/files/f796c8e2-3768-4c2d-8b73-48f0d7771de5/file_downloaded' -OutFile ml/data/evaluation/spaphish-v5.csv
Invoke-WebRequest 'https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2' -OutFile ml/data/evaluation/spamassassin-hard-ham-20030228.tar.bz2
& .\.ml-venv\Scripts\python.exe -B -m ml.prepare_evaluation --spaphish ml/data/evaluation/spaphish-v5.csv --hard-ham ml/data/evaluation/spamassassin-hard-ham-20030228.tar.bz2 --out ml/data/evaluation/public-independent.jsonl
& .\.ml-venv\Scripts\python.exe -B -m ml.evaluate ml/data/evaluation/public-independent.jsonl --kind independent --report ml/data/evaluation/public-aggregate.json --details ml/data/evaluation/public-private.json
~~~

The overlap audit searched all **17,353 usable, label-eligible Enron/Nazario source rows** before the original deduplication and split, a conservative superset of training. It found **zero exact and zero near matches** to those rows. Exact matching uses normalized subject plus body or a nonempty normalized body alone. Near matching uses token-trigram Jaccard of at least 0.82 with at least eight distinct trigrams per side. It compares body shingles when there are enough, otherwise subject plus body. It reuses the baseline's long-text shingle cap. This audit cannot rule out translations, heavily rewritten copies, or unannotated campaign overlap.

Within the evaluation set, the same checks removed 32 exact and 208 near duplicates across 1,645 inputs. SpaPhish lost 21 exact and 207 near rows. Hard ham lost 11 exact and one near row. Same-label groups keep their first row in source order. Mixed-label duplicate groups are excluded as conflicts, though none occurred here. Neither release provided campaign/thread IDs used by this run. Structural categories and the input order do not substitute for campaign-level sampling.

The remaining data gap is a rights-cleared **modern English** collection with reviewed promotions and newsletters, account notices, ordinary correspondence, transactional mail, and genuine phishing with lure-family or campaign annotations. SpaPhish provides genuine labeled phishing, but it is a Spanish, anonymized contributor sample with no validated English inbox distribution. The historical hard-ham subset can probe list mail and other challenging negatives but cannot provide class coverage or reliable estimates for individual modern business categories. [Phishing Pot's maintainer](https://github.com/rf-peixoto/phishing_pot/blob/main/DATASET_CARD.md) describes a non-commercial collection of phishing, spam, fraud, and malware-delivery attempts without a verified phishing-only label for every record. [PhishNChips' source notes](https://github.com/R-Lit/PhishNChips_Neurips/blob/main/SOURCE_LICENSES.md) distinguish synthetic emails and Nazario-derived validation. The [merged research release](https://github.com/Manar-ibr/Phishing-Email-Detection-Dataset) combines spam, scams, and phishing in its positive label and reuses baseline sources. These alternatives were screened out before scoring.

## Results

| Public slice | Input / scored | Legit / phishing scored | TN / FP / FN / TP | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| SpaPhish v5 | 1,395 / 1,167 | 646 / 521 | 5 / 641 / 23 / 498 | 43.72% | 95.59% | 60.00% | 99.23% |
| SpamAssassin hard ham | 250 / 238 | 238 / 0 | 183 / 55 / 0 / 0 | 0.00% | Undefined | 0.00% | 23.11% |
| Pooled counts, descriptive only | 1,645 / 1,405 | 884 / 521 | 188 / 696 / 23 / 498 | 41.71% | 95.59% | 58.08% | 78.73% |

There were zero uncertain rows in either public source. The pooled row mixes languages and a negative-only source at an artificial class balance. Do not use it as an inbox performance estimate.

| Category | Scored | False positives / legitimate | False negatives / phishing |
|---|---:|---:|---:|
| SpaPhish, URLs and no attachment | 799 | 314 / 317 | 21 / 482 |
| SpaPhish, URLs and attachment | 178 | 165 / 166 | 0 / 12 |
| SpaPhish, no URLs and no attachment | 104 | 86 / 86 | 0 / 18 |
| SpaPhish, no URLs and attachment | 86 | 76 / 77 | 2 / 9 |
| Hard ham, list-related headers | 54 | 6 / 54 | — |
| Hard ham, other | 184 | 49 / 184 | — |

SpaPhish's URL and attachment fields describe the published message, not additional features supplied to the model. Among its overlapping expert persuasion annotations, the model missed 15 of 474 positives marked for liking/similarity/deception and 8 of 47 without that marker. These are descriptive differences. Category sizes, co-occurring annotations, and campaign repetition limit interpretation. Lure-family miss rates for credential theft, payment diversion, QR codes, and attachment delivery still need annotated examples.

The synthetic mechanics fixture separately produced two correct classifications and excluded one uncertain record. The two reported live observations are a diagnostic record only: one user-confirmed legitimate forwarded promotion was a false positive, and the other forwarded reminder remains uncertain. Manual Spam placement verified ingestion. Neither observation enters the public metrics or a future untouched test set, and neither message was fetched or rescored here.

## Error analysis

**Corpus and language.** The reconstructed fit split matched the bundle's training row-ID fingerprint. Its 9,298 legitimate examples all came from Enron and its 952 phishing examples all came from Nazario. The token `de` appeared in 115 Enron and 58 Nazario training rows (1.24% and 6.09%, respectively) and its fitted coefficient was +2.4885. The original held-out FPR was 1.15%, far below the FPR on either independent slice. This supports concern about source dependence. Language, selection, time, and anonymization differ together across corpora, so the transfer gap cannot be assigned to any one factor. [Baseline report](reports/mail-tfidf-v1.json)

**Fitted feature contributions.** For each error, the evaluator computed TF-IDF times the learned coefficient. The intercept plus the sum of all contributions reproduces the classifier logit. In the 641 SpaPhish false positives, `de` was among the five largest phishing-side contributions in 630 cases, with mean contribution +0.750 logit units among those occurrences. `en` and `para` appeared in 534 and 499, respectively. In hard ham, `click` and `account` appeared among the five largest phishing-side contributions in 23 and 10 of 55 false positives. These are ordinary words that affected scores. The calculation does not establish malicious intent or explain the private promotion. SpaPhish false negatives activated a median of seven fitted features, versus 29 for its false positives. Their median score was 0.079168, below the frozen threshold.

**Forwarding, HTML, and URLs.** Training's CSV loader, the evaluator, and Gmail model scoring all use `subject-body-v1`. Gmail first decodes MIME, prefers plain text when present, and converts HTML to visible text when needed. It stores extracted links separately for the rules. The fitted text classifier receives subject and body only. The normalizer strips standard reply/forward prefixes, matching header lines, common separators, quoted `>` lines, addresses, and recognizable URLs. Remaining wrapper text, unrecognized separators, and visible link text can still contribute.

In a synthetic workshop bulletin, the direct version, an inline forward with standard headers, a visible tracking URL, and a Gmail HTML variant with a tracking-only href all produced identical normalized text and score **0.030401**. Quoting away the body yielded **0.068667**, and adding a forwarder's review note yielded **0.035382**. In a separate synthetic table, direct HTML normalization separated adjacent `th` cells and scored **0.143684**. Gmail's HTML conversion joined those cells and the same model scored **0.039149**, crossing the threshold in the opposite direction. These probes demonstrate cases of both invariance and input drift. They do not identify a cause of the live promotion's false positive.

## Next improvements, in order

1. Build a reviewed modern English evaluation set first. Seek explicit usage rights and independently label both classes. Cover newsletters and promotions, account notices, ordinary correspondence, receipts, and real phishing families. Keep uncertain examples separate, group campaigns and templates, and reserve an untouched holdout by source and time. Keep this now-inspected public evaluation and the live diagnostics out of that holdout.
2. Measure a shared HTML/text boundary against matched MIME and offline inputs. Start with the measured adjacent-table-cell difference and add paired tests for forwarding and wrappers. Validate any future normalization change on the development set so useful original text survives.
3. In a later training phase, compare a source-balanced TF-IDF baseline with the current artifact. Select any new threshold on a separate development split against a predeclared false-positive target, then report recall and FPR by source and category on the untouched holdout. The public transfer failures justify improving the data before deciding whether a larger model is useful.
