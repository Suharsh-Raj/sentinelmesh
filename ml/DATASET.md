# Dataset provenance

The baseline uses two CSVs from **Phishing Email Curated Datasets**, deposited by Arifa Islam Champa, Md Fazle Rabbi, and Minhaz Fahim Zibran. The official record metadata identifies the release as **CC BY 4.0**. The files were retrieved on **2026-11-09**, verified against the publisher's MD5 and byte counts, and fingerprinted with SHA-256. Credit is due to the deposit creators and the original corpus maintainers. This project locally filters and normalizes text and includes only aggregate results and fingerprints in the report. The source CSVs and fitted artifact are ignored. [Zenodo record](https://zenodo.org/records/8339691) · [Official license metadata](https://zenodo.org/api/records/8339691) · [CC BY 4.0 terms](https://creativecommons.org/licenses/by/4.0/)

## Compared sources

| Candidate | Provenance, terms, and fit |
|---|---|
| **Phishing Email Curated Datasets, selected slices** | The CC BY 4.0 deposit preserves separate corpora and subject/body fields. The selected negatives are authentic Enron ham. The positives come from José Nazario's collected phishing archive, whose author publishes CC BY 4.0 terms. The slices are historical and source and class are fully confounded. The corpus maintainers describe privacy considerations and imperfect labels. [Deposit](https://zenodo.org/records/8339691) · [Enron upstream](https://www.cs.cmu.edu/~enron/) · [Nazario archive and terms](https://monkey.org/~jose/phishing/README.txt) |
| **Phishing-Email-Detection-Dataset v2** | Research release by Alhuzali, Alloqmani, Aljabri, and Alharbi under CC BY 4.0. The merged email text includes source material from nine corpora. The authors explicitly combine spam, scams, and phishing into one positive label, which makes the merged binary target unsuitable here despite the presence of legitimate negatives. [Deposit](https://zenodo.org/records/17314806) · [Authors' labeling description](https://github.com/Manar-ibr/Phishing-Email-Detection-Dataset) |
| **SpaPhish v5** | CC BY 4.0. Expert-annotated, Spanish-native email from contributor inboxes, with 664 legitimate and 731 phishing examples, subject and body, and manual anonymization with fictitious replacements for sensitive spans. It has a better-defined phishing annotation protocol. The language, size, and anonymization make it a different benchmark from the English-oriented baseline used here. [Mendeley record and terms](https://data.mendeley.com/datasets/hz2d6gz7pc/5) |

## Selected files and mappings

| CSV | Downloaded rows and original labels | Mapping used |
|---|---|---|
| `Enron.csv` | 29,767 rows. 15,791 original `0` and 13,976 original `1`. | `0` becomes legitimate. All `1` rows are excluded because they are spam-labeled in this slice. |
| `Nazario.csv` | 1,565 rows, all original `1`. | `1` becomes phishing, based on the phishing-specific source. Internal mailbox sentinel records and rows without usable text are excluded. |

The [machine-readable dataset manifest](dataset.json) contains the exact file URLs, sizes, publisher MD5s, and observed SHA-256 hashes. Training stops on a hash mismatch or unexpected source label. No demo examples entered the benchmark. No URLs or attachments from message contents were fetched.

Only subject and body enter the vectorizer. Sender, recipient, timestamps, extracted URLs, filenames, source, and label stay outside the feature text. Normalization strips recognizable corpus markers and mail headers, removes web and email addresses and long identifiers, and converts recognizable HTML to plain text. Both sources contain historical, naturally occurring email with corpus-specific processing. Collection artifacts, wording, formatting, and organizational style can still reveal the corpus. Labels were accepted from the published sources and were not independently reviewed message by message.

The CSVs have no reliable thread or campaign IDs. The split groups detected near-duplicates and uses normalized reply/forward subjects as a thread proxy within each source. The proxy misses some threads and campaigns and may group unrelated messages with the same subject. Every retained Enron example is legitimate and every retained Nazario example is phishing. The binary test therefore uses held-out groups from the same corpora. It cannot separate corpus recognition from phishing recognition or measure performance on modern inboxes.
