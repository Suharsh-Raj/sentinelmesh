# Offline phishing email baseline

Run these commands in PowerShell from the SentinelMesh project root. The training package is separate from the application. Its environment, raw CSVs, caches, and fitted model stay under the checkout.

## Set up the dedicated environment

The recorded run used 64-bit CPython 3.13.8. Use the same Python patch and pinned packages for model loading. The application has its own Python environment.

~~~powershell
Set-Location -LiteralPath 'path\to\sentinelmesh' # Replace with your checkout folder
$cacheDir = Join-Path (Get-Location).Path '.ml-cache'
$env:TEMP = Join-Path $cacheDir 'tmp'
$env:TMP = $env:TEMP
$env:PIP_CACHE_DIR = Join-Path $cacheDir 'pip'
New-Item -ItemType Directory -Path $env:TEMP,$env:PIP_CACHE_DIR -Force | Out-Null
py -3.13 -B -m venv .ml-venv
.\.ml-venv\Scripts\python.exe -B -m pip --isolated install --cache-dir $env:PIP_CACHE_DIR --only-binary=:all: --index-url https://pypi.org/simple -r ml/requirements.txt
.\.ml-venv\Scripts\python.exe -B -m pip check
~~~

## Obtain the two CSVs

See [dataset provenance](DATASET.md) for terms, original label meanings, and limitations. The commands download only the named CSVs and check the expected SHA-256. Keep the CSVs local and treat their contents as untrusted text.

~~~powershell
$datasetSpec = Get-Content ml/dataset.json -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Path 'ml/data' -Force | Out-Null
foreach ($item in $datasetSpec.files) {
    $target = Join-Path 'ml/data' $item.name
    if (Test-Path -LiteralPath $target) {
        if ((Get-FileHash -LiteralPath $target).Hash -ne $item.sha256) {
            throw "Existing dataset hash mismatch for $($item.name)"
        }
        continue
    }
    $partial = "$target.partial"
    curl.exe --fail --silent --show-error --location --output $partial $item.url
    if ($LASTEXITCODE -ne 0) { throw "Download failed for $($item.name)" }
    if ((Get-FileHash -LiteralPath $partial).Hash -ne $item.sha256) {
        throw "Downloaded dataset hash mismatch for $($item.name)"
    }
    Move-Item -LiteralPath $partial -Destination $target
}
~~~

## Train and test offline

~~~powershell
.\.ml-venv\Scripts\python.exe -B -m unittest discover -s ml/tests -v
.\.ml-venv\Scripts\python.exe -B -m ml.train --report .ml-cache/training-report.json
~~~

The command creates a bundle under `ml/models/mail-tfidf-v1` and an aggregate JSON report at the supplied path. To repeat the frozen run with the current outputs present, give both outputs new paths.

~~~powershell
.\.ml-venv\Scripts\python.exe -B -m ml.train --model-dir .ml-cache/reproduction-model --report .ml-cache/reproduction.json
~~~

The script normalizes text and groups similar messages before splitting. It fits a word unigram/bigram TF-IDF and logistic regression pipeline on training data only. The hyperparameters are fixed. Validation chooses a threshold that maximizes phishing recall among options with a false-positive rate at or below 1%. Ties prefer a lower false-positive rate and then a higher threshold. The test split is scored after the threshold is frozen. See [evaluation](EVALUATION.md) for results.

## Score local text

~~~powershell
'Please review the updated project schedule before tomorrow.' | Set-Content -Encoding utf8 .ml-cache/example.txt
.\.ml-venv\Scripts\python.exe -B -m ml.infer --subject 'Project update' --body-file .ml-cache/example.txt
~~~

Pass `--html` for a UTF-8 HTML body. The parser extracts text locally without fetching resources. `--model-dir` selects a different locally trained bundle. The JSON response contains `model_version`, `phishing_score`, `model_prediction`, and `threshold`. The score is logistic regression's class-1 `predict_proba` output. Its calibration and accuracy on live mail have yet to be established.

Load only your own trusted training outputs. Joblib deserialization can execute code. The manifest and SHA-256 checks detect incompatibility or corruption in a trusted bundle. The loader checks format, preprocessing version, dependency versions, class order, and checksum.
