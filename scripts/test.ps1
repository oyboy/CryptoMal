Write-Host "Starting CryptoCore Complete Automated Tests (v0.7.0)..." -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($ScriptDir -like "*\scripts") {
    $ProjectRoot = Split-Path -Parent $ScriptDir
} else {
    $ProjectRoot = $ScriptDir
}
$TestFilesDir = Join-Path $ScriptDir "test_files"

Write-Host "Project Root: $ProjectRoot" -ForegroundColor Gray

# --- GLOBAL STATS ---
$global:TestResults = @()
$global:PassedCount = 0
$global:FailedCount = 0

# --- HELPER FUNCTIONS ---

function Write-Step { param($Msg) Write-Host ">>> $Msg" -ForegroundColor Blue }
function Write-Section { param($Msg)
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  $Msg" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
}

function Add-TestResult {
    param($Result, $Category = "General")

    $global:TestResults += [PSCustomObject]@{
        Category = $Category
        Result   = $Result
    }

    if ($Result -like "PASSED:*") {
        $global:PassedCount++
        Write-Host "  [OK] $($Result -replace 'PASSED: ','')" -ForegroundColor Green
    } else {
        $global:FailedCount++
        Write-Host "  [FAIL] $($Result -replace 'FAILED: ','')" -ForegroundColor Red
    }
}

# --- STEP 1: BUILD ---
Write-Section "Building Project"
Set-Location $ProjectRoot

Write-Step "Building release version..."
cargo build --release 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed! Please check your Cargo.toml and code." -ForegroundColor Red
    exit 1
} else {
    Add-TestResult "PASSED: Release build completed" "Build"
}

# Find Executable
$ExePath = Join-Path $ProjectRoot "target\release\cryptocore.exe"
if (-not (Test-Path $ExePath)) {
    $ExePath = Join-Path $ProjectRoot "target\release\CryptoMal.exe"
}
if (-not (Test-Path $ExePath)) {
    Write-Host "Executable not found at $ExePath" -ForegroundColor Red
    exit 1
}

Write-Host "Using executable: $ExePath" -ForegroundColor Green
Set-Location $ScriptDir

# --- STEP 2: CREATE TEST FILES ---
Write-Section "Creating Test Files"
if (-not (Test-Path $TestFilesDir)) { New-Item -ItemType Directory -Path $TestFilesDir -Force | Out-Null }

function Create-File { param($Name, $Content)
    $Path = Join-Path $TestFilesDir $Name
    [System.IO.File]::WriteAllText($Path, $Content)
}

Create-File "medium.txt" "This is a medium length test file for encryption testing."
Create-File "gcm_test.txt" "Hello GCM World with AAD!"
Create-File "hmac.txt" "Hi There"
Create-File "sha.txt" "abc"
Create-File "secret.txt" "TOP SECRET"

# Create binary file safely
$BinPath = Join-Path $TestFilesDir "binary.bin"
$Bytes = 0..15
[System.IO.File]::WriteAllBytes($BinPath, $Bytes)

Add-TestResult "PASSED: Test files created" "Files"

# --- STEP 3: UNIT TESTS ---
Write-Section "Unit Tests"
Set-Location $ProjectRoot
$UnitTests = @(
    "hash_integration",
    "gcm_integration",
#    "high_load_integration"
    "cryptor_integration"
)
foreach ($Test in $UnitTests) {
    Write-Host "Running test: $Test..." -NoNewline
    cargo test --release --test $Test -- --nocapture 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " Done."
        Add-TestResult "PASSED: $Test module" "UnitTests"
    } else {
        Write-Host " Failed."
        Add-TestResult "FAILED: $Test module" "UnitTests"
    }
}

# --- STEP 4: HASH & HMAC ---
Write-Section "Hash & HMAC Tests"

# SHA256
$ShaFile = Join-Path $TestFilesDir "sha.txt"
$Out = & $ExePath dgst --algorithm sha256 --input $ShaFile 2>&1
if ($Out -match "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
    Add-TestResult "PASSED: SHA-256" "Hash"
} else {
    Add-TestResult "FAILED: SHA-256 mismatch" "Hash"
}

# HMAC
$HmacFile = Join-Path $TestFilesDir "hmac.txt"
$Out = & $ExePath dgst --algorithm sha256 --hmac --key "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" --input $HmacFile 2>&1
if ($Out -match "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") {
    Add-TestResult "PASSED: HMAC-SHA256" "HMAC"
} else {
    Add-TestResult "FAILED: HMAC mismatch" "HMAC"
}

# --- STEP 5: KDF TESTS ---
Write-Section "Key Derivation Tests"

# Check execution and stdout parsing
$Out = & $ExePath derive --password "password" --salt "73616c74" --iterations 1 --length 32 2>&1
if ($Out -match "Generated key:") {
    Add-TestResult "PASSED: Derive command execution" "KDF"
} else {
    Add-TestResult "FAILED: Derive command failed" "KDF"
}

# --- STEP 6: GCM TESTS ---
Write-Section "GCM Mode Tests"
$GcmKey = "00000000000000000000000000000000"
$GcmIv = "000000000000000000000000" # 12 bytes
$GcmAad = "aabbccddeeff"
$GcmPlain = Join-Path $TestFilesDir "gcm_test.txt"
$GcmEnc = Join-Path $ScriptDir "gcm.bin"
$GcmDec = Join-Path $ScriptDir "gcm.dec"

# Encrypt (Using Flags Structure: --encrypt --mode gcm)
& $ExePath --encrypt --algorithm aes --mode gcm --key $GcmKey --iv $GcmIv --aad $GcmAad --input $GcmPlain --output $GcmEnc 2>&1 | Out-Null

if (Test-Path $GcmEnc) {
    # Decrypt
    & $ExePath --decrypt --algorithm aes --mode gcm --key $GcmKey --aad $GcmAad --input $GcmEnc --output $GcmDec 2>&1 | Out-Null

    if (Test-Path $GcmDec) {
        $Orig = Get-Content $GcmPlain -Raw
        $Res = Get-Content $GcmDec -Raw
        if ($Orig -eq $Res) {
            Add-TestResult "PASSED: GCM Roundtrip" "GCM"
        } else {
            Add-TestResult "FAILED: GCM Content Mismatch" "GCM"
        }
    } else {
        Add-TestResult "FAILED: GCM Decryption (No Output)" "GCM"
    }

    # Wrong AAD Test
    $GcmFail = Join-Path $ScriptDir "gcm_fail.txt"
    & $ExePath --decrypt --algorithm aes --mode gcm --key $GcmKey --aad "wrong" --input $GcmEnc --output $GcmFail 2>&1 | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Add-TestResult "PASSED: GCM Wrong AAD correctly failed" "GCM"
    } else {
        Add-TestResult "FAILED: GCM Wrong AAD did NOT fail" "GCM"
    }
} else {
    Add-TestResult "FAILED: GCM Encryption (No Output)" "GCM"
}

# Cleanup GCM temp files
Remove-Item $GcmEnc, $GcmDec, $GcmFail -ErrorAction SilentlyContinue

# --- STEP 7: CLASSIC MODES ---
Write-Section "Classic Encryption Modes"
$CKey = "00112233445566778899aabbccddeeff"
$CPlain = Join-Path $TestFilesDir "medium.txt"
$Modes = @("ecb", "cbc", "ctr")

foreach ($Mode in $Modes) {
    $CEnc = Join-Path $ScriptDir "$Mode.enc"
    $CDec = Join-Path $ScriptDir "$Mode.dec"

    # Encrypt
    & $ExePath --encrypt --algorithm aes --mode $Mode --key $CKey --input $CPlain --output $CEnc 2>&1 | Out-Null

    if (Test-Path $CEnc) {
        # Decrypt
        & $ExePath --decrypt --algorithm aes --mode $Mode --key $CKey --input $CEnc --output $CDec 2>&1 | Out-Null

        if (Test-Path $CDec) {
            $O = Get-Content $CPlain -Raw
            $D = Get-Content $CDec -Raw
            if ($O -eq $D) {
                Add-TestResult "PASSED: $Mode Roundtrip" "Classic"
            } else {
                Add-TestResult "FAILED: $Mode Mismatch" "Classic"
            }
        } else {
            Add-TestResult "FAILED: $Mode Decrypt failed" "Classic"
        }
    } else {
        Add-TestResult "FAILED: $Mode Encrypt failed" "Classic"
    }
    Remove-Item $CEnc, $CDec -ErrorAction SilentlyContinue
}

# --- STEP 8: PERFORMANCE ---
Write-Section "Performance"
$Sw = [System.Diagnostics.Stopwatch]::StartNew()
& $ExePath derive --password "perf" --salt "salt" --iterations 1000 --length 32 2>&1 | Out-Null
$Sw.Stop()

if ($LASTEXITCODE -eq 0) {
    Write-Host "  1000 Iterations took: $($Sw.ElapsedMilliseconds) ms" -ForegroundColor Gray
    Add-TestResult "PASSED: Performance Check" "Perf"
} else {
    Add-TestResult "FAILED: Performance Check" "Perf"
}

# --- STEP 9: WORKFLOW ---
Write-Section "Workflow Test"
$WfSecret = Join-Path $TestFilesDir "secret.txt"
$WfEnc = Join-Path $ScriptDir "wf.enc"
$WfDec = Join-Path $ScriptDir "wf.dec"

# 1. Derive Key (Parse from stdout)
$Out = & $ExePath derive --password "UserPass" --salt "SalesSalt" --iterations 10000 --length 16
if ($Out -match "Generated key: (.*)") {
    $WfKey = $Matches[1].Trim()

    # 2. Encrypt GCM
    & $ExePath --encrypt --algorithm aes --mode gcm --key $WfKey --iv "000000000000000000000000" --aad "AAABBC" --input $WfSecret --output $WfEnc

    if (Test-Path $WfEnc) {
        # 3. Decrypt GCM
        & $ExePath --decrypt --algorithm aes --mode gcm --key $WfKey --aad "AAABBC" --input $WfEnc --output $WfDec

        if (Test-Path $WfDec) {
            $Res = Get-Content $WfDec -Raw
            if ($Res -eq "TOP SECRET") {
                Add-TestResult "PASSED: Full Workflow" "Workflow"
            } else {
                Add-TestResult "FAILED: Workflow Content Mismatch" "Workflow"
            }
        } else {
            Add-TestResult "FAILED: Workflow Decrypt" "Workflow"
        }
    } else {
        Add-TestResult "FAILED: Workflow Encrypt" "Workflow"
    }
} else {
    Add-TestResult "FAILED: Workflow Key Gen" "Workflow"
}

# --- CLEANUP ---
Write-Section "Cleanup"
if (Test-Path $TestFilesDir) { Remove-Item $TestFilesDir -Recurse -Force -ErrorAction SilentlyContinue }
Remove-Item "$ScriptDir\*.enc" -ErrorAction SilentlyContinue
Remove-Item "$ScriptDir\*.dec" -ErrorAction SilentlyContinue
Remove-Item "$ScriptDir\*.bin" -ErrorAction SilentlyContinue

Add-TestResult "PASSED: Cleanup completed" "Cleanup"

# --- SUMMARY ---
Write-Section "Final Summary"

$UniqueCats = $global:TestResults | Select-Object -ExpandProperty Category -Unique

foreach ($Cat in $UniqueCats) {
    $CatResults = $global:TestResults | Where-Object { $_.Category -eq $Cat }
    $Passed = ($CatResults | Where-Object { $_.Result -like "PASSED*" }).Count
    $Failed = ($CatResults | Where-Object { $_.Result -like "FAILED*" }).Count

    $Color = if ($Failed -gt 0) { "Red" } else { "Green" }

    Write-Host "$Cat : $Passed Passed, $Failed Failed" -ForegroundColor $Color

    if ($Failed -gt 0) {
        foreach ($Fail in ($CatResults | Where-Object { $_.Result -like "FAILED*" })) {
            Write-Host "    - $($Fail.Result)" -ForegroundColor Red
        }
    }
}

Write-Host "`nTotal Passed: $global:PassedCount" -ForegroundColor Green
Write-Host "Total Failed: $global:FailedCount" -ForegroundColor Red

if ($global:FailedCount -eq 0) {
    Write-Host "ALL TESTS PASSED!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "SOME TESTS FAILED!" -ForegroundColor Red
    exit 1
}