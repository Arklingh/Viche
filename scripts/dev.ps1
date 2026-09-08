<#
.SYNOPSIS
    Fast local dev hosting for Viche: anvil + a fresh contract deploy +
    viche-relayer + the Trunk frontend dev server, all native (no Docker),
    running in parallel with logs streamed to files.

.DESCRIPTION
    This is the "one command, everything's up" script for local development --
    the native-toolchain equivalent of `docker-compose up`, but using
    `cargo run`/`trunk serve` directly so you get incremental compilation and
    hot reload instead of a full container rebuild per change.

    What it does, in order:
      1. Checks contracts/lib/forge-std (a git submodule) is actually
         populated, and runs `git submodule update --init --recursive` if
         it isn't -- a plain `git clone` without --recurse-submodules leaves
         it empty, which otherwise fails deep inside `forge script` with a
         confusing "cannot find Script.sol" error.
      2. Kills any anvil/viche-relayer/trunk processes left over from a
         previous run (stale locks on :8545/:3000/:8080 are the #1 cause of
         "why won't this start").
      3. Starts anvil and waits for its RPC to respond.
      4. Deploys VotingManager (+ Groth16Verifier, if VERIFIER_ADDRESS isn't
         already set) via the existing Foundry script, and captures the
         printed addresses.
      5. Writes crates/viche-relayer/.env from .env.example (if missing) and
         patches in the freshly deployed addresses.
      6. Resyncs crates/viche-frontend/public/circuits/{vote.wasm,
         vote_final.zkey} from circuits/build/ if they've drifted -- this
         exact staleness silently breaks every on-chain vote with
         "InvalidProof" and does NOT show up until you actually try to vote,
         so it's worth checking on every start, not just once.
      7. Starts viche-relayer (cargo run) and waits for /health.
      8. Starts the Trunk dev server (hot reload) for the frontend.
      9. Prints URLs and PIDs, then blocks -- Ctrl+C tears everything down.

.PARAMETER SkipDeploy
    Skip steps 2-3 (anvil start + contract deploy) and reuse whatever's
    already configured in crates/viche-relayer/.env. Useful if you already
    have anvil + a deployment running from a previous invocation and just
    want to restart the relayer/frontend.

.EXAMPLE
    ./scripts/dev.ps1
    Start everything fresh.

.EXAMPLE
    ./scripts/dev.ps1 -SkipDeploy
    Reuse an already-running anvil + existing .env; just (re)start the
    relayer and frontend.
#>
[CmdletBinding()]
param(
    [switch]$SkipDeploy
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

$LogDir = Join-Path $RepoRoot ".dev-logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$AnvilKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
$RelayerDir = Join-Path $RepoRoot "crates\viche-relayer"
$FrontendDir = Join-Path $RepoRoot "crates\viche-frontend"

$script:Procs = @()

function Write-Step($msg) {
    Write-Host ">> $msg" -ForegroundColor Cyan
}

function Require-Command($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Error "'$name' not found in PATH. See the Makefile's dependency list (forge, cast, anvil, cargo, trunk)."
        exit 1
    }
}

function Stop-AllChildren {
    Write-Host ""
    Write-Step "Shutting down..."
    foreach ($entry in $script:Procs) {
        $p = $entry.Proc
        if ($p -and -not $p.HasExited) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    # Belt-and-braces: also sweep by image name in case a process detached
    # from its parent (e.g. cargo spawning the actual relayer binary).
    foreach ($name in @("anvil", "viche-relayer", "trunk")) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Wait-ForHttp($url, $timeoutSec, $label) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) { return $true }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    Write-Error "$label did not respond at $url within ${timeoutSec}s. Check $LogDir for its log."
    return $false
}

function Wait-ForRpc($timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    $body = '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:8545" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 2 -ErrorAction Stop | Out-Null
            return $true
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    Write-Error "anvil did not respond on :8545 within ${timeoutSec}s. Check $LogDir\anvil.log."
    return $false
}

try {
    Require-Command cargo
    Require-Command trunk
    if (-not $SkipDeploy) {
        Require-Command anvil
        Require-Command forge
    }

    if (-not $SkipDeploy) {
        # contracts/lib/forge-std is a git submodule (see .gitmodules) -- a
        # plain `git clone` without --recurse-submodules leaves it as an
        # empty directory, which makes `forge script` fail deep inside solc
        # with a confusing "cannot find Script.sol" path error rather than
        # anything mentioning submodules. Catch it here instead.
        $forgeStdMarker = Join-Path $RepoRoot "contracts\lib\forge-std\src\Script.sol"
        if (-not (Test-Path $forgeStdMarker)) {
            Write-Step "contracts/lib/forge-std submodule not initialized -- fetching it..."
            if (Get-Command git -ErrorAction SilentlyContinue) {
                & git -C $RepoRoot submodule update --init --recursive
            }
            if (-not (Test-Path $forgeStdMarker)) {
                Write-Error "contracts/lib/forge-std is still missing Script.sol after 'git submodule update --init --recursive'. Run that command manually from $RepoRoot and check its output."
                exit 1
            }
        }
    }

    Write-Step "Clearing any leftover anvil/viche-relayer/trunk processes..."
    foreach ($name in @("anvil", "viche-relayer", "trunk")) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 300

    if (-not $SkipDeploy) {
        Write-Step "Starting anvil..."
        $anvilLog = Join-Path $LogDir "anvil.log"
        $anvilProc = Start-Process -FilePath "anvil" -RedirectStandardOutput $anvilLog -RedirectStandardError "$anvilLog.err" -PassThru -WindowStyle Hidden
        $script:Procs += [pscustomobject]@{ Name = "anvil"; Proc = $anvilProc }
        if (-not (Wait-ForRpc 30)) { exit 1 }
        Write-Host "   anvil ready on http://127.0.0.1:8545 (pid $($anvilProc.Id))"

        Write-Step "Deploying VotingManager..."
        $deployLog = Join-Path $LogDir "deploy.log"
        & forge script "contracts/script/DeployVotingManager.s.sol" `
            --rpc-url "http://127.0.0.1:8545" `
            --broadcast `
            --private-key $AnvilKey *> $deployLog

        if ($LASTEXITCODE -ne 0) {
            Write-Host (Get-Content $deployLog -Raw)
            Write-Error "Contract deploy failed -- see $deployLog. Common causes: 'make circuits' hasn't been run yet (VotingManager needs the generated Groth16Verifier.sol), or a missing/stale git submodule under contracts/lib."
            exit 1
        }

        $deployOut = Get-Content $deployLog -Raw
        $votingManager = [regex]::Match($deployOut, "VotingManager\s*:\s*(0x[0-9a-fA-F]{40})").Groups[1].Value
        $verifier = [regex]::Match($deployOut, "Groth16Verifier\s*:\s*(0x[0-9a-fA-F]{40})").Groups[1].Value

        if (-not $votingManager) {
            Write-Host $deployOut
            Write-Error "Could not find a deployed VotingManager address in the deploy output above."
            exit 1
        }
        Write-Host "   VotingManager   : $votingManager"
        Write-Host "   Groth16Verifier : $verifier"

        Write-Step "Writing crates/viche-relayer/.env..."
        $envPath = Join-Path $RelayerDir ".env"
        $envExamplePath = Join-Path $RelayerDir ".env.example"
        if (-not (Test-Path $envPath)) {
            Copy-Item $envExamplePath $envPath
        }
        $envContent = Get-Content $envPath -Raw
        $envContent = $envContent -replace "(?m)^VOTING_MANAGER_ADDRESS=.*$", "VOTING_MANAGER_ADDRESS=$votingManager"
        if ($verifier) {
            $envContent = $envContent -replace "(?m)^VERIFIER_ADDRESS=.*$", "VERIFIER_ADDRESS=$verifier"
        }
        Set-Content -Path $envPath -Value $envContent -NoNewline

        # Registration state from a previous poll shouldn't survive a fresh
        # anvil + fresh contracts underneath it -- the old merkle roots it's
        # keyed by will never match anything on the new chain.
        $registrationsPath = Join-Path $RelayerDir "registrations.json"
        if (Test-Path $registrationsPath) { Remove-Item $registrationsPath }
    } else {
        Write-Step "Skipping deploy (-SkipDeploy) -- reusing crates/viche-relayer/.env as-is."
    }

    Write-Step "Checking frontend circuit assets are in sync with circuits/build..."
    $buildZkey = Join-Path $RepoRoot "circuits\build\vote_final.zkey"
    $buildWasm = Join-Path $RepoRoot "circuits\build\vote_js\vote.wasm"
    $publicDir = Join-Path $FrontendDir "public\circuits"
    if (Test-Path $buildZkey) {
        New-Item -ItemType Directory -Force -Path $publicDir | Out-Null
        $publicZkey = Join-Path $publicDir "vote_final.zkey"
        $publicWasm = Join-Path $publicDir "vote.wasm"

        # Deliberately not using -and/-or short-circuit-style chaining here:
        # unlike && / ||, PowerShell's -and/-or evaluate BOTH sides always,
        # so a one-liner would call Get-FileHash on a file that might not
        # exist yet and fail before the existence check even mattered.
        if (Test-Path $publicZkey) {
            $needsZkeySync = (Get-FileHash $buildZkey).Hash -ne (Get-FileHash $publicZkey).Hash
        } else {
            $needsZkeySync = $true
        }

        $needsWasmSync = $false
        if (Test-Path $buildWasm) {
            if (Test-Path $publicWasm) {
                $needsWasmSync = (Get-FileHash $buildWasm).Hash -ne (Get-FileHash $publicWasm).Hash
            } else {
                $needsWasmSync = $true
            }
        }

        if ($needsZkeySync) {
            Copy-Item $buildZkey $publicZkey -Force
            Write-Host "   resynced vote_final.zkey (was stale or missing)"
        }
        if ($needsWasmSync) {
            Copy-Item $buildWasm $publicWasm -Force
            Write-Host "   resynced vote.wasm (was stale or missing)"
        }
        if (-not $needsZkeySync -and -not $needsWasmSync) {
            Write-Host "   already in sync"
        }
    } else {
        Write-Host "   circuits/build/vote_final.zkey not found -- run 'make circuits' first if you need real voting to work." -ForegroundColor Yellow
        Write-Host "   (poll creation/admin flows work fine without it; only proof generation needs it)" -ForegroundColor Yellow
    }

    Write-Step "Starting viche-relayer..."
    $relayerLog = Join-Path $LogDir "relayer.log"
    $relayerProc = Start-Process -FilePath "cargo" -ArgumentList "run", "-p", "viche-relayer" `
        -WorkingDirectory $RelayerDir `
        -RedirectStandardOutput $relayerLog -RedirectStandardError "$relayerLog.err" `
        -PassThru -WindowStyle Hidden
    $script:Procs += [pscustomobject]@{ Name = "viche-relayer"; Proc = $relayerProc }
    if (-not (Wait-ForHttp "http://127.0.0.1:3000/health" 120 "viche-relayer")) { exit 1 }
    Write-Host "   relayer ready on http://127.0.0.1:3000 (pid $($relayerProc.Id))"

    Write-Step "Starting Trunk (frontend dev server, hot reload)..."
    $frontendLog = Join-Path $LogDir "frontend.log"
    # Trunk's CLI only accepts NO_COLOR as literally "true"/"false"; some
    # shells (this one included) set the widely-used "1" convention instead,
    # which makes trunk refuse to start at all. Clear it for this child
    # process only -- doesn't touch the value in your own shell.
    $prevNoColor = $env:NO_COLOR
    $env:NO_COLOR = $null
    $trunkProc = Start-Process -FilePath "trunk" -ArgumentList "serve" `
        -WorkingDirectory $FrontendDir `
        -RedirectStandardOutput $frontendLog -RedirectStandardError "$frontendLog.err" `
        -PassThru -WindowStyle Hidden
    $env:NO_COLOR = $prevNoColor
    $script:Procs += [pscustomobject]@{ Name = "trunk"; Proc = $trunkProc }
    if (-not (Wait-ForHttp "http://127.0.0.1:8080" 120 "trunk")) { exit 1 }
    Write-Host "   frontend ready on http://127.0.0.1:8080 (pid $($trunkProc.Id))"

    Write-Host ""
    Write-Host "Everything's up:" -ForegroundColor Green
    if (-not $SkipDeploy) {
        Write-Host "  anvil     http://127.0.0.1:8545   log: $LogDir\anvil.log"
    }
    Write-Host "  relayer   http://127.0.0.1:3000   log: $LogDir\relayer.log"
    Write-Host "  frontend  http://127.0.0.1:8080   log: $LogDir\frontend.log"
    Write-Host ""
    Write-Host "Press Ctrl+C to stop everything." -ForegroundColor DarkGray

    while ($true) {
        Start-Sleep -Seconds 2
        # If a process died on its own (e.g. a compile error), stop the rest
        # too rather than leaving a half-up environment running silently.
        foreach ($entry in $script:Procs) {
            if ($entry.Proc.HasExited) {
                Write-Host ""
                Write-Error "$($entry.Name) (pid $($entry.Proc.Id)) exited unexpectedly. Check its log in $LogDir."
                exit 1
            }
        }
    }
} catch {
    # Built-in cmdlet errors (e.g. "Cannot bind argument to parameter 'Path'
    # because it is null") don't say WHICH line called the cmdlet or what
    # was actually null -- PositionMessage does, so surface it instead of
    # letting PowerShell's default one-line summary hide that.
    Write-Host ""
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor Red
    exit 1
} finally {
    Stop-AllChildren
}
