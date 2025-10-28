# BSC Honeypot Detector

A Python script that analyzes BEP-20 tokens on Binance Smart Chain (BSC) to detect honeypot characteristics using multiple detection techniques.

Now with colorized, readable output powered by Rich, optional external honeypot simulation, JSON output, and cached BNB/USD pricing.

## Features

The detector performs the following checks:

1. **Basic Token Information** - Retrieves name, symbol, decimals, and total supply
2. **Source Code Verification** - Checks if contract is verified on BSCScan
3. **Ownership Analysis** - Checks if ownership is renounced and owner's token holdings
4. **Bytecode Analysis** - Scans for suspicious opcodes (selfdestruct, delegatecall)
5. **Max Transaction Limits** - Detects unreasonably low transaction limits
6. **Pause/Lock Mechanisms** - Checks if trading is paused or disabled
7. **Liquidity Check** - Verifies PancakeSwap liquidity pool existence and depth
8. **Transfer Restrictions** - Tests for transfer limitations or blocks
9. **Tax/Fee Analysis** - Estimates buy and sell taxes from slippage analysis
10. **Gas Estimation** - Compares gas costs to detect unusual behavior
11. **Buy/Sell Simulation** - Simulates trades to detect selling restrictions and calculate slippage
12. **External Honeypot Check (optional)** - Uses honeypot.is public API for an additional simulation signal
13. **JSON Output** - Machine-readable output for automation with `--json`
14. **Price Caching** - BNB/USD fetched and cached (fallback to env or default)

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

Tip: Use a virtual environment:
```bash
python -m venv env
source env/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

## Usage

Run the script with a single command-line argument:

```bash
python honeypot_detector.py --address <contract_address>

# Optional flags
python honeypot_detector.py --address <contract_address> --no-external    # skip external honeypot API
python honeypot_detector.py --address <contract_address> --external-only  # run ONLY external check (fast)
python honeypot_detector.py --address <contract_address> --json           # JSON output
python honeypot_detector.py --address <contract_address> --no-verify      # skip explorer source verification
```

### Example

```bash
python honeypot_detector.py --address 0x1234567890123456789012345678901234567890
```

## Output

The script will:
- Display token information
- List all findings with severity levels (INFO, MEDIUM, HIGH, CRITICAL)
- Calculate a risk score
- Provide a final verdict:
  - ✅ APPEARS SAFE - Low risk detected
  - ⚡ MEDIUM RISK - Be cautious
  - ⚠️  HIGH RISK - Proceed with extreme caution
  - 🚨 HONEYPOT DETECTED - Do not invest!

Colorized output is enabled automatically when the Rich library is available (installed via requirements.txt). If Rich isn't installed, the script falls back to plain text. When `--json` is provided, the script suppresses tables and prints a JSON document.

## Exit Codes

- `0` - Token appears safe or medium risk
- `1` - High risk detected
- `2` - Honeypot detected
- `3` - Error during analysis

## Detection Techniques

### 1. Basic Token Info
- Retrieves token name, symbol, decimals, and total supply
- Validates contract is properly deployed

### 2. Source Code Verification
- Checks if contract is verified on BSCScan
- Unverified contracts are flagged as high risk
- Verified contracts allow for code review

### 3. Ownership Check
- Verifies if contract ownership is renounced
- Checks owner's percentage of total supply
- High owner concentration is flagged as risky

### 4. Bytecode Analysis
- Scans for dangerous opcodes that could enable backdoors
- Detects selfdestruct and delegatecall patterns
- Identifies potential hidden admin functions

### 5. Max Transaction Limits
- Checks for `maxTxAmount` restrictions
- Flags extremely low limits (<0.1% of supply) as honeypot indicators
- Low limits can prevent selling meaningful amounts

### 6. Pause/Lock Mechanisms
- Detects if contract is paused
- Checks if trading is disabled
- Identifies tokens that can be frozen by owner

### 7. Liquidity Analysis
- Checks for liquidity pair on PancakeSwap
- Evaluates liquidity depth in BNB
- Low liquidity indicates higher risk and manipulation potential

### 8. Transfer Restrictions
- Tests if transfer function is callable
- Identifies paused or blocked transfers
- Detects hidden transfer restrictions

### 9. Tax/Fee Analysis
- Estimates combined buy and sell taxes
- Calculates effective tax from round-trip simulation
- Flags tokens with extremely high taxes (>50%)
- High taxes can make it unprofitable to sell

### 10. Gas Estimation
- Estimates gas costs for transfers
- Normal transfers should cost 50k-100k gas
- Extremely high gas (>500k) indicates complex/suspicious logic

### 11. Buy/Sell Simulation
- Simulates buying tokens with BNB
- Simulates selling tokens back to BNB
- Calculates round-trip slippage
- Detects if selling is blocked or heavily taxed
- **Most critical test** - proves if you can actually sell

## Requirements

- Python 3.7+
- Active internet connection
- BSC RPC endpoint access

Optional environment variables:
- `ETHERSCAN_API`: Preferred key for Etherscan API v2 (multi-chain, including BSC). Create a free key on etherscan.io and it works for BscScan via v2.
- `BSCSCAN_API_KEY`: Legacy fallback for BscScan v1 endpoint if v2 is unavailable.
- `BNB_PRICE_USD`: Override the auto-fetched BNB price (used for USD estimates). If not set, the script fetches from Binance/Coingecko and caches it for ~10 minutes.

## Disclaimer

⚠️ This tool is for educational and research purposes only. It is NOT financial advice. Always conduct your own research (DYOR) before investing in any cryptocurrency or token. The tool may produce false positives or false negatives. Use at your own risk.

## Network

- **Chain**: Binance Smart Chain (BSC)
- **Chain ID**: 56
- **RPC**: https://bsc-dataseed1.binance.org/
- **DEX**: PancakeSwap V2

External services (best-effort, optional):
- Etherscan API v2 (with `ETHERSCAN_API`) for source verification
- Legacy BscScan API (with `BSCSCAN_API_KEY`) as a fallback
- Sourcify repository (no key) as an additional fallback for verified source
- honeypot.is public API for additional honeypot simulation signal
- Binance/Coingecko public price APIs for BNB/USD price

## License

MIT License
