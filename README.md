# BSC Honeypot Detector

A Python script that analyzes BEP-20 tokens on Binance Smart Chain (BSC) to detect honeypot characteristics using multiple detection techniques.

## Features

The detector performs the following checks:

1. **Basic Token Information** - Retrieves name, symbol, decimals, and total supply
2. **Ownership Analysis** - Checks if ownership is renounced and owner's token holdings
3. **Bytecode Analysis** - Scans for suspicious opcodes (selfdestruct, delegatecall)
4. **Liquidity Check** - Verifies PancakeSwap liquidity pool existence and depth
5. **Transfer Restrictions** - Tests for transfer limitations or blocks
6. **Buy/Sell Simulation** - Simulates trades to detect selling restrictions and calculate slippage

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the script with a single command-line argument:

```bash
python honeypot_detector.py --address <contract_address>
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

## Exit Codes

- `0` - Token appears safe or medium risk
- `1` - High risk detected
- `2` - Honeypot detected
- `3` - Error during analysis

## Detection Techniques

### 1. Ownership Check
- Verifies if contract ownership is renounced
- Checks owner's percentage of total supply
- High owner concentration is flagged as risky

### 2. Bytecode Analysis
- Scans for dangerous opcodes that could enable backdoors
- Detects selfdestruct and delegatecall patterns

### 3. Liquidity Analysis
- Checks for liquidity pair on PancakeSwap
- Evaluates liquidity depth
- Low liquidity indicates higher risk

### 4. Buy/Sell Simulation
- Simulates buying tokens with BNB
- Simulates selling tokens back to BNB
- Calculates round-trip slippage
- Detects if selling is blocked or restricted

### 5. Transfer Restrictions
- Tests if transfer function is callable
- Identifies paused or blocked transfers

## Requirements

- Python 3.7+
- Active internet connection
- BSC RPC endpoint access

## Disclaimer

⚠️ This tool is for educational and research purposes only. It is NOT financial advice. Always conduct your own research (DYOR) before investing in any cryptocurrency or token. The tool may produce false positives or false negatives. Use at your own risk.

## Network

- **Chain**: Binance Smart Chain (BSC)
- **Chain ID**: 56
- **RPC**: https://bsc-dataseed1.binance.org/
- **DEX**: PancakeSwap V2

## License

MIT License
