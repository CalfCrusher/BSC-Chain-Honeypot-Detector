#!/usr/bin/env python3
"""
BSC Honeypot Detector
Analyzes BEP-20 tokens on Binance Smart Chain to detect honeypot characteristics
"""

import sys
import argparse
from web3 import Web3
from typing import Dict, List, Tuple
import json
import requests

# BSC RPC endpoints
BSC_RPC_URL = "https://bsc-dataseed1.binance.org/"
BSC_CHAIN_ID = 56

# PancakeSwap Router v2 address
PANCAKESWAP_ROUTER = "0x10ED43C718714eb63d5aA57B78B54704E256024E"

# WBNB address
WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"

# BSCScan API endpoint
BSCSCAN_API = "https://api.bscscan.com/api"

# Standard BEP-20 ABI (minimal)
BEP20_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}, {"name": "_spender", "type": "address"}],
        "name": "allowance",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "_spender", "type": "address"}, {"name": "_value", "type": "uint256"}],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "owner",
        "outputs": [{"name": "", "type": "address"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "_maxTxAmount",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "maxTxAmount",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "paused",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "tradingEnabled",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    }
]

# PancakeSwap Router ABI (minimal)
ROUTER_ABI = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"}
        ],
        "name": "getAmountsOut",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "view",
        "type": "function"
    }
]


class HoneypotDetector:
    def __init__(self, contract_address: str):
        """Initialize the honeypot detector"""
        self.w3 = Web3(Web3.HTTPProvider(BSC_RPC_URL))
        if not self.w3.is_connected():
            raise Exception("Failed to connect to BSC network")
        
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.contract = self.w3.eth.contract(address=self.contract_address, abi=BEP20_ABI)
        self.router = self.w3.eth.contract(address=Web3.to_checksum_address(PANCAKESWAP_ROUTER), abi=ROUTER_ABI)
        
        self.findings = []
        self.is_honeypot = False
        self.risk_score = 0
    
    def add_finding(self, finding: str, severity: str = "INFO"):
        """Add a finding to the report"""
        self.findings.append(f"[{severity}] {finding}")
        if severity in ["HIGH", "CRITICAL"]:
            self.risk_score += 2
        elif severity == "MEDIUM":
            self.risk_score += 1
    
    def check_basic_info(self) -> Dict:
        """Get basic token information"""
        try:
            name = self.contract.functions.name().call()
            symbol = self.contract.functions.symbol().call()
            decimals = self.contract.functions.decimals().call()
            total_supply = self.contract.functions.totalSupply().call()
            
            self.add_finding(f"Token: {name} ({symbol})", "INFO")
            self.add_finding(f"Decimals: {decimals}, Total Supply: {total_supply / (10**decimals):,.2f}", "INFO")
            
            return {
                "name": name,
                "symbol": symbol,
                "decimals": decimals,
                "total_supply": total_supply
            }
        except Exception as e:
            self.add_finding(f"Failed to get basic info: {str(e)}", "HIGH")
            return {}
    
    def check_ownership(self):
        """Check if contract has an owner and if ownership is renounced"""
        try:
            owner = self.contract.functions.owner().call()
            if owner == "0x0000000000000000000000000000000000000000":
                self.add_finding("Ownership renounced (owner is zero address)", "INFO")
            else:
                self.add_finding(f"Contract has owner: {owner}", "MEDIUM")
                # Check owner's balance
                owner_balance = self.contract.functions.balanceOf(owner).call()
                total_supply = self.contract.functions.totalSupply().call()
                if total_supply > 0:
                    owner_percentage = (owner_balance / total_supply) * 100
                    if owner_percentage > 50:
                        self.add_finding(f"Owner holds {owner_percentage:.2f}% of supply", "HIGH")
                    elif owner_percentage > 10:
                        self.add_finding(f"Owner holds {owner_percentage:.2f}% of supply", "MEDIUM")
        except Exception as e:
            self.add_finding(f"No owner() function found or error: {str(e)}", "INFO")
    
    def check_contract_code(self):
        """Analyze contract bytecode for suspicious patterns"""
        try:
            code = self.w3.eth.get_code(self.contract_address)
            code_hex = code.hex()
            
            # Check if contract is verified (has source code)
            if len(code_hex) <= 4:
                self.add_finding("Contract has no code (not deployed or proxy)", "CRITICAL")
                return
            
            # Look for suspicious function selectors in bytecode
            suspicious_patterns = {
                "selfdestruct": "ff",  # SELFDESTRUCT opcode
                "delegatecall": "f4",  # DELEGATECALL opcode
            }
            
            for pattern_name, opcode in suspicious_patterns.items():
                if opcode in code_hex:
                    self.add_finding(f"Contains {pattern_name.upper()} opcode - potential backdoor", "HIGH")
            
        except Exception as e:
            self.add_finding(f"Error analyzing bytecode: {str(e)}", "MEDIUM")
    
    def simulate_buy_sell(self):
        """Simulate buy and sell transactions to detect honeypot behavior"""
        try:
            # Try to get amounts for a simulated buy
            test_amount = self.w3.to_wei(0.01, 'ether')  # 0.01 BNB
            path = [Web3.to_checksum_address(WBNB), self.contract_address]
            
            try:
                amounts_out = self.router.functions.getAmountsOut(test_amount, path).call()
                tokens_received = amounts_out[1]
                self.add_finding(f"Simulated buy: 0.01 BNB → {tokens_received} tokens", "INFO")
            except Exception as e:
                self.add_finding(f"Buy simulation failed: {str(e)}", "CRITICAL")
                self.is_honeypot = True
                return
            
            # Try to simulate sell
            if tokens_received > 0:
                path_sell = [self.contract_address, Web3.to_checksum_address(WBNB)]
                try:
                    amounts_out_sell = self.router.functions.getAmountsOut(tokens_received, path_sell).call()
                    bnb_received = amounts_out_sell[1]
                    
                    # Calculate slippage
                    buy_price = test_amount / tokens_received if tokens_received > 0 else 0
                    sell_price = bnb_received / tokens_received if tokens_received > 0 else 0
                    
                    if bnb_received == 0:
                        self.add_finding("Sell simulation returned 0 BNB - HONEYPOT DETECTED!", "CRITICAL")
                        self.is_honeypot = True
                    else:
                        slippage = ((test_amount - bnb_received) / test_amount) * 100
                        self.add_finding(f"Simulated sell: {tokens_received} tokens → {self.w3.from_wei(bnb_received, 'ether'):.6f} BNB", "INFO")
                        self.add_finding(f"Round-trip slippage: {slippage:.2f}%", "INFO")
                        
                        if slippage > 90:
                            self.add_finding("Extremely high slippage (>90%) - likely HONEYPOT!", "CRITICAL")
                            self.is_honeypot = True
                        elif slippage > 50:
                            self.add_finding("Very high slippage (>50%) - high risk!", "HIGH")
                
                except Exception as e:
                    self.add_finding(f"Sell simulation failed: {str(e)}", "CRITICAL")
                    self.is_honeypot = True
        
        except Exception as e:
            self.add_finding(f"Error in buy/sell simulation: {str(e)}", "HIGH")
    
    def check_transfer_restrictions(self):
        """Check for transfer restrictions"""
        try:
            # Try to call transfer with zero amount to see if it reverts
            test_address = "0x0000000000000000000000000000000000000001"
            
            # This is a static call, won't actually execute
            try:
                self.contract.functions.transfer(
                    Web3.to_checksum_address(test_address), 
                    0
                ).call({'from': self.contract_address})
                self.add_finding("Transfer function callable", "INFO")
            except Exception as e:
                error_msg = str(e).lower()
                if "transfer" in error_msg or "paused" in error_msg or "blocked" in error_msg:
                    self.add_finding(f"Transfer restrictions detected: {str(e)[:100]}", "HIGH")
        except Exception as e:
            self.add_finding(f"Error checking transfers: {str(e)}", "MEDIUM")
    
    def check_liquidity(self):
        """Check if token has liquidity on PancakeSwap"""
        try:
            # Try to get liquidity pair info
            factory_address = "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"  # PancakeSwap Factory
            factory_abi = [
                {
                    "constant": True,
                    "inputs": [
                        {"internalType": "address", "name": "", "type": "address"},
                        {"internalType": "address", "name": "", "type": "address"}
                    ],
                    "name": "getPair",
                    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
                    "type": "function"
                }
            ]
            
            factory = self.w3.eth.contract(address=Web3.to_checksum_address(factory_address), abi=factory_abi)
            pair_address = factory.functions.getPair(
                self.contract_address, 
                Web3.to_checksum_address(WBNB)
            ).call()
            
            if pair_address == "0x0000000000000000000000000000000000000000":
                self.add_finding("No liquidity pair found with BNB", "HIGH")
            else:
                self.add_finding(f"Liquidity pair exists: {pair_address}", "INFO")
                
                # Check liquidity amount
                bnb_balance = self.w3.eth.get_balance(pair_address)
                bnb_amount = self.w3.from_wei(bnb_balance, 'ether')
                self.add_finding(f"Pair BNB liquidity: {bnb_amount:.4f} BNB", "INFO")
                
                if bnb_amount < 0.1:
                    self.add_finding("Very low liquidity - high risk!", "HIGH")
        
        except Exception as e:
            self.add_finding(f"Error checking liquidity: {str(e)}", "MEDIUM")
    
    def check_source_verification(self):
        """Check if contract source code is verified on BSCScan"""
        try:
            # Call BSCScan API to check if contract is verified
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': self.contract_address,
                'apikey': 'YourApiKeyToken'  # Free tier works without real key
            }
            
            response = requests.get(BSCSCAN_API, params=params, timeout=10)
            data = response.json()
            
            if data['status'] == '1' and data['result']:
                source_code = data['result'][0].get('SourceCode', '')
                contract_name = data['result'][0].get('ContractName', '')
                
                if source_code and source_code != '':
                    self.add_finding(f"Contract verified on BSCScan: {contract_name}", "INFO")
                else:
                    self.add_finding("Contract NOT verified on BSCScan - high risk!", "HIGH")
            else:
                self.add_finding("Contract NOT verified on BSCScan - high risk!", "HIGH")
        
        except Exception as e:
            self.add_finding(f"Could not verify source code: {str(e)}", "MEDIUM")
    
    def check_max_transaction_limit(self):
        """Check for maximum transaction amount limits"""
        try:
            total_supply = self.contract.functions.totalSupply().call()
            max_tx = None
            
            # Try different common max tx variable names
            try:
                max_tx = self.contract.functions._maxTxAmount().call()
            except:
                try:
                    max_tx = self.contract.functions.maxTxAmount().call()
                except:
                    pass
            
            if max_tx is not None and max_tx > 0:
                max_tx_percentage = (max_tx / total_supply) * 100
                self.add_finding(f"Max transaction limit: {max_tx_percentage:.2f}% of supply", "INFO")
                
                if max_tx_percentage < 0.1:
                    self.add_finding(f"Extremely low max TX (<0.1%) - likely HONEYPOT!", "CRITICAL")
                    self.is_honeypot = True
                elif max_tx_percentage < 0.5:
                    self.add_finding(f"Very low max TX (<0.5%) - high risk!", "HIGH")
                elif max_tx_percentage < 1:
                    self.add_finding(f"Low max TX (<1%) - risky!", "MEDIUM")
            else:
                self.add_finding("No max transaction limit detected", "INFO")
        
        except Exception as e:
            self.add_finding(f"Could not check max TX limit: {str(e)}", "INFO")
    
    def check_pause_mechanism(self):
        """Check if contract has pause/lock mechanisms"""
        try:
            # Check for paused state
            try:
                is_paused = self.contract.functions.paused().call()
                if is_paused:
                    self.add_finding("Contract is PAUSED - trading disabled!", "CRITICAL")
                    self.is_honeypot = True
                else:
                    self.add_finding("Contract not paused", "INFO")
            except:
                pass
            
            # Check for trading enabled flag
            try:
                trading_enabled = self.contract.functions.tradingEnabled().call()
                if not trading_enabled:
                    self.add_finding("Trading is DISABLED!", "CRITICAL")
                    self.is_honeypot = True
                else:
                    self.add_finding("Trading enabled", "INFO")
            except:
                pass
        
        except Exception as e:
            self.add_finding(f"Could not check pause mechanism: {str(e)}", "INFO")
    
    def check_tax_fees(self):
        """Analyze buy and sell taxes by simulating transfers"""
        try:
            test_amount = self.w3.to_wei(0.01, 'ether')
            path_buy = [Web3.to_checksum_address(WBNB), self.contract_address]
            
            # Get expected tokens from buy
            try:
                amounts_out = self.router.functions.getAmountsOut(test_amount, path_buy).call()
                tokens_expected = amounts_out[1]
                
                if tokens_expected == 0:
                    return
                
                # Now check sell and calculate effective tax
                path_sell = [self.contract_address, Web3.to_checksum_address(WBNB)]
                try:
                    amounts_out_sell = self.router.functions.getAmountsOut(tokens_expected, path_sell).call()
                    bnb_received = amounts_out_sell[1]
                    
                    # Calculate effective total tax (including slippage)
                    effective_tax = ((test_amount - bnb_received) / test_amount) * 100
                    
                    # Rough estimate: assume half is slippage, half is tax (for low liquidity)
                    # For better liquidity, most loss is from tax
                    if effective_tax > 30:
                        estimated_tax = max(0, effective_tax - 10)  # Remove ~10% slippage estimate
                        self.add_finding(f"Estimated total buy+sell tax: ~{estimated_tax:.1f}%", "INFO")
                        
                        if estimated_tax > 50:
                            self.add_finding("Extremely high tax (>50%) detected!", "CRITICAL")
                        elif estimated_tax > 30:
                            self.add_finding("Very high tax (>30%) - be cautious!", "HIGH")
                        elif estimated_tax > 20:
                            self.add_finding("High tax (>20%) detected", "MEDIUM")
                
                except:
                    pass
            
            except:
                pass
        
        except Exception as e:
            self.add_finding(f"Could not analyze taxes: {str(e)}", "INFO")
    
    def check_gas_estimates(self):
        """Compare gas estimates for buy vs sell to detect restrictions"""
        try:
            # Create test addresses
            test_buyer = "0x0000000000000000000000000000000000000001"
            test_seller = "0x0000000000000000000000000000000000000002"
            
            test_amount_tokens = self.w3.to_wei(1, 'ether')  # 1 token
            
            # Estimate gas for a transfer (simulates selling)
            try:
                gas_transfer = self.w3.eth.estimate_gas({
                    'from': Web3.to_checksum_address(test_seller),
                    'to': self.contract_address,
                    'data': self.contract.encodeABI(fn_name='transfer', args=[
                        Web3.to_checksum_address(test_buyer),
                        test_amount_tokens
                    ])
                })
                
                self.add_finding(f"Estimated gas for transfer: {gas_transfer:,}", "INFO")
                
                # Normal BEP-20 transfer should be 50k-100k gas
                if gas_transfer > 500000:
                    self.add_finding("Extremely high gas for transfer (>500k) - suspicious!", "HIGH")
                elif gas_transfer > 300000:
                    self.add_finding("High gas for transfer (>300k) - unusual", "MEDIUM")
            
            except Exception as e:
                # If gas estimation fails, it means the transaction would revert
                error_msg = str(e).lower()
                if 'revert' in error_msg or 'execution reverted' in error_msg:
                    self.add_finding(f"Transfer gas estimation failed - may indicate sell restrictions!", "HIGH")
        
        except Exception as e:
            self.add_finding(f"Could not estimate gas: {str(e)}", "INFO")
    
    def analyze(self) -> Dict:
        """Run all detection checks"""
        print(f"\n{'='*60}")
        print(f"BSC Honeypot Detector")
        print(f"{'='*60}")
        print(f"Analyzing contract: {self.contract_address}")
        print(f"{'='*60}\n")
        
        # Run all checks
        token_info = self.check_basic_info()
        self.check_source_verification()
        self.check_ownership()
        self.check_contract_code()
        self.check_max_transaction_limit()
        self.check_pause_mechanism()
        self.check_liquidity()
        self.check_transfer_restrictions()
        self.check_tax_fees()
        self.check_gas_estimates()
        self.simulate_buy_sell()
        
        # Determine final verdict
        if self.is_honeypot or self.risk_score >= 4:
            verdict = "🚨 HONEYPOT DETECTED"
            verdict_color = "CRITICAL"
        elif self.risk_score >= 2:
            verdict = "⚠️  HIGH RISK - Proceed with extreme caution"
            verdict_color = "HIGH"
        elif self.risk_score >= 1:
            verdict = "⚡ MEDIUM RISK - Be cautious"
            verdict_color = "MEDIUM"
        else:
            verdict = "✅ APPEARS SAFE - Low risk detected"
            verdict_color = "INFO"
        
        return {
            "contract_address": self.contract_address,
            "token_info": token_info,
            "verdict": verdict,
            "verdict_color": verdict_color,
            "risk_score": self.risk_score,
            "findings": self.findings
        }
    
    def print_report(self, analysis: Dict):
        """Print the analysis report"""
        print("\n" + "="*60)
        print("FINDINGS:")
        print("="*60)
        for finding in analysis["findings"]:
            print(finding)
        
        print("\n" + "="*60)
        print("FINAL VERDICT:")
        print("="*60)
        print(f"{analysis['verdict']}")
        print(f"Risk Score: {analysis['risk_score']}/10")
        print("="*60 + "\n")
        
        if analysis["verdict_color"] in ["CRITICAL", "HIGH"]:
            print("⚠️  WARNING: This token shows characteristics of a honeypot!")
            print("DO NOT invest without thorough research and verification.")
        elif analysis["verdict_color"] == "MEDIUM":
            print("⚠️  CAUTION: This token has some concerning characteristics.")
            print("Research thoroughly before investing.")
        else:
            print("ℹ️  Note: This analysis is not financial advice.")
            print("Always DYOR (Do Your Own Research) before investing.")
        
        print()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Detect honeypots on Binance Smart Chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python honeypot_detector.py --address 0x1234567890123456789012345678901234567890
        """
    )
    
    parser.add_argument(
        '--address',
        type=str,
        required=True,
        help='BEP-20 token contract address to analyze'
    )
    
    args = parser.parse_args()
    
    try:
        # Validate address format
        if not args.address.startswith('0x') or len(args.address) != 42:
            print("Error: Invalid contract address format")
            print("Address must be in format: 0x followed by 40 hexadecimal characters")
            sys.exit(1)
        
        # Create detector and run analysis
        detector = HoneypotDetector(args.address)
        analysis = detector.analyze()
        detector.print_report(analysis)
        
        # Exit with appropriate code
        if analysis["verdict_color"] == "CRITICAL":
            sys.exit(2)  # Honeypot detected
        elif analysis["verdict_color"] == "HIGH":
            sys.exit(1)  # High risk
        else:
            sys.exit(0)  # Safe or medium risk
    
    except Exception as e:
        print(f"\n❌ Error: {str(e)}\n")
        sys.exit(3)


if __name__ == "__main__":
    main()
