#!/usr/bin/env python3
"""
BSC Honeypot Detector
Analyzes BEP-20 tokens on Binance Smart Chain to detect honeypot characteristics
"""

import sys
import argparse
from web3 import Web3
from typing import Dict, List, Optional, Any
import json
import requests
import os
import time

# Load .env if present (for ETHERSCAN_API, etc.)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Optional rich import for colored output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    _HAS_RICH = True
    console = Console()
except Exception:
    _HAS_RICH = False
    console = None

# BSC RPC endpoints
BSC_RPC_URL = "https://bsc-dataseed1.binance.org/"
BSC_CHAIN_ID = 56

# PancakeSwap Router v2 address
PANCAKESWAP_ROUTER = "0x10ED43C718714eb63d5aA57B78B54704E256024E"

# WBNB address
WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"

# Explorer API endpoints (Etherscan v2 preferred, legacy BscScan as fallback)
ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"
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
    # Some tokens use getOwner()
    {
        "constant": True,
        "inputs": [],
        "name": "getOwner",
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
    },
    # Common alt flags
    {
        "constant": True,
        "inputs": [],
        "name": "tradingOpen",
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
    def __init__(self, contract_address: str, use_external: bool = True, external_only: bool = False, skip_verify: bool = False):
        """Initialize the honeypot detector"""
        self.w3 = Web3(Web3.HTTPProvider(BSC_RPC_URL))
        if not self.w3.is_connected():
            raise Exception("Failed to connect to BSC network")
        
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.contract = self.w3.eth.contract(address=self.contract_address, abi=BEP20_ABI)
        self.router = self.w3.eth.contract(address=Web3.to_checksum_address(PANCAKESWAP_ROUTER), abi=ROUTER_ABI)
        
        # findings: list of dicts: {severity, message}
        self.findings: List[Dict[str, str]] = []
        self.is_honeypot = False
        self.risk_score = 0
        self.red_flags = 0  # Count of serious issues
        self.green_flags = 0  # Count of positive indicators
        self.token_info_cache: Optional[Dict] = None
        # API keys: prefer Etherscan v2 key, fallback to legacy BscScan key
        # Support both ETHERSCAN_API and ETHERSCAN_API_KEY env names
        self._etherscan_api_key = os.environ.get("ETHERSCAN_API") or os.environ.get("ETHERSCAN_API_KEY")
        self._bscscan_api_key = os.environ.get("BSCSCAN_API_KEY")
        self.use_external = use_external
        self.external_only = external_only
        self.skip_verify = skip_verify
    
    def add_finding(self, message: str, severity: str = "INFO"):
        """Add a finding to the report"""
        self.findings.append({"severity": severity, "message": message})
        if severity == "CRITICAL":
            self.risk_score += 3
            self.red_flags += 1
        elif severity == "HIGH":
            self.risk_score += 2
            self.red_flags += 1
        elif severity == "MEDIUM":
            self.risk_score += 1
        elif severity == "GOOD":
            # Positive indicators reduce risk slightly
            self.risk_score = max(0, self.risk_score - 1)
            self.green_flags += 1
    
    def check_basic_info(self) -> Dict:
        """Get basic token information"""
        try:
            name = self.contract.functions.name().call()
            symbol = self.contract.functions.symbol().call()
            decimals = int(self.contract.functions.decimals().call())
            total_supply = int(self.contract.functions.totalSupply().call())
            
            self.add_finding(f"Token: {name} ({symbol})", "INFO")
            self.add_finding(f"Decimals: {decimals}, Total Supply: {total_supply / (10**decimals):,.2f}", "INFO")
            
            self.token_info_cache = {
                "name": name,
                "symbol": symbol,
                "decimals": decimals,
                "total_supply": total_supply
            }
            return self.token_info_cache
        except Exception as e:
            self.add_finding(f"Failed to get basic info: {str(e)}", "HIGH")
            return {}
    
    def check_ownership(self):
        """Check if contract has an owner and if ownership is renounced"""
        try:
            owner = None
            # Try owner() first
            try:
                owner = self.contract.functions.owner().call()
            except Exception:
                pass
            # Try getOwner()
            if owner in (None, "0x0000000000000000000000000000000000000000"):
                try:
                    owner = self.contract.functions.getOwner().call()
                except Exception:
                    pass
            if owner is None:
                raise Exception("owner() / getOwner() not available")
            if owner == "0x0000000000000000000000000000000000000000":
                # Renounced ownership can be good OR bad
                # Good: If contract is verified and audited
                # Bad: If contract is unverified (can't check for backdoors)
                self.add_finding("⚠️  Ownership renounced - owner cannot change contract", "INFO")
                self.add_finding("⚠️  WARNING: If contract is unverified, this is HIGH RISK!", "INFO")
            else:
                # Check owner's balance - this is the important part
                owner_balance = int(self.contract.functions.balanceOf(owner).call())
                total_supply = int(self.contract.functions.totalSupply().call())
                if total_supply > 0:
                    owner_percentage = (owner_balance / total_supply) * 100
                    if owner_percentage > 50:
                        self.add_finding(f"Owner: {owner}", "INFO")
                        self.add_finding(f"🚨 Owner holds {owner_percentage:.2f}% of supply - EXTREME CENTRALIZATION!", "CRITICAL")
                    elif owner_percentage > 30:
                        self.add_finding(f"Owner: {owner}", "INFO")
                        self.add_finding(f"⚠️  Owner holds {owner_percentage:.2f}% of supply - high centralization risk", "HIGH")
                    elif owner_percentage > 10:
                        self.add_finding(f"Owner holds {owner_percentage:.2f}% of supply - moderate risk", "MEDIUM")
                    elif owner_percentage > 2:
                        self.add_finding(f"Owner holds {owner_percentage:.2f}% of supply", "INFO")
                    else:
                        self.add_finding(f"✓ Owner holds minimal supply ({owner_percentage:.2f}%)", "GOOD")
                else:
                    self.add_finding(f"Owner: {owner}", "INFO")
        except Exception as e:
            self.add_finding(f"No owner function found or error: {str(e)}", "INFO")
    
    def check_contract_code(self):
        """Analyze contract bytecode for suspicious patterns"""
        try:
            code = self.w3.eth.get_code(self.contract_address)
            code_hex = code.hex()
            
            # Check if contract is verified (has source code)
            if len(code_hex) <= 4:
                self.add_finding("Contract has no code (not deployed or proxy)", "CRITICAL")
                return
            
            # Avoid naive opcode scanning; just sanity-check presence of bytecode and size
            if len(code_hex) < 100:
                self.add_finding("Contract bytecode unusually small - may be proxy or non-standard", "MEDIUM")
            
            self.add_finding("Bytecode analysis: Basic checks passed", "INFO")
            
        except Exception as e:
            self.add_finding(f"Error analyzing bytecode: {str(e)}", "MEDIUM")
    
    def simulate_buy_sell(self):
        """Simulate buy/sell via router quotes (heuristic only)"""
        try:
            # Skip if this IS WBNB (can't trade WBNB for WBNB)
            if self.contract_address.lower() == WBNB.lower():
                self.add_finding("Token is WBNB - skipping buy/sell simulation", "INFO")
                return
            
            # Try to get amounts for a simulated buy
            test_amount = self.w3.to_wei(0.01, 'ether')  # 0.01 BNB
            path = [Web3.to_checksum_address(WBNB), self.contract_address]
            
            try:
                amounts_out = self.router.functions.getAmountsOut(test_amount, path).call()
                tokens_received = amounts_out[1]
                # If we know decimals, format nicely
                if self.token_info_cache:
                    dec = self.token_info_cache.get("decimals", 18)
                    pretty = tokens_received / (10 ** dec)
                    self.add_finding(f"Simulated buy: 0.01 BNB → {pretty:,.6f} tokens", "INFO")
                else:
                    self.add_finding(f"Simulated buy: 0.01 BNB → {tokens_received} tokens", "INFO")
            except Exception as e:
                error_msg = str(e)
                # Check if it's just a missing pair issue vs actual honeypot
                if "IDENTICAL_ADDRESSES" in error_msg or "INSUFFICIENT_LIQUIDITY" in error_msg:
                    self.add_finding(f"Cannot simulate trade (no liquidity pair)", "INFO")
                else:
                    self.add_finding(f"Buy simulation failed: {str(e)[:200]}", "CRITICAL")
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
                        self.add_finding(f"Simulated sell: tokens → {self.w3.from_wei(bnb_received, 'ether'):.6f} BNB", "INFO")
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
        """Heuristic checks for transfer restrictions (non-invasive)."""
        try:
            # We avoid unreliable static transfer tests that often false-positive.
            # Instead, look for presence of common flags via function probes.
            flags = [
                ("paused", "Contract is PAUSABLE"),
                ("tradingEnabled", "Has trading enable switch"),
                ("tradingOpen", "Has trading open flag"),
            ]
            for fn, desc in flags:
                try:
                    _ = getattr(self.contract.functions, fn)().call()
                    self.add_finding(f"{desc} ({fn} present)", "INFO")
                except Exception:
                    continue
        except Exception as e:
            self.add_finding(f"Error checking transfer flags: {str(e)}", "MEDIUM")
    
    def check_liquidity(self):
        """Check if token has liquidity on PancakeSwap"""
        try:
            # Skip if this IS WBNB
            if self.contract_address.lower() == WBNB.lower():
                self.add_finding("Token is WBNB (base trading pair) - no pair check needed", "INFO")
                return
            
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
            
            # Pair ABI for getting reserves
            pair_abi = [
                {
                    "constant": True,
                    "inputs": [],
                    "name": "getReserves",
                    "outputs": [
                        {"internalType": "uint112", "name": "_reserve0", "type": "uint112"},
                        {"internalType": "uint112", "name": "_reserve1", "type": "uint112"},
                        {"internalType": "uint32", "name": "_blockTimestampLast", "type": "uint32"}
                    ],
                    "type": "function"
                },
                {
                    "constant": True,
                    "inputs": [],
                    "name": "token0",
                    "outputs": [{"internalType": "address", "name": "", "type": "address"}],
                    "type": "function"
                },
                {
                    "constant": True,
                    "inputs": [],
                    "name": "token1",
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
                return
            
            self.add_finding(f"Liquidity pair exists: {pair_address}", "INFO")
            
            # Get actual reserves from the pair contract
            pair_contract = self.w3.eth.contract(address=Web3.to_checksum_address(pair_address), abi=pair_abi)
            reserves = pair_contract.functions.getReserves().call()
            token0 = pair_contract.functions.token0().call()
            token1 = pair_contract.functions.token1().call()
            
            # Determine which reserve is WBNB and which is the token
            if token0.lower() == WBNB.lower():
                bnb_reserve = reserves[0]
                token_reserve = reserves[1]
            else:
                bnb_reserve = reserves[1]
                token_reserve = reserves[0]
            
            bnb_amount = self.w3.from_wei(bnb_reserve, 'ether')
            
            # Calculate market cap (approximate, based on liquidity)
            # In a typical LP, liquidity is split 50/50, so market cap ≈ 2 * BNB liquidity
            estimated_mcap_bnb = float(bnb_amount) * 2
            
            # Get BNB price via cache/fetch
            bnb_price = self.get_bnb_price_usd()
            bnb_amount_f = float(bnb_amount)
            self.add_finding(f"Liquidity: {bnb_amount_f:.4f} BNB (~${bnb_amount_f * bnb_price:.0f} USD)", "INFO")
            self.add_finding(f"Est. Market Cap: ~{estimated_mcap_bnb:.1f} BNB (~${estimated_mcap_bnb * bnb_price:.0f} USD)", "INFO")
            
            # Risk assessment based on liquidity depth
            # Critical thresholds considering rug pull risk
            if bnb_amount < 0.1:
                self.add_finding("💀 Extremely low liquidity (<0.1 BNB / <$60) - EXTREME RUG RISK!", "CRITICAL")
            elif bnb_amount < 1:
                self.add_finding("⚠️  Very low liquidity (<1 BNB / <$600) - high rug pull risk!", "HIGH")
            elif bnb_amount < 10:
                self.add_finding("⚠️  Low liquidity (<10 BNB / <$6k) - significant risk", "HIGH")
            elif bnb_amount < 50:
                self.add_finding("⚠️  Below average liquidity (<50 BNB / <$30k) - risky", "MEDIUM")
            elif bnb_amount < 100:
                self.add_finding("Moderate liquidity (50-100 BNB) - acceptable for small caps", "INFO")
            elif bnb_amount < 500:
                self.add_finding("✓ Good liquidity (100-500 BNB)", "GOOD")
            else:
                self.add_finding("✓ Excellent liquidity (>500 BNB)", "GOOD")
        
        except Exception as e:
            self.add_finding(f"Error checking liquidity: {str(e)}", "MEDIUM")
    
    def check_source_verification(self):
        """Check if contract is verified using multiple sources in order:
        1) Etherscan API v2 (multi-chain) if ETHERSCAN_API(_KEY) is set
        2) Sourcify repository check (no key required)
        3) Legacy BscScan API only if BSCSCAN_API_KEY is set
        """
        # 1) Etherscan v2 (preferred)
        try:
            if self._etherscan_api_key:
                headers = {"X-API-Key": self._etherscan_api_key}
                # Try a few permutations for compatibility across v2 deployments
                chains = ["bsc", "bsc-mainnet"]
                addr_keys = ["address", "contractaddress"]
                for chain_val in chains:
                    for addr_key in addr_keys:
                        params_v2 = {
                            "chain": chain_val,
                            "module": "contract",
                            "action": "getsourcecode",
                            addr_key: self.contract_address,
                        }
                        r = requests.get(ETHERSCAN_V2_API, params=params_v2, headers=headers, timeout=10)
                        if r.status_code != 200:
                            continue
                        data = r.json()
                        result = data.get("result")
                        if isinstance(result, list) and len(result) > 0:
                            result0 = result[0]
                            source_code = result0.get("SourceCode") or result0.get("Sourcecode") or ""
                            contract_name = result0.get("ContractName") or result0.get("Contractname") or ""
                            if source_code:
                                self.add_finding(f"✓ Contract verified (Etherscan v2): {contract_name}", "GOOD")
                            else:
                                self.add_finding("⚠️  Contract NOT verified (Etherscan v2)", "MEDIUM")
                            return
                        # Check alt success shapes
                        status = str(data.get("status", "")).lower()
                        message = str(data.get("message", "")).lower()
                        if status in ("1", "ok", "success"):
                            # Treat as not verified if success but no source
                            self.add_finding("⚠️  Contract NOT verified (Etherscan v2)", "MEDIUM")
                            return
                # If all permutations failed, continue to sourcify
        except Exception as e:
            self.add_finding(f"Etherscan v2 check failed: {str(e)}", "INFO")

        # 2) Sourcify check (no key, fast)
        try:
            # Status endpoint indicates if address is verified (perfect/partial)
            sourcify_url = f"https://repo.sourcify.dev/status/address/{self.contract_address}/56"
            rs = requests.get(sourcify_url, timeout=8)
            if rs.status_code == 200:
                sdata = rs.json()
                # Expect a list with entries having status: 'perfect' or 'partial'
                def _extract_status(obj):
                    if isinstance(obj, dict):
                        return obj.get("status")
                    return None
                statuses = []
                if isinstance(sdata, list):
                    statuses = [ _extract_status(x) for x in sdata ]
                elif isinstance(sdata, dict):
                    statuses = [_extract_status(sdata)]
                statuses = [s for s in statuses if s]
                if any(s in ("perfect", "partial") for s in statuses):
                    tag = next((s for s in statuses if s in ("perfect", "partial")), "verified")
                    self.add_finding(f"✓ Contract verified via Sourcify ({tag})", "GOOD")
                    return
        except Exception:
            # ignore and continue
            pass

        # 3) Legacy BscScan endpoint (only if user provided a key)
        try:
            if self._bscscan_api_key:
                params = {
                    'module': 'contract',
                    'action': 'getsourcecode',
                    'address': self.contract_address,
                    'apikey': self._bscscan_api_key
                }
                response = requests.get(BSCSCAN_API, params=params, timeout=10)
                data = response.json()
                # Legacy schema uses status/result
                result_list = data.get('result') or []
                if isinstance(result_list, list) and result_list:
                    result0 = result_list[0]
                    source_code = result0.get('SourceCode', '')
                    contract_name = result0.get('ContractName', '')
                    if source_code:
                        self.add_finding(f"✓ Contract verified on BscScan: {contract_name}", "GOOD")
                    else:
                        self.add_finding("⚠️  Contract NOT verified on BscScan", "MEDIUM")
                else:
                    # Don't spam raw NOTOK; make it human-readable
                    message = data.get('message') or 'no result'
                    self.add_finding(f"BscScan legacy check returned: {message}", "INFO")
                return
        except Exception as e:
            self.add_finding(f"BscScan legacy check failed: {str(e)}", "INFO")

        # If we got here, we couldn't determine status
        self.add_finding("Source verification status unknown (no response from explorers)", "INFO")
    
    def check_max_transaction_limit(self):
        """Check for maximum transaction amount limits"""
        try:
            total_supply = int(self.contract.functions.totalSupply().call())
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
                # Try common max wallet checks as additional restriction indicators
                max_wallet = None
                for fn in ("_maxWalletSize", "maxWalletAmount", "maxWallet", "_maxWalletAmount"):
                    try:
                        max_wallet = getattr(self.contract.functions, fn)().call()
                        break
                    except Exception:
                        continue
                if max_wallet:
                    perc = (max_wallet / total_supply) * 100
                    self.add_finding(f"Max wallet limit: {perc:.2f}% of supply", "INFO")
                    if perc < 0.5:
                        self.add_finding("Very low max wallet (<0.5%) - high risk of sell blocks", "HIGH")
                    elif perc < 1:
                        self.add_finding("Low max wallet (<1%) - risky", "MEDIUM")
                else:
                    self.add_finding("No max transaction/wallet limit detected", "INFO")
        
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
            except Exception:
                pass
            
            # Check for trading enabled flags (multiple variants)
            for fn in ("tradingEnabled", "tradingOpen"):
                try:
                    trading_enabled = getattr(self.contract.functions, fn)().call()
                    if not trading_enabled:
                        self.add_finding("Trading is DISABLED!", "CRITICAL")
                        self.is_honeypot = True
                    else:
                        self.add_finding("Trading enabled", "INFO")
                    break
                except Exception:
                    continue
        
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
                    effective_loss = ((test_amount - bnb_received) / test_amount) * 100
                    
                    # Only report tax if the loss is significant
                    # Normal slippage for good liquidity should be <5%
                    # Anything above that is likely tax
                    if effective_loss > 15:
                        # Assume first 5% is slippage, rest is tax
                        estimated_tax = max(0, effective_loss - 5)
                        self.add_finding(f"Estimated total buy+sell tax (heuristic): ~{estimated_tax:.1f}%", "INFO")
                        
                        if estimated_tax > 50:
                            self.add_finding("⚠️  Extremely high tax (>50%) detected!", "CRITICAL")
                        elif estimated_tax > 30:
                            self.add_finding("High tax (>30%) - reduces profits significantly", "HIGH")
                        elif estimated_tax > 20:
                            self.add_finding("Moderate tax (>20%)", "MEDIUM")
                
                except:
                    pass
            
            except:
                pass
        
        except Exception as e:
            self.add_finding(f"Could not analyze taxes: {str(e)}", "INFO")
    
    def check_gas_estimates(self):
        """Lightweight gas probe for transfer(0) to avoid false positives."""
        try:
            test_from = "0x1111111111111111111111111111111111111111"
            test_to = "0x2222222222222222222222222222222222222222"
            try:
                gas_transfer = self.w3.eth.estimate_gas({
                    'from': Web3.to_checksum_address(test_from),
                    'to': self.contract_address,
                    'data': self.contract.encodeABI(fn_name='transfer', args=[
                        Web3.to_checksum_address(test_to),
                        0
                    ])
                })
                self.add_finding(f"Estimated gas for transfer(0): {gas_transfer:,}", "INFO")
            except Exception:
                # Many tokens revert on transfer(0); don't over-weight this
                self.add_finding("transfer(0) gas estimation reverted - not necessarily an issue", "INFO")
        except Exception as e:
            self.add_finding(f"Could not estimate gas: {str(e)}", "INFO")

    def external_honeypot_check(self):
        """Use honeypot.is public API for simulation-based detection when available."""
        try:
            if not self.use_external:
                return
            url = "https://api.honeypot.is/v2/IsHoneypot"
            params = {"address": self.contract_address, "chain": "bsc"}
            resp = requests.get(url, params=params, timeout=12)
            if resp.status_code != 200:
                self.add_finding("External honeypot API unavailable", "INFO")
                return
            data = resp.json()
            result = data.get("result") or data
            is_honey = result.get("IsHoneypot") if isinstance(result, dict) else None
            sim = result.get("SimulationResult", {}) if isinstance(result, dict) else {}
            buy_tax = sim.get("BuyTax")
            sell_tax = sim.get("SellTax")
            err_buy = (sim.get("Buy") or {}).get("IsError")
            err_sell = (sim.get("Sell") or {}).get("IsError")
            if buy_tax is not None and sell_tax is not None:
                self.add_finding(f"External est. taxes: Buy {buy_tax:.2f}%, Sell {sell_tax:.2f}%", "INFO")
                if sell_tax >= 50 or buy_tax >= 50:
                    self.add_finding("Extremely high tax reported by external API", "HIGH")
            if err_sell:
                self.add_finding("External simulation: SELL reverted — likely honeypot", "CRITICAL")
                self.is_honeypot = True
            if is_honey is True:
                self.add_finding("External API flags as HONEYPOT", "CRITICAL")
                self.is_honeypot = True
            elif is_honey is False:
                self.add_finding("External API: not a honeypot (at time of check)", "GOOD")
        except Exception as e:
            self.add_finding(f"External honeypot check failed: {str(e)}", "INFO")
    
    def analyze(self) -> Dict:
        """Run all detection checks"""
        if _HAS_RICH and not getattr(self, "_force_plain", False):
            console.print(Panel.fit(Text("BSC Honeypot Detector", justify="center", style="bold white"), title="", border_style="cyan", padding=(0,1)))
            console.print(Text(f"Analyzing contract: {self.contract_address}", style="bold cyan"))
        else:
            print(f"\n{'='*60}")
            print(f"BSC Honeypot Detector")
            print(f"{'='*60}")
            print(f"Analyzing contract: {self.contract_address}")
            print(f"{'='*60}\n")
        
        # Run all checks
        token_info = {}
        if self.external_only:
            token_info = self.check_basic_info()
            self.external_honeypot_check()
        else:
            token_info = self.check_basic_info()
            if not self.skip_verify:
                self.check_source_verification()
            self.check_ownership()
            self.check_contract_code()
            self.check_max_transaction_limit()
            self.check_pause_mechanism()
            self.check_liquidity()
            self.check_transfer_restrictions()
            self.check_tax_fees()
            self.check_gas_estimates()
            # External API check (best-effort)
            self.external_honeypot_check()
            self.simulate_buy_sell()
        
        # Cap risk score at 10
        self.risk_score = min(self.risk_score, 10)
        
        # Determine final verdict based on multiple factors
        # Honeypot if explicitly detected OR multiple critical red flags
        if self.is_honeypot:
            verdict = "🚨 HONEYPOT DETECTED"
            verdict_color = "CRITICAL"
        elif self.red_flags >= 2:  # Multiple serious issues
            verdict = "🚨 VERY HIGH RISK - Likely scam or honeypot"
            verdict_color = "CRITICAL"
        elif self.risk_score >= 7:
            verdict = "⛔ EXTREME RISK - Do NOT invest"
            verdict_color = "CRITICAL"
        elif self.risk_score >= 5:
            verdict = "⚠️  HIGH RISK - Dangerous, proceed with extreme caution"
            verdict_color = "HIGH"
        elif self.risk_score >= 3:
            verdict = "⚠️  MEDIUM RISK - Significant concerns, DYOR carefully"
            verdict_color = "MEDIUM"
        elif self.risk_score >= 1:
            verdict = "⚡ LOW-MEDIUM RISK - Some concerns, verify before investing"
            verdict_color = "LOW"
        else:
            # Only mark as safe if we have some green flags
            if self.green_flags >= 2:
                verdict = "✅ LOW RISK - Appears relatively safe"
                verdict_color = "INFO"
            else:
                verdict = "⚡ LOW RISK - No major red flags detected"
                verdict_color = "LOW"
        
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
        if _HAS_RICH and not getattr(self, "_force_plain", False):
            # Findings table
            table = Table(title="Findings", box=box.MINIMAL_DOUBLE_HEAD, expand=True)
            table.add_column("Severity", style="bold")
            table.add_column("Message", style="")

            severity_styles = {
                "CRITICAL": "bold red",
                "HIGH": "red3",
                "MEDIUM": "yellow3",
                "LOW": "white",
                "INFO": "bright_black",
                "GOOD": "green3",
            }
            for item in analysis["findings"]:
                sev = item.get("severity", "INFO")
                msg = item.get("message", "")
                table.add_row(Text(sev, style=severity_styles.get(sev, "white")), Text(msg))
            console.print(table)

            # Verdict panel
            color_map = {
                "CRITICAL": "red",
                "HIGH": "red3",
                "MEDIUM": "yellow3",
                "LOW": "cyan",
                "INFO": "green3",
            }
            verdict_style = color_map.get(analysis["verdict_color"], "white")
            console.print(Panel.fit(Text(f"{analysis['verdict']}\nRisk Score: {analysis['risk_score']}/10", style=f"bold {verdict_style}"), border_style=verdict_style))

            advisory = None
            if analysis["verdict_color"] in ["CRITICAL", "HIGH"]:
                advisory = "⚠️  WARNING: This token shows characteristics of a honeypot!\nDO NOT invest without thorough research and verification."
            elif analysis["verdict_color"] == "MEDIUM":
                advisory = "⚠️  CAUTION: This token has some concerning characteristics.\nResearch thoroughly before investing."
            else:
                advisory = "ℹ️  Note: This analysis is not financial advice.\nAlways DYOR (Do Your Own Research) before investing."
            console.print(Text(advisory, style="bright_black"))
        else:
            print("\n" + "="*60)
            print("FINDINGS:")
            print("="*60)
            for item in analysis["findings"]:
                print(f"[{item.get('severity','INFO')}] {item.get('message','')}")
            
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

    @staticmethod
    def _price_cache_path() -> str:
        try:
            cache_dir = os.path.join(os.path.expanduser("~"), ".cache")
            os.makedirs(cache_dir, exist_ok=True)
            return os.path.join(cache_dir, "bsc_honeypot_detector_price.json")
        except Exception:
            return os.path.join(os.getcwd(), ".bnb_price_cache.json")

    def get_bnb_price_usd(self) -> float:
        """Get BNB price in USD with a short-lived cache; fallback to env or default.
        Order: ENV -> Cache (<10min) -> Binance -> Coingecko -> default 600.
        """
        # ENV override
        try:
            env_price = os.environ.get("BNB_PRICE_USD")
            if env_price:
                return float(env_price)
        except Exception:
            pass

        # Cache
        cache_path = self._price_cache_path()
        try:
            if os.path.exists(cache_path):
                with open(cache_path, "r") as f:
                    data = json.load(f)
                ts = int(data.get("timestamp", 0))
                price = float(data.get("price", 0))
                if price > 0 and (time.time() - ts) < 600:
                    return price
        except Exception:
            pass

        # Fetch from Binance
        price = None
        try:
            r = requests.get("https://api.binance.com/api/v3/ticker/price", params={"symbol": "BNBUSDT"}, timeout=6)
            if r.status_code == 200:
                price = float(r.json().get("price"))
        except Exception:
            price = None

        # Fallback to Coingecko
        if price is None:
            try:
                r = requests.get("https://api.coingecko.com/api/v3/simple/price", params={"ids": "binancecoin", "vs_currencies": "usd"}, timeout=6)
                if r.status_code == 200:
                    price = float(r.json().get("binancecoin", {}).get("usd", 0))
            except Exception:
                price = None

        # Save cache
        if price and price > 0:
            try:
                with open(cache_path, "w") as f:
                    json.dump({"price": price, "timestamp": int(time.time())}, f)
            except Exception:
                pass
            return price

        # Final fallback
        return 600.0


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
    parser.add_argument(
        '--no-external',
        action='store_true',
        help='Skip external honeypot API checks'
    )
    parser.add_argument(
        '--external-only',
        action='store_true',
        help='Only run the external honeypot API check (fast)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output machine-readable JSON instead of a formatted table'
    )
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Skip explorer source verification checks'
    )
    
    args = parser.parse_args()
    
    try:
        # Validate address format
        if not args.address.startswith('0x') or len(args.address) != 42:
            print("Error: Invalid contract address format")
            print("Address must be in format: 0x followed by 40 hexadecimal characters")
            sys.exit(1)
        
        # Create detector and run analysis
        detector = HoneypotDetector(
            args.address,
            use_external=(not args.no_external),
            external_only=args.external_only,
            skip_verify=args.no_verify,
        )
        if args.json:
            setattr(detector, "_force_plain", True)
        analysis = detector.analyze()
        if args.json:
            print(json.dumps(analysis, indent=2))
        else:
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
