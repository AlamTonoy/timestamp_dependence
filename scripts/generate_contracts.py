"""
generate_contracts.py
=====================
Generates ~700 Solidity smart-contract source files (100 per subtype) that
each contain a Timestamp Dependence vulnerability, and writes a companion
metadata JSON file (vulnerability-feedback format) for every contract.

Usage
-----
    python scripts/generate_contracts.py

Outputs
-------
  contracts/generated/<subtype>/contract_<NNN>.sol
  metadata/generated/<subtype>/contract_<NNN>.json
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
GEN_CONTRACTS = REPO_ROOT / "contracts" / "generated"
GEN_METADATA  = REPO_ROOT / "metadata"  / "generated"

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_address() -> str:
    h = hashlib.sha256(str(random.random()).encode()).hexdigest()
    return "0x" + h[:40]


def _fake_tx() -> str:
    h = hashlib.sha256(str(random.random()).encode()).hexdigest()
    return "0x" + h


def _random_date(start: str = "2019-01-01", end: str = "2024-12-31") -> str:
    s = datetime.strptime(start, "%Y-%m-%d")
    e = datetime.strptime(end,   "%Y-%m-%d")
    return (s + timedelta(days=random.randint(0, (e - s).days))).strftime("%Y-%m-%d")


def _compiler_version() -> str:
    return random.choice([
        "0.6.12", "0.7.6", "0.8.0", "0.8.7", "0.8.10",
        "0.8.17", "0.8.19", "0.8.20", "0.8.21",
    ])


def _protocol_type() -> str:
    return random.choice([
        "AMM", "Lending", "Lottery", "NFT", "DAO", "Staking",
        "Options", "Insurance", "Bridge", "Vault",
    ])


def _protocol_name(ptype: str) -> str:
    prefixes = ["Alpha", "Beta", "Gamma", "Delta", "Zeta", "Omega", "Nova"]
    suffixes = {
        "AMM":       ["Swap", "DEX", "Pool"],
        "Lending":   ["Lend", "Finance", "Protocol"],
        "Lottery":   ["Luck", "Jackpot", "Fortune"],
        "NFT":       ["Art", "Mint", "Gallery"],
        "DAO":       ["DAO", "Governance", "Vote"],
        "Staking":   ["Stake", "Yield", "Farm"],
        "Options":   ["Options", "Hedge", "Derivatives"],
        "Insurance": ["Shield", "Cover", "Guard"],
        "Bridge":    ["Bridge", "Cross", "Portal"],
        "Vault":     ["Vault", "Safe", "Treasury"],
    }
    return random.choice(prefixes) + random.choice(suffixes.get(ptype, ["Fi"]))


_AUDIT_OPTIONS = [
    None, "Trail_of_Bits_2023", "Certik_2023", "OpenZeppelin_2022",
    "ConsenSys_Diligence_2023", "Peckshield_2024", "Halborn_2024",
    "Quantstamp_2023", "Hacken_2024", "Trail_of_Bits_2024",
]

_SOLIDITY_VERSIONS = [
    "^0.6.0", "^0.7.0", "^0.8.0", ">=0.8.0 <0.9.0", "^0.8.17",
]

# ---------------------------------------------------------------------------
# Solidity contract templates (multiple per subtype)
# ---------------------------------------------------------------------------

# ------ block_timestamp_manipulation ----------------------------------------
_BTM_TEMPLATES = [
    # 0 – Lottery
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Timestamp-Dependent Lottery
        /// @notice VULNERABLE: block.timestamp used as randomness source (SWC-116)
        contract {p['name']} {{
            address public owner;
            uint256 public ticketPrice = {p['price']} ether;
            address[] public players;

            event WinnerPicked(address indexed winner, uint256 amount);

            constructor() {{
                owner = msg.sender;
            }}

            modifier onlyOwner() {{
                require(msg.sender == owner, "Not owner");
                _;
            }}

            function enter() external payable {{
                require(msg.value == ticketPrice, "Wrong ticket price");
                players.push(msg.sender);
            }}

            // VULN: block.timestamp is miner-controlled; predictable within ~15 seconds
            function pickWinner() external onlyOwner {{
                require(players.length > 0, "No players");
                uint256 idx = block.timestamp % players.length;
                address winner = players[idx];
                uint256 prize  = address(this).balance;
                players = new address[](0);
                (bool ok,) = winner.call{{value: prize}}("");
                require(ok, "Transfer failed");
                emit WinnerPicked(winner, prize);
            }}

            receive() external payable {{}}
        }}
        """),

    # 1 – Coin flip
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Timestamp-Based Coin Flip
        /// @notice VULNERABLE: outcome depends on block.timestamp (SWC-116)
        contract {p['name']} {{
            uint256 public betAmount = {p['price']} ether;

            event Result(address player, bool won, uint256 payout);

            // VULN: miner can manipulate block.timestamp to win consistently
            function flip(bool _guess) external payable {{
                require(msg.value == betAmount, "Wrong bet");
                bool outcome = (block.timestamp % 2 == 0);
                if (outcome == _guess) {{
                    uint256 payout = msg.value * 2;
                    (bool ok,) = msg.sender.call{{value: payout}}("");
                    require(ok);
                    emit Result(msg.sender, true, payout);
                }} else {{
                    emit Result(msg.sender, false, 0);
                }}
            }}

            receive() external payable {{}}
        }}
        """),

    # 2 – Time-locked access
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Timestamp Access Control
        /// @notice VULNERABLE: access window controlled via block.timestamp (SWC-116)
        contract {p['name']} {{
            address public owner;
            uint256 public openTime;
            uint256 public closeTime;
            bool public initialized;

            constructor(uint256 _open, uint256 _duration) {{
                owner     = msg.sender;
                openTime  = _open;
                closeTime = _open + _duration;
            }}

            // VULN: miners can tweak timestamp to enter or skip the window
            modifier withinWindow() {{
                require(block.timestamp >= openTime,  "Not open yet");
                require(block.timestamp <= closeTime, "Window closed");
                _;
            }}

            function deposit() external payable withinWindow {{
                initialized = true;
            }}

            function withdraw(uint256 amount) external {{
                require(msg.sender == owner);
                // VULN: no proper timestamp validation for withdrawal window
                require(block.timestamp > closeTime, "Window still open");
                (bool ok,) = owner.call{{value: amount}}("");
                require(ok);
            }}
        }}
        """),

    # 3 – Random dice
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Dice Game
        /// @notice VULNERABLE: dice outcome derived from block.timestamp (SWC-116)
        contract {p['name']} {{
            uint256 public betAmount = {p['price']} ether;
            mapping(address => uint256) public wins;

            event Rolled(address indexed player, uint8 result, bool won);

            // VULN: block.timestamp predictable by miner; outcome can be gamed
            function roll(uint8 guess) external payable {{
                require(guess >= 1 && guess <= 6, "Invalid guess");
                require(msg.value == betAmount, "Wrong bet");
                uint8 result = uint8((block.timestamp % 6) + 1);
                if (result == guess) {{
                    wins[msg.sender]++;
                    (bool ok,) = msg.sender.call{{value: msg.value * 5}}("");
                    require(ok, "Payout failed");
                    emit Rolled(msg.sender, result, true);
                }} else {{
                    emit Rolled(msg.sender, result, false);
                }}
            }}

            receive() external payable {{}}
        }}
        """),

    # 4 – Token sale
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        interface IERC20 {{
            function transfer(address to, uint256 amount) external returns (bool);
        }}

        /// @title {p['name']} - ICO/Token Sale
        /// @notice VULNERABLE: sale period enforced with block.timestamp (SWC-116)
        contract {p['name']} {{
            address public owner;
            IERC20  public token;
            uint256 public startTime;
            uint256 public endTime;
            uint256 public rate = {p['rate']};

            constructor(address _token, uint256 _start, uint256 _duration) {{
                owner     = msg.sender;
                token     = IERC20(_token);
                startTime = _start;
                endTime   = _start + _duration;
            }}

            // VULN: miner can delay or advance block.timestamp to join/exit sale
            function buy() external payable {{
                require(block.timestamp >= startTime, "Sale not started");
                require(block.timestamp <= endTime,   "Sale ended");
                uint256 tokenAmount = msg.value * rate;
                require(token.transfer(msg.sender, tokenAmount), "Transfer failed");
            }}

            function withdraw() external {{
                require(msg.sender == owner);
                require(block.timestamp > endTime, "Sale ongoing");
                (bool ok,) = owner.call{{value: address(this).balance}}("");
                require(ok);
            }}
        }}
        """),

    # 5 – Staking rewards
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Staking Rewards
        /// @notice VULNERABLE: reward calculation based on block.timestamp (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public stakedAt;
            mapping(address => uint256) public stakedAmount;
            uint256 public rewardRate = {p['rate']}; // tokens per second per wei staked

            event Staked(address indexed user, uint256 amount);
            event Claimed(address indexed user, uint256 reward);

            function stake() external payable {{
                require(msg.value > 0, "Nothing staked");
                stakedAt[msg.sender]     = block.timestamp;
                stakedAmount[msg.sender] = msg.value;
                emit Staked(msg.sender, msg.value);
            }}

            // VULN: miner can advance block.timestamp to inflate staking rewards
            function claimReward() external {{
                uint256 elapsed = block.timestamp - stakedAt[msg.sender];
                uint256 reward  = elapsed * rewardRate * stakedAmount[msg.sender];
                stakedAt[msg.sender] = block.timestamp;
                (bool ok,) = msg.sender.call{{value: reward}}("");
                require(ok, "Reward transfer failed");
                emit Claimed(msg.sender, reward);
            }}
        }}
        """),

    # 6 – Price oracle
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Timestamp-Based Price Oracle
        /// @notice VULNERABLE: price validity window uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address public owner;
            uint256 public price;
            uint256 public lastUpdate;
            uint256 public staleness = {p['window']}; // seconds

            constructor() {{
                owner = msg.sender;
            }}

            function updatePrice(uint256 _price) external {{
                require(msg.sender == owner, "Not owner");
                price      = _price;
                lastUpdate = block.timestamp;
            }}

            // VULN: miner can manipulate block.timestamp to make stale price appear fresh
            function getValidPrice() external view returns (uint256) {{
                require(
                    block.timestamp - lastUpdate <= staleness,
                    "Price is stale"
                );
                return price;
            }}
        }}
        """),

    # 7 – NFT mint window
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - NFT Mint with Timestamp Window
        /// @notice VULNERABLE: mint window enforced via block.timestamp (SWC-116)
        contract {p['name']} {{
            address public owner;
            uint256 public mintStart;
            uint256 public mintEnd;
            uint256 public nextId;
            mapping(uint256 => address) public ownerOf;

            constructor(uint256 _start, uint256 _duration) {{
                owner     = msg.sender;
                mintStart = _start;
                mintEnd   = _start + _duration;
            }}

            // VULN: miners can tweak timestamp to mint outside intended window
            function mint() external payable {{
                require(msg.value >= 0.05 ether, "Insufficient payment");
                require(block.timestamp >= mintStart, "Mint not started");
                require(block.timestamp <= mintEnd,   "Mint ended");
                ownerOf[nextId] = msg.sender;
                nextId++;
            }}

            function withdraw() external {{
                require(msg.sender == owner);
                (bool ok,) = owner.call{{value: address(this).balance}}("");
                require(ok);
            }}
        }}
        """),

    # 8 – DAO voting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - DAO Governance Voting
        /// @notice VULNERABLE: voting period uses block.timestamp (SWC-116)
        contract {p['name']} {{
            struct Proposal {{
                string  description;
                uint256 startTime;
                uint256 endTime;
                uint256 yesVotes;
                uint256 noVotes;
                bool    executed;
            }}

            Proposal[] public proposals;
            mapping(uint256 => mapping(address => bool)) public voted;

            function createProposal(string calldata desc, uint256 duration)
                external returns (uint256)
            {{
                proposals.push(Proposal({{
                    description: desc,
                    startTime:   block.timestamp,
                    endTime:     block.timestamp + duration,
                    yesVotes:    0,
                    noVotes:     0,
                    executed:    false
                }}));
                return proposals.length - 1;
            }}

            // VULN: miner can extend or collapse the voting window via timestamp
            function vote(uint256 proposalId, bool support) external {{
                Proposal storage p = proposals[proposalId];
                require(block.timestamp >= p.startTime, "Voting not started");
                require(block.timestamp <= p.endTime,   "Voting ended");
                require(!voted[proposalId][msg.sender],  "Already voted");
                voted[proposalId][msg.sender] = true;
                if (support) p.yesVotes++; else p.noVotes++;
            }}
        }}
        """),

    # 9 – Insurance claim
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Insurance Policy
        /// @notice VULNERABLE: claim window verified with block.timestamp (SWC-116)
        contract {p['name']} {{
            address public insurer;
            address public insured;
            uint256 public policyEnd;
            uint256 public coverageAmount;
            bool    public claimed;

            constructor(address _insured, uint256 _duration, uint256 _coverage)
                payable
            {{
                insurer        = msg.sender;
                insured        = _insured;
                policyEnd      = block.timestamp + _duration;
                coverageAmount = _coverage;
            }}

            // VULN: miner can manipulate timestamp to file claim after deadline
            function fileClaim() external {{
                require(msg.sender == insured, "Not insured");
                require(!claimed, "Already claimed");
                // Should be <, but miner can push timestamp to just before policyEnd
                require(block.timestamp <= policyEnd, "Policy expired");
                claimed = true;
                (bool ok,) = insured.call{{value: coverageAmount}}("");
                require(ok, "Payout failed");
            }}
        }}
        """),

    # 10 – Governance timelock
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Governance Timelock
        /// @notice VULNERABLE: timelock delay enforced via block.timestamp (SWC-116)
        contract {p['name']} {{
            address public admin;
            uint256 public delay = {p['window']};

            struct QueuedTx {{
                address target;
                uint256 value;
                bytes   data;
                uint256 eta;
                bool    executed;
            }}

            mapping(bytes32 => QueuedTx) public queue;

            constructor() {{
                admin = msg.sender;
            }}

            function queueTransaction(
                address target, uint256 value, bytes calldata data
            ) external returns (bytes32 txHash) {{
                require(msg.sender == admin);
                uint256 eta = block.timestamp + delay;
                txHash = keccak256(abi.encode(target, value, data, eta));
                queue[txHash] = QueuedTx(target, value, data, eta, false);
            }}

            // VULN: miner can advance block.timestamp to execute before intended delay
            function executeTransaction(bytes32 txHash) external {{
                QueuedTx storage t = queue[txHash];
                require(!t.executed, "Already executed");
                require(block.timestamp >= t.eta, "Too early");
                t.executed = true;
                (bool ok,) = t.target.call{{value: t.value}}(t.data);
                require(ok, "Execution failed");
            }}
        }}
        """),

    # 11 – Flash sale
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        interface IERC20 {{
            function transfer(address to, uint256 amount) external returns (bool);
            function balanceOf(address who) external view returns (uint256);
        }}

        /// @title {p['name']} - Flash Sale
        /// @notice VULNERABLE: flash-sale window uses block.timestamp (SWC-116)
        contract {p['name']} {{
            IERC20  public token;
            address public owner;
            uint256 public saleStart;
            uint256 public saleDuration = {p['window']};
            uint256 public discountRate = {p['rate']}; // basis points

            constructor(address _token) {{
                token = IERC20(_token);
                owner = msg.sender;
            }}

            function startSale() external {{
                require(msg.sender == owner);
                saleStart = block.timestamp;
            }}

            // VULN: miner delays block.timestamp to participate after sale should end
            function buyDiscounted() external payable {{
                require(block.timestamp >= saleStart, "Sale not started");
                require(
                    block.timestamp <= saleStart + saleDuration,
                    "Flash sale ended"
                );
                uint256 tokens = (msg.value * discountRate) / 10000;
                require(token.transfer(msg.sender, tokens), "Transfer failed");
            }}
        }}
        """),

    # 12 – Yield farming
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Yield Farming
        /// @notice VULNERABLE: reward epoch uses block.timestamp (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public depositTime;
            mapping(address => uint256) public balance;
            uint256 public rewardPerSecond = {p['rate']};

            function deposit() external payable {{
                require(msg.value > 0);
                _harvest();
                balance[msg.sender]     += msg.value;
                depositTime[msg.sender]  = block.timestamp;
            }}

            // VULN: timestamp can be manipulated to harvest inflated rewards
            function _harvest() internal {{
                if (balance[msg.sender] == 0) return;
                uint256 elapsed = block.timestamp - depositTime[msg.sender];
                uint256 reward  = elapsed * rewardPerSecond * balance[msg.sender];
                depositTime[msg.sender] = block.timestamp;
                (bool ok,) = msg.sender.call{{value: reward}}("");
                require(ok);
            }}

            function harvest() external {{ _harvest(); }}
        }}
        """),

    # 13 – Randomness (keccak + timestamp)
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Keccak Randomness with Timestamp
        /// @notice VULNERABLE: pseudo-randomness uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address public owner;
            uint256 public prize = {p['price']} ether;
            uint256 public nonce;

            constructor() payable {{
                owner = msg.sender;
            }}

            // VULN: keccak(timestamp, blockhash, sender) is predictable to miners
            function play(uint256 guess) external payable {{
                require(msg.value == prize, "Wrong entry fee");
                uint256 answer = uint256(
                    keccak256(
                        abi.encodePacked(block.timestamp, blockhash(block.number - 1), msg.sender, nonce++)
                    )
                ) % 100;
                if (guess == answer) {{
                    (bool ok,) = msg.sender.call{{value: address(this).balance}}("");
                    require(ok);
                }}
            }}

            receive() external payable {{}}
        }}
        """),
]

# ------ deadline_bypass -------------------------------------------------------
_DB_TEMPLATES = [
    # 0 – English auction
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - English Auction with Deadline
        /// @notice VULNERABLE: auction end enforced via block.timestamp (SWC-116)
        contract {p['name']} {{
            address public seller;
            address public highestBidder;
            uint256 public highestBid;
            uint256 public auctionEnd;
            bool    public ended;

            event BidPlaced(address bidder, uint256 amount);
            event AuctionEnded(address winner, uint256 amount);

            constructor(uint256 _duration) {{
                seller     = msg.sender;
                auctionEnd = block.timestamp + _duration;
            }}

            // VULN: miner can push timestamp past auctionEnd to prevent outbidding
            function bid() external payable {{
                require(!ended, "Auction finished");
                require(block.timestamp < auctionEnd, "Auction expired");
                require(msg.value > highestBid, "Bid too low");
                if (highestBidder != address(0)) {{
                    (bool ok,) = highestBidder.call{{value: highestBid}}("");
                    require(ok);
                }}
                highestBidder = msg.sender;
                highestBid    = msg.value;
                emit BidPlaced(msg.sender, msg.value);
            }}

            function endAuction() external {{
                require(block.timestamp >= auctionEnd, "Not ended");
                require(!ended, "Already ended");
                ended = true;
                (bool ok,) = seller.call{{value: highestBid}}("");
                require(ok);
                emit AuctionEnded(highestBidder, highestBid);
            }}
        }}
        """),

    # 1 – DEX swap deadline
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - DEX Swap with Deadline
        /// @notice VULNERABLE: swap deadline enforced by block.timestamp (SWC-116)
        contract {p['name']} {{
            address public owner;
            mapping(address => uint256) public reserves;

            constructor() {{
                owner = msg.sender;
            }}

            // VULN: miner delays block.timestamp past deadline, transaction reverts or passes
            function swapExactETHForTokens(
                uint256 amountOutMin,
                address tokenOut,
                address to,
                uint256 deadline
            ) external payable returns (uint256 amountOut) {{
                require(block.timestamp <= deadline, "Deadline exceeded");
                // simplified swap logic
                amountOut = msg.value * 1000;
                require(amountOut >= amountOutMin, "Slippage too high");
                reserves[tokenOut] -= amountOut;
                (bool ok,) = to.call{{value: 0}}("");
                _ = ok;
            }}
        }}
        """),

    # 2 – Escrow with expiry
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Escrow with Timestamp Expiry
        /// @notice VULNERABLE: escrow expiry uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address public depositor;
            address public beneficiary;
            uint256 public expiry;
            uint256 public amount;
            bool    public released;

            constructor(address _beneficiary, uint256 _duration) payable {{
                depositor   = msg.sender;
                beneficiary = _beneficiary;
                expiry      = block.timestamp + _duration;
                amount      = msg.value;
            }}

            // VULN: miner can manipulate expiry boundary to block/allow release
            function release() external {{
                require(!released, "Already released");
                require(msg.sender == beneficiary, "Not beneficiary");
                require(block.timestamp < expiry, "Escrow expired");
                released = true;
                (bool ok,) = beneficiary.call{{value: amount}}("");
                require(ok);
            }}

            function refund() external {{
                require(!released, "Already released");
                require(msg.sender == depositor, "Not depositor");
                require(block.timestamp >= expiry, "Not expired yet");
                released = true;
                (bool ok,) = depositor.call{{value: amount}}("");
                require(ok);
            }}
        }}
        """),

    # 3 – Time-locked withdrawal
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Time-Locked Withdrawal
        /// @notice VULNERABLE: lock expiry checked via block.timestamp (SWC-116)
        contract {p['name']} {{
            address public beneficiary;
            uint256 public releaseTime;

            constructor(address _beneficiary, uint256 _releaseTime) payable {{
                require(_releaseTime > block.timestamp, "Release time in past");
                beneficiary = _beneficiary;
                releaseTime = _releaseTime;
            }}

            // VULN: miner can advance block.timestamp to unlock funds early
            function release() external {{
                require(block.timestamp >= releaseTime, "Funds still locked");
                (bool ok,) = beneficiary.call{{value: address(this).balance}}("");
                require(ok);
            }}
        }}
        """),

    # 4 – Options contract
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Call Option Contract
        /// @notice VULNERABLE: option expiry uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address public writer;
            address public holder;
            uint256 public strikePrice;
            uint256 public expiry;
            uint256 public premium;
            bool    public exercised;

            constructor(
                address _holder,
                uint256 _strikePrice,
                uint256 _expiry,
                uint256 _premium
            ) payable {{
                writer      = msg.sender;
                holder      = _holder;
                strikePrice = _strikePrice;
                expiry      = _expiry;
                premium     = _premium;
            }}

            // VULN: miner can push timestamp past expiry to prevent exercise
            function exercise() external payable {{
                require(msg.sender == holder, "Not holder");
                require(!exercised, "Already exercised");
                require(block.timestamp <= expiry, "Option expired");
                require(msg.value == strikePrice, "Wrong strike price");
                exercised = true;
                (bool ok,) = holder.call{{value: address(this).balance}}("");
                require(ok);
            }}

            function expire() external {{
                require(block.timestamp > expiry, "Not expired");
                require(!exercised, "Already exercised");
                (bool ok,) = writer.call{{value: address(this).balance}}("");
                require(ok);
            }}
        }}
        """),

    # 5 – Crowdfund deadline
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Crowdfunding with Deadline
        /// @notice VULNERABLE: deadline enforced via block.timestamp (SWC-116)
        contract {p['name']} {{
            address public creator;
            uint256 public goal;
            uint256 public deadline;
            uint256 public raised;
            mapping(address => uint256) public contributions;
            bool public goalMet;

            constructor(uint256 _goal, uint256 _duration) {{
                creator  = msg.sender;
                goal     = _goal;
                deadline = block.timestamp + _duration;
            }}

            // VULN: miner can extend timestamp past deadline to block last contributions
            function contribute() external payable {{
                require(block.timestamp < deadline, "Campaign ended");
                contributions[msg.sender] += msg.value;
                raised += msg.value;
                if (raised >= goal) goalMet = true;
            }}

            function claimFunds() external {{
                require(msg.sender == creator);
                require(goalMet, "Goal not met");
                require(block.timestamp >= deadline, "Campaign active");
                (bool ok,) = creator.call{{value: address(this).balance}}("");
                require(ok);
            }}

            function refund() external {{
                require(block.timestamp >= deadline, "Campaign active");
                require(!goalMet, "Goal was met");
                uint256 amount = contributions[msg.sender];
                contributions[msg.sender] = 0;
                (bool ok,) = msg.sender.call{{value: amount}}("");
                require(ok);
            }}
        }}
        """),

    # 6 – Time-limited discount
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        interface IERC20 {{
            function transfer(address to, uint256 amount) external returns (bool);
        }}

        /// @title {p['name']} - Time-Limited Discount Sale
        /// @notice VULNERABLE: discount period uses block.timestamp (SWC-116)
        contract {p['name']} {{
            IERC20  public token;
            address public admin;
            uint256 public discountEnd;
            uint256 public normalRate = {p['rate']};
            uint256 public discountRate;

            constructor(address _token, uint256 _discountDuration) {{
                token        = IERC20(_token);
                admin        = msg.sender;
                discountEnd  = block.timestamp + _discountDuration;
                discountRate = normalRate * 2; // 2× tokens during discount
            }}

            // VULN: miner can extend discount window by manipulating block.timestamp
            function buy() external payable {{
                uint256 rate = (block.timestamp <= discountEnd)
                    ? discountRate
                    : normalRate;
                uint256 tokens = msg.value * rate;
                require(token.transfer(msg.sender, tokens), "Transfer failed");
            }}
        }}
        """),

    # 7 – Subscription expiry
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Subscription Service
        /// @notice VULNERABLE: subscription checks use block.timestamp (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public subscriptionExpiry;
            uint256 public monthlyFee  = {p['price']} ether;
            uint256 public periodLength = 30 days;

            function subscribe() external payable {{
                require(msg.value == monthlyFee, "Wrong fee");
                // VULN: miner can advance timestamp to immediately expire subscription
                if (subscriptionExpiry[msg.sender] < block.timestamp) {{
                    subscriptionExpiry[msg.sender] = block.timestamp + periodLength;
                }} else {{
                    subscriptionExpiry[msg.sender] += periodLength;
                }}
            }}

            // VULN: miner can manipulate timestamp to grant/deny access
            function isSubscribed(address user) external view returns (bool) {{
                return block.timestamp <= subscriptionExpiry[user];
            }}
        }}
        """),

    # 8 – Multi-sig with deadline
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Multi-Sig with Timestamp Deadline
        /// @notice VULNERABLE: approval deadline uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address[] public owners;
            uint256   public required;

            struct Transaction {{
                address to;
                uint256 value;
                bytes   data;
                uint256 deadline;
                uint256 approvals;
                bool    executed;
            }}

            Transaction[] public transactions;
            mapping(uint256 => mapping(address => bool)) public approved;

            constructor(address[] memory _owners, uint256 _required) {{
                owners   = _owners;
                required = _required;
            }}

            function submit(address to, uint256 value, bytes calldata data, uint256 duration)
                external returns (uint256 txId)
            {{
                transactions.push(Transaction({{
                    to: to, value: value, data: data,
                    deadline: block.timestamp + duration,
                    approvals: 0, executed: false
                }}));
                txId = transactions.length - 1;
            }}

            // VULN: miner can push block.timestamp to kill approval window early
            function approve(uint256 txId) external {{
                Transaction storage t = transactions[txId];
                require(block.timestamp <= t.deadline, "Deadline passed");
                require(!approved[txId][msg.sender], "Already approved");
                approved[txId][msg.sender] = true;
                t.approvals++;
                if (t.approvals >= required) {{
                    t.executed = true;
                    (bool ok,) = t.to.call{{value: t.value}}(t.data);
                    require(ok);
                }}
            }}
        }}
        """),

    # 9 – Futures settlement
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Futures Contract Settlement
        /// @notice VULNERABLE: settlement time uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address public long;
            address public short;
            uint256 public settleAt;
            uint256 public notional;
            uint256 public entryPrice;
            bool    public settled;

            constructor(address _short, uint256 _settleAt, uint256 _entry) payable {{
                long       = msg.sender;
                short      = _short;
                settleAt   = _settleAt;
                notional   = msg.value;
                entryPrice = _entry;
            }}

            // VULN: miner can delay settlement by manipulating block.timestamp
            function settle(uint256 currentPrice) external {{
                require(block.timestamp >= settleAt, "Too early to settle");
                require(!settled, "Already settled");
                settled = true;
                address winner = currentPrice > entryPrice ? long : short;
                (bool ok,) = winner.call{{value: address(this).balance}}("");
                require(ok);
            }}
        }}
        """),

    # 10 – Bond maturity
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - On-Chain Bond
        /// @notice VULNERABLE: maturity date uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address public issuer;
            address public holder;
            uint256 public principal;
            uint256 public couponRate; // basis points per second
            uint256 public maturity;
            uint256 public issuedAt;

            constructor(address _holder, uint256 _duration, uint256 _coupon) payable {{
                issuer     = msg.sender;
                holder     = _holder;
                principal  = msg.value;
                couponRate = _coupon;
                maturity   = block.timestamp + _duration;
                issuedAt   = block.timestamp;
            }}

            // VULN: miner advances timestamp to collect coupon before maturity
            function redeem() external {{
                require(msg.sender == holder, "Not holder");
                require(block.timestamp >= maturity, "Not matured");
                uint256 elapsed  = block.timestamp - issuedAt;
                uint256 interest = principal * couponRate * elapsed / 10000;
                (bool ok,) = holder.call{{value: principal + interest}}("");
                require(ok);
            }}
        }}
        """),
]

# ------ block_number_manipulation --------------------------------------------
_BNM_TEMPLATES = [
    # 0 – Block-based lottery
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Block-Number Lottery
        /// @notice VULNERABLE: uses block.number for randomness (SWC-116)
        contract {p['name']} {{
            address public owner;
            address[] public players;
            uint256 public ticketPrice = {p['price']} ether;
            uint256 public drawBlock;

            constructor(uint256 blocksFromNow) {{
                owner     = msg.sender;
                drawBlock = block.number + blocksFromNow;
            }}

            function enter() external payable {{
                require(msg.value == ticketPrice, "Wrong price");
                players.push(msg.sender);
            }}

            // VULN: miner knows block.number in advance and can game the lottery
            function draw() external {{
                require(block.number >= drawBlock, "Too early");
                require(players.length > 0, "No players");
                uint256 idx    = block.number % players.length;
                address winner = players[idx];
                players = new address[](0);
                drawBlock = block.number + {p['window']};
                (bool ok,) = winner.call{{value: address(this).balance}}("");
                require(ok);
            }}
        }}
        """),

    # 1 – Block-based voting period
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Block-Number Governed Voting
        /// @notice VULNERABLE: voting window uses block.number (SWC-116)
        contract {p['name']} {{
            uint256 public startBlock;
            uint256 public endBlock;
            uint256 public yesVotes;
            uint256 public noVotes;
            mapping(address => bool) public voted;

            constructor(uint256 _durationBlocks) {{
                startBlock = block.number;
                endBlock   = block.number + _durationBlocks;
            }}

            // VULN: miners control block production; can delay/speed voting window
            function vote(bool support) external {{
                require(block.number >= startBlock, "Not started");
                require(block.number <= endBlock,   "Ended");
                require(!voted[msg.sender], "Already voted");
                voted[msg.sender] = true;
                if (support) yesVotes++; else noVotes++;
            }}
        }}
        """),

    # 2 – Future-block commit/reveal
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Commit-Reveal Randomness via Future Block
        /// @notice VULNERABLE: future blockhash used for randomness (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public commitBlock;
            mapping(address => uint256) public commitHash;
            uint256 public revealDelay = {p['window']};

            function commit(uint256 secretHash) external {{
                commitBlock[msg.sender] = block.number;
                commitHash[msg.sender]  = secretHash;
            }}

            // VULN: blockhash only available for last 256 blocks; can be 0 for older blocks
            function reveal(uint256 secret) external view returns (uint256 rand) {{
                uint256 cb = commitBlock[msg.sender];
                require(block.number >= cb + revealDelay, "Too early");
                require(block.number <  cb + revealDelay + 256, "Hash unavailable");
                bytes32 bh = blockhash(cb + revealDelay);
                rand = uint256(keccak256(abi.encodePacked(bh, secret))) % 100;
            }}
        }}
        """),

    # 3 – Mining reward with block number
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Mining Reward Token
        /// @notice VULNERABLE: reward depends on block.number difference (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public lastMineBlock;
            mapping(address => uint256) public balance;
            uint256 public blockReward = {p['rate']};

            // VULN: miner can manipulate when they mine to claim extra rewards
            function mine() external {{
                uint256 blocks = block.number - lastMineBlock[msg.sender];
                lastMineBlock[msg.sender] = block.number;
                balance[msg.sender] += blocks * blockReward;
            }}
        }}
        """),

    # 4 – Token unlock schedule
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Block-Based Token Unlock
        /// @notice VULNERABLE: unlock uses block.number (SWC-116)
        contract {p['name']} {{
            address public beneficiary;
            uint256 public totalAmount;
            uint256 public startBlock;
            uint256 public vestingBlocks;
            uint256 public claimed;

            constructor(address _beneficiary, uint256 _blocks) payable {{
                beneficiary   = _beneficiary;
                totalAmount   = msg.value;
                startBlock    = block.number;
                vestingBlocks = _blocks;
            }}

            // VULN: miner can manipulate block production rate to speed up vesting
            function claim() external {{
                require(msg.sender == beneficiary, "Not beneficiary");
                uint256 elapsed   = block.number - startBlock;
                uint256 vested    = (totalAmount * elapsed) / vestingBlocks;
                uint256 claimable = vested - claimed;
                require(claimable > 0, "Nothing to claim");
                claimed += claimable;
                (bool ok,) = beneficiary.call{{value: claimable}}("");
                require(ok);
            }}
        }}
        """),

    # 5 – Snapshot governance
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Snapshot-Based Governance
        /// @notice VULNERABLE: snapshot block is predictable (SWC-116)
        contract {p['name']} {{
            mapping(uint256 => mapping(address => uint256)) public snapshots;
            uint256 public snapshotBlock;

            function takeSnapshot() external {{
                // VULN: block number known before this tx is mined
                snapshotBlock = block.number;
            }}

            function recordBalance(address user, uint256 bal) external {{
                snapshots[snapshotBlock][user] = bal;
            }}

            function votingPower(address user) external view returns (uint256) {{
                return snapshots[snapshotBlock][user];
            }}
        }}
        """),

    # 6 – Block-based rate limiting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Block-Based Rate Limiter
        /// @notice VULNERABLE: rate limit window uses block.number (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public lastActionBlock;
            uint256 public cooldownBlocks = {p['window']};

            // VULN: miner can include own tx in a specific block to bypass cooldown
            function action() external {{
                require(
                    block.number >= lastActionBlock[msg.sender] + cooldownBlocks,
                    "Cooldown active"
                );
                lastActionBlock[msg.sender] = block.number;
                // ... perform action
            }}
        }}
        """),

    # 7 – Block reward halving
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Block Reward with Halving
        /// @notice VULNERABLE: halving schedule uses block.number (SWC-116)
        contract {p['name']} {{
            uint256 public initialReward = {p['rate']};
            uint256 public halvingInterval = {p['window']};
            uint256 public deployBlock;
            mapping(address => uint256) public lastClaim;

            constructor() {{
                deployBlock = block.number;
            }}

            function currentReward() public view returns (uint256) {{
                // VULN: block.number controlled by miners; halving timing manipulable
                uint256 halvings = (block.number - deployBlock) / halvingInterval;
                return initialReward >> halvings;
            }}

            function claim() external {{
                require(block.number > lastClaim[msg.sender], "Already claimed this block");
                lastClaim[msg.sender] = block.number;
                uint256 reward = currentReward();
                (bool ok,) = msg.sender.call{{value: reward}}("");
                require(ok);
            }}

            receive() external payable {{}}
        }}
        """),
]

# ------ time_window_attack ----------------------------------------------------
_TWA_TEMPLATES = [
    # 0 – Flash loan with time window
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Flash Loan with Time Constraint
        /// @notice VULNERABLE: time window exploitable via block.timestamp (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public balances;
            uint256 public windowStart;
            uint256 public windowSize = {p['window']};

            function deposit() external payable {{
                balances[msg.sender] += msg.value;
            }}

            function openWindow() external {{
                // VULN: miner can delay/advance block.timestamp to exploit window
                windowStart = block.timestamp;
            }}

            function flashLoan(uint256 amount) external {{
                require(
                    block.timestamp >= windowStart &&
                    block.timestamp <= windowStart + windowSize,
                    "Outside window"
                );
                require(address(this).balance >= amount, "Insufficient liquidity");
                uint256 before = address(this).balance;
                (bool ok,) = msg.sender.call{{value: amount}}("");
                require(ok);
                require(address(this).balance >= before, "Loan not repaid");
            }}
        }}
        """),

    # 1 – Liquidity window
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Liquidity Provision Window
        /// @notice VULNERABLE: add-liquidity window uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address public admin;
            uint256 public liquidityStart;
            uint256 public liquidityEnd;
            mapping(address => uint256) public liquidity;

            constructor(uint256 _duration) {{
                admin          = msg.sender;
                liquidityStart = block.timestamp;
                liquidityEnd   = block.timestamp + _duration;
            }}

            // VULN: miner can extend the window to add more liquidity at favourable time
            function addLiquidity() external payable {{
                require(block.timestamp >= liquidityStart, "Window not open");
                require(block.timestamp <= liquidityEnd,   "Window closed");
                liquidity[msg.sender] += msg.value;
            }}

            function removeLiquidity() external {{
                require(block.timestamp > liquidityEnd, "Window still open");
                uint256 amount = liquidity[msg.sender];
                liquidity[msg.sender] = 0;
                (bool ok,) = msg.sender.call{{value: amount}}("");
                require(ok);
            }}
        }}
        """),

    # 2 – Priority gas auction window
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Priority Fee Auction Window
        /// @notice VULNERABLE: bidding window uses block.timestamp (SWC-116)
        contract {p['name']} {{
            uint256 public auctionStart;
            uint256 public windowDuration = {p['window']};
            address public topBidder;
            uint256 public topBid;

            function startAuction() external {{
                auctionStart = block.timestamp;
            }}

            // VULN: miner can open/close window to selectively accept bids
            function bid() external payable {{
                require(
                    block.timestamp >= auctionStart &&
                    block.timestamp <= auctionStart + windowDuration,
                    "Not in bidding window"
                );
                if (msg.value > topBid) {{
                    if (topBidder != address(0)) {{
                        (bool ok,) = topBidder.call{{value: topBid}}("");
                        require(ok);
                    }}
                    topBidder = msg.sender;
                    topBid    = msg.value;
                }} else {{
                    revert("Bid too low");
                }}
            }}
        }}
        """),

    # 3 – Oracle update window
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Oracle Update Time Window
        /// @notice VULNERABLE: oracle updates restricted by block.timestamp (SWC-116)
        contract {p['name']} {{
            uint256 public price;
            uint256 public lastUpdate;
            uint256 public updateWindow = {p['window']}; // seconds per epoch
            address public oracle;

            constructor(address _oracle) {{
                oracle = _oracle;
            }}

            // VULN: miner can pick the update moment within window to set favourable price
            function updatePrice(uint256 newPrice) external {{
                require(msg.sender == oracle, "Not oracle");
                require(
                    block.timestamp >= lastUpdate + updateWindow,
                    "Update too frequent"
                );
                price      = newPrice;
                lastUpdate = block.timestamp;
            }}
        }}
        """),

    # 4 – MEV sandwich window
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - AMM with Timestamp Slippage Window
        /// @notice VULNERABLE: slippage window exploitable by miners (SWC-116)
        contract {p['name']} {{
            uint256 public reserveETH = 1000 ether;
            uint256 public reserveToken = 1_000_000 * 1e18;
            uint256 public lastSwapTime;
            uint256 public cooldown = {p['window']};

            event Swapped(address indexed user, uint256 amountIn, uint256 amountOut);

            // VULN: miner can sandwich user tx by manipulating timestamp/block ordering
            function swap(uint256 minOut) external payable returns (uint256 out) {{
                require(
                    block.timestamp >= lastSwapTime + cooldown,
                    "Swap cooldown active"
                );
                out = (msg.value * reserveToken) / (reserveETH + msg.value);
                require(out >= minOut, "Slippage exceeded");
                reserveETH   += msg.value;
                reserveToken -= out;
                lastSwapTime  = block.timestamp;
                emit Swapped(msg.sender, msg.value, out);
            }}
        }}
        """),

    # 5 – Penalty window
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Early Withdrawal Penalty Window
        /// @notice VULNERABLE: penalty window checked via block.timestamp (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public depositTime;
            mapping(address => uint256) public deposits;
            uint256 public lockPeriod = {p['window']};
            uint256 public penaltyBps = 1000; // 10%

            function deposit() external payable {{
                deposits[msg.sender]    += msg.value;
                depositTime[msg.sender]  = block.timestamp;
            }}

            // VULN: miner can delay timestamp to help user avoid penalty
            function withdraw() external {{
                uint256 amount = deposits[msg.sender];
                require(amount > 0, "Nothing to withdraw");
                deposits[msg.sender] = 0;
                if (block.timestamp < depositTime[msg.sender] + lockPeriod) {{
                    uint256 penalty = (amount * penaltyBps) / 10000;
                    amount -= penalty;
                }}
                (bool ok,) = msg.sender.call{{value: amount}}("");
                require(ok);
            }}
        }}
        """),

    # 6 – TWAP manipulation
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Naive TWAP Oracle
        /// @notice VULNERABLE: TWAP window manipulable via block.timestamp (SWC-116)
        contract {p['name']} {{
            uint256 public cumulativePrice;
            uint256 public lastPrice;
            uint256 public lastUpdateTime;
            uint256 public twapWindow = {p['window']};

            function updatePrice(uint256 newPrice) external {{
                if (lastUpdateTime != 0) {{
                    uint256 elapsed = block.timestamp - lastUpdateTime;
                    cumulativePrice += lastPrice * elapsed;
                }}
                lastPrice      = newPrice;
                lastUpdateTime = block.timestamp;
            }}

            // VULN: miner can artificially inflate elapsed time to skew TWAP
            function getTWAP(uint256 startCumulative, uint256 startTime)
                external view returns (uint256)
            {{
                uint256 elapsed = block.timestamp - startTime;
                require(elapsed >= twapWindow, "Window too short");
                uint256 cumulative = cumulativePrice + lastPrice * (block.timestamp - lastUpdateTime);
                return (cumulative - startCumulative) / elapsed;
            }}
        }}
        """),
]

# ------ timestamp_overflow ----------------------------------------------------
_TO_TEMPLATES = [
    # 0 – uint32 expiry
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - uint32 Timestamp Expiry
        /// @notice VULNERABLE: uint32 overflows in year 2038 (SWC-101, SWC-116)
        contract {p['name']} {{
            // VULN: uint32 max = 4294967295 = 2106-02-07, but practical limit near 2038
            uint32 public expiry;

            constructor(uint32 _expiry) {{
                expiry = _expiry;
            }}

            function isExpired() external view returns (bool) {{
                // VULN: if block.timestamp > 2^32, cast overflows silently
                return uint32(block.timestamp) > expiry;
            }}

            function setExpiry(uint32 _expiry) external {{
                expiry = _expiry;
            }}
        }}
        """),

    # 1 – uint32 lock
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Time Lock with uint32 Overflow
        /// @notice VULNERABLE: uint32 truncation of block.timestamp (SWC-101)
        contract {p['name']} {{
            address public owner;
            uint32  public lockUntil; // VULN: overflows in 2038

            constructor(uint32 _lockUntil) {{
                owner     = msg.sender;
                lockUntil = _lockUntil;
            }}

            function withdraw() external {{
                require(msg.sender == owner, "Not owner");
                // VULN: comparison silently wraps when timestamp > 2^32
                require(uint32(block.timestamp) >= lockUntil, "Still locked");
                (bool ok,) = owner.call{{value: address(this).balance}}("");
                require(ok);
            }}

            receive() external payable {{}}
        }}
        """),

    # 2 – uint40 vesting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Vesting with uint40 Timestamp
        /// @notice VULNERABLE: downcast of block.timestamp loses precision (SWC-101)
        contract {p['name']} {{
            struct VestingSchedule {{
                uint40 start;   // VULN: uint40 overflows in year 36,812
                uint40 cliff;
                uint40 end;
                uint256 total;
                uint256 claimed;
            }}

            mapping(address => VestingSchedule) public schedules;

            function createSchedule(
                address beneficiary,
                uint40 cliffSeconds,
                uint40 totalSeconds,
                uint256 amount
            ) external payable {{
                require(msg.value == amount, "Wrong amount");
                schedules[beneficiary] = VestingSchedule({{
                    start:   uint40(block.timestamp),   // VULN: silent truncation
                    cliff:   uint40(block.timestamp) + cliffSeconds,
                    end:     uint40(block.timestamp) + totalSeconds,
                    total:   amount,
                    claimed: 0
                }});
            }}

            function claimable(address beneficiary) public view returns (uint256) {{
                VestingSchedule storage s = schedules[beneficiary];
                if (uint40(block.timestamp) < s.cliff) return 0;
                if (uint40(block.timestamp) >= s.end)  return s.total - s.claimed;
                uint256 elapsed  = uint40(block.timestamp) - s.start;
                uint256 duration = s.end - s.start;
                return (s.total * elapsed / duration) - s.claimed;
            }}
        }}
        """),

    # 3 – Addition overflow
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity 0.6.{p['minor']};

        /// @title {p['name']} - Timestamp Addition Overflow (Solidity 0.6)
        /// @notice VULNERABLE: arithmetic overflow in timestamp addition (SWC-101)
        contract {p['name']} {{
            uint256 public lockEnd;

            // VULN: if duration is very large, block.timestamp + duration overflows
            constructor(uint256 duration) public {{
                lockEnd = block.timestamp + duration;
            }}

            function isLocked() public view returns (bool) {{
                return block.timestamp < lockEnd;
            }}
        }}
        """),

    # 4 – Year 2038 subscription
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Subscription with Year-2038 Bug
        /// @notice VULNERABLE: uint32 timestamp overflows in year 2038 (SWC-101, SWC-116)
        contract {p['name']} {{
            mapping(address => uint32) public expiry; // VULN: uint32 max ≈ 2106 but wraps

            uint32 public constant YEAR = 365 days; // VULN: uint32 cast of 365 days

            function subscribe() external payable {{
                require(msg.value >= 0.01 ether, "Too cheap");
                // VULN: addition overflows when expiry > 2^32 - 1
                expiry[msg.sender] = uint32(block.timestamp) + YEAR;
            }}

            function isActive(address user) external view returns (bool) {{
                return uint32(block.timestamp) < expiry[user];
            }}
        }}
        """),

    # 5 – Cumulative overflow
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Cumulative Timestamp Overflow
        /// @notice VULNERABLE: cumulative seconds can overflow uint32 (SWC-101)
        contract {p['name']} {{
            uint32 public cumulativeTime;  // VULN: wraps after ~136 years total
            uint256 public lastUpdate;

            function tick() external {{
                if (lastUpdate != 0) {{
                    // VULN: delta silently truncated then added to wrapping accumulator
                    uint32 delta = uint32(block.timestamp - lastUpdate);
                    cumulativeTime += delta;
                }}
                lastUpdate = block.timestamp;
            }}
        }}
        """),
]

# ------ vesting_schedule_manipulation ----------------------------------------
_VSM_TEMPLATES = [
    # 0 – Linear vesting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Linear Token Vesting
        /// @notice VULNERABLE: vesting calculation uses block.timestamp (SWC-116)
        contract {p['name']} {{
            address public beneficiary;
            uint256 public startTime;
            uint256 public duration;
            uint256 public totalTokens;
            uint256 public claimed;

            constructor(address _beneficiary, uint256 _duration) payable {{
                beneficiary  = _beneficiary;
                startTime    = block.timestamp;
                duration     = _duration;
                totalTokens  = msg.value;
            }}

            // VULN: miner can advance block.timestamp to vest tokens faster
            function vestedAmount() public view returns (uint256) {{
                if (block.timestamp >= startTime + duration) {{
                    return totalTokens;
                }}
                return totalTokens * (block.timestamp - startTime) / duration;
            }}

            function claim() external {{
                require(msg.sender == beneficiary, "Not beneficiary");
                uint256 claimable = vestedAmount() - claimed;
                require(claimable > 0, "Nothing to claim");
                claimed += claimable;
                (bool ok,) = beneficiary.call{{value: claimable}}("");
                require(ok);
            }}
        }}
        """),

    # 1 – Cliff vesting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Cliff + Linear Vesting
        /// @notice VULNERABLE: cliff and vesting periods use block.timestamp (SWC-116)
        contract {p['name']} {{
            address public beneficiary;
            uint256 public startTime;
            uint256 public cliffDuration;
            uint256 public vestingDuration;
            uint256 public totalAmount;
            uint256 public released;

            constructor(
                address _beneficiary,
                uint256 _cliff,
                uint256 _vesting
            ) payable {{
                beneficiary     = _beneficiary;
                startTime       = block.timestamp;
                cliffDuration   = _cliff;
                vestingDuration = _vesting;
                totalAmount     = msg.value;
            }}

            // VULN: miner pushes block.timestamp past cliff to unlock tokens early
            function releasable() public view returns (uint256) {{
                if (block.timestamp < startTime + cliffDuration) return 0;
                if (block.timestamp >= startTime + vestingDuration) {{
                    return totalAmount - released;
                }}
                uint256 elapsed = block.timestamp - startTime;
                return (totalAmount * elapsed / vestingDuration) - released;
            }}

            function release() external {{
                uint256 amount = releasable();
                require(amount > 0, "Nothing to release");
                released += amount;
                (bool ok,) = beneficiary.call{{value: amount}}("");
                require(ok);
            }}
        }}
        """),

    # 2 – Milestone-based vesting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Milestone Vesting
        /// @notice VULNERABLE: milestone timestamps use block.timestamp (SWC-116)
        contract {p['name']} {{
            address public beneficiary;
            address public admin;
            uint256 public totalAmount;
            uint256 public released;

            struct Milestone {{
                uint256 unlockTime;
                uint256 amount;
                bool    claimed;
            }}

            Milestone[] public milestones;

            constructor(address _beneficiary) payable {{
                admin       = msg.sender;
                beneficiary = _beneficiary;
                totalAmount = msg.value;
            }}

            function addMilestone(uint256 unlockTime, uint256 amount) external {{
                require(msg.sender == admin, "Not admin");
                milestones.push(Milestone(unlockTime, amount, false));
            }}

            // VULN: miner can advance block.timestamp to unlock milestones early
            function claimMilestone(uint256 idx) external {{
                Milestone storage m = milestones[idx];
                require(msg.sender == beneficiary, "Not beneficiary");
                require(!m.claimed, "Already claimed");
                require(block.timestamp >= m.unlockTime, "Not yet unlocked");
                m.claimed = true;
                released += m.amount;
                (bool ok,) = beneficiary.call{{value: m.amount}}("");
                require(ok);
            }}
        }}
        """),

    # 3 – Team token vesting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        interface IERC20 {{
            function transfer(address to, uint256 amount) external returns (bool);
        }}

        /// @title {p['name']} - Team Token Vesting
        /// @notice VULNERABLE: vesting schedule uses block.timestamp (SWC-116)
        contract {p['name']} {{
            IERC20  public token;
            address public team;
            uint256 public startTime;
            uint256 public cliffMonths = {p['window']};
            uint256 public vestMonths  = {p['rate']};
            uint256 public totalTokens;
            uint256 public released;

            uint256 constant MONTH = 30 days;

            constructor(address _token, address _team, uint256 _total) {{
                token      = IERC20(_token);
                team       = _team;
                startTime  = block.timestamp;
                totalTokens = _total;
            }}

            // VULN: miner can manipulate block.timestamp to skip cliff period
            function release() external {{
                uint256 elapsed  = block.timestamp - startTime;
                uint256 months   = elapsed / MONTH;
                require(months >= cliffMonths, "Cliff not reached");
                uint256 vested   = totalTokens * months / vestMonths;
                if (vested > totalTokens) vested = totalTokens;
                uint256 claimable = vested - released;
                require(claimable > 0, "Nothing to release");
                released += claimable;
                require(token.transfer(team, claimable), "Transfer failed");
            }}
        }}
        """),

    # 4 – Investor vesting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Investor Vesting Contract
        /// @notice VULNERABLE: investor unlocks depend on block.timestamp (SWC-116)
        contract {p['name']} {{
            struct InvestorVesting {{
                uint256 totalAmount;
                uint256 startTime;
                uint256 lockupPeriod;
                uint256 vestingPeriod;
                uint256 released;
            }}

            mapping(address => InvestorVesting) public vestings;
            address public admin;

            constructor() {{
                admin = msg.sender;
            }}

            function grantVesting(
                address investor,
                uint256 lockup,
                uint256 vesting
            ) external payable {{
                require(msg.sender == admin, "Not admin");
                vestings[investor] = InvestorVesting({{
                    totalAmount:  msg.value,
                    startTime:    block.timestamp,
                    lockupPeriod: lockup,
                    vestingPeriod: vesting,
                    released:     0
                }});
            }}

            // VULN: miner can bypass lockup by advancing block.timestamp
            function release() external {{
                InvestorVesting storage v = vestings[msg.sender];
                require(v.totalAmount > 0, "No vesting");
                require(
                    block.timestamp >= v.startTime + v.lockupPeriod,
                    "Lockup active"
                );
                uint256 elapsed   = block.timestamp - v.startTime;
                uint256 vested    = v.totalAmount * elapsed / v.vestingPeriod;
                if (vested > v.totalAmount) vested = v.totalAmount;
                uint256 claimable = vested - v.released;
                require(claimable > 0, "Nothing claimable");
                v.released += claimable;
                (bool ok,) = msg.sender.call{{value: claimable}}("");
                require(ok);
            }}
        }}
        """),

    # 5 – NFT staking vesting
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - NFT Staking Vesting Rewards
        /// @notice VULNERABLE: staking duration measured with block.timestamp (SWC-116)
        contract {p['name']} {{
            mapping(uint256 => address) public nftStaker;
            mapping(uint256 => uint256) public stakeTime;
            uint256 public rewardPerSecond = {p['rate']};

            function stakeNFT(uint256 tokenId) external {{
                // simplified: no actual NFT transfer
                nftStaker[tokenId] = msg.sender;
                stakeTime[tokenId] = block.timestamp;
            }}

            // VULN: miner can advance block.timestamp to inflate NFT staking rewards
            function unstakeNFT(uint256 tokenId) external {{
                require(nftStaker[tokenId] == msg.sender, "Not staker");
                uint256 elapsed = block.timestamp - stakeTime[tokenId];
                uint256 reward  = elapsed * rewardPerSecond;
                delete nftStaker[tokenId];
                delete stakeTime[tokenId];
                (bool ok,) = msg.sender.call{{value: reward}}("");
                require(ok);
            }}

            receive() external payable {{}}
        }}
        """),
]

# ------ miner_scheduled_execution --------------------------------------------
_MSE_TEMPLATES = [
    # 0 – Scheduled payment
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Validator-Scheduled Payment
        /// @notice VULNERABLE: execution timing depends on block.timestamp (SWC-116)
        contract {p['name']} {{
            struct Payment {{
                address recipient;
                uint256 amount;
                uint256 executeAfter;
                bool    executed;
            }}

            Payment[] public payments;
            address public scheduler;

            constructor() {{
                scheduler = msg.sender;
            }}

            function schedule(address recipient, uint256 delay) external payable {{
                require(msg.sender == scheduler, "Not scheduler");
                payments.push(Payment({{
                    recipient:    recipient,
                    amount:       msg.value,
                    // VULN: execute window manipulable within ~15 second miner window
                    executeAfter: block.timestamp + delay,
                    executed:     false
                }}));
            }}

            // VULN: validator can include this tx at a timestamp of their choosing
            function execute(uint256 idx) external {{
                Payment storage p = payments[idx];
                require(!p.executed, "Already executed");
                require(block.timestamp >= p.executeAfter, "Too early");
                p.executed = true;
                (bool ok,) = p.recipient.call{{value: p.amount}}("");
                require(ok, "Payment failed");
            }}
        }}
        """),

    # 1 – Keeper with timestamp
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Keeper-Based Job Scheduler
        /// @notice VULNERABLE: job upkeep timing uses block.timestamp (SWC-116)
        contract {p['name']} {{
            uint256 public lastRun;
            uint256 public interval = {p['window']};
            address public keeper;

            constructor(address _keeper) {{
                keeper  = _keeper;
                lastRun = block.timestamp;
            }}

            function checkUpkeep() external view returns (bool) {{
                // VULN: miner sets block.timestamp to trigger upkeep prematurely
                return block.timestamp >= lastRun + interval;
            }}

            function performUpkeep() external {{
                require(msg.sender == keeper, "Not keeper");
                require(block.timestamp >= lastRun + interval, "Too soon");
                lastRun = block.timestamp;
                _doWork();
            }}

            function _doWork() internal {{
                // ... protocol maintenance work
            }}
        }}
        """),

    # 2 – Auto-compound
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Auto-Compounding Vault
        /// @notice VULNERABLE: compound interval uses block.timestamp (SWC-116)
        contract {p['name']} {{
            mapping(address => uint256) public deposits;
            mapping(address => uint256) public lastCompound;
            uint256 public apr = {p['rate']}; // basis points
            uint256 public compoundInterval = {p['window']};

            function deposit() external payable {{
                _compound(msg.sender);
                deposits[msg.sender]    += msg.value;
                lastCompound[msg.sender] = block.timestamp;
            }}

            // VULN: miner picks block.timestamp to maximise compound amount
            function _compound(address user) internal {{
                if (lastCompound[user] == 0) return;
                uint256 elapsed  = block.timestamp - lastCompound[user];
                if (elapsed < compoundInterval) return;
                uint256 interest = deposits[user] * apr * elapsed / (10000 * 365 days);
                deposits[user]      += interest;
                lastCompound[user]   = block.timestamp;
            }}

            function compound() external {{ _compound(msg.sender); }}

            function withdraw() external {{
                _compound(msg.sender);
                uint256 amount = deposits[msg.sender];
                deposits[msg.sender] = 0;
                (bool ok,) = msg.sender.call{{value: amount}}("");
                require(ok);
            }}
        }}
        """),

    # 3 – Gas price auction via timestamp
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Time-Decaying Gas Auction
        /// @notice VULNERABLE: price decay uses block.timestamp (SWC-116)
        contract {p['name']} {{
            uint256 public startPrice = {p['rate']};
            uint256 public auctionStart;
            uint256 public decayRate = 1; // wei per second
            address public owner;

            constructor() {{
                owner        = msg.sender;
                auctionStart = block.timestamp;
            }}

            // VULN: miner delays block.timestamp to lower the current price
            function currentPrice() public view returns (uint256) {{
                uint256 elapsed = block.timestamp - auctionStart;
                if (elapsed * decayRate >= startPrice) return 0;
                return startPrice - elapsed * decayRate;
            }}

            function buy() external payable {{
                uint256 price = currentPrice();
                require(price > 0, "Auction ended");
                require(msg.value >= price, "Underpaid");
                if (msg.value > price) {{
                    (bool ok,) = msg.sender.call{{value: msg.value - price}}("");
                    require(ok);
                }}
                (bool ok2,) = owner.call{{value: price}}("");
                require(ok2);
            }}
        }}
        """),

    # 4 – Batch execution
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Batch Executor with Timestamp Guard
        /// @notice VULNERABLE: batch window enforced by block.timestamp (SWC-116)
        contract {p['name']} {{
            address public admin;
            uint256 public batchWindow = {p['window']};
            uint256 public lastBatch;

            struct Call {{
                address target;
                bytes   data;
                uint256 value;
            }}

            constructor() {{
                admin = msg.sender;
                lastBatch = block.timestamp;
            }}

            // VULN: validator includes this tx at a timestamp that opens the window
            function executeBatch(Call[] calldata calls) external {{
                require(msg.sender == admin, "Not admin");
                require(
                    block.timestamp >= lastBatch + batchWindow,
                    "Window not open"
                );
                lastBatch = block.timestamp;
                for (uint256 i = 0; i < calls.length; i++) {{
                    (bool ok,) = calls[i].target.call{{value: calls[i].value}}(calls[i].data);
                    require(ok, "Call failed");
                }}
            }}
        }}
        """),

    # 5 – Recurring subscription executor
    lambda p: textwrap.dedent(f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity {p['sver']};

        /// @title {p['name']} - Recurring Subscription Executor
        /// @notice VULNERABLE: payment interval uses block.timestamp (SWC-116)
        contract {p['name']} {{
            struct Subscription {{
                address subscriber;
                address merchant;
                uint256 amount;
                uint256 interval;
                uint256 lastCharge;
                bool    active;
            }}

            Subscription[] public subscriptions;

            function subscribe(address merchant, uint256 amount, uint256 interval)
                external payable returns (uint256 subId)
            {{
                subId = subscriptions.length;
                subscriptions.push(Subscription({{
                    subscriber: msg.sender,
                    merchant:   merchant,
                    amount:     amount,
                    interval:   interval,
                    lastCharge: block.timestamp,
                    active:     true
                }}));
            }}

            // VULN: validator can time tx to charge slightly before/after interval
            function charge(uint256 subId) external {{
                Subscription storage s = subscriptions[subId];
                require(s.active, "Not active");
                require(
                    block.timestamp >= s.lastCharge + s.interval,
                    "Interval not elapsed"
                );
                s.lastCharge = block.timestamp;
                (bool ok,) = s.merchant.call{{value: s.amount}}("");
                require(ok, "Charge failed");
            }}
        }}
        """),
]

# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------
TEMPLATES = {
    "block_timestamp_manipulation": _BTM_TEMPLATES,
    "deadline_bypass":              _DB_TEMPLATES,
    "block_number_manipulation":    _BNM_TEMPLATES,
    "time_window_attack":           _TWA_TEMPLATES,
    "timestamp_overflow":           _TO_TEMPLATES,
    "vesting_schedule_manipulation":_VSM_TEMPLATES,
    "miner_scheduled_execution":    _MSE_TEMPLATES,
}

# Labels for each subtype (CWE / SWC / severity)
SUBTYPE_META = {
    "block_timestamp_manipulation": {
        "cwe": ["CWE-829", "CWE-330"],
        "swc": ["SWC-116"],
        "severity": "medium",
    },
    "deadline_bypass": {
        "cwe": ["CWE-829"],
        "swc": ["SWC-116"],
        "severity": "high",
    },
    "block_number_manipulation": {
        "cwe": ["CWE-829"],
        "swc": ["SWC-116"],
        "severity": "medium",
    },
    "time_window_attack": {
        "cwe": ["CWE-362"],
        "swc": ["SWC-116"],
        "severity": "medium",
    },
    "timestamp_overflow": {
        "cwe": ["CWE-190"],
        "swc": ["SWC-116", "SWC-101"],
        "severity": "low",
    },
    "vesting_schedule_manipulation": {
        "cwe": ["CWE-829"],
        "swc": ["SWC-116"],
        "severity": "high",
    },
    "miner_scheduled_execution": {
        "cwe": ["CWE-829"],
        "swc": ["SWC-116"],
        "severity": "medium",
    },
}

# Context names for generating unique contract names
_CONTEXTS = [
    "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta",
    "Eta", "Theta", "Iota", "Kappa", "Lambda", "Mu",
    "Nu", "Xi", "Omicron", "Pi", "Rho", "Sigma",
    "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega",
    "Apex", "Base", "Core", "Dawn", "Edge", "Flux",
    "Gate", "Halo", "Iris", "Jade", "Kite", "Lynx",
    "Mesa", "Node", "Orb", "Peak", "Quark", "Reef",
    "Sage", "Tide", "Ultra", "Vega", "Wave", "Xeno",
    "Yield", "Zenith",
]

_SUFFIXES = [
    "V1", "V2", "V3", "Pro", "Plus", "Lite", "Max", "Prime",
    "X", "Zero", "One", "Two", "Three", "Four", "Five",
    "A", "B", "C", "D", "E", "F", "G", "H",
]


def _make_params(subtype: str, idx: int) -> dict:
    """Return a dict of template parameters for the given subtype and index."""
    ctx    = _CONTEXTS[idx % len(_CONTEXTS)]
    suffix = _SUFFIXES[idx % len(_SUFFIXES)]
    sver   = random.choice(_SOLIDITY_VERSIONS)

    base: dict = {
        "name":   f"{ctx}{suffix}",
        "sver":   sver,
        "price":  random.choice(["0.001", "0.01", "0.05", "0.1", "1"]),
        "rate":   random.randint(1, 1000),
        "window": random.choice([60, 300, 900, 1800, 3600, 86400, 604800]),
        "minor":  random.randint(0, 12),
    }
    # timestamp_overflow requires old-style Solidity for some templates
    if subtype == "timestamp_overflow":
        base["sver"] = random.choice(["0.6.12", "0.7.6", "^0.8.0"])
    return base


def _build_metadata(
    contract_id: str,
    subtype: str,
    name: str,
    compiler: str,
    idx: int,
    source: str = "ai_generated",
) -> dict:
    """Build the vulnerability-feedback JSON record."""
    smeta  = SUBTYPE_META[subtype]
    ptype  = _protocol_type()
    deploy = _random_date()
    audit  = random.choice(_AUDIT_OPTIONS)

    exploited = random.random() < 0.1  # 10% chance of exploit in generated set
    exploit_record: dict = {"exploited": False}
    if exploited:
        edate = _random_date(start=deploy)
        exploit_record = {
            "exploited":       True,
            "exploit_date":    edate,
            "exploit_value_usd": random.randint(10_000, 5_000_000),
            "exploit_tx":      _fake_tx(),
        }

    vuln_key = "timestamp_dependence"
    line_start = random.randint(10, 80)
    meta = {
        "contract_id":          contract_id,
        "collection_source":    source,
        "compiler_version":     compiler,
        "solidity_version":     "^" + compiler if not compiler.startswith("^") else compiler,
        "optimization_enabled": random.choice([True, False]),
        "optimization_runs":    random.choice([200, 500, 1000]),
        "protocol_type":        ptype,
        "protocol_name":        _protocol_name(ptype),
        "total_value_locked_usd": random.randint(0, 50_000_000),
        "deployment_date":      deploy,
        "audit_status":         audit,
        "exploit_history":      exploit_record,
        "vulnerability_labels": {
            vuln_key: {
                "present":      True,
                "subtype":      subtype,
                "severity":     smeta["severity"],
                "confidence":   round(random.uniform(0.75, 1.0), 2),
                "line_numbers": [line_start, line_start + random.randint(5, 20)],
                "cwe":          smeta["cwe"],
                "swc":          smeta["swc"],
            }
        },
    }
    return meta


def generate(contracts_per_subtype: int = 100) -> None:
    """Generate contracts_per_subtype contracts for each of the 7 subtypes."""
    total = 0
    for subtype, templates in TEMPLATES.items():
        out_dir_sol  = GEN_CONTRACTS / subtype
        out_dir_meta = GEN_META_DIR = GEN_METADATA / subtype
        out_dir_sol.mkdir(parents=True, exist_ok=True)
        out_dir_meta.mkdir(parents=True, exist_ok=True)

        for i in range(contracts_per_subtype):
            tmpl_fn = templates[i % len(templates)]
            params  = _make_params(subtype, i)
            code    = tmpl_fn(params)

            # Unique identifier
            contract_id = _fake_address()
            compiler    = _compiler_version()
            name        = params["name"]
            filename    = f"contract_{i+1:03d}"

            sol_path  = out_dir_sol  / f"{filename}.sol"
            meta_path = out_dir_meta / f"{filename}.json"

            sol_path.write_text(code, encoding="utf-8")

            meta = _build_metadata(contract_id, subtype, name, compiler, i)
            meta_path.write_text(
                json.dumps(meta, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            total += 1

    print(f"Generated {total} contracts across {len(TEMPLATES)} subtypes.")


if __name__ == "__main__":
    generate(contracts_per_subtype=100)
