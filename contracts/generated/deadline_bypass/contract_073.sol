// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title PsiPro - Time-Limited Discount Sale
/// @notice VULNERABLE: discount period uses block.timestamp (SWC-116)
contract PsiPro {
    IERC20  public token;
    address public admin;
    uint256 public discountEnd;
    uint256 public normalRate = 505;
    uint256 public discountRate;

    constructor(address _token, uint256 _discountDuration) {
        token        = IERC20(_token);
        admin        = msg.sender;
        discountEnd  = block.timestamp + _discountDuration;
        discountRate = normalRate * 2; // 2× tokens during discount
    }

    // VULN: miner can extend discount window by manipulating block.timestamp
    function buy() external payable {
        uint256 rate = (block.timestamp <= discountEnd)
            ? discountRate
            : normalRate;
        uint256 tokens = msg.value * rate;
        require(token.transfer(msg.sender, tokens), "Transfer failed");
    }
}
