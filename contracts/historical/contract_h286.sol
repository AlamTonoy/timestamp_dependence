// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title RoninBridgeTimestamp - Bridge Signature Validity Window
/// @notice Pattern from Ronin Bridge 2022; timestamp window on relay signatures.
contract RoninBridgeTimestampLite {
    mapping(bytes32 => bool) public processedRequests;
    mapping(address => bool) public validators;
    uint256 public validatorCount;
    uint256 public requiredSignatures;
    uint256 public signatureValidWindow = 24 hours;

    event Deposited(address indexed to, uint256 amount);

    function addValidator(address v) external {
        validators[v] = true;
        validatorCount++;
        requiredSignatures = (validatorCount * 2) / 3 + 1;
    }

    // VULN: timestamp in requestId; validators can replay within window
    function withdraw(
        address to,
        uint256 amount,
        uint256 requestTimestamp,
        bytes[] calldata sigs
    ) external {
        require(
            block.timestamp <= requestTimestamp + signatureValidWindow,
            "Request expired"
        );
        bytes32 requestId = keccak256(abi.encodePacked(to, amount, requestTimestamp));
        require(!processedRequests[requestId], "Already processed");
        require(_verifySignatures(requestId, sigs), "Invalid signatures");
        processedRequests[requestId] = true;
        (bool ok,) = to.call{value: amount}("");
        require(ok);
        emit Deposited(to, amount);
    }

    function _verifySignatures(bytes32 hash, bytes[] calldata sigs)
        internal view returns (bool)
    {
        uint256 valid;
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = _recover(hash, sigs[i]);
            if (validators[signer]) valid++;
        }
        return valid >= requiredSignatures;
    }

    function _recover(bytes32 hash, bytes calldata sig)
        internal pure returns (address)
    {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)),
            v, r, s
        );
    }

    receive() external payable {}
}
