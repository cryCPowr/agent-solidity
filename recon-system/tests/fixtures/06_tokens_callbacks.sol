// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IERC721Like {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
}

interface IERC1155Like {
    function safeBatchTransferFrom(
        address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data
    ) external;
    function setApprovalForAll(address operator, bool approved) external;
}

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external returns (bytes4);
}

contract Marketplace is IERC721Receiver {
    IERC20Like public paymentToken;
    IERC721Like public nft;
    IERC1155Like public multiToken;

    function payOut(address to, uint256 amount) external {
        paymentToken.transfer(to, amount);
    }

    function pullPayment(address from, uint256 amount) external {
        paymentToken.transferFrom(from, address(this), amount);
    }

    function approveSpender(address spender, uint256 amount) external {
        paymentToken.approve(spender, amount);
    }

    function moveNft(address from, address to, uint256 tokenId) external {
        nft.safeTransferFrom(from, to, tokenId);
    }

    function moveMulti(
        address from, address to, uint256[] calldata ids, uint256[] calldata amounts
    ) external {
        multiToken.safeBatchTransferFrom(from, to, ids, amounts, "");
    }

    // Callback-compatible receiver hook.
    function onERC721Received(address, address, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }
}
