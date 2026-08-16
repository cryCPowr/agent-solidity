//SPDX-License-Identifier: MIT

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import { IJackpot } from "../interfaces/IJackpot.sol";


pragma solidity ^0.8.18;

contract ReentrantUSDCMock is ERC20 {

    // Reentrancy testing configuration
    address public callbackTarget;
    bytes public callbackData;
    bool public callbackEnabled = false;
    uint256 public callbackCount = 0;
    uint256 public maxCallbacks = 1;

    constructor(
        uint256 _mintAmount,
        string memory name,
        string memory symbol
    )
        ERC20(name, symbol)
    {
        _mint(msg.sender, _mintAmount);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    // ====== REENTRANCY TESTING FUNCTIONS ======
    
    /**
     * @notice Sets the target contract for reentrancy callbacks
     * @param _target Address of the contract to callback (typically Jackpot contract)
     */
    function setCallbackTarget(address _target) external {
        callbackTarget = _target;
        callbackCount = 0; // Reset counter when setting new target
    }

    /**
     * @notice Sets the data to be passed to the callback target
     * @param _data Data to be passed to the callback target
     */
    function setCallbackData(bytes memory _data) external {
        callbackData = _data;
    }
    
    /**
     * @notice Enables callback execution on transfer calls
     */
    function enableCallback() external {
        callbackEnabled = true;
        callbackCount = 0; // Reset counter when enabling
    }
    
    /**
     * @notice Disables callback execution
     */
    function disableCallback() external {
        callbackEnabled = false;
        callbackCount = 0;
    }
    
    /**
     * @notice Sets maximum number of callbacks to prevent infinite loops
     * @param _max Maximum number of callbacks allowed
     */
    function setMaxCallbacks(uint256 _max) external {
        maxCallbacks = _max;
    }
    
    /**
     * @notice Resets the callback counter
     */
    function resetCallbackCount() external {
        callbackCount = 0;
    }

    // ====== OVERRIDDEN TRANSFER FUNCTIONS ======
    
    /**
     * @notice Transfer tokens with optional reentrancy callback
     * @dev Calls runJackpot() on the target contract if callback is enabled
     */
    function transfer(address to, uint256 amount) public override returns (bool) {
        bool success = super.transfer(to, amount);

        if (success && callbackEnabled && callbackTarget != address(0) && callbackCount < maxCallbacks) {
            callbackCount++;
            _executeCallback();
        }
        
        return success;
    }
    
    /**
     * @notice TransferFrom tokens with optional reentrancy callback
     * @dev Calls runJackpot() on the target contract if callback is enabled
     */
    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        bool success = super.transferFrom(from, to, amount);
        
        if (success && callbackEnabled && callbackTarget != address(0) && callbackCount < maxCallbacks) {
            callbackCount++;
            _executeCallback();
        }
        
        return success;
    }
    
    /**
     * @notice Executes the reentrancy callback to runJackpot()
     * @dev Calls runJackpot() with 1 ether value, ignores failures to allow testing
     */
    function _executeCallback() internal {
        (bool success, bytes memory returndata) = callbackTarget.call(callbackData);
        if (!success) {
            if (returndata.length > 0) {
                assembly {
                    revert(add(returndata, 32), mload(returndata))
                }
            } else {
                revert("Callback failed");
            }
        }
    }
    
    // ====== HELPER FUNCTIONS FOR TESTING ======
    
    /**
     * @notice Mints tokens to specified address (for test setup)
     */
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
    
    /**
     * @notice Returns current callback configuration
     */
    function getCallbackConfig() external view returns (address target, bool enabled, uint256 count, uint256 max) {
        return (callbackTarget, callbackEnabled, callbackCount, maxCallbacks);
    }
    
    // ====== RECEIVE FUNCTION FOR ETH ======
    
    /**
     * @notice Allows contract to receive ETH for callback testing
     */
    receive() external payable {}
}
