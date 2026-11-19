// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

library SignalIndex {
    uint256 internal constant N = 8;

    uint256 internal constant IDX_NULLIFIER = 0;

    // CT[k].R.x = 1 + 4*k
    // CT[k].R.y = 2 + 4*k
    // CT[k].S.x = 3 + 4*k
    // CT[k].S.y = 4 + 4*k

    function ctRx(uint256 k) internal pure returns (uint256) {
        require(k < N, "SignalIndex: k out of range");
        return 1 + 4 * k;
    }

    function ctRy(uint256 k) internal pure returns (uint256) {
        require(k < N, "SignalIndex: k out of range");
        return 2 + 4 * k;
    }

    function ctSx(uint256 k) internal pure returns (uint256) {
        require(k < N, "SignalIndex: k out of range");
        return 3 + 4 * k;
    }

    function ctSy(uint256 k) internal pure returns (uint256) {
        require(k < N, "SignalIndex: k out of range");
        return 4 + 4 * k;
    }

    uint256 internal constant IDX_REGISTRY_ROOT = 33;
    uint256 internal constant IDX_POLL_ID = 34;
    uint256 internal constant IDX_PK_X = 35;
    uint256 internal constant IDX_PK_Y = 36;

    function ciphertextCount() internal pure returns (uint256) {
        return N;
    }

    function ciphertextCoordinateCount() internal pure returns (uint256) {
        return 4 * N;
    }
}
