// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import "./SignalIndex.sol";

interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[37] calldata _pubSignals
    ) external view returns (bool);
}

contract StrongN8Poll {
    using SignalIndex for uint256;

    uint256 public constant N = 8;
    uint256 public constant L_VOTE = 8;
    uint256 public constant L_AGG = 11;
    uint256 public constant MAX_TAU = 2040;

    string public constant PROTOCOL_TAG = "STRONG_N8_POLL_V1";

    bytes32 public constant BALLOT_SEED_V1 = keccak256("BALLOT_SEED_V1");
    bytes32 public constant BALLOT_NODE_V1 = keccak256("BALLOT_NODE_V1");
    bytes32 public constant BALLOT_FINAL_V1 = keccak256("BALLOT_FINAL_V1");
    bytes32 public constant BALLOT_LEAF_V1 = keccak256("BALLOT_LEAF_V1");

    uint256 public immutable committeePK_X;
    uint256 public immutable committeePK_Y;
    bytes32 public immutable backendSetupHash;

    IGroth16Verifier public immutable voteVerifier;
    uint256 public immutable registryRoot;
    uint256 public immutable pollId;
    uint256 public immutable tau;
    address public immutable outcomePublisher;
    uint256 public immutable votingDeadline;
    bytes32 public immutable POLL_DOMAIN;

    uint256 public acceptedBallotCount;
    bytes32 public accumulator;
    bytes32 public ballotSetCommitment;
    bytes32 public backendTranscriptHash;
    uint8 public outcomeBit;

    mapping(uint256 => bool) public usedNullifiers;

    enum Phase { Open, Sealed, Claimed, Abandoned }
    Phase public phase;

    event BallotAccepted(
        uint256 indexed ballotIndex,
        uint256 nullifier,
        uint256[32] ciphertext,
        bytes32 ballotLeaf,
        bytes32 accumulator
    );
    event BallotSetSealed(bytes32 ballotSetCommitment);
    event OutcomeClaimPublished(
        bytes32 ballotSetCommitment,
        bytes32 backendTranscriptHash,
        uint8 outcomeBit
    );
    event PollAbandoned();

    modifier onlyOpen() {
        require(phase == Phase.Open, "StrongN8Poll: poll is not open");
        _;
    }

    modifier onlySealed() {
        require(phase == Phase.Sealed, "StrongN8Poll: poll is not sealed");
        _;
    }

    modifier onlyOutcomePublisher() {
        require(msg.sender == outcomePublisher, "StrongN8Poll: not outcome publisher");
        _;
    }

    constructor(
        address _voteVerifier,
        uint256 _registryRoot,
        uint256 _pollId,
        uint256 _tau,
        address _outcomePublisher,
        uint256 _votingDeadline,
        uint256 _committeePK_X,
        uint256 _committeePK_Y,
        bytes32 _backendSetupHash
    ) {
        require(_voteVerifier != address(0), "StrongN8Poll: zero verifier");
        require(_outcomePublisher != address(0), "StrongN8Poll: zero publisher");
        require(_tau <= MAX_TAU, "StrongN8Poll: tau exceeds max");
        require(_votingDeadline > block.timestamp, "StrongN8Poll: deadline in past");
        require(_backendSetupHash != bytes32(0), "StrongN8Poll: zero setup hash");

        voteVerifier = IGroth16Verifier(_voteVerifier);
        registryRoot = _registryRoot;
        pollId = _pollId;
        tau = _tau;
        outcomePublisher = _outcomePublisher;
        votingDeadline = _votingDeadline;
        committeePK_X = _committeePK_X;
        committeePK_Y = _committeePK_Y;
        backendSetupHash = _backendSetupHash;

        POLL_DOMAIN = keccak256(
            abi.encode(
                PROTOCOL_TAG,
                block.chainid,
                address(this),
                _voteVerifier,
                _registryRoot,
                _pollId,
                _committeePK_X,
                _committeePK_Y,
                _backendSetupHash,
                _tau,
                N,
                L_VOTE,
                L_AGG
            )
        );

        accumulator = keccak256(abi.encode(BALLOT_SEED_V1, POLL_DOMAIN));
        phase = Phase.Open;
    }

    function submitBallot(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[37] calldata _pubSignals
    ) external onlyOpen {
        require(block.timestamp < votingDeadline, "StrongN8Poll: voting deadline passed");
        require(acceptedBallotCount < N, "StrongN8Poll: poll has reached N ballots");

        require(
            _pubSignals[SignalIndex.IDX_REGISTRY_ROOT] == registryRoot,
            "StrongN8Poll: wrong registry root"
        );
        require(
            _pubSignals[SignalIndex.IDX_POLL_ID] == pollId,
            "StrongN8Poll: wrong pollId"
        );
        require(
            _pubSignals[SignalIndex.IDX_PK_X] == committeePK_X,
            "StrongN8Poll: wrong PK.x"
        );
        require(
            _pubSignals[SignalIndex.IDX_PK_Y] == committeePK_Y,
            "StrongN8Poll: wrong PK.y"
        );

        for (uint256 k = 0; k < N; k++) {
            require(
                !(_pubSignals[SignalIndex.ctRx(k)] == 0 &&
                  _pubSignals[SignalIndex.ctRy(k)] == 1),
                "StrongN8Poll: CT R is identity"
            );
        }

        uint256 nullifier = _pubSignals[SignalIndex.IDX_NULLIFIER];
        require(!usedNullifiers[nullifier], "StrongN8Poll: duplicate nullifier");

        bool valid = voteVerifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        require(valid, "StrongN8Poll: invalid proof");

        usedNullifiers[nullifier] = true;

        uint256 ballotIndex = acceptedBallotCount;

        uint256[32] memory ciphertext;
        for (uint256 k = 0; k < N; k++) {
            uint256 base = 4 * k;
            ciphertext[base]     = _pubSignals[SignalIndex.ctRx(k)];
            ciphertext[base + 1] = _pubSignals[SignalIndex.ctRy(k)];
            ciphertext[base + 2] = _pubSignals[SignalIndex.ctSx(k)];
            ciphertext[base + 3] = _pubSignals[SignalIndex.ctSy(k)];
        }

        bytes32 leaf = keccak256(
            abi.encode(
                BALLOT_LEAF_V1,
                POLL_DOMAIN,
                ballotIndex,
                nullifier,
                ciphertext[0],  ciphertext[1],  ciphertext[2],  ciphertext[3],
                ciphertext[4],  ciphertext[5],  ciphertext[6],  ciphertext[7],
                ciphertext[8],  ciphertext[9],  ciphertext[10], ciphertext[11],
                ciphertext[12], ciphertext[13], ciphertext[14], ciphertext[15],
                ciphertext[16], ciphertext[17], ciphertext[18], ciphertext[19],
                ciphertext[20], ciphertext[21], ciphertext[22], ciphertext[23],
                ciphertext[24], ciphertext[25], ciphertext[26], ciphertext[27],
                ciphertext[28], ciphertext[29], ciphertext[30], ciphertext[31]
            )
        );

        bytes32 prevAccumulator = accumulator;
        accumulator = keccak256(
            abi.encode(BALLOT_NODE_V1, POLL_DOMAIN, prevAccumulator, leaf)
        );

        acceptedBallotCount += 1;

        emit BallotAccepted(ballotIndex, nullifier, ciphertext, leaf, accumulator);

        if (acceptedBallotCount == N) {
            ballotSetCommitment = keccak256(
                abi.encode(BALLOT_FINAL_V1, POLL_DOMAIN, uint256(N), accumulator)
            );
            phase = Phase.Sealed;
            emit BallotSetSealed(ballotSetCommitment);
        }
    }

    function abandon() external {
        require(phase == Phase.Open, "StrongN8Poll: not open");
        require(block.timestamp >= votingDeadline, "StrongN8Poll: deadline not reached");
        require(acceptedBallotCount < N, "StrongN8Poll: poll already filled");

        phase = Phase.Abandoned;
        emit PollAbandoned();
    }

    function publishOutcomeClaim(
        bytes32 _ballotSetCommitment,
        bytes32 _backendTranscriptHash,
        uint8 _b
    ) external onlySealed onlyOutcomePublisher {
        require(_ballotSetCommitment == ballotSetCommitment, "StrongN8Poll: wrong commitment");
        require(_backendTranscriptHash != bytes32(0), "StrongN8Poll: zero transcript");
        require(_b == 0 || _b == 1, "StrongN8Poll: invalid b");

        backendTranscriptHash = _backendTranscriptHash;
        outcomeBit = _b;
        phase = Phase.Claimed;

        emit OutcomeClaimPublished(ballotSetCommitment, _backendTranscriptHash, _b);
    }
}
