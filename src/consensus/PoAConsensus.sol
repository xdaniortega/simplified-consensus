// SPDX-License-Identifier: MIT
// pragma solidity ^0.8.20;

// import "../interfaces/IConsensus.sol";
// import "@openzeppelin/contracts/access/Ownable.sol";
// import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
//
// This implementation can be used for PoA consensus, but is commented to not affect coverage
// /**
//  * @title PoAConsensus
//  * @notice Authority-based consensus implementation using predefined authorities
//  * @dev Implements IConsensus interface with centralized authority approval
//  */
// contract PoAConsensus is IConsensus, Ownable, ReentrancyGuard {
    
//     // ==================== ERRORS ====================
    
//     error ProposalNotFound();
//     error ProposalAlreadyExists();
//     error InvalidProposalState();
//     error NotAnAuthority();
//     error AlreadyVoted();
//     error InvalidSignature();
//     error InvalidSignatureLength();
    
//     // ==================== STRUCTS ====================
    
//     struct ProposalData {
//         bytes32 proposalId;
//         string transaction;
//         address proposer;
//         uint256 blockNumber;
//         ProposalStatus status;
//         uint8 approvalCount;           // Number of authority approvals
//         address[] authorities;         // Authorities for this proposal
//     }
    
//     // ==================== STATE VARIABLES ====================
    
//     mapping(address => bool) public isAuthority;
//     mapping(bytes32 => ProposalData) public proposals;
//     mapping(bytes32 => mapping(address => bool)) public hasAuthorityVoted;
    
//     address[] public authorities;
//     uint256 public requiredApprovals = 1; // Default: single authority approval needed
//     bool public disputesEnabled = false;  // Authority consensus typically doesn't support disputes
    
//     // ==================== EVENTS ====================
    
//     event AuthorityAdded(address indexed authority);
//     event AuthorityRemoved(address indexed authority);
//     event RequiredApprovalsChanged(uint256 oldRequired, uint256 newRequired);
//     event AuthorityVoted(bytes32 indexed proposalId, address indexed authority, bool approved);
    
//     // ==================== CONSTRUCTOR ====================
    
//     constructor(address[] memory _authorities, uint256 _requiredApprovals) Ownable(msg.sender) {
//         require(_authorities.length > 0, "Must have at least one authority");
//         require(_requiredApprovals > 0 && _requiredApprovals <= _authorities.length, "Invalid required approvals");
        
//         for (uint256 i = 0; i < _authorities.length; i++) {
//             require(_authorities[i] != address(0), "Invalid authority address");
//             isAuthority[_authorities[i]] = true;
//             authorities.push(_authorities[i]);
//         }
        
//         requiredApprovals = _requiredApprovals;
//     }
    
//     // ==================== ICONSENSUS IMPLEMENTATION ====================
    
//     /**
//      * @dev Initialize consensus for a new proposal
//      */
//     function initializeConsensus(
//         bytes32 proposalId,
//         string calldata transaction,
//         address proposer
//     ) external nonReentrant returns (bool approved) {
//         if (proposals[proposalId].proposalId != bytes32(0)) revert ProposalAlreadyExists();
        
//         // Create proposal in pending state (authorities need to approve)
//         proposals[proposalId] = ProposalData({
//             proposalId: proposalId,
//             transaction: transaction,
//             proposer: proposer,
//             blockNumber: block.number,
//             status: ProposalStatus.Pending,
//             approvalCount: 0,
//             authorities: authorities // Copy current authorities
//         });
        
//         emit ProposalInitialized(proposalId, proposer);
        
//         // Authority consensus requires explicit approval
//         return false;
//     }
    
    
//     /**
//      * @dev Finalize a proposal and return the result
//      */
//     function finalizeProposal(bytes32 proposalId) external nonReentrant returns (bool approved) {
//         ProposalData storage proposal = proposals[proposalId];
//         if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
//         if (proposal.status != ProposalStatus.Pending) revert InvalidProposalState();
        
//         if (proposal.approvalCount >= requiredApprovals) {
//             proposal.status = ProposalStatus.Approved;
//             approved = true;
//         } else {
//             proposal.status = ProposalStatus.Rejected;
//             approved = false;
//         }
        
//         emit ProposalFinalized(proposalId, approved);
//         return approved;
//     }
    
//     // ==================== VALIDATOR FUNCTIONS ====================
    
//     /**
//      * @dev Get current validators (authorities in this case)
//      */
//     function getValidators() external view returns (address[] memory validators) {
//         return authorities;
//     }
    
//     /**
//      * @dev Get validator count (authority count)
//      */
//     function getValidatorCount() external view returns (uint256 count) {
//         return authorities.length;
//     }
    
//     // ==================== CHALLENGE/DISPUTE FUNCTIONS ====================
    
//     /**
//      * @dev Check if a proposal can be challenged (not supported in Authority consensus)
//      */
//     function canChallengeProposal(bytes32 proposalId) external pure returns (bool canChallenge) {
//         return false; // Authority consensus doesn't support challenges
//     }
    
//     /**
//      * @dev Submit a challenge against a proposal (not supported)
//      */
//     function challengeProposal(bytes32 proposalId, address challenger) external pure {
//         revert("Challenges not supported in Authority consensus");
//     }
    
//     /**
//      * @dev Submit a vote on a challenged proposal (not supported)
//      */
//     function submitVote(
//         bytes32 proposalId,
//         address voter,
//         bool support,
//         bytes calldata signature
//     ) external pure {
//         revert("Voting not supported in Authority consensus");
//     }
    
//     // ==================== AUTHORITY APPROVAL ====================
    
//     /**
//      * @dev Authority approves or rejects a proposal
//      * @param proposalId Proposal identifier
//      * @param approved Whether the authority approves the proposal
//      */
//     function authorityVote(bytes32 proposalId, bool approved) external {
//         ProposalData storage proposal = proposals[proposalId];
//         if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
//         if (proposal.status != ProposalStatus.Pending) revert InvalidProposalState();
//         if (!isAuthority[msg.sender]) revert NotAnAuthority();
//         if (hasAuthorityVoted[proposalId][msg.sender]) revert AlreadyVoted();
        
//         hasAuthorityVoted[proposalId][msg.sender] = true;
        
//         if (approved) {
//             proposal.approvalCount++;
            
//             // Auto-finalize if we have enough approvals
//             if (proposal.approvalCount >= requiredApprovals) {
//                 proposal.status = ProposalStatus.Approved;
//                 emit ProposalFinalized(proposalId, true);
//             }
//         }
        
//         emit AuthorityVoted(proposalId, msg.sender, approved);
//     }
    
//     // ==================== INFO FUNCTIONS ====================
    
//     /**
//      * @dev Get consensus type identifier
//      */
//     function getConsensusType() external pure returns (string memory consensusType) {
//         return "Authority";
//     }
    
//     /**
//      * @dev Check if consensus supports challenges/disputes
//      */
//     function supportsDisputes() external pure returns (bool) {
//         return false; // Authority consensus doesn't support disputes
//     }
    
//     // ==================== ADMIN FUNCTIONS ====================
    
//     /**
//      * @dev Add a new authority
//      * @param authority Address to add as authority
//      */
//     function addAuthority(address authority) external onlyOwner {
//         require(authority != address(0), "Invalid authority address");
//         require(!isAuthority[authority], "Already an authority");
        
//         isAuthority[authority] = true;
//         authorities.push(authority);
        
//         emit AuthorityAdded(authority);
//     }
    
//     /**
//      * @dev Remove an authority
//      * @param authority Address to remove from authorities
//      */
//     function removeAuthority(address authority) external onlyOwner {
//         require(isAuthority[authority], "Not an authority");
//         require(authorities.length > requiredApprovals, "Cannot remove authority: would fall below required approvals");
        
//         isAuthority[authority] = false;
        
//         // Remove from authorities array
//         for (uint256 i = 0; i < authorities.length; i++) {
//             if (authorities[i] == authority) {
//                 authorities[i] = authorities[authorities.length - 1];
//                 authorities.pop();
//                 break;
//             }
//         }
        
//         emit AuthorityRemoved(authority);
//     }
    
//     /**
//      * @dev Set required number of approvals
//      * @param _requiredApprovals New required approvals count
//      */
//     function setRequiredApprovals(uint256 _requiredApprovals) external onlyOwner {
//         require(_requiredApprovals > 0 && _requiredApprovals <= authorities.length, "Invalid required approvals");
        
//         uint256 oldRequired = requiredApprovals;
//         requiredApprovals = _requiredApprovals;
        
//         emit RequiredApprovalsChanged(oldRequired, _requiredApprovals);
//     }
    
//     // ==================== VIEW FUNCTIONS ====================
    
//     /**
//      * @dev Get proposal information
//      */
//     function getProposal(bytes32 proposalId) 
//         external 
//         view 
//         returns (
//             string memory transaction,
//             address proposer,
//             uint256 blockNumber,
//             ProposalStatus status,
//             uint256 signatureCount,
//             address[] memory selectedValidators
//         ) 
//     {
//         ProposalData memory proposal = proposals[proposalId];
//         return (
//             proposal.transaction,
//             proposal.proposer,
//             proposal.blockNumber,
//             proposal.status,
//             proposal.approvalCount, // Use approvalCount as signatureCount for PoA
//             proposal.authorities
//         );
//     }
    
//     /**
//      * @dev Check if authority has voted on a proposal
//      * @param proposalId Proposal identifier
//      * @param authority Authority address
//      * @return voted Whether the authority has voted
//      */
//     function hasVoted(bytes32 proposalId, address authority) external view returns (bool voted) {
//         return hasAuthorityVoted[proposalId][authority];
//     }
    
//     /**
//      * @dev Get all authorities
//      * @return All authority addresses
//      */
//     function getAllAuthorities() external view returns (address[] memory) {
//         return authorities;
//     }
// } 