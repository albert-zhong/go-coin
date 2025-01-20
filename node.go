package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/bits"
	"time"
)

const (
	GenesisId uint32 = 0

	MinimumRequiredLeadingZeros = 1
	MiningReward                = 10
)

type Node struct {
	Chain *Chain
}

func NewNode(chain *Chain) *Node {
	return &Node{
		Chain: chain,
	}
}

// Mine a new block.
// Inductive hypothesis: existing chain is valid.
func (n *Node) Mine(newBody *BlockBody) (*Block, error) {
	newBlock, err := NewBlock(newBody)
	if err != nil {
		return nil, err
	}
	if err = verifyExceptNonce(n.Chain.Blocks, newBlock); err != nil {
		return nil, err
	}
	var nonce uint32 = 0
	for {
		if err = newBlock.SetFields(nonce, time.Now()); err != nil {
			return nil, err
		}
		if !nonceIsValid(newBlock) {
			nonce++
			if nonce == 0 {
				// handle integer overflow
				return nil, fmt.Errorf("new block %s has no valid nonces", newBlock.String())
			}
			continue
		}
		break

	}
	return newBlock, nil
}

func nonceIsValid(block *Block) bool {
	return leadingZeros(block.BodyHash) >= MinimumRequiredLeadingZeros
}

func leadingZeros(data []byte) int {
	count := 0
	for _, b := range data {
		if b == 0 {
			count += 8
		} else {
			count += bits.LeadingZeros8(b)
			break
		}
	}
	return count
}

func verifyExceptNonce(blocks []*Block, newBlock *Block) error {
	if newBlock.Body.Version != CurrentVersion {
		return fmt.Errorf("new block %s has invalid version %d, want %d", newBlock.String(), newBlock.Body.Version, CurrentVersion)
	}
	if len(blocks) > 0 {
		headBlock := blocks[len(blocks)-1]
		if newBlock.Body.Id != headBlock.Body.Id+1 {
			return fmt.Errorf("new block %s has invalid id %d, want %d", newBlock.String(), newBlock.String(), headBlock.Body.Id+1)
		}
		if !bytes.Equal(newBlock.Body.PrevHash, headBlock.BodyHash) {
			return fmt.Errorf("new block %s has invalid prev hash %s, not equal to head block hash %s", newBlock.String(), string(newBlock.Body.PrevHash), string(headBlock.BodyHash))
		}
		if !newBlock.Body.Time.After(headBlock.Body.Time) {
			return fmt.Errorf("new block %s has invalid timestamp %s, not after head block timestamp %s", newBlock.String(), newBlock.Body.Time, headBlock.Body.Time)
		}
	} else {
		if newBlock.Body.Id != GenesisId {
			return fmt.Errorf("new block %s is genesis block, want id %d", newBlock.String(), GenesisId)
		}
	}

	now := time.Now()
	if newBlock.Body.Time.After(now) {
		return fmt.Errorf("new block %s has invalid timestamp %s, not before or equal to now %s", newBlock.String(), newBlock.Body.Time, now)
	}

	if len(newBlock.Body.Transactions) == 0 {
		return fmt.Errorf("new block %s contains no transactions", newBlock.String())
	}

	allTransactions := make(map[string]*Transaction)
	for _, block := range blocks {
		for _, transaction := range block.Body.Transactions {
			allTransactions[transaction.String()] = transaction
		}
	}
	coinBaseTransaction := newBlock.Body.Transactions[0]
	allTransactions[coinBaseTransaction.String()] = coinBaseTransaction
	var newBlockFees uint32

	// Verify non-coinbase transactions
	for _, transaction := range newBlock.Body.Transactions[1:] {
		if len(transaction.Body.InputTransactionHashes) != len(transaction.OwnerSignatures) {
			return fmt.Errorf("new block %s txn %s has %d input txns != %d owner signatures", newBlock.String(), transaction.String(), len(transaction.Body.InputTransactionHashes), len(transaction.OwnerSignatures))
		}
		var expectedInputValue uint32
		for i, inputTransactionHash := range transaction.Body.InputTransactionHashes {
			inputTransaction, ok := allTransactions[hex.EncodeToString(inputTransactionHash)]
			if !ok {
				return fmt.Errorf("new block %s txn %s references input txn %s that does not exist", newBlock.String(), hex.EncodeToString(inputTransactionHash), transaction.String())
			}
			inputOwnerSignature := transaction.OwnerSignatures[i]
			if !ecdsa.Verify(inputTransaction.Body.NextOwner, transaction.BodyHash, inputOwnerSignature.R, inputOwnerSignature.S) {
				return fmt.Errorf("new block %s txn %s contains invalid signature", newBlock.String(), transaction.String())
			}
			expectedInputValue += inputTransaction.OutputValue()
		}
		if expectedInputValue != transaction.Body.InputValue {
			return fmt.Errorf("new block %s txn %s has unexpected input value %d, want %d", newBlock.String(), transaction.String(), transaction.Body.InputValue, expectedInputValue)
		}
		if transaction.Body.InputValue < transaction.Body.Change+transaction.Body.Fee {
			return fmt.Errorf("new block %s txn %s has input value %d less than change + fee %d", newBlock.String(), transaction.String(), transaction.Body.InputValue, transaction.Body.Change+transaction.Body.Fee)
		}
		// transaction is now valid
		allTransactions[transaction.String()] = transaction
		newBlockFees += transaction.Body.Fee
	}

	// Verify coinbase transaction
	if coinBaseTransaction.Body.InputValue != newBlockFees+MiningReward {
		return fmt.Errorf("new block %s coinbase txn has input value %d, expected %d", newBlock.String(), coinBaseTransaction.Body.InputValue, newBlockFees+MiningReward)
	}

	return nil
}
