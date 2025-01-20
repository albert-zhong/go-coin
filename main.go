package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
)

func main() {
	if err := testGenesisBlock(); err != nil {
		log.Fatal(err)
	}
}

func testGenesisBlock() error {
	emptyChain := NewChain(nil)
	node := NewNode(emptyChain)

	alicePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	bobPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// alice gives the mining reward to herself
	coinbaseTransaction, err := NewTransaction(
		&TransactionBody{
			InputTransactionHashes: nil,
			NextOwner:              &alicePriv.PublicKey,
			InputValue:             MiningReward,
			Change:                 0,
			Fee:                    0,
		},
		nil,
		true,
	)
	if err != nil {
		return err
	}
	// alice gives 5 coins to bob
	transaction, err := NewTransaction(
		&TransactionBody{
			InputTransactionHashes: [][]byte{
				coinbaseTransaction.BodyHash,
			},
			NextOwner:  &bobPriv.PublicKey,
			InputValue: 10,
			Change:     5,
			Fee:        0,
		},
		[]*ecdsa.PrivateKey{
			alicePriv,
		},
		false,
	)
	if err != nil {
		return err
	}

	// create genesis block with the two transactions
	blockBody := &BlockBody{
		Version:  CurrentVersion,
		Id:       0,
		PrevHash: nil,
		Transactions: []*Transaction{
			coinbaseTransaction,
			transaction,
		},
	}
	block, err := node.Mine(blockBody)
	if err != nil {
		return err
	}
	block.Print()
	return nil
}
