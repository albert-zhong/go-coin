package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
)

const (
	CurrentVersion = 1
)

type Chain struct {
	Blocks []*Block
}

func NewChain(blocks []*Block) *Chain {
	return &Chain{
		Blocks: blocks,
	}
}

type Block struct {
	Body     *BlockBody
	BodyHash []byte

	bodyStaticHash []byte
}

func NewBlock(body *BlockBody) (*Block, error) {
	bodyStaticHash, err := body.staticHash()
	if err != nil {
		return nil, err
	}
	bodyHash, err := calculateBodyHash(bodyStaticHash, body.Nonce, body.Time)
	if err != nil {
		return nil, err
	}
	block := &Block{
		Body:           body,
		BodyHash:       bodyHash,
		bodyStaticHash: bodyStaticHash,
	}
	return block, nil
}

func (b *Block) SetFields(nonce uint32, time time.Time) error {
	b.Body.Nonce = nonce
	b.Body.Time = time
	bodyHash, err := calculateBodyHash(b.bodyStaticHash, b.Body.Nonce, b.Body.Time)
	if err != nil {
		return err
	}
	b.BodyHash = bodyHash
	return nil
}

func (b *Block) String() string {
	return hex.EncodeToString(b.BodyHash)
}

/*
	Version      uint32
	Id           uint32
	PrevHash     []byte
	Transactions []*Transaction

	// non-static fields
	Nonce uint32
	Time  time.Time
*/

func (b *Block) Print() {
	fmt.Printf("block %s\n", hex.EncodeToString(b.BodyHash))
	fmt.Printf("  id %d\n", b.Body.Id)
	fmt.Printf("  prev hash %s\n", hex.EncodeToString(b.Body.PrevHash))
	fmt.Printf("  nonce %d\n", b.Body.Nonce)
	fmt.Printf("  time %s\n", b.Body.Time)
	fmt.Printf("  %d txns\n", len(b.Body.Transactions))
	for _, transaction := range b.Body.Transactions {
		fmt.Printf("    txn %s\n", hex.EncodeToString(transaction.BodyHash))
		var inputTransactionHashStrings []string
		for _, inputTransactionHash := range transaction.Body.InputTransactionHashes {
			inputTransactionHashStrings = append(inputTransactionHashStrings, hex.EncodeToString(inputTransactionHash))
		}
		nextOwnerString := hex.EncodeToString(elliptic.MarshalCompressed(transaction.Body.NextOwner.Curve, transaction.Body.NextOwner.X, transaction.Body.NextOwner.Y))
		fmt.Printf("      input txns [ %s ]\n", strings.Join(inputTransactionHashStrings, " "))
		fmt.Printf("      next owner %s\n", nextOwnerString)
		fmt.Printf("      input value %d\n", transaction.Body.InputValue)
		fmt.Printf("      change %d\n", transaction.Body.Change)
		fmt.Printf("      fee %d\n", transaction.Body.Fee)
	}
}

type BlockBody struct {
	Version      uint32
	Id           uint32
	PrevHash     []byte
	Transactions []*Transaction

	// non-static fields
	Nonce uint32
	Time  time.Time
}

func calculateBodyHash(bodyStaticHash []byte, nonce uint32, time time.Time) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(bodyStaticHash); err != nil {
		return nil, err
	}
	if err := binary.Write(h, binary.LittleEndian, nonce); err != nil {
		return nil, err
	}
	timeText, err := time.MarshalText()
	if err != nil {
		return nil, err
	}
	if _, err := h.Write(timeText); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (b *BlockBody) staticHash() ([]byte, error) {
	h := sha256.New()
	if err := binary.Write(h, binary.LittleEndian, b.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(h, binary.LittleEndian, b.Id); err != nil {
		return nil, err
	}
	if _, err := h.Write(b.PrevHash); err != nil {
		return nil, err
	}
	for _, transaction := range b.Transactions {
		if _, err := h.Write(transaction.BodyHash); err != nil {
			return nil, err
		}
	}
	// skip non-static fields (nonce, time)
	return h.Sum(nil), nil
}

type Transaction struct {
	Body            *TransactionBody
	BodyHash        []byte
	OwnerSignatures []OwnerSignature

	isCoinbase bool
}

func NewTransaction(body *TransactionBody, privs []*ecdsa.PrivateKey, isCoinbase bool) (*Transaction, error) {
	bodyHash, err := body.hash()
	if err != nil {
		return nil, err
	}
	ownerSignatures := make([]OwnerSignature, 0, len(privs))
	for _, priv := range privs {
		r, s, err := ecdsa.Sign(rand.Reader, priv, bodyHash)
		if err != nil {
			return nil, err
		}
		ownerSignature := OwnerSignature{
			R: r,
			S: s,
		}
		ownerSignatures = append(ownerSignatures, ownerSignature)
	}
	transaction := &Transaction{
		Body:            body,
		BodyHash:        bodyHash,
		OwnerSignatures: ownerSignatures,
		isCoinbase:      isCoinbase,
	}
	return transaction, nil
}

func (t *Transaction) String() string {
	return hex.EncodeToString(t.BodyHash)
}

type TransactionBody struct {
	InputTransactionHashes [][]byte
	NextOwner              *ecdsa.PublicKey
	InputValue             uint32
	Change                 uint32
	Fee                    uint32
}

func (t *TransactionBody) hash() ([]byte, error) {
	h := sha256.New()
	for _, inputTransactionHash := range t.InputTransactionHashes {
		if _, err := h.Write(inputTransactionHash); err != nil {
			return nil, err
		}
	}
	if _, err := h.Write(elliptic.MarshalCompressed(t.NextOwner.Curve, t.NextOwner.X, t.NextOwner.Y)); err != nil {
		return nil, err
	}
	if err := binary.Write(h, binary.LittleEndian, t.InputValue); err != nil {
		return nil, err
	}
	if err := binary.Write(h, binary.LittleEndian, t.Change); err != nil {
		return nil, err
	}
	if err := binary.Write(h, binary.LittleEndian, t.Fee); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (t *Transaction) OutputValue() uint32 {
	if !t.isCoinbase {
		return t.Body.InputValue - t.Body.Change - t.Body.Fee
	}
	return t.Body.InputValue
}

type OwnerSignature struct {
	R *big.Int
	S *big.Int
}
