package types

import (
	"encoding/json"
	"errors"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"golang.org/x/crypto/sha3"
)

var (
	ErrIncorrectRefundConfig = errors.New("incorrect refund config")
)

// SBundle is a bundle of transactions that must be executed atomically
// unlike ordinary bundle it also supports refunds
type SBundle struct {
	Inclusion BundleInclusion
	Body      []BundleBody
	Validity  BundleValidity

	hash atomic.Value
}

type RpcSBundle struct {
	BlockNumber     *hexutil.Big    `json:"blockNumber,omitempty"`
	MaxBlock        *hexutil.Big    `json:"maxBlock,omitempty"`
	Txs             []hexutil.Bytes `json:"txs"`
	RevertingHashes []common.Hash   `json:"revertingHashes,omitempty"`
	RefundPercent   *int            `json:"percent,omitempty"`
}

type SBundleFromSuave struct {
	BlockNumber     *big.Int      `json:"blockNumber,omitempty"` // if BlockNumber is set it must match DecryptionCondition!
	MaxBlock        *big.Int      `json:"maxBlock,omitempty"`
	Txs             Transactions  `json:"txs"`
	RevertingHashes []common.Hash `json:"revertingHashes,omitempty"`
	RefundPercent   *int          `json:"percent,omitempty"`
}

func (s *SBundleFromSuave) MarshalJSON() ([]byte, error) {
	txs := []hexutil.Bytes{}
	for _, tx := range s.Txs {
		txBytes, err := tx.MarshalBinary()
		if err != nil {
			return nil, err
		}
		txs = append(txs, txBytes)
	}

	var blockNumber *hexutil.Big
	if s.BlockNumber != nil {
		blockNumber = new(hexutil.Big)
		*blockNumber = hexutil.Big(*s.BlockNumber)
	}

	return json.Marshal(&RpcSBundle{
		BlockNumber:     blockNumber,
		Txs:             txs,
		RevertingHashes: s.RevertingHashes,
		RefundPercent:   s.RefundPercent,
	})
}

func (s *SBundleFromSuave) UnmarshalJSON(data []byte) error {
	var rpcSBundle RpcSBundle
	if err := json.Unmarshal(data, &rpcSBundle); err != nil {
		return err
	}

	var txs Transactions
	for _, txBytes := range rpcSBundle.Txs {
		var tx Transaction
		err := tx.UnmarshalBinary(txBytes)
		if err != nil {
			return err
		}

		txs = append(txs, &tx)
	}

	s.BlockNumber = (*big.Int)(rpcSBundle.BlockNumber)
	s.MaxBlock = (*big.Int)(rpcSBundle.MaxBlock)
	s.Txs = txs
	s.RevertingHashes = rpcSBundle.RevertingHashes
	s.RefundPercent = rpcSBundle.RefundPercent

	return nil
}

type BundleInclusion struct {
	BlockNumber    uint64
	MaxBlockNumber uint64
}

type BundleBody struct {
	Tx        *Transaction
	Bundle    *SBundle
	CanRevert bool
}

type BundleValidity struct {
	Refund       []RefundConstraint `json:"refund,omitempty"`
	RefundConfig []RefundConfig     `json:"refundConfig,omitempty"`
}

type RefundConstraint struct {
	BodyIdx int `json:"bodyIdx"`
	Percent int `json:"percent"`
}

type RefundConfig struct {
	Address common.Address `json:"address"`
	Percent int            `json:"percent"`
}

type BundlePrivacy struct {
	RefundAddress common.Address
}

func (b *SBundle) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}

	bodyHashes := make([]common.Hash, len(b.Body))
	for i, body := range b.Body {
		if body.Tx != nil {
			bodyHashes[i] = body.Tx.Hash()
		} else if body.Bundle != nil {
			bodyHashes[i] = body.Bundle.Hash()
		}
	}

	var h common.Hash
	if len(bodyHashes) == 1 {
		h = bodyHashes[0]
	} else {
		hasher := sha3.NewLegacyKeccak256()
		for _, h := range bodyHashes {
			hasher.Write(h[:])
		}
		h = common.BytesToHash(hasher.Sum(nil))
	}
	b.hash.Store(h)
	return h
}

func (b *SBundle) Txs() Transactions {
	txs := make(Transactions, len(b.Body))
	for i, body := range b.Body {
		txs[i] = body.Tx
	}
	return txs
}

func (b *SBundle) RefundPercent() *int {
	if (len(b.Validity.RefundConfig)) == 0 {
		return nil
	}
	return &b.Validity.RefundConfig[0].Percent
}

type SimSBundle struct {
	Bundle *SBundle
	// MevGasPrice = (total coinbase profit) / (gas used)
	MevGasPrice *big.Int
	Profit      *big.Int
}

func GetRefundConfig(body *BundleBody, signer Signer) ([]RefundConfig, error) {
	if body.Tx != nil {
		address, err := signer.Sender(body.Tx)
		if err != nil {
			return nil, err
		}
		return []RefundConfig{{Address: address, Percent: 100}}, nil
	}
	if bundle := body.Bundle; bundle != nil {
		if len(bundle.Validity.RefundConfig) > 0 {
			return bundle.Validity.RefundConfig, nil
		} else {
			if len(bundle.Body) == 0 {
				return nil, ErrIncorrectRefundConfig
			}
			return GetRefundConfig(&bundle.Body[0], signer)
		}
	}
	return nil, ErrIncorrectRefundConfig
}

// UsedSBundle is a bundle that was used in the block building
type UsedSBundle struct {
	Bundle  *SBundle
	Success bool
}
