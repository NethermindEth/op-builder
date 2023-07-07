package miner

import (
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// / To use it:
// / 1. Copy relevant data from the worker
// / 2. Call buildBlock
// / 2. If new bundles, txs arrive, call buildBlock again
// / This struct lifecycle is tied to 1 block-building task
type greedyBucketsBuilder struct {
	inputEnvironment *environment
	chainData        chainData
	builderKey       *ecdsa.PrivateKey
	interrupt        *int32
	gasUsedMap       map[*types.TxWithMinerFee]uint64
	algoConf         algorithmConfig
}

func newGreedyBucketsBuilder(
	chain *core.BlockChain, chainConfig *params.ChainConfig, algoConf *algorithmConfig,
	blacklist map[common.Address]struct{}, env *environment, key *ecdsa.PrivateKey, interrupt *int32,
) *greedyBucketsBuilder {
	if algoConf == nil {
		algoConf = &algorithmConfig{
			EnforceProfit:          true,
			ExpectedProfit:         nil,
			ProfitThresholdPercent: defaultProfitThreshold,
		}
	}
	return &greedyBucketsBuilder{
		inputEnvironment: env,
		chainData:        chainData{chainConfig: chainConfig, chain: chain, blacklist: blacklist},
		builderKey:       key,
		interrupt:        interrupt,
		gasUsedMap:       make(map[*types.TxWithMinerFee]uint64),
		algoConf:         *algoConf,
	}
}

// CutoffPriceFromOrder returns the cutoff price for a given order based on the cutoff percent.
// For example, if the cutoff percent is 90, the cutoff price will be 90% of the order price, rounded down to the nearest integer.
func CutoffPriceFromOrder(order *types.TxWithMinerFee, cutoffPercent int) *big.Int {
	return common.PercentOf(order.Price(), cutoffPercent)
}

// IsOrderInPriceRange returns true if the order price is greater than or equal to the minPrice.
func IsOrderInPriceRange(order *types.TxWithMinerFee, minPrice *big.Int) bool {
	return order.Price().Cmp(minPrice) >= 0
}

func (b *greedyBucketsBuilder) commit(envDiff *environmentDiff,
	transactions []*types.TxWithMinerFee,
	orders *types.TransactionsByPriceAndNonce,
	gasUsedMap map[*types.TxWithMinerFee]uint64, retryMap map[*types.TxWithMinerFee]int, retryLimit int,
) ([]types.SimulatedBundle, []types.UsedSBundle) {
	var (
		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle
		algoConf     = b.algoConf

		CheckRetryOrderAndReinsert = func(
			order *types.TxWithMinerFee, orders *types.TransactionsByPriceAndNonce,
			retryMap map[*types.TxWithMinerFee]int, retryLimit int,
		) bool {
			var isRetryable bool = false
			if retryCount, exists := retryMap[order]; exists {
				if retryCount != retryLimit {
					isRetryable = true
					retryMap[order] = retryCount + 1
				}
			} else {
				retryMap[order] = 0
				isRetryable = true
			}

			if isRetryable {
				orders.Push(order)
			}

			return isRetryable
		}
	)

	for _, order := range transactions {
		if tx := order.Tx(); tx != nil {
			receipt, skip, err := envDiff.commitTx(tx, b.chainData)
			if err != nil {
				log.Error("could not apply tx", "hash", tx.Hash(), "err", err)

				// attempt to retry transaction commit up to retryLimit
				// the gas used is set for the order to re-calculate profit of the transaction for subsequent retries
				if receipt != nil {
					// if the receipt is nil we don't attempt to retry the transaction - this is to mitigate abuse since
					// without a receipt the default profit calculation for a transaction uses the gas limit which
					// can cause the transaction to always be first in any profit-sorted transaction list
					gasUsedMap[order] = receipt.GasUsed
					CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
				}
				continue
			}

			if skip == shiftTx {
				orders.ShiftAndPushByAccountForTx(tx)
			}

			effGapPrice, err := tx.EffectiveGasTip(envDiff.baseEnvironment.header.BaseFee)
			if err == nil {
				log.Trace("Included tx", "EGP", effGapPrice.String(), "gasUsed", receipt.GasUsed)
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err := envDiff.commitBundle(bundle, b.chainData, b.interrupt, algoConf)
			if err != nil {
				log.Error("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)

				var e *lowProfitError
				if errors.As(err, &e) {
					if e.ActualEffectiveGasPrice != nil {
						order.SetPrice(e.ActualEffectiveGasPrice)
					}

					if e.ActualProfit != nil {
						order.SetProfit(e.ActualProfit)
					}
					// if the bundle was not included due to low profit, we can retry the bundle
					CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
				}
				continue
			}

			log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(),
				"gasUsed", bundle.TotalGasUsed, "ethToCoinbase", ethIntToFloat(bundle.TotalEth))
			usedBundles = append(usedBundles, *bundle)
		} else if sbundle := order.SBundle(); sbundle != nil {
			usedEntry := types.UsedSBundle{
				Bundle: sbundle.Bundle,
			}
			err := envDiff.commitSBundle(sbundle, b.chainData, b.interrupt, b.builderKey, algoConf)
			if err != nil {
				log.Error("Could not apply sbundle", "bundle", sbundle.Bundle.Hash(), "err", err)

				var e *lowProfitError
				if errors.As(err, &e) {
					if e.ActualEffectiveGasPrice != nil {
						order.SetPrice(e.ActualEffectiveGasPrice)
					}

					if e.ActualProfit != nil {
						order.SetProfit(e.ActualProfit)
					}

					// if the sbundle was not included due to low profit, we can retry the bundle
					if ok := CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit); !ok {
						usedEntry.Success = false
						usedSbundles = append(usedSbundles, usedEntry)
					}
				}
				continue
			}

			log.Trace("Included sbundle", "bundleEGP", sbundle.MevGasPrice.String(), "ethToCoinbase", ethIntToFloat(sbundle.Profit))
			usedEntry.Success = true
			usedSbundles = append(usedSbundles, usedEntry)
		} else {
			// note: this should never happen because we should not be inserting invalid transaction types into
			// the orders heap
			panic("unsupported order type found")
		}
	}
	return usedBundles, usedSbundles
}

func (b *greedyBucketsBuilder) mergeOrdersIntoEnvDiff(
	envDiff *environmentDiff, orders *types.TransactionsByPriceAndNonce) ([]types.SimulatedBundle, []types.UsedSBundle,
) {
	if orders.Peek() == nil {
		return nil, nil
	}

	const retryLimit = 1

	var (
		SortInPlaceByProfit = func(baseFee *big.Int, transactions []*types.TxWithMinerFee, gasUsedMap map[*types.TxWithMinerFee]uint64) {
			sort.SliceStable(transactions, func(i, j int) bool {
				return transactions[i].Profit(baseFee, gasUsedMap[transactions[i]]).Cmp(transactions[j].Profit(baseFee, gasUsedMap[transactions[j]])) > 0
			})
		}

		baseFee            = envDiff.baseEnvironment.header.BaseFee
		retryMap           = make(map[*types.TxWithMinerFee]int)
		usedBundles        []types.SimulatedBundle
		usedSbundles       []types.UsedSBundle
		transactions       []*types.TxWithMinerFee
		priceCutoffPercent = b.algoConf.PriceCutoffPercent
	)

	minPrice := CutoffPriceFromOrder(orders.Peek(), priceCutoffPercent)
	for {
		order := orders.Peek()
		if order == nil {
			if len(transactions) != 0 {
				SortInPlaceByProfit(baseFee, transactions, b.gasUsedMap)
				bundles, sbundles := b.commit(envDiff, transactions, orders, b.gasUsedMap, retryMap, retryLimit)
				usedBundles = append(usedBundles, bundles...)
				usedSbundles = append(usedSbundles, sbundles...)
				transactions = nil
				// re-run since committing transactions may have pushed higher nonce transactions, or previously
				// failed transactions back into orders heap
				continue
			}
			break
		}

		if ok := IsOrderInPriceRange(order, minPrice); ok {
			orders.Pop()
			transactions = append(transactions, order)
		} else {
			if len(transactions) != 0 {
				SortInPlaceByProfit(baseFee, transactions, b.gasUsedMap)
				bundles, sbundles := b.commit(envDiff, transactions, orders, b.gasUsedMap, retryMap, retryLimit)
				usedBundles = append(usedBundles, bundles...)
				usedSbundles = append(usedSbundles, sbundles...)
				transactions = nil
			}
			minPrice = CutoffPriceFromOrder(order, priceCutoffPercent)
		}
	}

	return usedBundles, usedSbundles
}

func (b *greedyBucketsBuilder) buildBlock(
	simBundles []types.SimulatedBundle, simSBundles []*types.SimSBundle,
	transactions map[common.Address]types.Transactions) (*environment, []types.SimulatedBundle, []types.UsedSBundle) {

	//orders := types.NewTransactionsByPriceAndNonce(b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee)
	//envDiff := newEnvironmentDiff(b.inputEnvironment.copy())
	//usedBundles, usedSbundles := b.mergeOrdersIntoEnvDiff(envDiff, orders)
	//envDiff.applyToBaseEnv()
	//return envDiff.baseEnvironment, usedBundles, usedSbundles
	var (
		orders = types.NewTransactionsByPriceAndNonce(
			b.inputEnvironment.signer, transactions, simBundles, simSBundles, b.inputEnvironment.header.BaseFee,
		)

		algoConf = b.algoConf
		//root     = b.inputEnvironment.state.OriginalRoot()

		usedBundles  []types.SimulatedBundle
		usedSbundles []types.UsedSBundle
	)

	//sdb, err := b.chainData.chain.StateAt(root)
	//if err != nil {
	//	log.Error("Failed to initialize state from header parent", "err", err, "root", root.Hex())
	//	panic(err)
	//}
	//sdb.StartPrefetcher("algo")
	sdb := b.inputEnvironment.state.Copy()
	sdb.StartPrefetcher("algo")

	//envDiff := newEnvironmentDiff(b.inputEnvironment.copy())
	//envDiff := &environmentDiff{
	//	baseEnvironment: b.inputEnvironment.copy(),
	//	header:          types.CopyHeader(b.inputEnvironment.header),
	//	gasPool:         new(core.GasPool).AddGas(b.inputEnvironment.gasPool.Gas()),
	//	state:           sdb,
	//	newProfit:       new(big.Int),
	//}
	env := &environment{
		signer:    b.inputEnvironment.signer,
		state:     b.inputEnvironment.state,
		ancestors: b.inputEnvironment.ancestors.Clone(),
		family:    b.inputEnvironment.family.Clone(),
		tcount:    b.inputEnvironment.tcount,
		coinbase:  b.inputEnvironment.coinbase,
		profit:    new(big.Int).Set(b.inputEnvironment.profit),
		header:    types.CopyHeader(b.inputEnvironment.header),
		receipts:  copyReceipts(b.inputEnvironment.receipts),
		gasPool:   new(core.GasPool).AddGas(b.inputEnvironment.gasPool.Gas()),
	}
	env.txs = make([]*types.Transaction, len(b.inputEnvironment.txs))
	copy(env.txs, b.inputEnvironment.txs)
	env.uncles = make(map[common.Hash]*types.Header, len(b.inputEnvironment.uncles))
	for hash, uncle := range b.inputEnvironment.uncles {
		env.uncles[hash] = uncle
	}

	envDiff := &environmentDiff{
		baseEnvironment: env,
		header:          types.CopyHeader(b.inputEnvironment.header),
		gasPool:         new(core.GasPool).AddGas(b.inputEnvironment.gasPool.Gas()),
		state:           sdb,
		newProfit:       new(big.Int),
	}

	if orders.Peek() == nil {
		return envDiff.baseEnvironment, nil, nil
	}

	const retryLimit = 1

	var (
		coinbase = envDiff.baseEnvironment.coinbase

		CheckRetryOrderAndReinsert = func(
			order *types.TxWithMinerFee, orders *types.TransactionsByPriceAndNonce,
			retryMap map[*types.TxWithMinerFee]int, retryLimit int,
		) bool {
			var isRetryable bool = false
			if retryCount, exists := retryMap[order]; exists {
				if retryCount != retryLimit {
					isRetryable = true
					retryMap[order] = retryCount + 1
				}
			} else {
				retryMap[order] = 0
				isRetryable = true
			}

			if isRetryable {
				orders.Push(order)
			}

			return isRetryable
		}

		Apply = func(
			config *params.ChainConfig, bc core.ChainContext, author common.Address,
			gp *core.GasPool, statedb *state.StateDB, header *types.Header,
			tx *types.Transaction, gasUsed uint64, vmConf *vm.Config, preFinalizeHook func() error,
		) (cumulativeGas uint64, gasPool *core.GasPool, receipt *types.Receipt, err error) {

			msg, err := core.TransactionToMessage(tx, types.MakeSigner(config, header.Number), header.BaseFee)
			if err != nil {
				return cumulativeGas, gasPool, receipt, err
			}

			// Create a new context to be used in the EVM environment
			blockContext := core.NewEVMBlockContext(header, bc, &author)
			txContext := core.NewEVMTxContext(msg)
			vmenv := vm.NewEVM(blockContext, txContext, statedb, config, *vmConf)
			gasPool = new(core.GasPool).AddGas(gp.Gas())

			result, err := core.NewStateTransition(vmenv, msg, gasPool).TransitionDb()
			if err != nil {
				return cumulativeGas, gasPool, receipt, err
			}

			if preFinalizeHook != nil {
				if err := preFinalizeHook(); err != nil {
					return cumulativeGas, gasPool, receipt, err
				}
			}

			cumulativeGas = gasUsed + result.UsedGas
			// Create a new receipt for the transaction, storing the intermediate root and gas used
			// by the tx.
			receipt = &types.Receipt{Type: tx.Type(), PostState: make([]byte, 0), CumulativeGasUsed: cumulativeGas}
			if result.Failed() {
				receipt.Status = types.ReceiptStatusFailed
			} else {
				receipt.Status = types.ReceiptStatusSuccessful
			}
			receipt.TxHash = tx.Hash()
			receipt.GasUsed = result.UsedGas

			// If the transaction created a contract, store the creation address in the receipt.
			if msg.To == nil {
				receipt.ContractAddress = crypto.CreateAddress(vmenv.TxContext.Origin, tx.Nonce())
			}

			var (
				blockNumber = header.Number
				blockHash   = header.Hash()
			)
			// Set the receipt logs and create the bloom filter.
			receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
			receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
			receipt.BlockHash = blockHash
			receipt.BlockNumber = blockNumber
			receipt.TransactionIndex = uint(statedb.TxIndex())
			return cumulativeGas, gasPool, receipt, err
		}

		DetermineTxOp = func(signer types.Signer, tx *types.Transaction,
			receipt *types.Receipt, err error) int {
			if err != nil {
				from, _ := types.Sender(signer, tx)
				switch {
				case errors.Is(err, core.ErrGasLimitReached):
					// Pop the current out-of-gas transaction without shifting in the next from the account
					log.Trace("Gas limit exceeded for current block", "sender", from)
					return popTx

				case errors.Is(err, core.ErrNonceTooLow):
					// New head notification data race between the transaction pool and miner, shift
					log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
					return shiftTx

				case errors.Is(err, core.ErrNonceTooHigh):
					// Reorg notification data race between the transaction pool and miner, skip account =
					log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
					return popTx

				case errors.Is(err, core.ErrTxTypeNotSupported):
					// Pop the unsupported transaction without shifting in the next from the account
					log.Trace("Skipping unsupported transaction type", "sender", from, "type", tx.Type())
					return popTx

				default:
					// Strange error, discard the transaction and get the next in line (note, the
					// nonce-too-high clause will prevent us from executing in vain).
					log.Trace("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
					return shiftTx
				}
			}

			return shiftTx
		}

		CommitTx = func(envDiff *environmentDiff, tx *types.Transaction, chData chainData, coinbase common.Address) (
			cumulativeGas uint64,
			gasPool *core.GasPool,
			receipt *types.Receipt,
			profit *big.Int,
			err error,
		) {

			var (
				header = types.CopyHeader(envDiff.header)
				//signer    = envDiff.baseEnvironment.signer
				statedb = envDiff.state
				vmConf  = chData.chain.GetVMConfig()
				gasUsed = header.GasUsed
				//blacklist = make(map[common.Address]struct{})
			)
			//if chData.blacklist != nil {
			//	for k, v := range chData.blacklist {
			//		blacklist[k] = v
			//	}
			//}

			gasPool = new(core.GasPool).AddGas(envDiff.gasPool.Gas())
			gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
			if err != nil {
				return cumulativeGas, gasPool, receipt, profit, err
			}

			statedb.SetTxContext(tx.Hash(), envDiff.baseEnvironment.tcount+len(envDiff.newTxs))

			//if len(blacklist) == 0 {
			//	cumulativeGas, gasPool, receipt, err = Apply(
			//		chData.chainConfig, chData.chain,
			//		coinbase, gasPool, statedb, header, tx, gasUsed, vmConf, nil)
			//	if receipt != nil {
			//		profit = new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(receipt.GasUsed))
			//	}
			//	return cumulativeGas, gasPool, receipt, profit, err
			//}

			//sender, err := types.Sender(signer, tx)
			//if err != nil {
			//	return cumulativeGas, gasPool, receipt, profit, err
			//}
			//
			//if _, in := blacklist[sender]; in {
			//	return cumulativeGas, gasPool, receipt, profit, errors.New("blacklist violation, tx.sender")
			//}
			//
			//if to := tx.To(); to != nil {
			//	if _, in := blacklist[*to]; in {
			//		return cumulativeGas, gasPool, receipt, profit, errors.New("blacklist violation, tx.to")
			//	}
			//}

			// we set precompile to nil, but they are set in the validation code
			// there will be no difference in the result if precompile is not it the blocklist
			//touchTracer := logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, nil)
			//vmConf.Tracer = touchTracer
			//vmConf.Debug = true
			//
			//hook := func() error {
			//	for _, accessTuple := range touchTracer.AccessList() {
			//		if _, in := blacklist[accessTuple.Address]; in {
			//			return errors.New("blacklist violation, tx trace")
			//		}
			//	}
			//	return nil
			//}

			//cumulativeGas, gasPool, receipt, err = Apply(
			//	chData.chainConfig, chData.chain,
			//	coinbase, gasPool, statedb, header, tx, gasUsed, vmConf, hook)

			cumulativeGas, gasPool, receipt, err = Apply(
				chData.chainConfig, chData.chain,
				coinbase, gasPool, statedb, header, tx, gasUsed, vmConf, nil)

			if receipt != nil {
				profit = new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(receipt.GasUsed))
			}
			return cumulativeGas, gasPool, receipt, profit, err
		}

		CommitBundle = func(
			envDiff *environmentDiff, coinbase common.Address, bundle *types.SimulatedBundle,
			chData chainData, interrupt *int32, algoConf algorithmConfig) (*big.Int, error) {
			var (
				tmpEnvDiff = &environmentDiff{
					baseEnvironment: envDiff.baseEnvironment,
					header:          types.CopyHeader(envDiff.header),
					gasPool:         new(core.GasPool).AddGas(envDiff.gasPool.Gas()),
					state:           envDiff.state,
					newProfit:       new(big.Int).Set(envDiff.newProfit),
					newTxs:          envDiff.newTxs[:],
					newReceipts:     envDiff.newReceipts[:],
				}
				coinbaseBalanceBefore = tmpEnvDiff.state.GetBalance(coinbase)

				profitBefore  = new(big.Int).Set(tmpEnvDiff.newProfit)
				txProfitTally = new(big.Int)
				gasUsed       uint64
				bundleErr     error
			)

			for _, tx := range bundle.OriginalBundle.Txs {
				if tmpEnvDiff.header.BaseFee != nil && tx.Type() == types.DynamicFeeTxType {
					// Sanity check for extremely large numbers
					if tx.GasFeeCap().BitLen() > 256 {
						bundleErr = core.ErrFeeCapVeryHigh
						break
					}
					if tx.GasTipCap().BitLen() > 256 {
						bundleErr = core.ErrTipVeryHigh
						break
					}
					// Ensure gasFeeCap is greater than or equal to gasTipCap.
					if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
						bundleErr = core.ErrTipAboveFeeCap
						break
					}
				}

				if tx.Value().Sign() == -1 {
					bundleErr = core.ErrNegativeValue
					break
				}

				_, err := tx.EffectiveGasTip(envDiff.header.BaseFee)
				if err != nil {
					bundleErr = err
					break
				}

				_, err = types.Sender(envDiff.baseEnvironment.signer, tx)
				if err != nil {
					bundleErr = err
					break
				}

				if checkInterrupt(interrupt) {
					bundleErr = errInterrupt
					break
				}

				cumulativeGas, gp, receipt, profit, err := CommitTx(tmpEnvDiff, tx, chData, coinbase)

				if err != nil {
					bundleErr = err
					break
				}

				if receipt.Status != types.ReceiptStatusSuccessful && !bundle.OriginalBundle.RevertingHash(tx.Hash()) {
					bundleErr = errors.New("bundle tx revert")
					break
				}

				txProfitTally.Add(txProfitTally, profit)
				tmpEnvDiff.gasPool.SetGas(gp.Gas())
				tmpEnvDiff.header.GasUsed = cumulativeGas
				tmpEnvDiff.newTxs = append(tmpEnvDiff.newTxs, tx)
				tmpEnvDiff.newReceipts = append(tmpEnvDiff.newReceipts, receipt)
				gasUsed += receipt.GasUsed
			}

			if bundleErr != nil {
				return txProfitTally, bundleErr
			}

			coinbaseBalanceAfter := tmpEnvDiff.state.GetBalance(coinbase)
			coinbaseBalanceDelta := new(big.Int).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
			tmpEnvDiff.newProfit.Add(profitBefore, coinbaseBalanceDelta)

			bundleProfit := coinbaseBalanceDelta

			bundleActualEffGP := bundleProfit.Div(bundleProfit, big.NewInt(int64(gasUsed)))
			bundleSimEffGP := new(big.Int).Set(bundle.MevGasPrice)

			// allow >-1% divergence
			actualEGP := new(big.Int).Mul(bundleActualEffGP, common.Big100)  // bundle actual effective gas price * 100
			simulatedEGP := new(big.Int).Mul(bundleSimEffGP, big.NewInt(90)) // bundle simulated effective gas price * 90

			if simulatedEGP.Cmp(actualEGP) > 0 {
				log.Trace("Bundle underpays after inclusion", "bundle", bundle.OriginalBundle.Hash)

				return txProfitTally, &lowProfitError{
					ExpectedEffectiveGasPrice: bundleSimEffGP,
					ActualEffectiveGasPrice:   bundleActualEffGP,
				}
			}

			if algoConf.EnforceProfit {
				// if profit is enforced between simulation and actual commit, only allow ProfitThresholdPercent divergence
				simulatedBundleProfit := new(big.Int).Set(bundle.TotalEth)
				actualBundleProfit := new(big.Int).Mul(bundleActualEffGP, big.NewInt(int64(gasUsed)))

				// We want to make simulated profit smaller to allow for some leeway in cases where the actual profit is
				// lower due to transaction ordering
				simulatedProfitMultiple := new(big.Int).Mul(simulatedBundleProfit, algoConf.ProfitThresholdPercent)
				actualProfitMultiple := new(big.Int).Mul(actualBundleProfit, common.Big100)

				if simulatedProfitMultiple.Cmp(actualProfitMultiple) > 0 {
					log.Trace("Lower bundle profit found after inclusion", "bundle", bundle.OriginalBundle.Hash)
					return txProfitTally, &lowProfitError{
						ExpectedProfit: simulatedBundleProfit,
						ActualProfit:   actualBundleProfit,
					}
				}
			}

			*envDiff = *tmpEnvDiff
			return txProfitTally, nil
		}

		Commit = func(envDiff *environmentDiff,
			txs []*types.TxWithMinerFee, orders *types.TransactionsByPriceAndNonce,
			gasUsedMap map[*types.TxWithMinerFee]uint64, retryMap map[*types.TxWithMinerFee]int, retryLimit int) {

			for _, order := range txs {
				if tx := order.Tx(); tx != nil {
					snap := envDiff.state.Snapshot()
					cumulativeGas, gasPool, receipt, profit, err := CommitTx(envDiff, tx, b.chainData, coinbase)
					skip := DetermineTxOp(envDiff.baseEnvironment.signer, tx, receipt, err)
					if err != nil {
						envDiff.state.RevertToSnapshot(snap)
						if receipt != nil {
							gasUsedMap[order] = receipt.GasUsed
							CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
						}
						continue
					}

					if skip == shiftTx {
						orders.ShiftAndPushByAccountForTx(tx)
					}

					envDiff.header.GasUsed = cumulativeGas
					envDiff.gasPool.SetGas(gasPool.Gas())
					envDiff.newProfit = envDiff.newProfit.Add(envDiff.newProfit, profit)
					envDiff.newTxs = append(envDiff.newTxs, tx)
					envDiff.newReceipts = append(envDiff.newReceipts, receipt)
					envDiff.state.Finalise(true)
				} else if bundle := order.Bundle(); bundle != nil {
					snap := envDiff.state.Snapshot()
					_, err := CommitBundle(envDiff, coinbase, bundle, b.chainData, b.interrupt, algoConf)
					if err != nil {
						log.Trace("error committing bundle",
							"err", err, "snap", snap, "bundle", bundle.OriginalBundle.Hash.Hex(),
							"txs", len(bundle.OriginalBundle.Txs), "gas-used", envDiff.header.GasUsed)
						var e *lowProfitError
						if errors.As(err, &e) {
							if e.ActualEffectiveGasPrice != nil {
								order.SetPrice(e.ActualEffectiveGasPrice)
							}

							if e.ActualProfit != nil {
								order.SetProfit(e.ActualProfit)
							}
							CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit)
						} else {
							envDiff.state.RevertToSnapshot(snap)
						}
						continue
					}

					usedBundles = append(usedBundles, *bundle)
					envDiff.state.Finalise(true)
				} else if sbundle := order.SBundle(); sbundle != nil {
					usedEntry := types.UsedSBundle{
						Bundle: sbundle.Bundle,
					}
					err := envDiff.commitSBundle(sbundle, b.chainData, b.interrupt, b.builderKey, algoConf)
					if err != nil {
						var e *lowProfitError
						if errors.As(err, &e) {
							if e.ActualEffectiveGasPrice != nil {
								order.SetPrice(e.ActualEffectiveGasPrice)
							}

							if e.ActualProfit != nil {
								order.SetProfit(e.ActualProfit)
							}

							if ok := CheckRetryOrderAndReinsert(order, orders, retryMap, retryLimit); !ok {
								usedEntry.Success = false
								usedSbundles = append(usedSbundles, usedEntry)
							}
						} else {
							usedEntry.Success = false
							usedSbundles = append(usedSbundles, usedEntry)
						}
						continue
					}

					usedEntry.Success = true
					usedSbundles = append(usedSbundles, usedEntry)
				} else {
					// note: this should never happen because we should not be inserting invalid transaction types into
					// the orders heap
					panic("unsupported order type found")
				}
			}
		}

		SortInPlaceByProfit = func(baseFee *big.Int, transactions []*types.TxWithMinerFee, gasUsedMap map[*types.TxWithMinerFee]uint64) {
			sort.SliceStable(transactions, func(i, j int) bool {
				return transactions[i].Profit(baseFee, gasUsedMap[transactions[i]]).Cmp(transactions[j].Profit(baseFee, gasUsedMap[transactions[j]])) > 0
			})
		}

		baseFee            = envDiff.baseEnvironment.header.BaseFee
		priceCutoffPercent = b.algoConf.PriceCutoffPercent
		retryMap           = make(map[*types.TxWithMinerFee]int)
		txs                []*types.TxWithMinerFee
	)

	minPrice := CutoffPriceFromOrder(orders.Peek(), priceCutoffPercent)
	for {
		order := orders.Peek()
		if order == nil {
			if len(txs) != 0 {
				SortInPlaceByProfit(baseFee, txs, b.gasUsedMap)
				Commit(envDiff, txs, orders, b.gasUsedMap, retryMap, retryLimit)
				//bundles, sbundles := b.commit(envDiff, txs, orders, b.gasUsedMap, retryMap, retryLimit)
				//usedBundles = append(usedBundles, bundles...)
				//usedSbundles = append(usedSbundles, sbundles...)
				txs = nil
				// re-run since committing transactions may have pushed higher nonce transactions, or previously
				// failed transactions back into orders heap
				continue
			}
			break
		}

		if ok := IsOrderInPriceRange(order, minPrice); ok {
			orders.Pop()
			txs = append(txs, order)
		} else {
			if len(txs) != 0 {
				SortInPlaceByProfit(baseFee, txs, b.gasUsedMap)
				Commit(envDiff, txs, orders, b.gasUsedMap, retryMap, retryLimit)
				//bundles, sbundles := b.commit(envDiff, txs, orders, b.gasUsedMap, retryMap, retryLimit)
				//usedBundles = append(usedBundles, bundles...)
				//usedSbundles = append(usedSbundles, sbundles...)
				txs = nil
			}
			minPrice = CutoffPriceFromOrder(order, priceCutoffPercent)
		}
	}
	envDiff.applyToBaseEnv()
	return envDiff.baseEnvironment, usedBundles, usedSbundles
}
