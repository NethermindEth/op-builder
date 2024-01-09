package suave

import (
	"context"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
)

type SuavexAPI struct {
	b            *eth.Ethereum
	beaconClient *OpBeaconClient
	stop         chan struct{}

	slotMu    sync.Mutex
	slotAttrs types.BuilderPayloadAttributes
}

func NewSuavexAPI(stack *node.Node, b *eth.Ethereum, config *Config) *SuavexAPI {
	client := NewOpBeaconClient(config.BeaconEndpoint)
	return &SuavexAPI{
		b:            b,
		beaconClient: client,
		stop:         make(chan struct{}, 1),
	}
}

func (api *SuavexAPI) Start() error {
	go func() {
		c := make(chan types.BuilderPayloadAttributes)
		go api.beaconClient.SubscribeToPayloadAttributesEvents(c)

		currentSlot := uint64(0)

		for {
			select {
			case <-api.stop:
				return
			case payloadAttributes := <-c:
				log.Info("received payload attributes", "slot", payloadAttributes.Slot, "headHash", payloadAttributes.HeadHash.String())
				// Right now we are building only on a single head. This might change in the future!
				if payloadAttributes.Slot <= currentSlot {
					continue
				} else if payloadAttributes.Slot > currentSlot {
					currentSlot = payloadAttributes.Slot
					err := api.OnPayloadAttribute(&payloadAttributes)
					if err != nil {
						log.Error("error with builder processing on payload attribute",
							"latestSlot", currentSlot,
							"processedSlot", payloadAttributes.Slot,
							"headHash", payloadAttributes.HeadHash.String(),
							"error", err)
					}
				}
			}
		}

	}()
	return api.beaconClient.Start()
}

func (api *SuavexAPI) Stop() error {
	close(api.stop)
	return nil
}

func (api *SuavexAPI) OnPayloadAttribute(attrs *types.BuilderPayloadAttributes) error {
	log.Info("OnPayloadAttribute", "attrs", attrs)
	parentBlock := api.b.BlockChain().GetBlockByHash(attrs.HeadHash)

	if parentBlock == nil {
		return fmt.Errorf("could not find parent block with hash %s", attrs.HeadHash)
	}

	api.slotMu.Lock()
	defer api.slotMu.Unlock()

	api.slotAttrs = *attrs
	return nil
}

func (api *SuavexAPI) getCurrentDepositTxs() (types.Transactions, error) {
	api.slotMu.Lock()
	defer api.slotMu.Unlock()

	return api.slotAttrs.Transactions, nil
}

func (api *SuavexAPI) BuildEthBlock(ctx context.Context, buildArgs *types.BuildBlockArgs, txs types.Transactions) (*engine.ExecutionPayloadEnvelope, error) {
	if buildArgs == nil {
		buildArgs = &types.BuildBlockArgs{
			Slot:         api.slotAttrs.Slot,
			Parent:       api.slotAttrs.HeadHash,
			Timestamp:    uint64(api.slotAttrs.Timestamp),
			FeeRecipient: api.slotAttrs.SuggestedFeeRecipient,
			GasLimit:     api.slotAttrs.GasLimit,
			Random:       api.slotAttrs.Random,
			Withdrawals:  api.slotAttrs.Withdrawals,
			Transactions: api.slotAttrs.Transactions,
		}
	}

	block, profit, err := api.b.APIBackend.BuildBlockFromTxs(ctx, buildArgs, txs)
	if err != nil {
		return nil, err
	}

	return engine.BlockToExecutableData(block, profit), nil
}

func (api *SuavexAPI) BuildEthBlockFromBundles(ctx context.Context, buildArgs *types.BuildBlockArgs, bundles []types.SBundle) (*engine.ExecutionPayloadEnvelope, error) {
	if buildArgs == nil {
		buildArgs = &types.BuildBlockArgs{
			Slot:         api.slotAttrs.Slot,
			Parent:       api.slotAttrs.HeadHash,
			Timestamp:    uint64(api.slotAttrs.Timestamp),
			FeeRecipient: api.slotAttrs.SuggestedFeeRecipient,
			GasLimit:     api.slotAttrs.GasLimit,
			Random:       api.slotAttrs.Random,
			Withdrawals:  api.slotAttrs.Withdrawals,
			Transactions: api.slotAttrs.Transactions,
		}
	}

	block, profit, err := api.b.APIBackend.BuildBlockFromBundles(ctx, buildArgs, bundles)
	if err != nil {
		return nil, err
	}

	return engine.BlockToExecutableData(block, profit), nil
}

func Register(stack *node.Node, backend *eth.Ethereum, cfg *Config) error {
	suaveService := NewSuavexAPI(stack, backend, cfg)

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace:     "suave",
			Version:       "1.0",
			Service:       suaveService,
			Public:        true,
			Authenticated: false, // DEMO ONLY
		},
	})

	stack.RegisterLifecycle(suaveService)
	return nil
}
