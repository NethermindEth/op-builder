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

type SuaveAPI struct {
	b            *eth.Ethereum
	beaconClient *OpBeaconClient
	stop         chan struct{}

	slotMu    sync.Mutex
	slotAttrs types.BuilderPayloadAttributes
}

func NewSuaveAPI(stack *node.Node, b *eth.Ethereum, config *Config) *SuaveAPI {
	client := NewOpBeaconClient(config.BeaconEndpoint)
	return &SuaveAPI{
		b:            b,
		beaconClient: client,
		stop:         make(chan struct{}, 1),
	}
}

func (api *SuaveAPI) Start() error {
	log.Info("starting Suave api")
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
						log.Error("error with processing on payload attribute",
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

func (api *SuaveAPI) Stop() error {
	close(api.stop)
	return nil
}

func (api *SuaveAPI) OnPayloadAttribute(attrs *types.BuilderPayloadAttributes) error {
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

func (api *SuaveAPI) getCurrentDepositTxs() (types.Transactions, error) {
	api.slotMu.Lock()
	defer api.slotMu.Unlock()

	return api.slotAttrs.Transactions, nil
}

func (api *SuaveAPI) BuildEthBlock(ctx context.Context, buildArgs *types.BuildBlockArgs, txs types.Transactions) (*engine.ExecutionPayloadEnvelope, error) {
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

	block, profit, err := api.b.APIBackend.BuildBlockFromTxs(ctx, buildArgs, txs)
	if err != nil {
		return nil, err
	}

	return engine.BlockToExecutableData(block, profit), nil
}

func (api *SuaveAPI) BuildEthBlockFromBundles(ctx context.Context, buildArgs *types.BuildBlockArgs, bundles []types.SBundleFromSuave) (*engine.ExecutionPayloadEnvelope, error) {
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
	log.Info("BuildEthBlockFromBundles", "buildArgs", buildArgs, "bundles", bundles)

	for _, bundle := range bundles {
		for _, tx := range bundle.Txs {
			log.Info("Transaction dump", "tx", tx)
		}
	}

	block, profit, err := api.b.APIBackend.BuildBlockFromBundles(ctx, buildArgs, bundles)
	if err != nil {
		return nil, err
	}

	return engine.BlockToExecutableData(block, profit), nil
}

func Register(stack *node.Node, backend *eth.Ethereum, cfg *Config) error {
	suaveService := NewSuaveAPI(stack, backend, cfg)

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace:     "suavex",
			Version:       "1.0",
			Service:       suaveService,
			Public:        true,
			Authenticated: false, // DEMO ONLY
		},
	})

	stack.RegisterLifecycle(suaveService)
	return nil
}
