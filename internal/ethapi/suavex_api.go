package ethapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/r3labs/sse"
)

type PubkeyHex string

type OpBeaconClient struct {
	ctx      context.Context
	cancelFn context.CancelFunc

	endpoint string
}

func NewOpBeaconClient(endpoint string) *OpBeaconClient {
	ctx, cancelFn := context.WithCancel(context.Background())
	return &OpBeaconClient{
		ctx:      ctx,
		cancelFn: cancelFn,

		endpoint: endpoint,
	}
}

func (opbc *OpBeaconClient) SubscribeToPayloadAttributesEvents(payloadAttrC chan types.BuilderPayloadAttributes) {
	eventsURL := fmt.Sprintf("%s/events", opbc.endpoint)
	log.Info("subscribing to payload_attributes events opbs")

	for {
		client := sse.NewClient(eventsURL)
		err := client.SubscribeWithContext(opbc.ctx, "payload_attributes", func(msg *sse.Event) {
			data := new(types.BuilderPayloadAttributes)
			err := json.Unmarshal(msg.Data, data)
			if err != nil {
				log.Error("could not unmarshal payload_attributes event", "err", err)
			} else {
				payloadAttrC <- *data
			}
		})
		if err != nil {
			log.Error("failed to subscribe to payload_attributes events", "err", err)
			time.Sleep(1 * time.Second)
		}
		log.Warn("opnode Subscribe ended, reconnecting")
	}
}

func (opbc *OpBeaconClient) Start() error {
	return nil
}

func (opbc *OpBeaconClient) Stop() {
	opbc.cancelFn()
}

type SuavexAPI struct {
	b            Backend
	chain        *core.BlockChain
	beaconClient *OpBeaconClient
	stop         chan struct{}

	slotMu    sync.Mutex
	slotAttrs types.BuilderPayloadAttributes
}

func NewSuavexAPI(b Backend, chain *core.BlockChain, endpoint string) *SuavexAPI {
	client := NewOpBeaconClient(endpoint)
	return &SuavexAPI{
		b:            b,
		chain:        chain,
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

	parentBlock := api.chain.GetBlockByHash(attrs.HeadHash)
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
		head := api.b.CurrentHeader()
		buildArgs = &types.BuildBlockArgs{
			Parent:       head.Hash(),
			Timestamp:    head.Time + uint64(12),
			FeeRecipient: common.Address{0x42},
			GasLimit:     30000000,
			Random:       head.Root,
			Withdrawals:  nil,
		}
	}

	depositTxs, err := api.getCurrentDepositTxs()
	if err != nil {
		return nil, err
	}

	buildArgs.Transactions = depositTxs
	block, profit, err := api.b.BuildBlockFromTxs(ctx, buildArgs, txs)
	if err != nil {
		return nil, err
	}

	return engine.BlockToExecutableData(block, profit), nil
}

func (api *SuavexAPI) BuildEthBlockFromBundles(ctx context.Context, buildArgs *types.BuildBlockArgs, bundles []types.SBundle) (*engine.ExecutionPayloadEnvelope, error) {
	if buildArgs == nil {
		head := api.b.CurrentHeader()
		buildArgs = &types.BuildBlockArgs{
			Parent:       head.Hash(),
			Timestamp:    head.Time + uint64(12),
			FeeRecipient: common.Address{0x42},
			GasLimit:     30000000,
			Random:       head.Root,
			Withdrawals:  nil,
		}
	}

	depositTxs, err := api.getCurrentDepositTxs()
	if err != nil {
		return nil, err
	}

	buildArgs.Transactions = depositTxs
	block, profit, err := api.b.BuildBlockFromBundles(ctx, buildArgs, bundles)
	if err != nil {
		return nil, err
	}

	return engine.BlockToExecutableData(block, profit), nil
}
