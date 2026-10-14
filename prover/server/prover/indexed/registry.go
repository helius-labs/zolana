package indexed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	ring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
	"github.com/helius-labs/zolana/prover/server/prover/transcript"
)

type RegistryRequest struct {
	Ring      string `json:"ringProgramId"`
	Root      Hash   `json:"root"`
	NextIndex uint64 `json:"nextIndex"`
}

func prepareRegistry(p *ring.PolicyParams, request *RegistryRequest) error {
	if p.KeyEscrow != (request != nil) {
		return fmt.Errorf("invalid registry request")
	}
	for _, output := range p.Outputs {
		if output.Key != nil {
			return fmt.Errorf("prepared output contains registry witness")
		}
	}
	if !p.KeyEscrow {
		return nil
	}
	return validateRegistryAnchor(p.KeyRegistryRoot, request)
}

func validateRegistryAnchor(root ring.Field, request *RegistryRequest) error {
	if request == nil {
		return fmt.Errorf("missing registry anchor")
	}
	if _, err := decodeHash(request.Ring); err != nil {
		return err
	}
	anchor, err := request.Root.field()
	if err != nil || request.NextIndex < 1 || request.NextIndex > 1<<registry.Height {
		return fmt.Errorf("invalid registry anchor")
	}
	if root.Int == nil || anchor.Cmp(root.Int) != 0 {
		return fmt.Errorf("registry root mismatch")
	}
	return nil
}

var errMemberUnregistered = errors.New("registry member missing")

type UnregisteredMemberError struct {
	Member   Hash
	mismatch bool
}

func (e *UnregisteredMemberError) Error() string {
	return fmt.Sprintf("registry member %s missing", e.Member)
}

type registryEntry struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Root       Hash   `json:"root"`
	Member     Hash   `json:"member"`
	Next       Hash   `json:"next"`
	NextIndex  uint64 `json:"nextIndex"`
	Index      uint64 `json:"index"`
	Ciphertext []byte `json:"ciphertext"`
	Proof      []Hash `json:"proof"`
}

func (r *Resolver) resolvePolicyRegistry(ctx context.Context, request Request, p *ring.PolicyParams) error {
	if request.Registry == nil {
		return nil
	}
	keys := make(map[Hash]*ring.RegistryKey)
	for i := range p.Outputs {
		output := &p.Outputs[i]
		if i >= int(p.NOut) || output.Domain.Cmp(big.NewInt(shared.UtxoDomain)) != 0 {
			continue
		}
		owner, err := transcript.HashFields([]*big.Int{output.OwnerPkHash.Int, output.NullifierPk.Int})
		if err != nil {
			return err
		}
		if owner.Cmp(p.NamespaceOwnerHash.Int) == 0 {
			continue
		}
		if output.Key, err = r.registryKey(ctx, request, keys, output.OwnerPkHash.Int, output.NullifierPk.Int); err != nil {
			return err
		}
	}
	return nil
}

func (r *Resolver) registryKey(ctx context.Context, request Request, keys map[Hash]*ring.RegistryKey, owner, nullifier *big.Int) (*ring.RegistryKey, error) {
	anchor := request.Registry
	member, err := hashField(owner)
	if err != nil || owner.Sign() == 0 {
		return nil, fmt.Errorf("invalid registry owner")
	}
	// 2. The membership leaf binds both the owner and its expected nullifier key.
	if known := keys[member]; known != nil {
		if verifyRegistryKey(member, nullifier, known, anchor.Root) != nil {
			return nil, &UnregisteredMemberError{Member: member, mismatch: true}
		}
		return known, nil
	}
	payload, err := r.rpc(ctx, "getRingKeyRegistryEntry", map[string]any{"ringProgramId": anchor.Ring, "member": member, "expectedRoot": anchor.Root, "expectedNextIndex": anchor.NextIndex})
	if errors.Is(err, errMemberUnregistered) {
		return nil, &UnregisteredMemberError{Member: member}
	}
	if err != nil {
		return nil, err
	}
	var entry registryEntry
	if json.Unmarshal(payload, &entry) != nil || entry.Root != anchor.Root || entry.Member != member || entry.NextIndex != anchor.NextIndex || entry.Index == 0 || entry.Index >= entry.NextIndex || len(entry.Proof) != registry.Height || len(entry.Ciphertext) != 32 {
		return nil, fmt.Errorf("invalid registry membership")
	}
	next, err := entry.Next.field()
	if err != nil {
		return nil, err
	}
	ciphertext, err := transcript.HashFields([]*big.Int{new(big.Int).SetBytes(entry.Ciphertext[:31]), new(big.Int).SetBytes(entry.Ciphertext[31:])})
	if err != nil {
		return nil, err
	}
	key := &ring.RegistryKey{Next: ring.Field{Int: next}, CtHash: ring.Field{Int: ciphertext}, Index: entry.Index, Path: hashFields(entry.Proof)}
	// A corrupt indexer path is indistinguishable from a key mismatch here.
	if verifyRegistryKey(member, nullifier, key, anchor.Root) != nil {
		return nil, &UnregisteredMemberError{Member: member, mismatch: true}
	}
	if entry.Context.Slot < request.MinContextSlot {
		return nil, ErrIndexerNotReady
	}
	keys[member] = key
	return key, nil
}

func verifyRegistryKey(member Hash, nullifier *big.Int, key *ring.RegistryKey, root Hash) error {
	keyHash, err := transcript.HashFields([]*big.Int{nullifier, key.CtHash.Int})
	if err != nil {
		return err
	}
	owner, err := member.field()
	if err != nil {
		return err
	}
	leaf, err := transcript.HashFields([]*big.Int{owner, key.Next.Int, keyHash})
	if err != nil {
		return err
	}
	hash, err := hashField(leaf)
	if err != nil {
		return err
	}
	path := make([]Hash, registry.Height)
	for level, sibling := range key.Path {
		path[level], err = hashField(sibling.Int)
		if err != nil {
			return err
		}
	}
	return verifyPath(hash, path, key.Index, root)
}
