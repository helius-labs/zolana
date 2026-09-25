package indexed

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/custom_rings/circuits/registry"
	"zolana/prover/prover/common"
	ring "zolana/prover/prover/custom_ring"
	"zolana/prover/prover/transcript"
)

type RegistryRequest struct {
	Ring      string `json:"ringProgramId"`
	Root      Hash   `json:"root"`
	NextIndex uint64 `json:"nextIndex"`
}

func prepareRegistry(base map[string]json.RawMessage, request *RegistryRequest) error {
	var enabled bool
	if json.Unmarshal(base["keyEscrow"], &enabled) != nil || enabled != (request != nil) {
		return fmt.Errorf("invalid registry request")
	}
	var outputs []map[string]json.RawMessage
	if json.Unmarshal(base["outputs"], &outputs) != nil {
		return fmt.Errorf("invalid policy outputs")
	}
	for _, output := range outputs {
		if output == nil || output["key"] != nil {
			return fmt.Errorf("prepared output contains registry witness")
		}
	}
	if !enabled {
		return nil
	}
	if _, err := decodeHash(request.Ring); err != nil {
		return err
	}
	root, err := request.Root.field()
	if err != nil || request.NextIndex < 1 || request.NextIndex > 1<<registry.Height {
		return fmt.Errorf("invalid registry anchor")
	}
	var encoded string
	if json.Unmarshal(base["keyRegistryRoot"], &encoded) != nil {
		return fmt.Errorf("invalid registry root")
	}
	expected, err := common.FeFromHex(encoded)
	if err != nil || root.Cmp(expected) != 0 {
		return fmt.Errorf("registry root mismatch")
	}
	zero := common.ToHex(new(big.Int))
	path := make([]string, registry.Height)
	for i := range path {
		path[i] = zero
	}
	// 1. Registry placeholders remain internal until membership is verified.
	for _, output := range outputs {
		output["key"], _ = json.Marshal(map[string]any{"next": zero, "ctHash": zero, "index": 0, "path": path})
	}
	base["outputs"], _ = json.Marshal(outputs)
	return nil
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

func (r *Resolver) resolvePolicyRegistry(ctx context.Context, request Request, policy *resolvedPolicy) error {
	if request.Registry == nil {
		return nil
	}
	anchor := request.Registry
	keys := make(map[Hash]*ring.RegistryKey)
	for i := range policy.base.Outputs {
		output := &policy.base.Outputs[i]
		output.Key = nil
		if i >= int(policy.base.NOut) || output.Domain.Cmp(big.NewInt(shared.UtxoDomain)) != 0 {
			continue
		}
		owner, err := transcript.HashFields([]*big.Int{output.OwnerPkHash, output.NullifierPk})
		if err != nil {
			return err
		}
		if owner.Cmp(policy.base.NamespaceOwnerHash) == 0 {
			continue
		}
		member, err := hashField(output.OwnerPkHash)
		if err != nil || output.OwnerPkHash.Sign() == 0 {
			return fmt.Errorf("invalid registry owner")
		}
		// 2. The membership leaf binds both the owner and its expected nullifier key.
		if known := keys[member]; known != nil {
			if err := verifyRegistryKey(member, output.NullifierPk, known, anchor.Root); err != nil {
				return err
			}
			output.Key = known
			continue
		}
		payload, err := r.rpc(ctx, "getRingKeyRegistryEntry", map[string]any{"ringProgramId": anchor.Ring, "member": member, "expectedRoot": anchor.Root, "expectedNextIndex": anchor.NextIndex})
		if err != nil {
			return err
		}
		var entry registryEntry
		if json.Unmarshal(payload, &entry) != nil || entry.Context.Slot < request.MinContextSlot || entry.Root != anchor.Root || entry.Member != member || entry.NextIndex != anchor.NextIndex || entry.Index == 0 || entry.Index >= entry.NextIndex || len(entry.Proof) != registry.Height || len(entry.Ciphertext) != 32 {
			return fmt.Errorf("invalid registry membership")
		}
		next, err := entry.Next.field()
		if err != nil {
			return err
		}
		ciphertext, err := transcript.HashFields([]*big.Int{new(big.Int).SetBytes(entry.Ciphertext[:31]), new(big.Int).SetBytes(entry.Ciphertext[31:])})
		if err != nil {
			return err
		}
		key := &ring.RegistryKey{Next: next, CtHash: ciphertext, Index: entry.Index}
		for level, sibling := range entry.Proof {
			key.Path[level], err = sibling.field()
			if err != nil {
				return err
			}
		}
		if err := verifyRegistryKey(member, output.NullifierPk, key, anchor.Root); err != nil {
			return err
		}
		keys[member], output.Key = key, key
	}
	return nil
}

func verifyRegistryKey(member Hash, nullifier *big.Int, key *ring.RegistryKey, root Hash) error {
	keyHash, err := transcript.HashFields([]*big.Int{nullifier, key.CtHash})
	if err != nil {
		return err
	}
	owner, err := member.field()
	if err != nil {
		return err
	}
	leaf, err := transcript.HashFields([]*big.Int{owner, key.Next, keyHash})
	if err != nil {
		return err
	}
	hash, err := hashField(leaf)
	if err != nil {
		return err
	}
	path := make([]Hash, registry.Height)
	for level, sibling := range key.Path {
		path[level], err = hashField(sibling)
		if err != nil {
			return err
		}
	}
	return verifyPath(hash, path, key.Index, root)
}
