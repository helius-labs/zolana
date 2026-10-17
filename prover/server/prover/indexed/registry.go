package indexed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	ring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
	"github.com/helius-labs/zolana/prover/server/prover/transcript"
)

// RegistryRequest anchors member lookups to the registry root the statement binds.
type RegistryRequest struct {
	Ring      string `json:"ringProgramId"`
	Root      Hash   `json:"root"`
	NextIndex uint64 `json:"nextIndex"`
}

// prepareRegistries checks the anchors against the roots the client binds, the indexer fills every opening.
func prepareRegistries(p *ring.PolicyParams, request Request) error {
	if p.Subjects != nil || p.ForeignSubjects != nil {
		return fmt.Errorf("prepared policy contains member openings")
	}
	for _, output := range p.Outputs {
		if output.CtHash.Int != nil {
			return fmt.Errorf("prepared output contains registry witness")
		}
	}
	if err := validateRegistryAnchor(p.MemberRegistryRoot, request.Registry); err != nil {
		return err
	}
	foreign := p.ForeignRoot.Int != nil && p.ForeignRoot.Sign() != 0
	if foreign != (request.ForeignRegistry != nil) {
		return fmt.Errorf("invalid foreign registry request")
	}
	if foreign {
		if err := validateRegistryAnchor(p.ForeignRoot, request.ForeignRegistry); err != nil {
			return err
		}
	}
	p.Subjects = make([]*ring.MemberOpening, len(p.Inputs)+2*len(p.Outputs))
	p.ForeignSubjects = make([]*ring.MemberOpening, len(p.Subjects))
	for i := range p.Outputs {
		p.Outputs[i].CtHash = ring.Field{Int: new(big.Int)}
	}
	return nil
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

// UnregisteredMemberError names an owner whose record carries no key for the output, or another key.
type UnregisteredMemberError struct {
	Member   Hash
	mismatch bool
}

func (e *UnregisteredMemberError) Error() string {
	return fmt.Sprintf("registry member %s missing", e.Member)
}

// memberRecordResponse is Photon's getRingMemberRecord result. A present member fills
// record, index and path, an absent one fills low with the record that brackets it.
// record.ciphertext is the 32-byte sealed nullifier secret behind escrowKey, null without one.
type memberRecordResponse struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Root      Hash           `json:"root"`
	RootIndex uint16         `json:"rootIndex"`
	NextIndex uint64         `json:"nextIndex"`
	Present   bool           `json:"present"`
	Record    *recordJSON    `json:"record"`
	Index     uint64         `json:"index"`
	Path      []Hash         `json:"path"`
	Low       *lowRecordJSON `json:"low"`
}

type recordJSON struct {
	Member     Hash   `json:"member"`
	Next       Hash   `json:"next"`
	Lists      uint64 `json:"lists"`
	EscrowKey  Hash   `json:"escrowKey"`
	Ciphertext []byte `json:"ciphertext"`
}

type lowRecordJSON struct {
	recordJSON
	Index uint64 `json:"index"`
	Path  []Hash `json:"path"`
}

// memberRecord is a verified lookup, ctHash is set when the record escrows a key.
type memberRecord struct {
	opening   ring.MemberOpening
	escrowKey *big.Int
	ctHash    *big.Int
}

type memberRecords struct {
	anchor  *RegistryRequest
	records map[Hash]*memberRecord
}

func (r *Resolver) resolvePolicyRegistry(ctx context.Context, request Request, p *ring.PolicyParams) error {
	own := memberRecords{anchor: request.Registry, records: map[Hash]*memberRecord{}}
	foreign := memberRecords{anchor: request.ForeignRegistry, records: map[Hash]*memberRecord{}}
	for _, slot := range liveSubjects(p) {
		opening := subjectOpening(p, slot)
		memberKey := opening.OwnerPkHash.Int
		if slot >= len(p.Inputs)+len(p.Outputs) {
			memberKey = opening.Asset.Int
		}
		record, err := r.memberRecord(ctx, request, &own, memberKey)
		if err != nil {
			return err
		}
		p.Subjects[slot] = &record.opening
		if request.ForeignRegistry != nil {
			curator, err := r.memberRecord(ctx, request, &foreign, memberKey)
			if err != nil {
				return err
			}
			p.ForeignSubjects[slot] = &curator.opening
		}
		if output := slot - len(p.Inputs); output >= 0 && output < len(p.Outputs) && p.KeyEscrow {
			member, _ := hashField(opening.OwnerPkHash.Int)
			if err := record.verifyEscrow(member, opening.NullifierPk.Int); err != nil {
				return err
			}
			p.Outputs[output].CtHash = ring.Field{Int: record.ctHash}
		}
	}
	return nil
}

// verifyEscrow requires the record to escrow the nullifier key the UTXO uses.
func (m *memberRecord) verifyEscrow(member Hash, nullifierPk *big.Int) error {
	if m.ctHash == nil {
		return &UnregisteredMemberError{Member: member}
	}
	key, err := transcript.HashFields([]*big.Int{nullifierPk, m.ctHash})
	if err != nil {
		return err
	}
	if key.Cmp(m.escrowKey) != 0 {
		return &UnregisteredMemberError{Member: member, mismatch: true}
	}
	return nil
}

func (r *Resolver) memberRecord(ctx context.Context, request Request, records *memberRecords, owner *big.Int) (*memberRecord, error) {
	anchor := records.anchor
	member, err := hashField(owner)
	if err != nil || owner.Sign() == 0 {
		return nil, fmt.Errorf("invalid registry owner")
	}
	if known := records.records[member]; known != nil {
		return known, nil
	}
	payload, err := r.rpc(ctx, "getRingMemberRecord", map[string]any{"ringProgramId": anchor.Ring, "member": member, "expectedRoot": anchor.Root, "expectedNextIndex": anchor.NextIndex})
	if errors.Is(err, errMemberUnregistered) {
		return nil, &UnregisteredMemberError{Member: member}
	}
	if err != nil {
		return nil, err
	}
	var response memberRecordResponse
	if json.Unmarshal(payload, &response) != nil || response.Root != anchor.Root || response.NextIndex != anchor.NextIndex {
		return nil, fmt.Errorf("invalid registry membership")
	}
	record, err := verifyMemberRecord(member, response)
	if err != nil {
		return nil, err
	}
	if response.Context.Slot < request.MinContextSlot {
		return nil, ErrIndexerNotReady
	}
	records.records[member] = record
	return record, nil
}

// verifyMemberRecord binds the response to the member under the anchored root.
func verifyMemberRecord(member Hash, response memberRecordResponse) (*memberRecord, error) {
	subject, err := member.field()
	if err != nil {
		return nil, err
	}
	record := &memberRecord{opening: ring.MemberOpening{Present: response.Present}}
	opening := &record.opening
	opening.Next, opening.EscrowKey, opening.LowMember, opening.LowNext, opening.LowEscrow = zeroField(), zeroField(), zeroField(), zeroField(), zeroField()
	if response.Present {
		leaf := response.Record
		if leaf == nil || response.Low != nil || leaf.Member != member || response.Index == 0 || response.Index >= response.NextIndex || len(response.Path) != registry.Height {
			return nil, fmt.Errorf("invalid registry membership")
		}
		if err := verifyRecordPath(leaf.recordView(), response.Path, response.Index, response.Root); err != nil {
			return nil, err
		}
		next, err := leaf.Next.field()
		if err != nil {
			return nil, err
		}
		if record.escrowKey, err = leaf.EscrowKey.field(); err != nil {
			return nil, err
		}
		if record.ctHash, err = leaf.ciphertextHash(record.escrowKey); err != nil {
			return nil, err
		}
		opening.Next, opening.Lists, opening.EscrowKey = ring.Field{Int: next}, leaf.Lists, ring.Field{Int: record.escrowKey}
		opening.Index, opening.Path = response.Index, hashFields(response.Path)
		return record, nil
	}
	low := response.Low
	if low == nil || response.Record != nil || len(response.Path) != 0 || response.Index != 0 || low.Index >= response.NextIndex || len(low.Path) != registry.Height {
		return nil, fmt.Errorf("invalid registry membership")
	}
	lowMember, err := low.Member.field()
	if err != nil {
		return nil, err
	}
	lowNext, err := low.Next.field()
	if err != nil || lowMember.Cmp(subject) >= 0 || lowNext.Cmp(subject) <= 0 {
		return nil, fmt.Errorf("invalid registry absence range")
	}
	if err := verifyRecordPath(low.recordView(), low.Path, low.Index, response.Root); err != nil {
		return nil, err
	}
	lowEscrow, err := low.EscrowKey.field()
	if err != nil {
		return nil, err
	}
	record.escrowKey = new(big.Int)
	opening.LowMember, opening.LowNext, opening.LowLists, opening.LowEscrow = ring.Field{Int: lowMember}, ring.Field{Int: lowNext}, low.Lists, ring.Field{Int: lowEscrow}
	opening.Index, opening.Path = low.Index, hashFields(low.Path)
	return record, nil
}

func (leaf recordJSON) recordView() []*big.Int {
	return []*big.Int{
		new(big.Int).SetBytes(leaf.Member[:]), new(big.Int).SetBytes(leaf.Next[:]),
		new(big.Int).SetUint64(leaf.Lists), new(big.Int).SetBytes(leaf.EscrowKey[:]),
	}
}

// ciphertextHash hashes the sealed key, which must accompany a nonzero escrow key and nothing else.
func (leaf recordJSON) ciphertextHash(escrowKey *big.Int) (*big.Int, error) {
	if leaf.Ciphertext == nil {
		if escrowKey.Sign() != 0 {
			return nil, fmt.Errorf("invalid registry membership")
		}
		return nil, nil
	}
	if len(leaf.Ciphertext) != 32 || escrowKey.Sign() == 0 {
		return nil, fmt.Errorf("invalid registry membership")
	}
	return transcript.HashFields([]*big.Int{new(big.Int).SetBytes(leaf.Ciphertext[:31]), new(big.Int).SetBytes(leaf.Ciphertext[31:])})
}

func verifyRecordPath(record []*big.Int, path []Hash, index uint64, root Hash) error {
	for _, value := range record {
		if _, err := hashField(value); err != nil {
			return err
		}
	}
	leaf, err := transcript.HashFields(record)
	if err != nil {
		return err
	}
	hash, err := hashField(leaf)
	if err != nil {
		return err
	}
	return verifyPath(hash, path, index, root)
}

func zeroField() ring.Field {
	return ring.Field{Int: new(big.Int)}
}
