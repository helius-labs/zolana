// Package policy proves rules and auditor disclosure for the transaction SPP settles.
//
// The two proofs meet at PrivateTxHash. This package reopens that hash from note
// fields, applies the policy to those fields, and encrypts the same fields to the
// configured auditor. SPP separately proves ownership, inclusion, nullifiers and
// balance conservation. A policy proof alone cannot authorize settlement.
//
// The constraint flow is:
//
//  1. Pin capacities, privacy mode and member/delegate rail from the chosen key.
//  2. Decode and validate rules, sources, amount guards and outflow limits.
//  3. Reopen PrivateTxHash and exclude the administrative namespace as an owner.
//  4. Authenticate owner and asset records against the own and curator roots.
//  5. Apply every enabled rule to every live subject. Padding creates no subject.
//  6. Bound member outflow and derive approval. Delegates keep their explicit
//     outflow exemption but require escrow and separate on-chain authorization.
//  7. Bind each escrow-required output to its owner's registered commitment.
//  8. Encrypt auditor disclosure, in an anonymous ring prove every ring output body is
//     the recipient's encryption of its note, and bind them, the table and roots to
//     verification.
//
// PublicTable replaces repeated hashing with direct verifier inputs. Its trust
// boundary is the program-owned PolicyConfig account. Authorized policy writes
// validate and hash that table. An independent verifier must establish the same
// provenance rather than accept a table supplied by the prover.
//
// Registry proofs authenticate records, not the process that created them.
// RegisterKey must be the only writer of an escrow commitment. UpdateMembers
// preserves that commitment on chain. Recent roots intentionally remain usable
// until they leave the history, so a list update is not immediate revocation.
//
// Ordinary recipient ciphertext is outside this proof. Auditor clients must use
// verified disclosure even when wallet-delivery metadata cannot be decrypted.
package policy
