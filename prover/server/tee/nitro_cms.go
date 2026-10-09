package tee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
)

const (
	seedSize    = 32
	maxBERDepth = 12

	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30
	tagSet         = 0x31
	tagContext0    = 0x80
	tagConstructed = 0x20
)

var (
	oidEnvelopedData = oidContent(1, 2, 840, 113549, 1, 7, 3)
	oidData          = oidContent(1, 2, 840, 113549, 1, 7, 1)
	oidRSAESOAEP     = oidContent(1, 2, 840, 113549, 1, 1, 7)
	oidMGF1          = oidContent(1, 2, 840, 113549, 1, 1, 8)
	oidSHA256        = oidContent(2, 16, 840, 1, 101, 3, 4, 2, 1)
	oidAES256CBC     = oidContent(2, 16, 840, 1, 101, 3, 4, 1, 42)
)

func openEnvelope(envelope []byte, recipient *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := decryptEnvelope(envelope, recipient)
	if err != nil {
		return nil, fmt.Errorf("CiphertextForRecipient: %w", err)
	}
	if len(plaintext) != seedSize {
		clear(plaintext)
		return nil, fmt.Errorf("CiphertextForRecipient holds %d bytes, want %d", len(plaintext), seedSize)
	}
	return plaintext, nil
}

func decryptEnvelope(envelope []byte, recipient *rsa.PrivateKey) ([]byte, error) {
	if len(envelope) > maxKMSCiphertext {
		return nil, fmt.Errorf("envelope exceeds %d bytes", maxKMSCiphertext)
	}
	root, rest, err := parseBER(envelope, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after the envelope")
	}
	info, err := fields(root, tagSequence, 2)
	if err != nil {
		return nil, err
	}
	if !isOID(info[0], oidEnvelopedData) {
		return nil, errors.New("content type is not EnvelopedData")
	}
	explicit, err := fields(info[1], tagContext0|tagConstructed, 1)
	if err != nil {
		return nil, err
	}
	enveloped, err := fields(explicit[0], tagSequence, 3)
	if err != nil {
		return nil, err
	}
	if !isVersion(enveloped[0], 2) {
		return nil, errors.New("EnvelopedData version is not 2")
	}
	recipients, err := fields(enveloped[1], tagSet, 1)
	if err != nil {
		return nil, fmt.Errorf("want exactly one recipient: %w", err)
	}
	encryptedKey, err := keyTransport(recipients[0])
	if err != nil {
		return nil, err
	}
	iv, ciphertext, err := encryptedContent(enveloped[2])
	if err != nil {
		return nil, err
	}
	contentKey, err := rsa.DecryptOAEP(sha256.New(), nil, recipient, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap the content key: %w", err)
	}
	defer clear(contentKey)
	return decryptCBC(contentKey, iv, ciphertext)
}

func keyTransport(recipient berValue) ([]byte, error) {
	info, err := fields(recipient, tagSequence, 4)
	if err != nil {
		return nil, err
	}
	// Version 2 carries a subjectKeyIdentifier.
	if !isVersion(info[0], 2) || info[1].tag != tagContext0 {
		return nil, errors.New("recipient is not a version 2 KeyTransRecipientInfo")
	}
	params, err := algorithm(info[2], oidRSAESOAEP, 1)
	if err != nil {
		return nil, err
	}
	// An absent pSourceFunc is the empty label.
	oaep, err := fields(params[0], tagSequence, 2)
	if err != nil {
		return nil, err
	}
	hash, err := fields(oaep[0], tagContext0|tagConstructed, 1)
	if err != nil || !isSHA256(hash[0]) {
		return nil, errors.New("OAEP hash is not SHA-256")
	}
	mask, err := fields(oaep[1], tagContext0|tagConstructed|1, 1)
	if err != nil {
		return nil, errors.New("OAEP mask generation is not MGF1")
	}
	maskHash, err := algorithm(mask[0], oidMGF1, 1)
	if err != nil || !isSHA256(maskHash[0]) {
		return nil, errors.New("OAEP mask generation is not MGF1 SHA-256")
	}
	return octets(info[3], tagOctetString)
}

func encryptedContent(content berValue) (iv, ciphertext []byte, err error) {
	info, err := fields(content, tagSequence, 3)
	if err != nil {
		return nil, nil, err
	}
	if !isOID(info[0], oidData) {
		return nil, nil, errors.New("encrypted content type is not data")
	}
	params, err := algorithm(info[1], oidAES256CBC, 1)
	if err != nil {
		return nil, nil, err
	}
	if params[0].tag != tagOctetString || len(params[0].content) != aes.BlockSize {
		return nil, nil, errors.New("AES-256-CBC IV is malformed")
	}
	ciphertext, err = octets(info[2], tagContext0)
	if err != nil {
		return nil, nil, err
	}
	return params[0].content, ciphertext, nil
}

func decryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not whole AES blocks")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("content key has %d bytes, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	pad := int(plaintext[len(plaintext)-1])
	if pad == 0 || pad > aes.BlockSize || !bytes.Equal(plaintext[len(plaintext)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		clear(plaintext)
		return nil, errors.New("PKCS#7 padding is invalid")
	}
	return plaintext[:len(plaintext)-pad], nil
}

// Low tag numbers only.
type berValue struct {
	tag      byte
	content  []byte
	children []berValue
}

// parseBER accepts the indefinite lengths KMS emits.
func parseBER(in []byte, depth int) (berValue, []byte, error) {
	if depth > maxBERDepth {
		return berValue{}, nil, errors.New("BER nests too deep")
	}
	if len(in) < 2 {
		return berValue{}, nil, errors.New("BER is truncated")
	}
	v := berValue{tag: in[0]}
	if v.tag&0x1f == 0x1f {
		return berValue{}, nil, errors.New("BER high tag numbers are unsupported")
	}
	constructed := v.tag&tagConstructed != 0
	length, rest := int(in[1]), in[2:]
	switch {
	case length == 0x80:
		if !constructed {
			return berValue{}, nil, errors.New("BER primitive has an indefinite length")
		}
		for len(rest) < 2 || rest[0] != 0 || rest[1] != 0 {
			child, next, err := parseBER(rest, depth+1)
			if err != nil {
				return berValue{}, nil, err
			}
			v.children, rest = append(v.children, child), next
		}
		return v, rest[2:], nil
	case length > 0x80:
		size := length & 0x7f
		if size > 2 || len(rest) < size {
			return berValue{}, nil, errors.New("BER length is malformed")
		}
		length = 0
		for _, b := range rest[:size] {
			length = length<<8 | int(b)
		}
		rest = rest[size:]
	}
	if length > len(rest) {
		return berValue{}, nil, errors.New("BER is truncated")
	}
	v.content, rest = rest[:length], rest[length:]
	if !constructed {
		return v, rest, nil
	}
	for body := v.content; len(body) > 0; {
		child, next, err := parseBER(body, depth+1)
		if err != nil {
			return berValue{}, nil, err
		}
		v.children, body = append(v.children, child), next
	}
	v.content = nil
	return v, rest, nil
}

func fields(v berValue, tag byte, count int) ([]berValue, error) {
	if v.tag != tag || len(v.children) != count {
		return nil, fmt.Errorf("want tag %#x with %d fields, got %#x with %d", tag, count, v.tag, len(v.children))
	}
	return v.children, nil
}

// BER may split a string into constructed segments.
func octets(v berValue, tag byte) ([]byte, error) {
	switch v.tag {
	case tag:
		return v.content, nil
	case tag | tagConstructed:
		var joined []byte
		for _, segment := range v.children {
			if segment.tag != tagOctetString {
				return nil, errors.New("constructed string holds a non OCTET STRING segment")
			}
			joined = append(joined, segment.content...)
		}
		return joined, nil
	default:
		return nil, fmt.Errorf("want string tag %#x, got %#x", tag, v.tag)
	}
}

func algorithm(v berValue, oid []byte, params int) ([]berValue, error) {
	identifier, err := fields(v, tagSequence, 1+params)
	if err != nil || !isOID(identifier[0], oid) {
		return nil, fmt.Errorf("algorithm is not %x", oid)
	}
	return identifier[1:], nil
}

// RFC 4055 allows absent or NULL parameters.
func isSHA256(v berValue) bool {
	if _, err := algorithm(v, oidSHA256, 0); err == nil {
		return true
	}
	params, err := algorithm(v, oidSHA256, 1)
	return err == nil && params[0].tag == tagNull && len(params[0].content) == 0
}

func isOID(v berValue, oid []byte) bool {
	return v.tag == tagOID && bytes.Equal(v.content, oid)
}

func isVersion(v berValue, version byte) bool {
	return v.tag == tagInteger && bytes.Equal(v.content, []byte{version})
}

func oidContent(arcs ...int) []byte {
	der, err := asn1.Marshal(asn1.ObjectIdentifier(arcs))
	if err != nil {
		panic(err)
	}
	return der[2:]
}
