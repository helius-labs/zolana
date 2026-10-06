package tee

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const DefaultPCCSURL = "https://pccs.phala.network"

// maxPCCSBody fails a larger response instead of truncating a CRL.
const maxPCCSBody = 4 << 20

// Clients still reject a cached bundle past its own nextUpdate.
const collateralTTL = time.Hour

var (
	oidSGXExtension = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	oidFMSPC        = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
)

// Collateral is the dcap-qvl QuoteCollateralV3 in hex, Intel signed so any server may relay it.
type Collateral struct {
	PCKCRLIssuerChain     string `json:"pck_crl_issuer_chain"`
	RootCACRL             string `json:"root_ca_crl"`
	PCKCRL                string `json:"pck_crl"`
	TCBInfoIssuerChain    string `json:"tcb_info_issuer_chain"`
	TCBInfo               string `json:"tcb_info"`
	TCBInfoSignature      string `json:"tcb_info_signature"`
	QEIdentityIssuerChain string `json:"qe_identity_issuer_chain"`
	QEIdentity            string `json:"qe_identity"`
	QEIdentitySignature   string `json:"qe_identity_signature"`
}

type pckPlatform struct {
	fmspc string
	ca    string
}

type collateralSource struct {
	base   string
	client *http.Client

	mu    sync.Mutex
	cache map[pckPlatform]cachedCollateral
}

type cachedCollateral struct {
	collateral Collateral
	fetched    time.Time
}

func newCollateralSource(base string) *collateralSource {
	return &collateralSource{
		base:   strings.TrimRight(base, "/"),
		client: &http.Client{Timeout: 30 * time.Second},
		cache:  map[pckPlatform]cachedCollateral{},
	}
}

func (s *collateralSource) forQuote(ctx context.Context, quote []byte) (Collateral, error) {
	chain, err := pckChain(quote)
	if err != nil {
		return Collateral{}, err
	}
	platform, err := pckPlatformOf(chain)
	if err != nil {
		return Collateral{}, err
	}
	s.mu.Lock()
	cached, ok := s.cache[platform]
	s.mu.Unlock()
	if ok && time.Since(cached.fetched) < collateralTTL {
		return cached.collateral, nil
	}
	collateral, err := s.fetch(ctx, platform)
	if err != nil {
		return Collateral{}, err
	}
	s.mu.Lock()
	s.cache[platform] = cachedCollateral{collateral: collateral, fetched: time.Now()}
	s.mu.Unlock()
	return collateral, nil
}

func (s *collateralSource) fetch(ctx context.Context, platform pckPlatform) (Collateral, error) {
	pckCRL, pckCRLChain, err := s.get(ctx, "/sgx/certification/v4/pckcrl?ca="+platform.ca+"&encoding=der", "SGX-PCK-CRL-Issuer-Chain")
	if err != nil {
		return Collateral{}, err
	}
	tcbBody, tcbChain, err := s.get(ctx, "/tdx/certification/v4/tcb?fmspc="+platform.fmspc+"&update=standard", "TCB-Info-Issuer-Chain", "SGX-TCB-Info-Issuer-Chain")
	if err != nil {
		return Collateral{}, err
	}
	qeBody, qeChain, err := s.get(ctx, "/tdx/certification/v4/qe/identity?update=standard", "SGX-Enclave-Identity-Issuer-Chain")
	if err != nil {
		return Collateral{}, err
	}
	rootCRLHex, _, err := s.get(ctx, "/sgx/certification/v4/rootcacrl")
	if err != nil {
		return Collateral{}, err
	}
	// PCCS serves the root CA CRL hex encoded, unlike the DER PCK CRL.
	rootCRL := strings.TrimSpace(string(rootCRLHex))
	if _, err := hex.DecodeString(rootCRL); err != nil {
		return Collateral{}, fmt.Errorf("PCCS root CA CRL is not hex: %w", err)
	}

	var tcb struct {
		TCBInfo   json.RawMessage `json:"tcbInfo"`
		Signature string          `json:"signature"`
	}
	if err := json.Unmarshal(tcbBody, &tcb); err != nil {
		return Collateral{}, fmt.Errorf("PCCS TCB info: %w", err)
	}
	var qe struct {
		EnclaveIdentity json.RawMessage `json:"enclaveIdentity"`
		Signature       string          `json:"signature"`
	}
	if err := json.Unmarshal(qeBody, &qe); err != nil {
		return Collateral{}, fmt.Errorf("PCCS QE identity: %w", err)
	}
	// Intel signs the exact tcbInfo and enclaveIdentity bytes, so they stay as served.
	return Collateral{
		PCKCRLIssuerChain:     pckCRLChain,
		RootCACRL:             strings.ToLower(rootCRL),
		PCKCRL:                hex.EncodeToString(pckCRL),
		TCBInfoIssuerChain:    tcbChain,
		TCBInfo:               string(tcb.TCBInfo),
		TCBInfoSignature:      tcb.Signature,
		QEIdentityIssuerChain: qeChain,
		QEIdentity:            string(qe.EnclaveIdentity),
		QEIdentitySignature:   qe.Signature,
	}, nil
}

// get returns the body and the first present header, URL decoded.
func (s *collateralSource) get(ctx context.Context, path string, headers ...string) ([]byte, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+path, nil)
	if err != nil {
		return nil, "", err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("PCCS %s: %w", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPCCSBody+1))
	if err != nil {
		return nil, "", fmt.Errorf("PCCS %s: %w", path, err)
	}
	if len(body) > maxPCCSBody {
		return nil, "", fmt.Errorf("PCCS %s: body exceeds %d bytes", path, maxPCCSBody)
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("PCCS %s: HTTP %d", path, response.StatusCode)
	}
	if len(headers) == 0 {
		return body, "", nil
	}
	for _, name := range headers {
		if value := response.Header.Get(name); value != "" {
			decoded, err := url.QueryUnescape(value)
			if err != nil {
				return nil, "", fmt.Errorf("PCCS %s: header %s: %w", path, name, err)
			}
			return body, decoded, nil
		}
	}
	return nil, "", fmt.Errorf("PCCS %s: missing %s", path, headers[0])
}

const (
	certDataQEReport = 6
	certDataPCKChain = 5
	quoteHeaderSize  = 48
	tdReport10Size   = 584
)

// pckChain extracts the PEM PCK chain nested in a v4 or v5 TDX quote.
func pckChain(quote []byte) ([]byte, error) {
	r := quoteReader{data: quote}
	header := r.take(quoteHeaderSize)
	if header == nil {
		return nil, errors.New("quote too short")
	}
	switch binary.LittleEndian.Uint16(header) {
	case 4:
		r.take(tdReport10Size)
	case 5:
		r.u16()
		r.take(int(r.u32()))
	default:
		return nil, fmt.Errorf("unsupported quote version %d", binary.LittleEndian.Uint16(header))
	}
	r.u32()
	r.take(64 + 64)
	if r.u16() != certDataQEReport {
		return nil, errors.New("quote certification data is not a QE report")
	}
	r.u32()
	r.take(384 + 64)
	r.take(int(r.u16()))
	if r.u16() != certDataPCKChain {
		return nil, errors.New("quote carries no PCK certificate chain")
	}
	chain := r.take(int(r.u32()))
	if r.err != nil || chain == nil {
		return nil, errors.New("quote certification data is truncated")
	}
	return chain, nil
}

func pckPlatformOf(chain []byte) (pckPlatform, error) {
	block, _ := pem.Decode(chain)
	if block == nil {
		return pckPlatform{}, errors.New("PCK chain holds no certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return pckPlatform{}, fmt.Errorf("PCK certificate: %w", err)
	}
	var ca string
	switch {
	case strings.Contains(leaf.Issuer.CommonName, "Processor"):
		ca = "processor"
	case strings.Contains(leaf.Issuer.CommonName, "Platform"):
		ca = "platform"
	default:
		return pckPlatform{}, fmt.Errorf("unknown PCK issuer %q", leaf.Issuer.CommonName)
	}
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(oidSGXExtension) {
			continue
		}
		var entries []struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(extension.Value, &entries); err != nil {
			return pckPlatform{}, fmt.Errorf("SGX extension: %w", err)
		}
		for _, entry := range entries {
			if entry.ID.Equal(oidFMSPC) && len(entry.Value.Bytes) == 6 {
				return pckPlatform{fmspc: strings.ToUpper(hex.EncodeToString(entry.Value.Bytes)), ca: ca}, nil
			}
		}
	}
	return pckPlatform{}, errors.New("PCK certificate carries no FMSPC")
}

// quoteReader latches the first out of bounds read, so parsing stays linear.
type quoteReader struct {
	data []byte
	err  error
}

func (r *quoteReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.data) {
		r.err = errors.New("out of bounds")
		return nil
	}
	out := r.data[:n]
	r.data = r.data[n:]
	return out
}

func (r *quoteReader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.LittleEndian.Uint16(b)
	}
	return 0
}

func (r *quoteReader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}
