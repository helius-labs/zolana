package main_test

import (
	"bytes"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"zolana/prover/logging"
	nullifiertreetest "zolana/prover/prover-test/nullifier_tree"
	"zolana/prover/prover/common"
	"zolana/prover/server"

	gnarkLogger "github.com/consensys/gnark/logger"
)

var isLightweightMode bool
var preloadKeys bool

const ProverAddress = "localhost:8081"
const MetricsAddress = "localhost:9999"

var instance server.RunningJob
var serverStopped bool

func proveEndpoint() string {
	return "http://" + ProverAddress + "/prove"
}

func StartServer(isLightweight bool) {
	StartServerWithPreload(isLightweight, true)
}

func StartServerWithPreload(isLightweight bool, preload bool) {
	logging.Logger().Info().Msg("Setting up the prover")
	var runMode common.RunMode
	if isLightweight {
		runMode = common.FullTest
	} else {
		runMode = common.Full
	}

	downloadConfig := common.DefaultDownloadConfig()
	downloadConfig.AutoDownload = true

	keyManager := common.NewLazyKeyManager("./proving-keys/", downloadConfig)

	if preload {
		// Preload keys for the test run mode
		err := keyManager.PreloadForRunMode(runMode)
		if err != nil {
			logging.Logger().Fatal().Err(err).Msg("Failed to preload proving keys")
			return
		}
	} else {
		var testCircuits []string
		if isLightweight {
			testCircuits = []string{
				"inclusion", "non-inclusion", "combined",
				"append-test", "update-test", "address-append-test",
			}
		} else {
			testCircuits = []string{
				"inclusion", "non-inclusion", "combined",
				"append", "update", "address-append",
			}
		}

		err := keyManager.PreloadCircuits(testCircuits)
		if err != nil {
			logging.Logger().Warn().Err(err).Msg("Failed to preload some test keys, will download on-demand")
		}
	}

	serverCfg := server.Config{
		ProverAddress:  ProverAddress,
		MetricsAddress: MetricsAddress,
	}
	logging.Logger().Info().Msg("Starting the server")
	instance = server.Run(&serverCfg, keyManager)
	serverStopped = false

	// sleep for 1 sec to ensure that the server is up and running before running the tests
	time.Sleep(1 * time.Second)

	logging.Logger().Info().Msg("Running the tests")
}

func StopServer() {
	if serverStopped {
		return
	}
	instance.RequestStop()
	instance.AwaitStop()
	serverStopped = true
}

func TestMain(m *testing.M) {
	gnarkLogger.Set(*logging.Logger())

	runIntegrationTests := false
	isLightweightMode = true
	preloadKeys = true

	for _, arg := range os.Args {
		if strings.Contains(arg, "-test.run=TestFull") {
			isLightweightMode = false
			runIntegrationTests = true
			break
		}
		if strings.Contains(arg, "-test.run=TestLightweightLazy") {
			runIntegrationTests = true
			preloadKeys = false
			break
		}
		if strings.Contains(arg, "-test.run=TestLightweight") {
			runIntegrationTests = true
			break
		}
	}

	if !runIntegrationTests {
		hasTestRunFlag := false
		for _, arg := range os.Args {
			if strings.HasPrefix(arg, "-test.run=") {
				hasTestRunFlag = true
				pattern := strings.TrimPrefix(arg, "-test.run=")
				if pattern == "" || pattern == "^Test" || strings.Contains(pattern, "Lightweight") || strings.Contains(pattern, "Full") {
					runIntegrationTests = true
				}
				break
			}
		}
		if !hasTestRunFlag {
			runIntegrationTests = true
		}
	}

	if runIntegrationTests {
		if isLightweightMode {
			if preloadKeys {
				logging.Logger().Info().Msg("Running in lightweight mode - preloading keys")
			} else {
				logging.Logger().Info().Msg("Running in lazy lightweight mode")
			}
		} else {
			logging.Logger().Info().Msg("Running in full mode - preloading keys")
		}

		StartServerWithPreload(isLightweightMode, preloadKeys)
		code := m.Run()
		StopServer()
		os.Exit(code)
	} else {
		logging.Logger().Info().Msg("Skipping key loading - no integration tests in this run")
		os.Exit(m.Run())
	}
}

func TestLightweight(t *testing.T) {
	if !isLightweightMode {
		t.Skip("This test only runs in lightweight mode")
	}
	runCommonTests(t)
	runLightweightOnlyTests(t)
}

func TestLightweightLazy(t *testing.T) {
	if preloadKeys {
		t.Skip("This test only runs when preloadKeys is false (lazy mode)")
	}

	logging.Logger().Info().Msg("TestLightweightLazy: Running tests with lazy key loading")

	runCommonTests(t)
	runLightweightOnlyTests(t)

	logging.Logger().Info().Msg("TestLightweightLazy: All tests passed with lazy loading")
}

func TestFull(t *testing.T) {
	if isLightweightMode {
		t.Skip("This test only runs in full mode")
	}
	runCommonTests(t)
	runFullOnlyTests(t)
}

// runCommonTests contains all tests that should run in both modes
func runCommonTests(t *testing.T) {
	t.Run("testWrongMethod", testWrongMethod)
}

// runFullOnlyTests contains tests that should only run in full mode
func runFullOnlyTests(t *testing.T) {
	t.Run("testBatchAddressAppendHappyPath40_250", testBatchAddressAppendHappyPath40_250)
	t.Run("testBatchAddressAppendWithPreviousState40_250", testBatchAddressAppendWithPreviousState40_250)
	t.Run("testBatchAddressAppendInvalidInput40_250", testBatchAddressAppendInvalidInput40_250)
}

func runLightweightOnlyTests(t *testing.T) {
	t.Run("testBatchAddressAppendHappyPath40_10", testBatchAddressAppendHappyPath40_10)
	t.Run("testBatchAddressAppendWithPreviousState40_10", testBatchAddressAppendWithPreviousState40_10)
	t.Run("testBatchAddressAppendInvalidInput40_10", testBatchAddressAppendInvalidInput40_10)
}

func testWrongMethod(t *testing.T) {
	response, err := http.Get(proveEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("Expected status code %d, got %d", http.StatusMethodNotAllowed, response.StatusCode)
	}
}

func testBatchAddressAppendHappyPath40_10(t *testing.T) {
	runBatchAddressAppendTest(t, 40, 10)
}

func testBatchAddressAppendHappyPath40_100(t *testing.T) {
	runBatchAddressAppendTest(t, 40, 100)
}

func testBatchAddressAppendHappyPath40_500(t *testing.T) {
	runBatchAddressAppendTest(t, 40, 500)
}

func testBatchAddressAppendHappyPath40_250(t *testing.T) {
	runBatchAddressAppendTest(t, 40, 250)
}

func testBatchAddressAppendHappyPath40_1000(t *testing.T) {
	runBatchAddressAppendTest(t, 40, 1000)
}

func runBatchAddressAppendTest(t *testing.T, treeHeight uint32, batchSize uint32) {
	params, err := nullifiertreetest.BuildTestAddressTree(treeHeight, batchSize, nil, 1)
	if err != nil {
		t.Fatalf("Failed to build test tree: %v", err)
	}

	jsonBytes, err := params.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}
	response, err := http.Post(proveEndpoint(), "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		t.Fatalf("Failed to send POST request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("Expected status code %d, got %d. Response body: %s", http.StatusOK, response.StatusCode, string(body))
	}

	// Verify that the new root is different from the old root
	if params.OldRoot.Cmp(params.NewRoot) == 0 {
		t.Errorf("Expected new root to be different from old root")
	}

	t.Logf("Successfully ran batch address append test with tree height %d and batch size %d", treeHeight, batchSize)
}

func testBatchAddressAppendWithPreviousState40_10(t *testing.T) {
	runBatchAddressAppendWithPreviousStateTest(t, 40, 10)
}

func testBatchAddressAppendWithPreviousState40_100(t *testing.T) {
	runBatchAddressAppendWithPreviousStateTest(t, 40, 100)
}

func testBatchAddressAppendWithPreviousState40_250(t *testing.T) {
	runBatchAddressAppendWithPreviousStateTest(t, 40, 250)
}

func runBatchAddressAppendWithPreviousStateTest(t *testing.T, treeHeight uint32, batchSize uint32) {
	startIndex := uint64(1)
	params1, err := nullifiertreetest.BuildTestAddressTree(treeHeight, batchSize, nil, startIndex)
	if err != nil {
		t.Fatalf("Failed to build first test tree: %v", err)
	}

	jsonBytes1, err := params1.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal first JSON: %v", err)
	}

	response1, err := http.Post(proveEndpoint(), "application/json", bytes.NewBuffer(jsonBytes1))
	if err != nil {
		t.Fatalf("Failed to send first POST request: %v", err)
	}
	if response1.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response1.Body)
		t.Fatalf("First batch: Expected status code %d, got %d. Response body: %s",
			http.StatusOK, response1.StatusCode, string(body))
	}
	response1.Body.Close()

	startIndex += uint64(batchSize)
	params2, err := nullifiertreetest.BuildTestAddressTree(treeHeight, batchSize, params1.Tree, startIndex)
	if err != nil {
		t.Fatalf("Failed to build second test tree: %v", err)
	}
	params2.OldRoot = params1.NewRoot

	jsonBytes2, err := params2.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal second JSON: %v", err)
	}

	response2, err := http.Post(proveEndpoint(), "application/json", bytes.NewBuffer(jsonBytes2))
	if err != nil {
		t.Fatalf("Failed to send second POST request: %v", err)
	}
	if response2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response2.Body)
		t.Fatalf("Second batch: Expected status code %d, got %d. Response body: %s",
			http.StatusOK, response2.StatusCode, string(body))
	}
	response2.Body.Close()

	if params2.OldRoot.Cmp(params2.NewRoot) == 0 {
		t.Errorf("Expected new root to be different from old root in second batch")
	}

	t.Logf("Successfully ran batch address append with previous state test with tree height %d and batch size %d",
		treeHeight, batchSize)
}

func testBatchAddressAppendInvalidInput40_10(t *testing.T) {
	treeHeight := uint32(40)
	batchSize := uint32(10)
	startIndex := uint64(0)

	params, err := nullifiertreetest.BuildTestAddressTree(treeHeight, batchSize, nil, startIndex)
	if err != nil {
		t.Fatalf("Failed to build test tree: %v", err)
	}

	// Invalidate input by setting wrong old root
	params.OldRoot = big.NewInt(0)

	jsonBytes, err := params.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	response, err := http.Post(proveEndpoint(), "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		t.Fatalf("Failed to send POST request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status code %d, got %d", http.StatusBadRequest, response.StatusCode)
	}

	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "proving_error") {
		t.Fatalf("Expected error message to contain 'proving_error', got: %s", string(body))
	}

	t.Logf("Successfully ran invalid input test with tree height %d and batch size %d",
		treeHeight, batchSize)
}

func testBatchAddressAppendInvalidInput40_250(t *testing.T) {
	treeHeight := uint32(40)
	batchSize := uint32(250)
	startIndex := uint64(0)

	params, err := nullifiertreetest.BuildTestAddressTree(treeHeight, batchSize, nil, startIndex)
	if err != nil {
		t.Fatalf("Failed to build test tree: %v", err)
	}

	// Invalidate input by setting wrong old root
	params.OldRoot = big.NewInt(0)

	jsonBytes, err := params.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	response, err := http.Post(proveEndpoint(), "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		t.Fatalf("Failed to send POST request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status code %d, got %d", http.StatusBadRequest, response.StatusCode)
	}

	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "proving_error") {
		t.Fatalf("Expected error message to contain 'proving_error', got: %s", string(body))
	}

	t.Logf("Successfully ran invalid input test with tree height %d and batch size %d",
		treeHeight, batchSize)
}
