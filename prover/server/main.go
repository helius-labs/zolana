package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"
	"zolana/prover/logging"
	"zolana/prover/prover/common"
	mergeprover "zolana/prover/prover/merge"
	"zolana/prover/prover/nullifier_tree"
	"zolana/prover/prover/transfer"
	transfereddsaonly "zolana/prover/prover/transfer_eddsa_only"
	"zolana/prover/server"

	"github.com/consensys/gnark/constraint"
	gnarkLogger "github.com/consensys/gnark/logger"
	"github.com/urfave/cli/v2"
)

//go:embed VERSION
var Version string

func main() {
	runCli()
}

func runCli() {
	gnarkLogger.Set(*logging.Logger())
	app := cli.App{
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name: "setup",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "circuit", Usage: "Type of circuit (\"inclusion\" / \"non-inclusion\" / \"combined\" / \"append\" / \"update\" / \"address-append\" )", Required: true},
					&cli.StringFlag{Name: "output", Usage: "Output file", Required: true},
					&cli.StringFlag{Name: "output-vkey", Usage: "Output file", Required: true},
					&cli.UintFlag{Name: "inclusion-tree-height", Usage: "[Inclusion]: Merkle tree height", Required: false},
					&cli.UintFlag{Name: "inclusion-compressed-accounts", Usage: "[Inclusion]: Number of compressed accounts", Required: false},
					&cli.UintFlag{Name: "non-inclusion-tree-height", Usage: "[Non-inclusion]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "non-inclusion-compressed-accounts", Usage: "[Non-inclusion]: number of compressed accounts", Required: false},
					&cli.UintFlag{Name: "append-tree-height", Usage: "[Batch append]: tree height", Required: false},
					&cli.UintFlag{Name: "append-batch-size", Usage: "[Batch append]: batch size", Required: false},
					&cli.UintFlag{Name: "update-tree-height", Usage: "[Batch update]: tree height", Required: false},
					&cli.UintFlag{Name: "update-batch-size", Usage: "[Batch update]: batch size", Required: false},
					&cli.UintFlag{Name: "address-append-tree-height", Usage: "[Batch address append]: tree height", Required: false},
					&cli.UintFlag{Name: "address-append-batch-size", Usage: "[Batch address append]: batch size", Required: false},
				},
				Action: func(context *cli.Context) error {
					circuit := common.CircuitType(context.String("circuit"))
					if circuit != common.InclusionCircuitType && circuit != common.NonInclusionCircuitType && circuit != common.CombinedCircuitType && circuit != common.BatchUpdateCircuitType && circuit != common.BatchAppendCircuitType && circuit != common.BatchAddressAppendCircuitType {
						return fmt.Errorf("invalid circuit type %s", circuit)
					}

					path := context.String("output")
					pathVkey := context.String("output-vkey")
					batchAddressAppendTreeHeight := uint32(context.Uint("address-append-tree-height"))
					batchAddressAppendBatchSize := uint32(context.Uint("address-append-batch-size"))

					if (batchAddressAppendTreeHeight == 0 || batchAddressAppendBatchSize == 0) && circuit == common.BatchAddressAppendCircuitType {
						return fmt.Errorf("[Batch address append]: tree height and batch size must be provided")
					}

					logging.Logger().Info().Msg("Running setup")
					var err error
					if circuit == common.BatchAddressAppendCircuitType {
						fmt.Println("Generating Address Append Circuit")
						var system *common.BatchProofSystem
						system, err = nullifiertree.SetupBatchOperationCircuit(common.BatchAddressAppendCircuitType, batchAddressAppendTreeHeight, batchAddressAppendBatchSize)
						if err != nil {
							return err
						}
						err = common.WriteProvingSystem(system, path, pathVkey)
					} else {
						return fmt.Errorf("unsupported circuit: %s", circuit)
					}

					if err != nil {
						return err
					}

					logging.Logger().Info().Msg("Setup completed successfully")
					return nil
				},
			},
			{
				Name: "setup-transfer",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "circuit", Usage: "Transfer circuit (\"transfer-confidential\" / \"transfer-p256-confidential\" / \"transfer-zone\" / \"transfer-p256-zone\" / \"transfer-zone-authority\")", Required: true},
					&cli.UintFlag{Name: "n-inputs", Usage: "Number of input slots", Required: true},
					&cli.UintFlag{Name: "n-outputs", Usage: "Number of output slots", Required: true},
					&cli.StringFlag{Name: "output", Usage: "Output key file", Required: true},
				},
				Action: func(context *cli.Context) error {
					circuit := common.CircuitType(context.String("circuit"))
					nInputs := uint32(context.Uint("n-inputs"))
					nOutputs := uint32(context.Uint("n-outputs"))
					path := context.String("output")

					var ps *common.TransferProofSystem
					var err error
					switch circuit {
					case common.TransferP256ConfidentialCircuitType,
						common.TransferP256ZoneCircuitType:
						ps, err = transfer.SetupTransferCircuit(circuit, nInputs, nOutputs)
					case common.TransferConfidentialCircuitType,
						common.TransferZoneCircuitType,
						common.TransferZoneAuthorityCircuitType:
						ps, err = transfereddsaonly.SetupTransferCircuit(circuit, nInputs, nOutputs)
					default:
						return fmt.Errorf("invalid transfer circuit type %s", circuit)
					}
					if err != nil {
						return err
					}

					file, err := os.Create(path)
					if err != nil {
						return err
					}
					defer func(file *os.File) {
						if cerr := file.Close(); cerr != nil {
							logging.Logger().Error().Err(cerr).Msg("error closing file")
						}
					}(file)

					written, err := ps.WriteTo(file)
					if err != nil {
						return err
					}
					logging.Logger().Info().
						Str("circuit", string(circuit)).
						Uint32("n_inputs", nInputs).
						Uint32("n_outputs", nOutputs).
						Int64("bytes_written", written).
						Str("output", path).
						Msg("Transfer proving system written")
					return nil
				},
			},
			{
				Name: "setup-merge",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Usage: "Output key file", Required: true},
					&cli.StringFlag{Name: "circuit", Usage: "Merge circuit (\"merge\" default / \"merge-zone\")", Required: false},
				},
				Action: func(context *cli.Context) error {
					path := context.String("output")
					var ps *common.TransferProofSystem
					var err error
					switch context.String("circuit") {
					case "", "merge":
						ps, err = mergeprover.SetupMerge()
					case "merge-zone":
						ps, err = mergeprover.SetupMergeZone()
					default:
						return fmt.Errorf("unknown merge circuit %q", context.String("circuit"))
					}
					if err != nil {
						return err
					}
					file, err := os.Create(path)
					if err != nil {
						return err
					}
					defer func(file *os.File) {
						if cerr := file.Close(); cerr != nil {
							logging.Logger().Error().Err(cerr).Msg("error closing file")
						}
					}(file)

					written, err := ps.WriteTo(file)
					if err != nil {
						return err
					}
					logging.Logger().Info().
						Uint32("n_inputs", mergeprover.MergeNInputs).
						Uint32("n_outputs", mergeprover.MergeNOutputs).
						Int64("bytes_written", written).
						Str("output", path).
						Msg("Merge proving system written")
					return nil
				},
			},
			{
				Name: "r1cs",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Usage: "Output file", Required: true},
					&cli.StringFlag{Name: "circuit", Usage: "Type of circuit (\"inclusion\" / \"non-inclusion\" / \"combined\" / \"append\" / \"update\" / \"address-append\")", Required: true},
					&cli.UintFlag{Name: "inclusion-tree-height", Usage: "[Inclusion]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "inclusion-compressed-accounts", Usage: "[Inclusion]: number of compressed accounts", Required: false},
					&cli.UintFlag{Name: "non-inclusion-tree-height", Usage: "[Non-inclusion]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "non-inclusion-compressed-accounts", Usage: "[Non-inclusion]: number of compressed accounts", Required: false},
					&cli.UintFlag{Name: "append-tree-height", Usage: "[Batch append]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "append-batch-size", Usage: "[Batch append]: batch size", Required: false},
					&cli.UintFlag{Name: "update-tree-height", Usage: "[Batch update]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "update-batch-size", Usage: "[Batch update]: batch size", Required: false},
					&cli.UintFlag{Name: "address-append-tree-height", Usage: "[Batch address append]: tree height", Required: false},
					&cli.UintFlag{Name: "address-append-batch-size", Usage: "[Batch address append]: batch size", Required: false},
				},
				Action: func(context *cli.Context) error {
					circuit := common.CircuitType(context.String("circuit"))
					if circuit != common.InclusionCircuitType &&
						circuit != common.NonInclusionCircuitType &&
						circuit != common.CombinedCircuitType &&
						circuit != common.BatchUpdateCircuitType &&
						circuit != common.BatchAppendCircuitType &&
						circuit != common.BatchAddressAppendCircuitType {
						return fmt.Errorf("invalid circuit type %s", circuit)
					}

					path := context.String("output")
					batchAddressAppendTreeHeight := uint32(context.Uint("address-append-tree-height"))
					batchAddressAppendBatchSize := uint32(context.Uint("address-append-batch-size"))

					if (batchAddressAppendTreeHeight == 0 || batchAddressAppendBatchSize == 0) && circuit == common.BatchAddressAppendCircuitType {
						return fmt.Errorf("[Batch address append]: tree height and batch size must be provided")
					}

					logging.Logger().Info().Msg("Building R1CS")

					var cs constraint.ConstraintSystem
					var err error

					if circuit == common.BatchAddressAppendCircuitType {
						cs, err = nullifiertree.R1CSBatchAddressAppend(batchAddressAppendTreeHeight, batchAddressAppendBatchSize)
					} else {
						return fmt.Errorf("invalid circuit type %s", circuit)
					}

					if err != nil {
						return err
					}
					file, err := os.Create(path)
					defer func(file *os.File) {
						err := file.Close()
						if err != nil {
							logging.Logger().Error().Err(err).Msg("error closing file")
						}
					}(file)
					if err != nil {
						return err
					}
					written, err := cs.WriteTo(file)
					if err != nil {
						return err
					}
					logging.Logger().Info().Int64("bytesWritten", written).Msg("R1CS written to file")
					return nil
				},
			},
			{
				Name: "import-setup",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "circuit", Usage: "Type of circuit (\"inclusion\" / \"non-inclusion\" / \"combined\")", Required: true},
					&cli.StringFlag{Name: "output", Usage: "Output file", Required: true},
					&cli.StringFlag{Name: "vkey-output", Usage: "Verifying key output file (optional)", Required: false},
					&cli.StringFlag{Name: "pk", Usage: "Proving key", Required: true},
					&cli.StringFlag{Name: "vk", Usage: "Verifying key", Required: true},
					&cli.StringFlag{Name: "r1cs", Usage: "R1CS file", Required: false},
					&cli.UintFlag{Name: "inclusion-tree-height", Usage: "[Inclusion]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "inclusion-compressed-accounts", Usage: "[Inclusion]: number of compressed accounts", Required: false},
					&cli.UintFlag{Name: "non-inclusion-tree-height", Usage: "[Non-inclusion]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "non-inclusion-compressed-accounts", Usage: "[Non-inclusion]: number of compressed accounts", Required: false},
					&cli.UintFlag{Name: "append-tree-height", Usage: "[Batch append]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "append-batch-size", Usage: "[Batch append]: batch size", Required: false},
					&cli.UintFlag{Name: "update-tree-height", Usage: "[Batch update]: merkle tree height", Required: false},
					&cli.UintFlag{Name: "update-batch-size", Usage: "[Batch update]: batch size", Required: false},
					&cli.UintFlag{Name: "address-append-tree-height", Usage: "[Batch address append]: tree height", Required: false},
					&cli.UintFlag{Name: "address-append-batch-size", Usage: "[Batch address append]: batch size", Required: false},
				},
				Action: func(context *cli.Context) error {
					circuit := context.String("circuit")

					path := context.String("output")
					pathVkey := context.String("vkey-output")
					pk := context.String("pk")
					vk := context.String("vk")
					r1csPath := context.String("r1cs")

					batchAddressAppendTreeHeight := uint32(context.Uint("address-append-tree-height"))
					batchAddressAppendBatchSize := uint32(context.Uint("address-append-batch-size"))

					var err error

					logging.Logger().Info().Msg("Importing setup")

					if circuit == "address-append" {
						if batchAddressAppendTreeHeight == 0 || batchAddressAppendBatchSize == 0 {
							return fmt.Errorf("append tree height and batch size must be provided")
						}
						var system *common.BatchProofSystem
						if r1csPath != "" {
							system, err = nullifiertree.ImportBatchAddressAppendSetupWithR1CS(batchAddressAppendTreeHeight, batchAddressAppendBatchSize, pk, vk, r1csPath)
						} else {
							system, err = nullifiertree.ImportBatchAddressAppendSetup(batchAddressAppendTreeHeight, batchAddressAppendBatchSize, pk, vk)
						}
						if err != nil {
							return err
						}
						err = common.WriteProvingSystem(system, path, pathVkey)
					} else {
						return fmt.Errorf("unsupported circuit: %s", circuit)
					}

					if err != nil {
						return err
					}

					logging.Logger().Info().Msg("Setup imported successfully")
					return nil
				},
			},
			{
				Name: "export-vk",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "keys-file", Aliases: []string{"k"}, Usage: "proving system file", Required: true},
					&cli.StringFlag{Name: "output", Usage: "output file", Required: true},
				},
				Action: func(context *cli.Context) error {
					keysFile := context.String("keys-file")
					outputFile := context.String("output")

					system, err := common.ReadSystemFromFile(keysFile)
					if err != nil {
						return fmt.Errorf("failed to read proving system: %v", err)
					}

					var buf bytes.Buffer
					switch s := system.(type) {
					case *common.MerkleProofSystem:
						_, err = s.VerifyingKey.WriteTo(&buf)
					case *common.BatchProofSystem:
						_, err = s.VerifyingKey.WriteRawTo(&buf)
					case *common.TransferProofSystem:
						_, err = s.VerifyingKey.WriteRawTo(&buf)
					default:
						return fmt.Errorf("unknown proving system type")
					}
					if err != nil {
						return fmt.Errorf("failed to serialize verification key: %v", err)
					}

					err = os.MkdirAll(filepath.Dir(outputFile), 0755)
					if err != nil {
						return fmt.Errorf("failed to create output directory: %v", err)
					}

					var dataToWrite = buf.Bytes()

					err = os.WriteFile(outputFile, dataToWrite, 0644)
					if err != nil {
						return fmt.Errorf("failed to write verification key to file: %v", err)
					}

					logging.Logger().Info().
						Str("file", outputFile).
						Int("bytes", len(dataToWrite)).
						Msg("Verification key exported successfully")

					return nil
				},
			},
			{
				Name:  "download",
				Usage: "Download proving keys",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "run-mode",
						Usage: "Download keys for specific run mode (rpc, forester, forester-test, full, full-test, local-rpc)",
						Value: "local-rpc",
					},
					&cli.StringSliceFlag{
						Name:  "circuit",
						Usage: "Download keys for specific circuits (inclusion, non-inclusion, combined, append, update, append-test, update-test, address-append, address-append-test)",
					},
					&cli.StringFlag{
						Name:  "keys-dir",
						Usage: "Directory where key files will be stored",
						Value: "./proving-keys/",
					},
					&cli.StringFlag{
						Name:  "download-url",
						Usage: "Base URL for downloading key files",
						Value: common.DefaultBaseURL,
					},
					&cli.IntFlag{
						Name:  "max-retries",
						Usage: "Maximum number of retries for downloading keys",
						Value: common.DefaultMaxRetries,
					},
					&cli.BoolFlag{
						Name:  "verify-only",
						Usage: "Only verify existing keys without downloading",
						Value: false,
					},
				},
				Action: func(context *cli.Context) error {
					circuits := context.StringSlice("circuit")
					runMode, err := parseRunMode(context.String("run-mode"))
					if err != nil {
						return err
					}

					keysDirPath := context.String("keys-dir")
					verifyOnly := context.Bool("verify-only")

					// Configure download settings
					downloadConfig := &common.DownloadConfig{
						BaseURL:       context.String("download-url"),
						MaxRetries:    context.Int("max-retries"),
						RetryDelay:    common.DefaultRetryDelay,
						MaxRetryDelay: common.DefaultMaxRetryDelay,
						AutoDownload:  !verifyOnly,
					}

					logging.Logger().Info().
						Str("run_mode", string(runMode)).
						Strs("circuits", circuits).
						Str("keys_dir", keysDirPath).
						Bool("verify_only", verifyOnly).
						Str("download_url", downloadConfig.BaseURL).
						Int("max_retries", downloadConfig.MaxRetries).
						Msg("Download configuration")

					// Get required keys
					keys := common.GetKeys(keysDirPath, runMode, circuits)

					if len(keys) == 0 {
						return fmt.Errorf("no keys to download for run-mode=%s circuits=%v", runMode, circuits)
					}

					logging.Logger().Info().
						Int("total_keys", len(keys)).
						Msg("Starting key download/verification")

					// Download/verify keys
					if err := common.EnsureKeysExist(keys, downloadConfig); err != nil {
						return fmt.Errorf("failed to ensure keys exist: %w", err)
					}

					if verifyOnly {
						logging.Logger().Info().Msg("All keys verified successfully")
					} else {
						logging.Logger().Info().Msg("All keys downloaded and verified successfully")
					}

					return nil
				},
			},
			{
				Name: "start",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "json-logging", Usage: "enable JSON logging", Required: false},
					&cli.StringFlag{Name: "prover-address", Usage: "address for the prover server", Value: "0.0.0.0:5000", Required: false},
					&cli.StringFlag{Name: "metrics-address", Usage: "address for the metrics server", Value: "0.0.0.0:9998", Required: false},
					&cli.StringFlag{Name: "keys-dir", Usage: "Directory where key files are stored", Value: "./proving-keys/", Required: false},
					&cli.StringSliceFlag{
						Name:  "circuit",
						Usage: "Specify the circuits to enable (inclusion, non-inclusion, combined, append, update, append-test, update-test, address-append, address-append-test)",
					},
					&cli.StringFlag{
						Name:  "preload-keys",
						Usage: "Preload keys: none (lazy load all), all (preload everything), or a run mode (rpc, forester, forester-test, full, full-test, local-rpc)",
						Value: "none",
					},
					&cli.StringSliceFlag{
						Name:  "preload-circuits",
						Usage: "Preload specific circuits, e.g.: update,append,batch_update_32_500,batch_append_32_500)",
					},
					&cli.StringFlag{
						Name:  "redis-url",
						Usage: "Redis URL for queue processing (e.g., redis://localhost:6379)",
						Value: "",
					},
					&cli.BoolFlag{
						Name:  "queue-only",
						Usage: "Run only queue workers (no HTTP server)",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "server-only",
						Usage: "Run only HTTP server (no queue workers)",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "auto-download",
						Usage: "Automatically download missing key files",
						Value: false,
					},
					&cli.StringFlag{
						Name:  "download-url",
						Usage: "Base URL for downloading key files",
						Value: common.DefaultBaseURL,
					},
					&cli.IntFlag{
						Name:  "download-max-retries",
						Usage: "Maximum number of retries for downloading keys",
						Value: common.DefaultMaxRetries,
					},
				},
				Action: func(context *cli.Context) error {
					if context.Bool("json-logging") {
						logging.SetJSONOutput()
					}

					var keysDirPath = context.String("keys-dir")

					// Configure download settings
					downloadConfig := &common.DownloadConfig{
						BaseURL:       context.String("download-url"),
						MaxRetries:    context.Int("download-max-retries"),
						RetryDelay:    common.DefaultRetryDelay,
						MaxRetryDelay: common.DefaultMaxRetryDelay,
						AutoDownload:  context.Bool("auto-download"),
					}

					keyManager := common.NewLazyKeyManager(keysDirPath, downloadConfig)

					preloadKeys := context.String("preload-keys")
					preloadCircuits := context.StringSlice("preload-circuits")

					logging.Logger().Info().
						Str("preload_keys", preloadKeys).
						Strs("preload_circuits", preloadCircuits).
						Str("keys_dir", keysDirPath).
						Msg("Initializing lazy key manager")

					// Preload keys asynchronously to allow health checks to pass during startup
					preloadAsync := func() {
						if preloadKeys == "all" {
							logging.Logger().Info().Msg("Preloading all keys (async)")
							if err := keyManager.PreloadAll(); err != nil {
								logging.Logger().Error().Err(err).Msg("Failed to preload all keys")
							}
						} else if preloadKeys != "none" {
							preloadRunMode, err := parseRunMode(preloadKeys)
							if err != nil {
								logging.Logger().Error().Err(err).Str("value", preloadKeys).Msg("Invalid --preload-keys value")
							} else {
								logging.Logger().Info().Str("run_mode", string(preloadRunMode)).Msg("Preloading keys for run mode (async)")
								if err := keyManager.PreloadForRunMode(preloadRunMode); err != nil {
									logging.Logger().Error().Err(err).Msg("Failed to preload keys for run mode")
								}
							}
						}

						if len(preloadCircuits) > 0 {
							logging.Logger().Info().Strs("circuits", preloadCircuits).Msg("Preloading specific circuits (async)")
							if err := keyManager.PreloadCircuits(preloadCircuits); err != nil {
								logging.Logger().Error().Err(err).Msg("Failed to preload circuits")
							}
						}

						stats := keyManager.GetStats()
						logging.Logger().Info().
							Interface("stats", stats).
							Msg("Key preloading completed")
					}

					redisURL := context.String("redis-url")
					if redisURL == "" {
						redisURL = os.Getenv("REDIS_URL")
					}

					queueOnly := context.Bool("queue-only")
					serverOnly := context.Bool("server-only")

					enableQueue := redisURL != "" && !serverOnly
					enableServer := !queueOnly

					if os.Getenv("QUEUE_MODE") == "true" {
						enableQueue = true
						if os.Getenv("SERVER_MODE") != "true" {
							enableServer = false
						}
					}

					logging.Logger().Info().
						Bool("enable_queue", enableQueue).
						Bool("enable_server", enableServer).
						Str("redis_url", redisURL).
						Msg("Starting ZK Prover service")

					var workers []server.QueueWorker
					var redisQueue *server.RedisQueue
					var instance server.RunningJob

					if enableQueue {
						if redisURL == "" {
							return fmt.Errorf("Redis URL is required for queue mode. Use --redis-url or set REDIS_URL environment variable")
						}

						var err error
						redisQueue, err = server.NewRedisQueue(redisURL)
						if err != nil {
							return fmt.Errorf("failed to connect to Redis: %w", err)
						}

						startCleanupRoutines(redisQueue)

						if stats, err := redisQueue.GetQueueStats(); err == nil {
							logging.Logger().Info().Interface("initial_queue_stats", stats).Msg("Redis connection successful")
						}

						logging.Logger().Info().Msg("Starting queue workers")

						enabledCircuits := context.StringSlice("circuit")
						enabledCircuitsMap := make(map[string]bool)
						for _, c := range enabledCircuits {
							enabledCircuitsMap[c] = true
						}

						startAll := len(enabledCircuits) == 0
						var workersStarted []string

						if startAll || enabledCircuitsMap["address-append"] || enabledCircuitsMap["address-append-test"] {
							addressAppendWorker := server.NewAddressAppendQueueWorker(redisQueue, keyManager)
							workers = append(workers, addressAppendWorker)
							go addressAppendWorker.Start()
							workersStarted = append(workersStarted, "address-append")
						}

						logging.Logger().Info().
							Strs("workers_started", workersStarted).
							Msg("Queue workers started")
					}

					if enableServer {
						config := server.Config{
							ProverAddress:  context.String("prover-address"),
							MetricsAddress: context.String("metrics-address"),
						}

						if redisQueue != nil {
							instance = server.RunWithQueue(&config, redisQueue, keyManager)
							logging.Logger().Info().
								Str("prover_address", config.ProverAddress).
								Str("metrics_address", config.MetricsAddress).
								Msg("Started enhanced server with Redis queue support")
						} else {
							instance = server.Run(&config, keyManager)
							logging.Logger().Info().
								Str("prover_address", config.ProverAddress).
								Str("metrics_address", config.MetricsAddress).
								Msg("Started standard server without queue support")
						}
					}

					if !enableServer && !enableQueue {
						return fmt.Errorf("at least one of server or queue mode must be enabled")
					}

					go preloadAsync()

					sigint := make(chan os.Signal, 1)
					signal.Notify(sigint, os.Interrupt)
					<-sigint
					logging.Logger().Info().Msg("Received sigint, shutting down")

					if len(workers) > 0 {
						logging.Logger().Info().Msg("Stopping queue workers...")
						for i, worker := range workers {
							logging.Logger().Info().Int("worker_id", i+1).Msg("Stopping worker")
							worker.Stop()
						}

						time.Sleep(2 * time.Second)
						logging.Logger().Info().Msg("All queue workers stopped")
					}

					if enableServer {
						logging.Logger().Info().Msg("Stopping HTTP server...")
						instance.RequestStop()
						instance.AwaitStop()
						logging.Logger().Info().Msg("HTTP server stopped")
					}

					if redisQueue != nil {
						if stats, err := redisQueue.GetQueueStats(); err == nil {
							logging.Logger().Info().Interface("final_queue_stats", stats).Msg("Final queue statistics")
						}
					}

					logging.Logger().Info().Msg("Shutdown completed")
					return nil
				},
			},
			{
				Name: "prove",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "inclusion", Usage: "Run inclusion circuit", Required: true},
					&cli.BoolFlag{Name: "non-inclusion", Usage: "Run non-inclusion circuit", Required: false},
					&cli.BoolFlag{Name: "append", Usage: "Run batch append circuit", Required: false},
					&cli.BoolFlag{Name: "update", Usage: "Run batch update circuit", Required: false},
					&cli.BoolFlag{Name: "address-append", Usage: "Run batch address append circuit", Required: false},
					&cli.StringFlag{Name: "keys-dir", Usage: "Directory where circuit key files are stored", Value: "./proving-keys/", Required: false},
					&cli.StringSliceFlag{Name: "keys-file", Aliases: []string{"k"}, Value: cli.NewStringSlice(), Usage: "Proving system file"},
					&cli.StringSliceFlag{
						Name:  "circuit",
						Usage: "Specify the circuits to enable (inclusion, non-inclusion, combined, append, update, append-test, update-test, address-append, address-append-test)",
						Value: cli.NewStringSlice("inclusion", "non-inclusion", "combined", "append", "update", "append-test", "update-test", "address-append", "address-append-test"),
					},
					&cli.StringFlag{
						Name:  "run-mode",
						Usage: "Specify the running mode (forester, forester-test, rpc, or full)",
					},
				},
				Action: func(context *cli.Context) error {
					circuits := context.StringSlice("circuit")
					runMode, err := parseRunMode(context.String("run-mode"))
					if err != nil {
						if len(circuits) == 0 {
							return err
						}
					}
					var keysDirPath = context.String("keys-dir")

					psv1, psv2, err := common.LoadKeys(keysDirPath, runMode, circuits)
					if err != nil {
						return err
					}

					if len(psv1) == 0 && len(psv2) == 0 {
						return fmt.Errorf("no proving systems loaded")
					}

					logging.Logger().Info().Msg("Reading params from stdin")
					inputsBytes, err := io.ReadAll(os.Stdin)
					if err != nil {
						return err
					}
					var proof *common.Proof

					if context.Bool("address-append") {
						var params nullifiertree.BatchAddressAppendParameters
						err = json.Unmarshal(inputsBytes, &params)
						if err != nil {
							return err
						}

						for _, provingSystem := range psv2 {
							if provingSystem.TreeHeight == params.TreeHeight && provingSystem.BatchSize == params.BatchSize {
								proof, err = nullifiertree.ProveBatchAddressAppend(provingSystem, &params)
								if err != nil {
									return err
								}
								r, _ := json.Marshal(&proof)
								fmt.Println(string(r))
								break
							}
						}
					}

					return nil
				},
			},
			{
				Name:  "version",
				Usage: "Print the prover version",
				Action: func(context *cli.Context) error {
					fmt.Println(Version)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logging.Logger().Fatal().Err(err).Msg("App failed.")
	}
}

func parseRunMode(runModeString string) (common.RunMode, error) {
	runMode := common.LocalRpc
	switch runModeString {
	case "rpc":
		logging.Logger().Info().Msg("Running in rpc mode")
		runMode = common.Rpc
	case "local-rpc":
		logging.Logger().Info().Msg("Running in local-rpc mode")
		runMode = common.LocalRpc
	case "forester":
		logging.Logger().Info().Msg("Running in forester mode")
		runMode = common.Forester
	case "forester-test":
		logging.Logger().Info().Msg("Running in forester test mode")
		runMode = common.ForesterTest
	case "full":
		logging.Logger().Info().Msg("Running in full mode")
		runMode = common.Full
	case "full-test":
		logging.Logger().Info().Msg("Running in full mode")
		runMode = common.FullTest
	default:
		return "", fmt.Errorf("invalid run mode %s", runModeString)
	}
	return runMode, nil
}

func debugProvingSystemKeys(keysDirPath string, runMode common.RunMode, circuits []string) {
	logging.Logger().Info().
		Str("keysDirPath", keysDirPath).
		Str("runMode", string(runMode)).
		Strs("circuits", circuits).
		Msg("Debug: Loading proving system keys")

	keys := common.GetKeys(keysDirPath, runMode, circuits)
	for _, key := range keys {
		if _, err := os.Stat(key); err != nil {
			if os.IsNotExist(err) {
				logging.Logger().Error().
					Str("key", key).
					Msg("Key file does not exist")
			} else {
				logging.Logger().Error().
					Str("key", key).
					Err(err).
					Msg("Error checking key file")
			}
		} else {
			fileInfo, err := os.Stat(key)
			if err != nil {
				logging.Logger().Error().
					Str("key", key).
					Err(err).
					Msg("Error getting key file info")
			} else {
				logging.Logger().Info().
					Str("key", key).
					Int64("size", fileInfo.Size()).
					Str("mode", fileInfo.Mode().String()).
					Msg("Key file exists")
			}
		}
	}
}

func startCleanupRoutines(redisQueue *server.RedisQueue) {
	logging.Logger().Info().Msg("Running immediate cleanup on startup")

	if err := redisQueue.CleanupOldRequests(); err != nil {
		logging.Logger().Error().
			Err(err).
			Msg("Failed to cleanup old proof requests on startup")
	} else {
		logging.Logger().Info().Msg("Startup cleanup of old proof requests completed")
	}

	if err := redisQueue.CleanupStuckProcessingJobs(); err != nil {
		logging.Logger().Error().
			Err(err).
			Msg("Failed to cleanup stuck processing jobs on startup")
	} else {
		logging.Logger().Info().Msg("Startup cleanup of stuck processing jobs completed")
	}

	if err := redisQueue.CleanupOldFailedJobs(); err != nil {
		logging.Logger().Error().
			Err(err).
			Msg("Failed to cleanup old failed jobs on startup")
	} else {
		logging.Logger().Info().Msg("Startup cleanup of old failed jobs completed")
	}

	if err := redisQueue.CleanupOldResults(); err != nil {
		logging.Logger().Error().
			Err(err).
			Msg("Failed to cleanup old results on startup")
	} else {
		logging.Logger().Info().Msg("Startup cleanup of old results completed")
	}

	if err := redisQueue.CleanupOldResultKeys(); err != nil {
		logging.Logger().Error().
			Err(err).
			Msg("Failed to cleanup old result keys on startup")
	} else {
		logging.Logger().Info().Msg("Startup cleanup of old result keys completed")
	}

	go func() {
		processingTicker := time.NewTicker(10 * time.Second)
		defer processingTicker.Stop()

		logging.Logger().Info().Msg("Started stuck processing jobs cleanup routine (every 10 seconds)")

		for range processingTicker.C {
			if err := redisQueue.CleanupStuckProcessingJobs(); err != nil {
				logging.Logger().Error().
					Err(err).
					Msg("Failed to cleanup stuck processing jobs")
			}
		}
	}()

	// Start cleanup for old proof requests (every 10 minutes)
	go func() {
		requestTicker := time.NewTicker(10 * time.Minute)
		defer requestTicker.Stop()

		logging.Logger().Info().Msg("Started old proof requests cleanup routine (every 10 minutes)")

		for range requestTicker.C {
			if err := redisQueue.CleanupOldRequests(); err != nil {
				logging.Logger().Error().
					Err(err).
					Msg("Failed to cleanup old proof requests")
			} else {
				logging.Logger().Debug().Msg("Old proof requests cleanup completed")
			}
		}
	}()

	// Start cleanup for old failed jobs (every 30 minutes)
	go func() {
		failedTicker := time.NewTicker(30 * time.Minute)
		defer failedTicker.Stop()

		logging.Logger().Info().Msg("Started old failed jobs cleanup routine (every 30 minutes)")

		for range failedTicker.C {
			if err := redisQueue.CleanupOldFailedJobs(); err != nil {
				logging.Logger().Error().
					Err(err).
					Msg("Failed to cleanup old failed jobs")
			} else {
				logging.Logger().Debug().Msg("Old failed jobs cleanup completed")
			}
		}
	}()

	// Start cleanup for old results (every 30 minutes)
	go func() {
		resultTicker := time.NewTicker(30 * time.Minute)
		defer resultTicker.Stop()

		logging.Logger().Info().Msg("Started old results cleanup routine (every 30 minutes)")

		for range resultTicker.C {
			if err := redisQueue.CleanupOldResults(); err != nil {
				logging.Logger().Error().
					Err(err).
					Msg("Failed to cleanup old results")
			} else {
				logging.Logger().Debug().Msg("Old results cleanup completed")
			}

			if err := redisQueue.CleanupOldResultKeys(); err != nil {
				logging.Logger().Error().
					Err(err).
					Msg("Failed to cleanup old result keys")
			} else {
				logging.Logger().Debug().Msg("Old result keys cleanup completed")
			}
		}
	}()
}
