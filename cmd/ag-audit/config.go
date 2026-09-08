package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kstone-sa/aesirguard-audit/internal/securefile"
)

const configVersion = 1

type fileConfig struct {
	Version    int              `json:"version"`
	Input      inputConfig      `json:"input"`
	Sink       sinkConfig       `json:"sink"`
	Checkpoint checkpointConfig `json:"checkpoint"`
	Collection collectionConfig `json:"collection"`
	Mapping    mappingConfig    `json:"mapping"`
	Operations operationsConfig `json:"operations"`
}

type inputConfig struct {
	Path       string `json:"path"`
	Follow     bool   `json:"follow"`
	SourceHost string `json:"source_host"`
	LockFile   string `json:"lock_file"`
}

type sinkConfig struct {
	File string `json:"file"`
	Sync bool   `json:"sync"`
}

type checkpointConfig struct {
	File     string `json:"file"`
	Interval string `json:"interval"`
}

type collectionConfig struct {
	PollInterval          string `json:"poll_interval"`
	EventTimeout          string `json:"event_timeout"`
	RotationDrainInterval string `json:"rotation_drain_interval"`
	MaxLineBytes          int    `json:"max_line_bytes"`
	MaxPendingEvents      int    `json:"max_pending_events"`
	MaxRecordsPerEvent    int    `json:"max_records_per_event"`
	MaxPendingBytes       int    `json:"max_pending_bytes"`
}

type mappingConfig struct {
	RenderMessage bool `json:"render_message"`
}

type operationsConfig struct {
	HeartbeatInterval string `json:"heartbeat_interval"`
}

func loadFileConfig(path string) (fileConfig, error) {
	file, err := openConfigFile(path)
	if err != nil {
		return fileConfig{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config fileConfig
	if err := decoder.Decode(&config); err != nil {
		return fileConfig{}, fmt.Errorf("decode configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fileConfig{}, fmt.Errorf("configuration contains trailing data")
		}
		return fileConfig{}, fmt.Errorf("decode configuration trailer: %w", err)
	}
	if config.Version != configVersion {
		return fileConfig{}, fmt.Errorf("unsupported configuration version %d", config.Version)
	}
	return config, nil
}

func openConfigFile(path string) (*os.File, error) {
	return securefile.OpenReadOnly(path, "configuration", true)
}

func (config fileConfig) apply(options *commandOptions) error {
	options.inputPath = config.Input.Path
	options.follow = config.Input.Follow
	options.sourceHost = config.Input.SourceHost
	options.lockPath = config.Input.LockFile
	options.outputPath = config.Sink.File
	options.syncOutput = config.Sink.Sync
	options.checkpointPath = config.Checkpoint.File
	options.renderMessage = config.Mapping.RenderMessage
	var err error
	if options.checkpointInterval, err = configuredDuration(config.Checkpoint.Interval, options.checkpointInterval); err != nil {
		return fmt.Errorf("checkpoint.interval: %w", err)
	}
	if options.pollInterval, err = configuredDuration(config.Collection.PollInterval, options.pollInterval); err != nil {
		return fmt.Errorf("collection.poll_interval: %w", err)
	}
	if options.eventTimeout, err = configuredDuration(config.Collection.EventTimeout, options.eventTimeout); err != nil {
		return fmt.Errorf("collection.event_timeout: %w", err)
	}
	if options.rotationDrain, err = configuredDuration(config.Collection.RotationDrainInterval, options.rotationDrain); err != nil {
		return fmt.Errorf("collection.rotation_drain_interval: %w", err)
	}
	if options.heartbeatInterval, err = configuredDuration(config.Operations.HeartbeatInterval, options.heartbeatInterval); err != nil {
		return fmt.Errorf("operations.heartbeat_interval: %w", err)
	}
	applyPositiveInt(config.Collection.MaxLineBytes, &options.maxLineBytes)
	applyPositiveInt(config.Collection.MaxPendingEvents, &options.maxPendingEvents)
	applyPositiveInt(config.Collection.MaxRecordsPerEvent, &options.maxRecordsPerEvent)
	applyPositiveInt(config.Collection.MaxPendingBytes, &options.maxPendingBytes)
	return nil
}

func configuredDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func applyPositiveInt(value int, target *int) {
	if value != 0 {
		*target = value
	}
}

func bootstrapConfigPath(args []string) (string, error) {
	var path string
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			break
		}
		if argument == "--config" || argument == "-config" {
			if index+1 >= len(args) {
				return "", fmt.Errorf("config requires a path")
			}
			if path != "" {
				return "", fmt.Errorf("config specified more than once")
			}
			path = args[index+1]
			if path == "" {
				return "", fmt.Errorf("config requires a path")
			}
			index++
			continue
		}
		for _, prefix := range []string{"--config=", "-config="} {
			if len(argument) >= len(prefix) && argument[:len(prefix)] == prefix {
				if path != "" {
					return "", fmt.Errorf("config specified more than once")
				}
				path = argument[len(prefix):]
				if path == "" {
					return "", fmt.Errorf("config requires a path")
				}
			}
		}
	}
	return path, nil
}
