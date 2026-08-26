package ipc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"sandbox/sandbox/config"
)

const maxSnapshotSize = 1 << 20

func WriteConfig(file *os.File, cfg config.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode configuration snapshot: %w", err)
	}
	if len(data) > maxSnapshotSize {
		return fmt.Errorf("configuration snapshot exceeds %d-byte limit", maxSnapshotSize)
	}
	frame := make([]byte, 4+len(data))
	frame[0] = byte(len(data) >> 24)
	frame[1] = byte(len(data) >> 16)
	frame[2] = byte(len(data) >> 8)
	frame[3] = byte(len(data))
	copy(frame[4:], data)
	if err := writeFull(file, frame); err != nil {
		return fmt.Errorf("send configuration snapshot: %w", err)
	}
	return nil
}

func ReadConfig(file *os.File) (config.Config, error) {
	var header [4]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return config.Config{}, fmt.Errorf("read configuration snapshot length: %w", err)
	}
	length := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length <= 0 || length > maxSnapshotSize {
		return config.Config{}, fmt.Errorf("invalid configuration snapshot length %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(file, data); err != nil {
		return config.Config{}, fmt.Errorf("read configuration snapshot: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg config.Config
	if err := decoder.Decode(&cfg); err != nil {
		return config.Config{}, fmt.Errorf("decode configuration snapshot: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return config.Config{}, fmt.Errorf("configuration snapshot has trailing data")
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, fmt.Errorf("invalid configuration snapshot: %w", err)
	}
	return cfg, nil
}

func writeFull(file *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
