package fs

import (
	"errors"
	"fmt"
	"os"
)

func ReadText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "<missing>"
		}
		if errors.Is(err, os.ErrPermission) {
			return fmt.Sprintf("<permission denied: %v>", err)
		}
		return fmt.Sprintf("<error: %v>", err)
	}
	return string(data)
}

func WriteText(path string, data string) error {
	return os.WriteFile(path, []byte(data), 0644)
}
