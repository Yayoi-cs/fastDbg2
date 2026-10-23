package display

import "fmt"

func FormatBytes(data []byte) string {
	return fmt.Sprintf("% x", data)
}
