package utils

import "runtime"

func IntPtr(i int) *int {
	return &i
}

// GetOperatingSystem 返回当前操作系统的名称
func GetOperatingSystem() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "darwin":
		return "MacOS"
	default:
		return "Other"
	}
}
