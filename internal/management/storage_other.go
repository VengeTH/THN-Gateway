//go:build !linux

package management

func readStorageStats(sys *SystemMetrics) {
	// Fallback placeholder on non-Linux
	sys.StorageTotalBytes = 64 * 1024 * 1024 * 1024
	sys.StorageUsedBytes = 12 * 1024 * 1024 * 1024
	sys.StorageAvailableBytes = 52 * 1024 * 1024 * 1024
}
