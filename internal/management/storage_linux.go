//go:build linux

package management

import "syscall"

func readStorageStats(sys *SystemMetrics) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		sys.StorageTotalBytes = stat.Blocks * uint64(stat.Bsize)
		sys.StorageAvailableBytes = stat.Bavail * uint64(stat.Bsize)
		if sys.StorageTotalBytes > sys.StorageAvailableBytes {
			sys.StorageUsedBytes = sys.StorageTotalBytes - sys.StorageAvailableBytes
		}
	}
}
