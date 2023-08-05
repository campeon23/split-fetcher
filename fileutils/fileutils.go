package fileutils

import "os"

func pathExists(path string) bool {
    _, err := os.Stat(path)
    return !os.IsNotExist(err)
}