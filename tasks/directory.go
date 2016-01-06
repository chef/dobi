package tasks

import (
	"os"
	"path/filepath"
	"time"
)

// TODO: use go routines to speed this up
// TODO: move this
// lastModified returns the latest modified time for all the files in all of
// the directories
func lastModified(dirs ...string) (time.Time, error) {
	var latest time.Time

	// TODO: does this error contain enough context?
	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	}

	for _, dir := range dirs {
		if err := filepath.Walk(dir, walker); err != nil {
			return latest, err
		}
	}
	return latest, nil
}
