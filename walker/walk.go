package walker

import (
	"os"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/log"

	"github.com/aquasecurity/fanal/utils"
)

var (
	ignoreDirs         = []string{".git", "node_modules", "vendor"}
	ignoreSystemDirs   = []string{"proc", "sys"}
	ignoreFileSuffixes = []string{".sys"}
)

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error

func isIgnored(filePath string, fi os.FileInfo) bool {
	filePath = strings.TrimLeft(filePath, "/")
	for _, path := range strings.Split(filePath, utils.PathSeparator) {
		if utils.StringInSlice(path, ignoreDirs) {
			return true
		}
	}

	// skip system directories such as /sys and /proc
	for _, ignore := range ignoreSystemDirs {
		if strings.HasPrefix(filePath, ignore) {
			return true
		}
	}

	// skip huge system files like pagefile.sys
	// WAGDE TODO add this list as a param (config file)
	for _, ignore := range ignoreFileSuffixes {
		if strings.HasSuffix(filePath, ignore) {
			log.Logger.Debugf("WalkDir: ignoring file %s", filePath)
			return true
		}
	}

	// WAGDE TODO change 200m top param
	if fi.Size() > 200000000 {
		log.Logger.Debugf("WalkDir: ignoring file %s %d", filePath, fi.Size())
		return true
	}

	return false
}
