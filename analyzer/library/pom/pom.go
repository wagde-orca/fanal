package pom

import (
	"bytes"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/pom"
)

func init() {
	analyzer.RegisterAnalyzer(&pomLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{"pom.xml"}

type pomLibraryAnalyzer struct{}

func (a pomLibraryAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	parser := pom.NewParser(target.FilePath)
	r := bytes.NewReader(target.Content)

	libs, err := parser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("pom parse error: %w", err)
	}

	return library.ToAnalysisResult(library.Pom, target.FilePath, libs), nil
}

func (a pomLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a pomLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePom
}

func (a pomLibraryAnalyzer) Version() int {
	return version
}
