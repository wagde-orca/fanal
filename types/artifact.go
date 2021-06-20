package types

import (
	"time"

	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

type OS struct {
	Family string
	Name   string
}

type Layer struct {
	Digest string `json:",omitempty"`
	DiffID string `json:",omitempty"`
}

type Package struct {
	Name            string `json:",omitempty" schema:"-"`
	Version         string `json:",omitempty" schema:"-"`
	Release         string `json:",omitempty" schema:"release,omitempty"`
	Epoch           int    `json:",omitempty" schema:"epoch,omitempty"`
	Arch            string `json:",omitempty" schema:"arch,omitempty"`
	SrcName         string `json:",omitempty" schema:"src_name,omitempty"`
	SrcVersion      string `json:",omitempty" schema:"src_version,omitempty"`
	SrcRelease      string `json:",omitempty" schema:"src_release,omitempty"`
	SrcEpoch        int    `json:",omitempty" schema:"src_epoch,omitempty"`
	Modularitylabel string `json:",omitempty" schema:"modularity_label,omitempty"`
	Layer           Layer  `json:",omitempty" schema:"-"`
}

type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

type PackageInfo struct {
	FilePath string
	Packages []Package
}

type LibraryInfo struct {
	Library godeptypes.Library `json:",omitempty"`
	Layer   Layer              `json:",omitempty"`
}

type Application struct {
	Type      string
	FilePath  string
	Libraries []LibraryInfo
}

type Config struct {
	Type     string
	FilePath string
	Content  interface{}
}

// ArtifactType represents a type of artifact
type ArtifactType string

const (
	ArtifactContainerImage   ArtifactType = "container_image"
	ArtifactFilesystem       ArtifactType = "filesystem"
	ArtifactRemoteRepository ArtifactType = "repository"
)

// ArtifactReference represents a reference of container image, local filesystem and repository
type ArtifactReference struct {
	Name        string // image name, tar file name, directory or repository name
	Type        ArtifactType
	ID          string
	BlobIDs     []string
	RepoTags    []string
	RepoDigests []string
}

// ArtifactInfo is stored in cache
type ArtifactInfo struct {
	SchemaVersion int
	Architecture  string
	Created       time.Time
	DockerVersion string
	OS            string

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package `json:",omitempty"`
}

// BlobInfo is stored in cache
type BlobInfo struct {
	SchemaVersion     int
	Digest            string             `json:",omitempty"`
	DiffID            string             `json:",omitempty"`
	OS                *OS                `json:",omitempty"`
	PackageInfos      []PackageInfo      `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	OpaqueDirs        []string           `json:",omitempty"`
	WhiteoutFiles     []string           `json:",omitempty"`
	Size              int                `json:",omitempty"`
}

// ArtifactDetail is generated by applying blobs
type ArtifactDetail struct {
	OS                *OS                `json:",omitempty"`
	Packages          []Package          `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Size              int                `json:",omitempty"`

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages []Package `json:",omitempty"`
}