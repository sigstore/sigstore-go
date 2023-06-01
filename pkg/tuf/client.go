package tuf

import (
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	tufclient "github.com/theupdateframework/go-tuf/client"
)

const TrustedRootTUFPath = "trusted_root.json"

type Writer struct {
	Bytes []byte
}

func (w *Writer) Write(b []byte) (int, error) {
	w.Bytes = append(w.Bytes, b...)
	return len(b), nil
}

func (w Writer) Delete() error {
	return nil
}

type Signed struct {
	Version int `json:"version"`
}
type RootMeta struct {
	Signed Signed `json:"signed"`
}

func GetTrustedrootJSON(tufRootURL, workPath string) (trustedrootJSON []byte, err error) {
	tufRemoteOptions := &tufclient.HTTPRemoteOptions{
		MetadataPath: "",
		TargetsPath:  "targets",
	}

	tufRemoteStore, err := tufclient.HTTPRemoteStore(fmt.Sprintf("https://%s", tufRootURL), tufRemoteOptions, nil)
	if err != nil {
		return nil, err
	}

	tufLocalStore := tufclient.MemoryLocalStore()
	var rootJSON json.RawMessage

	tufPath := filepath.Join(workPath, tufRootURL)

	err = os.MkdirAll(tufPath, 0755)
	if err != nil {
		return nil, err
	}

	rootJSONPath := filepath.Join(tufPath, "root.json")

	if _, err := os.Stat(rootJSONPath); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("No root.json found at %s", tufPath)
	}

	root, err := os.ReadFile(rootJSONPath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(root, &rootJSON)
	if err != nil {
		return nil, err
	}
	err = tufLocalStore.SetMeta("root.json", rootJSON)
	if err != nil {
		return nil, err
	}

	tufClient := tufclient.NewClient(tufLocalStore, tufRemoteStore)

	oldMetaJSON, err := tufLocalStore.GetMeta()
	if err != nil {
		return nil, err
	}

	oldMeta := RootMeta{}
	err = json.Unmarshal(oldMetaJSON["root.json"], &oldMeta)
	if err != nil {
		return nil, err
	}

	targetFiles, err := tufClient.Update()
	if err != nil {
		return nil, err
	}

	// Check to see if there's a new root.json, and if so write it to disk
	newMetaJSON, err := tufLocalStore.GetMeta()
	if err != nil {
		return nil, err
	}

	newMeta := RootMeta{}
	err = json.Unmarshal(newMetaJSON["root.json"], &newMeta)
	if err != nil {
		return nil, err
	}

	if newMeta.Signed.Version > oldMeta.Signed.Version {
		err = os.WriteFile(rootJSONPath, newMetaJSON["root.json"], 0600)
		if err != nil {
			return nil, err
		}
	}

	trustedrootMeta, ok := targetFiles[TrustedRootTUFPath]
	if !ok {
		return nil, fmt.Errorf("Unable to find %s via TUF", TrustedRootTUFPath)
	}

	trustedrootPath := filepath.Join(tufPath, TrustedRootTUFPath)

	// See if trustedroot is on disk; if so check its hash against TUF
	if _, err := os.Stat(trustedrootPath); !errors.Is(err, os.ErrNotExist) {
		trustedroot, err := os.ReadFile(trustedrootPath)
		if err == nil {
			hash := sha512.Sum512([]byte(trustedroot))

			if hash == [64]byte(trustedrootMeta.FileMeta.Hashes["sha512"]) {
				return []byte(trustedroot), nil
			}
		}
	}

	// What's on disk didn't match, so download from TUF (and write to disk)
	writer := &Writer{
		Bytes: make([]byte, 0),
	}

	err = tufClient.Download(TrustedRootTUFPath, writer)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(trustedrootPath, writer.Bytes, 0600)
	if err != nil {
		return nil, err
	}

	return writer.Bytes, nil
}
