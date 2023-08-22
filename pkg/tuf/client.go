package tuf

import (
	"crypto/sha256"
	"crypto/sha512"
	"embed"
	"encoding/json"
	"fmt"
	"path"

	tufclient "github.com/theupdateframework/go-tuf/client"
	filejsonstore "github.com/theupdateframework/go-tuf/client/filejsonstore"
)

//go:embed repository
var embeddedRepos embed.FS

const TrustedRootTUFPath = "trusted_root.json"
const RootTUFPath = "root.json"

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

func GetTrustedrootJSON(tufRootURL, workPath string) (trustedrootJSON []byte, err error) {
	// Ensure we have a RootTUFPath file for this TUF URL
	tufPath := path.Join(workPath, tufRootURL)

	fileJSONStore, err := filejsonstore.NewFileJSONStore(tufPath)
	if err != nil {
		return nil, err
	}

	tufMetaMap, err := fileJSONStore.GetMeta()
	if err != nil {
		return nil, err
	}

	_, ok := tufMetaMap[RootTUFPath]
	if !ok {
		// There isn't a RootTUFPath for this TUF URL, so see if the library has one embedded
		_, err = checkEmbedded(tufRootURL, fileJSONStore)

		if err != nil {
			return nil, err
		}
	}

	// Now that we have fileJSONStore, create a tufclient and check remote for updates
	tufRemoteOptions := &tufclient.HTTPRemoteOptions{
		MetadataPath: "",
		TargetsPath:  "targets",
		Retries:      tufclient.DefaultHTTPRetries,
	}

	tufRemoteStore, err := tufclient.HTTPRemoteStore(fmt.Sprintf("https://%s", tufRootURL), tufRemoteOptions, nil)
	if err != nil {
		return nil, err
	}

	tufClient := tufclient.NewClient(fileJSONStore, tufRemoteStore)
	targetFiles, err := tufClient.Update()
	if err != nil {
		return nil, err
	}

	// Now that we've updated, see if remote trustedroot metadata matches local disk
	trustedrootMeta, ok := targetFiles[TrustedRootTUFPath]
	if !ok {
		return nil, fmt.Errorf("Unable to find %s via TUF", TrustedRootTUFPath)
	}

	trustedroot, ok := tufMetaMap[TrustedRootTUFPath]
	if ok {
		for hashfunc, hash := range trustedrootMeta.FileMeta.Hashes {
			switch hashfunc {
			case "sha512":
				if len(hash) != 64 {
					return nil, fmt.Errorf("sha512 hash for %s is not 64 bytes", TrustedRootTUFPath)
				}
				if sha512.Sum512([]byte(trustedroot)) == [64]byte(hash) {
					return trustedroot, nil
				}
			case "sha256":
				if len(hash) != 32 {
					return nil, fmt.Errorf("sha256 hash for %s is not 32 bytes", TrustedRootTUFPath)
				}
				if sha256.Sum256([]byte(trustedroot)) == [32]byte(hash) {
					return trustedroot, nil
				}
			}
		}
	}

	// What's on disk didn't match, so download from TUF remote (and cache it to disk)
	writer := &Writer{
		Bytes: make([]byte, 0),
	}

	err = tufClient.Download(TrustedRootTUFPath, writer)
	if err != nil {
		return nil, err
	}

	err = fileJSONStore.SetMeta(TrustedRootTUFPath, writer.Bytes)
	if err != nil {
		return nil, err
	}

	return writer.Bytes, nil
}

func checkEmbedded(tufRootURL string, fileJSONStore *filejsonstore.FileJSONStore) (json.RawMessage, error) {
	embeddedRootPath := path.Join("repository", tufRootURL, RootTUFPath)

	root, err := embeddedRepos.ReadFile(embeddedRootPath)
	if err != nil {
		return nil, err
	}

	err = fileJSONStore.SetMeta(RootTUFPath, root)
	if err != nil {
		return nil, err
	}

	return root, nil
}
