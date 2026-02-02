package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	statusEncrypted   = "encrypted"
	statusDecrypted   = "decrypted"
	encryptedSuffix   = "_encryptedFile"
	defaultManifest   = "./files.txt"
	defaultUnlockHour = 19
	defaultFilePerm   = 0600
	manifestFilePerm  = 0600
)

var errUsage = errors.New("usage")

type Config struct {
	Command      string
	ManifestPath string
	Key          []byte
	UnlockHour   int
	Pause        bool
	AllowLegacy  bool
}

type FileRecord struct {
	Filename string
	FileDir  string
	Status   string
}

type ManifestLine struct {
	Raw    string
	Record *FileRecord
}

func main() {
	cfg, err := parseConfig(os.Args)
	if err != nil {
		if errors.Is(err, errUsage) {
			printUsage()
			if err != errUsage {
				fmt.Fprintln(os.Stderr, "Error:", err)
			}
			os.Exit(2)
		}
		log.Fatal(err)
	}

	if err := run(cfg); err != nil {
		log.Fatal(err)
	}

	if cfg.Pause {
		fmt.Print("Press 'Enter' to continue...")
		_, _ = fmt.Fscanln(os.Stdin)
	}
}

func parseConfig(args []string) (Config, error) {
	if len(args) < 2 {
		return Config{}, errUsage
	}

	command := args[1]
	if command != "encrypt" && command != "decrypt" {
		return Config{}, errUsage
	}

	flagSet := flag.NewFlagSet(command, flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)

	manifest := flagSet.String("manifest", defaultManifest, "path to manifest file")
	keyStr := flagSet.String("key", "", "encryption key (16/24/32 bytes). If empty, uses ZENCONTROL_KEY env")
	unlockHour := flagSet.Int("unlock-hour", defaultUnlockHour, "local hour (0-23) after which decryption is allowed")
	pause := flagSet.Bool("pause", false, "pause for Enter before exit")
	allowLegacy := flagSet.Bool("allow-legacy", false, "allow legacy AES-CFB decrypt for older files")

	if err := flagSet.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Config{}, errUsage
		}
		return Config{}, fmt.Errorf("%w: %v", errUsage, err)
	}

	if *unlockHour < 0 || *unlockHour > 23 {
		return Config{}, fmt.Errorf("invalid -unlock-hour: %d (expected 0-23)", *unlockHour)
	}

	keyValue := strings.TrimSpace(*keyStr)
	if keyValue == "" {
		keyValue = strings.TrimSpace(os.Getenv("ZENCONTROL_KEY"))
	}
	if keyValue == "" {
		return Config{}, errors.New("missing encryption key; provide -key or set ZENCONTROL_KEY")
	}
	key := []byte(keyValue)
	if err := validateKeyLength(key); err != nil {
		return Config{}, err
	}

	return Config{
		Command:      command,
		ManifestPath: *manifest,
		Key:          key,
		UnlockHour:   *unlockHour,
		Pause:        *pause,
		AllowLegacy:  *allowLegacy,
	}, nil
}

func run(cfg Config) error {
	now := time.Now()
	log.Printf("time=%s", now.Format(time.RFC3339))

	lines, err := loadManifest(cfg.ManifestPath)
	if err != nil {
		return err
	}

	changed := false
	for _, line := range lines {
		if line.Record == nil {
			continue
		}

		updatedStatus, updated, err := processFile(cfg.Command, cfg.Key, *line.Record, now, cfg.UnlockHour, cfg.AllowLegacy)
		if err != nil {
			log.Printf("file=%s: %v", line.Record.Filename, err)
			continue
		}
		if updated {
			line.Record.Status = updatedStatus
			changed = true
		}
	}

	if changed {
		if err := writeManifest(cfg.ManifestPath, lines); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
	}

	return nil
}

func loadManifest(path string) ([]ManifestLine, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lines []ManifestLine
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, ManifestLine{Raw: raw})
			continue
		}

		rec, err := parseManifestLine(raw)
		if err != nil {
			return nil, fmt.Errorf("manifest line %d: %w", lineNum, err)
		}
		lines = append(lines, ManifestLine{Record: rec})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func parseManifestLine(line string) (*FileRecord, error) {
	parts := strings.SplitN(line, "|", 3)
	if len(parts) != 3 {
		return nil, errors.New("expected format: filedir|filename|status")
	}
	fileDir := strings.TrimSpace(parts[0])
	filename := strings.TrimSpace(parts[1])
	status := strings.TrimSpace(parts[2])

	rec := &FileRecord{
		Filename: filename,
		FileDir:  fileDir,
		Status:   status,
	}
	if err := validateRecord(*rec); err != nil {
		return nil, err
	}

	return rec, nil
}

func writeManifest(path string, lines []ManifestLine) error {
	var builder strings.Builder
	for _, line := range lines {
		if line.Record == nil {
			builder.WriteString(line.Raw)
			builder.WriteByte('\n')
			continue
		}
		builder.WriteString(formatManifestLine(*line.Record))
		builder.WriteByte('\n')
	}
	return writeFileAtomic(path, []byte(builder.String()), manifestFilePerm)
}

func formatManifestLine(rec FileRecord) string {
	return fmt.Sprintf("%s|%s|%s", rec.FileDir, rec.Filename, rec.Status)
}

func validateRecord(rec FileRecord) error {
	if rec.Filename == "" {
		return errors.New("missing filename")
	}
	if rec.FileDir == "" {
		return errors.New("missing filedir")
	}
	if rec.Status != statusEncrypted && rec.Status != statusDecrypted {
		return fmt.Errorf("invalid status %q", rec.Status)
	}
	return nil
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  ZenControl encrypt [flags]")
	fmt.Println("  ZenControl decrypt [flags]")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println("  -manifest     path to manifest file (default ./files.txt)")
	fmt.Println("  -key          encryption key (16/24/32 bytes); or set ZENCONTROL_KEY")
	fmt.Println("  -unlock-hour  local hour (0-23) after which decryption is allowed (default 19)")
	fmt.Println("  -pause        pause for Enter before exit")
	fmt.Println("  -allow-legacy allow legacy AES-CFB decrypt for older files")
}

func processFile(command string, key []byte, rec FileRecord, now time.Time, unlockHour int, allowLegacy bool) (string, bool, error) {
	plainPath, encryptedPath := buildPaths(rec)

	switch command {
	case "encrypt":
		if rec.Status != statusDecrypted {
			return "", false, nil
		}

		msg, err := os.ReadFile(plainPath)
		if err != nil {
			return "", false, fmt.Errorf("read file: %w", err)
		}

		encrypted, err := encrypt(key, msg)
		if err != nil {
			return "", false, fmt.Errorf("encrypt: %w", err)
		}

		if err := writeFileAtomic(encryptedPath, []byte(encrypted), defaultFilePerm); err != nil {
			return "", false, fmt.Errorf("write encrypted file: %w", err)
		}

		if err := deleteFile(plainPath); err != nil {
			return "", false, fmt.Errorf("delete plaintext: %w", err)
		}

		log.Printf("encrypted %s", plainPath)
		return statusEncrypted, true, nil

	case "decrypt":
		if rec.Status != statusEncrypted {
			return "", false, nil
		}
		if now.Hour() < unlockHour {
			log.Printf("skip %s (locked until %02d:00 local time)", rec.Filename, unlockHour)
			return "", false, nil
		}

		msg, err := os.ReadFile(encryptedPath)
		if err != nil {
			return "", false, fmt.Errorf("read encrypted file: %w", err)
		}

		decrypted, err := decrypt(key, string(msg))
		if err != nil {
			if allowLegacy {
				legacyPlain, legacyErr := decryptLegacyCFB(key, string(msg))
				if legacyErr != nil {
					return "", false, fmt.Errorf("decrypt failed (gcm=%v, legacy=%v)", err, legacyErr)
				}
				decrypted = legacyPlain
				log.Printf("legacy decrypt used for %s", encryptedPath)
			} else {
				return "", false, fmt.Errorf("decrypt: %w", err)
			}
		}

		if err := writeFileAtomic(plainPath, []byte(decrypted), defaultFilePerm); err != nil {
			return "", false, fmt.Errorf("write plaintext: %w", err)
		}
		if err := deleteFile(encryptedPath); err != nil {
			return "", false, fmt.Errorf("delete encrypted: %w", err)
		}

		log.Printf("decrypted %s", plainPath)
		return statusDecrypted, true, nil
	default:
		return "", false, fmt.Errorf("unknown command: %s", command)
	}
}

func buildPaths(rec FileRecord) (string, string) {
	dir := filepath.Clean(rec.FileDir)
	plain := filepath.Join(dir, rec.Filename)
	encrypted := filepath.Join(dir, rec.Filename+encryptedSuffix)
	return plain, encrypted
}

func deleteFile(path string) error {
	return os.Remove(path)
}

func validateKeyLength(key []byte) error {
	switch len(key) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("invalid key length %d (must be 16, 24, or 32 bytes)", len(key))
	}
}

func encrypt(key []byte, message []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	cipherText := gcm.Seal(nil, nonce, message, nil)
	payload := append(nonce, cipherText...)
	return base64.StdEncoding.EncodeToString(payload), nil
}

func decrypt(key []byte, securemess string) (string, error) {
	payload, err := decodeBase64(securemess)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce := payload[:gcm.NonceSize()]
	cipherText := payload[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func decryptLegacyCFB(key []byte, securemess string) (string, error) {
	cipherText, err := decodeBase64(securemess)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(cipherText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return string(cipherText), nil
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if data, err := base64.StdEncoding.DecodeString(value); err == nil {
		return data, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}
