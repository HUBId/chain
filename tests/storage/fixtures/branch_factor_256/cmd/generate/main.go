package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/ava-labs/avalanchego/database/memdb"
	"github.com/ava-labs/avalanchego/x/merkledb"
)

const (
	outputFile         = "hashlists.json"
	defaultKeyMinLen   = 4
	defaultKeyMaxLen   = 32
	defaultValueMinLen = 1
	defaultValueMaxLen = 64
)

type operation struct {
	Type  string  `json:"type"`
	Key   string  `json:"key"`
	Value *string `json:"value,omitempty"`
	Root  string  `json:"root"`
}

type fixture struct {
	Name        string      `json:"name"`
	Seed        int64       `json:"seed"`
	Description string      `json:"description"`
	Operations  []operation `json:"operations"`
}

type fixtureFile struct {
	GeneratedAt   time.Time `json:"generated_at"`
	BranchFactor  int       `json:"branch_factor"`
	Hasher        string    `json:"hasher"`
	Fixtures      []fixture `json:"fixtures"`
	KeyLength     [2]int    `json:"key_length_bytes"`
	ValueLength   [2]int    `json:"value_length_bytes"`
	OperationNote string    `json:"operation_note"`
}

type generator struct {
	rand        *rand.Rand
	keyMinLen   int
	keyMaxLen   int
	valueMinLen int
	valueMaxLen int
	existing    map[string]struct{}
	keys        []string
}

func newGenerator(seed int64, keyMin, keyMax, valueMin, valueMax int) *generator {
	return &generator{
		rand:        rand.New(rand.NewSource(seed)),
		keyMinLen:   keyMin,
		keyMaxLen:   keyMax,
		valueMinLen: valueMin,
		valueMaxLen: valueMax,
		existing:    make(map[string]struct{}),
		keys:        make([]string, 0),
	}
}

func (g *generator) hasKeys() bool {
	return len(g.keys) > 0
}

func (g *generator) randomKeyBytes() []byte {
	length := g.keyMinLen + g.rand.Intn(g.keyMaxLen-g.keyMinLen+1)
	key := make([]byte, length)
	if _, err := g.rand.Read(key); err != nil {
		panic(fmt.Errorf("failed to draw random key: %w", err))
	}
	return key
}

func (g *generator) randomValueBytes() []byte {
	length := g.valueMinLen + g.rand.Intn(g.valueMaxLen-g.valueMinLen+1)
	val := make([]byte, length)
	if _, err := g.rand.Read(val); err != nil {
		panic(fmt.Errorf("failed to draw random value: %w", err))
	}
	return val
}

func (g *generator) addKey(hexKey string) {
	g.existing[hexKey] = struct{}{}
	g.keys = append(g.keys, hexKey)
}

func (g *generator) removeKey(index int) string {
	key := g.keys[index]
	delete(g.existing, key)
	lastIndex := len(g.keys) - 1
	g.keys[index] = g.keys[lastIndex]
	g.keys = g.keys[:lastIndex]
	return key
}

func (g *generator) randomExistingKey() (string, error) {
	if !g.hasKeys() {
		return "", errors.New("no keys available")
	}
	index := g.rand.Intn(len(g.keys))
	return g.keys[index], nil
}

func (g *generator) generateUniqueKey() []byte {
	for {
		key := g.randomKeyBytes()
		hexKey := hex.EncodeToString(key)
		if _, exists := g.existing[hexKey]; !exists {
			return key
		}
	}
}

func mustHexDecode(value string) []byte {
	bytes, err := hex.DecodeString(value)
	if err != nil {
		panic(fmt.Errorf("failed to decode hex %q: %w", value, err))
	}
	return bytes
}

func writeFixtureFile(path string, content fixtureFile) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(content)
}

func buildFixture(name, description string, seed int64, opCount int) (fixture, error) {
	ctx := context.Background()

	config := merkledb.NewConfig()
	config.BranchFactor = merkledb.BranchFactor256

	db, err := merkledb.New(ctx, memdb.New(), config)
	if err != nil {
		return fixture{}, fmt.Errorf("create merkledb: %w", err)
	}

	gen := newGenerator(seed, defaultKeyMinLen, defaultKeyMaxLen, defaultValueMinLen, defaultValueMaxLen)

	operations := make([]operation, 0, opCount)

	for len(operations) < opCount {
		var (
			op  operation
			key []byte
			err error
		)

		switch {
		case !gen.hasKeys():
			key = gen.generateUniqueKey()
			value := gen.randomValueBytes()
			if err = db.Put(key, value); err != nil {
				return fixture{}, fmt.Errorf("put initial key: %w", err)
			}
			hexKey := hex.EncodeToString(key)
			hexValue := hex.EncodeToString(value)
			gen.addKey(hexKey)
			op = operation{Type: "put", Key: hexKey, Value: &hexValue}

		default:
			choice := gen.rand.Intn(100)
			switch {
			case choice < 45:
				key = gen.generateUniqueKey()
				value := gen.randomValueBytes()
				if err = db.Put(key, value); err != nil {
					return fixture{}, fmt.Errorf("put new key: %w", err)
				}
				hexKey := hex.EncodeToString(key)
				hexValue := hex.EncodeToString(value)
				gen.addKey(hexKey)
				op = operation{Type: "put", Key: hexKey, Value: &hexValue}

			case choice < 80:
				hexKey, keyErr := gen.randomExistingKey()
				if keyErr != nil {
					return fixture{}, keyErr
				}
				key = mustHexDecode(hexKey)
				value := gen.randomValueBytes()
				if err = db.Put(key, value); err != nil {
					return fixture{}, fmt.Errorf("update key: %w", err)
				}
				hexValue := hex.EncodeToString(value)
				op = operation{Type: "put", Key: hexKey, Value: &hexValue}

			default:
				hexKey, keyErr := gen.randomExistingKey()
				if keyErr != nil {
					return fixture{}, keyErr
				}
				key = mustHexDecode(hexKey)
				if err = db.Delete(key); err != nil {
					return fixture{}, fmt.Errorf("delete key: %w", err)
				}
				// remove from generator
				for index, candidate := range gen.keys {
					if candidate == hexKey {
						gen.removeKey(index)
						break
					}
				}
				op = operation{Type: "delete", Key: hexKey}
			}
		}

		rootID, rootErr := db.GetMerkleRoot(ctx)
		if rootErr != nil {
			return fixture{}, fmt.Errorf("compute root: %w", rootErr)
		}
		rootHex := rootID.Hex()
		op.Root = rootHex
		operations = append(operations, op)
	}

	return fixture{
		Name:        name,
		Seed:        seed,
		Description: description,
		Operations:  operations,
	}, nil
}

func main() {
	fixtures := make([]fixture, 0, 2)

	f1, err := buildFixture(
		"seed_42_len32",
		"Deterministic sequence of insert/update/delete operations using seed 42.",
		42,
		32,
	)
	if err != nil {
		panic(err)
	}
	fixtures = append(fixtures, f1)

	f2, err := buildFixture(
		"seed_31337_len48",
		"Deterministic sequence with a higher operation count and more deletes.",
		31337,
		48,
	)
	if err != nil {
		panic(err)
	}
	fixtures = append(fixtures, f2)

	content := fixtureFile{
		GeneratedAt:   time.Now().UTC(),
		BranchFactor:  int(merkledb.BranchFactor256),
		Hasher:        "merkledb.DefaultHasher",
		Fixtures:      fixtures,
		KeyLength:     [2]int{defaultKeyMinLen, defaultKeyMaxLen},
		ValueLength:   [2]int{defaultValueMinLen, defaultValueMaxLen},
		OperationNote: "Operations are generated from a deterministic PRNG using the listed seed.",
	}

	if err := writeFixtureFile(outputFile, content); err != nil {
		panic(err)
	}
}
