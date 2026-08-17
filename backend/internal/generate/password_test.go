package generate

import (
	"errors"
	"io"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestGeneratePasswordAppliesDefaultsAndClassConstraints(t *testing.T) {
	generator := New()
	generator.random = zeroPasswordReader{}

	result, err := generator.GeneratePassword(PasswordParameters{})
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	password := result.PrivateBytes()
	if len(password) != 32 {
		t.Fatalf("password length = %d, want 32", len(password))
	}
	assertPasswordClassCounts(t, password, 1, 1, 1, 0)
	if strings.ContainsAny(string(password), symbolAlphabet+"\r\n") {
		t.Fatalf("default password contains a symbol or newline: %q", password)
	}

	wantParameters := EffectivePasswordParameters{
		Length:       32,
		Lowercase:    true,
		Uppercase:    true,
		Digits:       true,
		MinLowercase: 1,
		MinUppercase: 1,
		MinDigits:    1,
	}
	if got := result.EffectiveParameters(); !reflect.DeepEqual(got, wantParameters) {
		t.Fatalf("effective parameters = %#v, want %#v", got, wantParameters)
	}
}

func TestGeneratePasswordHonorsMinimaAndAmbiguousExclusion(t *testing.T) {
	length := 32
	minimumLowercase := 4
	minimumUppercase := 5
	minimumDigits := 6
	minimumSymbols := 7
	enabled := true

	generator := New()
	generator.random = zeroPasswordReader{}
	result, err := generator.GeneratePassword(PasswordParameters{
		Length:           &length,
		Lowercase:        &enabled,
		Uppercase:        &enabled,
		Digits:           &enabled,
		Symbols:          &enabled,
		MinLowercase:     &minimumLowercase,
		MinUppercase:     &minimumUppercase,
		MinDigits:        &minimumDigits,
		MinSymbols:       &minimumSymbols,
		ExcludeAmbiguous: &enabled,
	})
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	password := result.PrivateBytes()
	assertPasswordClassCounts(t, password, minimumLowercase, minimumUppercase, minimumDigits, minimumSymbols)
	if strings.ContainsAny(string(password), ambiguousAlphabet) {
		t.Fatalf("password contains an ambiguous character: %q", password)
	}
	for _, character := range password {
		if character < 0x21 || character > 0x7e || character == '\n' || character == '\r' {
			t.Fatalf("password contains non-printable ASCII: %q", password)
		}
	}
}

func TestGeneratePasswordEnforcesExactEntropyBoundaryBeforeRandomness(t *testing.T) {
	digitsOnly := false
	length38 := 38
	length39 := 39

	reader := &countingPasswordReader{}
	generator := New()
	generator.random = reader
	_, err := generator.GeneratePassword(PasswordParameters{
		Length:    &length38,
		Lowercase: &digitsOnly,
		Uppercase: &digitsOnly,
	})
	if !errors.Is(err, ErrInvalidParameters) {
		t.Fatalf("digits-only length 38 error = %v, want ErrInvalidParameters", err)
	}
	if reader.reads != 0 {
		t.Fatalf("sub-128-bit request consumed randomness %d times", reader.reads)
	}

	result, err := generator.GeneratePassword(PasswordParameters{
		Length:    &length39,
		Lowercase: &digitsOnly,
		Uppercase: &digitsOnly,
	})
	if err != nil {
		t.Fatalf("digits-only length 39 error = %v", err)
	}
	password := result.PrivateBytes()
	if len(password) != length39 || strings.Trim(string(password), digitAlphabet) != "" {
		t.Fatalf("digits-only password = %q", password)
	}
	if reader.reads == 0 {
		t.Fatal("valid request did not consume randomness")
	}
}

func TestPasswordAcceptedSetCountingAndWeightedSelection(t *testing.T) {
	classes := []passwordClass{
		{alphabet: []byte("ab"), minimum: 1},
		{alphabet: []byte("X"), minimum: 1},
	}
	counter := newPasswordCounter(3, classes)
	if got, want := counter.total(), big.NewInt(18); got.Cmp(want) != 0 {
		t.Fatalf("accepted cardinality = %s, want %s", got, want)
	}

	selectedCounts := map[int]int{}
	for rank := int64(0); rank < 18; rank++ {
		selected := counter.classCountForRank(0, 3, big.NewInt(rank))
		selectedCounts[selected]++
	}
	if !reflect.DeepEqual(selectedCounts, map[int]int{1: 6, 2: 12}) {
		t.Fatalf("weighted rank partition = %#v, want map[1:6 2:12]", selectedCounts)
	}
}

func TestGeneratePasswordRejectsInvalidShapesWithoutRandomness(t *testing.T) {
	disabled := false
	enabled := true
	zero := 0
	one := 1
	length21 := 21
	length32 := 32
	length129 := 129
	minimum32 := 32
	minimum33 := 33

	tests := []struct {
		name       string
		parameters PasswordParameters
	}{
		{name: "length below floor", parameters: PasswordParameters{Length: &length21}},
		{name: "length above ceiling", parameters: PasswordParameters{Length: &length129}},
		{name: "class minimum above ceiling", parameters: PasswordParameters{Length: &length32, MinLowercase: &minimum33}},
		{name: "no classes", parameters: PasswordParameters{Length: &length32, Lowercase: &disabled, Uppercase: &disabled, Digits: &disabled, Symbols: &disabled}},
		{name: "minimum on disabled class", parameters: PasswordParameters{Length: &length32, Lowercase: &disabled, MinLowercase: &one}},
		{name: "minima exceed length", parameters: PasswordParameters{Length: &length32, Symbols: &enabled, MinLowercase: &minimum32, MinUppercase: &minimum32, MinDigits: &zero, MinSymbols: &zero}},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			reader := &countingPasswordReader{}
			generator := New()
			generator.random = reader
			if _, err := generator.GeneratePassword(current.parameters); !errors.Is(err, ErrInvalidParameters) {
				t.Fatalf("GeneratePassword() error = %v, want ErrInvalidParameters", err)
			}
			if reader.reads != 0 {
				t.Fatalf("invalid request consumed randomness %d times", reader.reads)
			}
		})
	}
}

func TestGeneratePasswordRandomFailureReturnsNoMaterial(t *testing.T) {
	generator := New()
	generator.random = failingPasswordReader{}
	result, err := generator.GeneratePassword(PasswordParameters{})
	if !errors.Is(err, ErrGenerationFailed) {
		t.Fatalf("GeneratePassword() error = %v, want ErrGenerationFailed", err)
	}
	if private := result.PrivateBytes(); len(private) != 0 {
		t.Fatalf("failed result contains %d private bytes", len(private))
	}
}

func assertPasswordClassCounts(t *testing.T, password []byte, minimumLowercase, minimumUppercase, minimumDigits, minimumSymbols int) {
	t.Helper()
	counts := [4]int{}
	for _, character := range password {
		switch {
		case strings.ContainsRune(lowercaseAlphabet, rune(character)):
			counts[0]++
		case strings.ContainsRune(uppercaseAlphabet, rune(character)):
			counts[1]++
		case strings.ContainsRune(digitAlphabet, rune(character)):
			counts[2]++
		case strings.ContainsRune(symbolAlphabet, rune(character)):
			counts[3]++
		default:
			t.Fatalf("password contains character outside enabled protocol classes: %q", character)
		}
	}
	want := [4]int{minimumLowercase, minimumUppercase, minimumDigits, minimumSymbols}
	for index := range counts {
		if counts[index] < want[index] {
			t.Fatalf("password class counts = %v, want each >= %v", counts, want)
		}
	}
}

type zeroPasswordReader struct{}

func (zeroPasswordReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

type countingPasswordReader struct {
	reads int
}

func (r *countingPasswordReader) Read(buffer []byte) (int, error) {
	r.reads++
	clear(buffer)
	return len(buffer), nil
}

type failingPasswordReader struct{}

func (failingPasswordReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
