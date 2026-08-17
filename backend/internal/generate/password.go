package generate

import (
	cryptorand "crypto/rand"
	"io"
	"math/big"
)

const (
	defaultPasswordLength = 32
	minimumPasswordLength = 22
	maximumPasswordLength = 128
	maximumClassMinimum   = 32

	lowercaseAlphabet = "abcdefghijklmnopqrstuvwxyz"
	uppercaseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitAlphabet     = "0123456789"
	symbolAlphabet    = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
	ambiguousAlphabet = "0O1lI|"
)

var minimumPasswordCardinality = new(big.Int).Lsh(big.NewInt(1), 128)

type passwordClass struct {
	alphabet []byte
	minimum  int
}

// GeneratePassword creates one password uniformly over the complete set accepted by
// the effective class minima. Invalid or sub-128-bit parameter sets are
// rejected before the generator consumes randomness.
func (g *Generator) GeneratePassword(parameters PasswordParameters) (PasswordResult, error) {
	effective, classes, err := resolvePasswordParameters(parameters)
	if err != nil {
		return PasswordResult{}, err
	}
	if g == nil || g.random == nil {
		return PasswordResult{}, ErrGenerationFailed
	}

	counter := newPasswordCounter(effective.Length, classes)
	if counter.total().Cmp(minimumPasswordCardinality) < 0 {
		return PasswordResult{}, ErrInvalidParameters
	}

	counts, err := counter.sampleClassCounts(g.random)
	if err != nil {
		return PasswordResult{}, ErrGenerationFailed
	}
	password, err := samplePasswordCharacters(g.random, effective.Length, classes, counts)
	if err != nil {
		clear(password)
		return PasswordResult{}, ErrGenerationFailed
	}

	private := newPrivateMaterial(password)
	clear(password)
	return PasswordResult{private: private, parameters: effective}, nil
}

func resolvePasswordParameters(parameters PasswordParameters) (EffectivePasswordParameters, []passwordClass, error) {
	effective := EffectivePasswordParameters{
		Length:           intOrDefault(parameters.Length, defaultPasswordLength),
		Lowercase:        boolOrDefault(parameters.Lowercase, true),
		Uppercase:        boolOrDefault(parameters.Uppercase, true),
		Digits:           boolOrDefault(parameters.Digits, true),
		Symbols:          boolOrDefault(parameters.Symbols, false),
		ExcludeAmbiguous: boolOrDefault(parameters.ExcludeAmbiguous, false),
	}
	effective.MinLowercase = minimumOrDefault(parameters.MinLowercase, effective.Lowercase)
	effective.MinUppercase = minimumOrDefault(parameters.MinUppercase, effective.Uppercase)
	effective.MinDigits = minimumOrDefault(parameters.MinDigits, effective.Digits)
	effective.MinSymbols = minimumOrDefault(parameters.MinSymbols, effective.Symbols)

	if effective.Length < minimumPasswordLength || effective.Length > maximumPasswordLength {
		return EffectivePasswordParameters{}, nil, ErrInvalidParameters
	}

	type classDefinition struct {
		enabled  bool
		minimum  int
		alphabet string
	}
	definitions := []classDefinition{
		{enabled: effective.Lowercase, minimum: effective.MinLowercase, alphabet: lowercaseAlphabet},
		{enabled: effective.Uppercase, minimum: effective.MinUppercase, alphabet: uppercaseAlphabet},
		{enabled: effective.Digits, minimum: effective.MinDigits, alphabet: digitAlphabet},
		{enabled: effective.Symbols, minimum: effective.MinSymbols, alphabet: symbolAlphabet},
	}

	classes := make([]passwordClass, 0, len(definitions))
	minimumTotal := 0
	for _, definition := range definitions {
		if definition.minimum < 0 || definition.minimum > maximumClassMinimum {
			return EffectivePasswordParameters{}, nil, ErrInvalidParameters
		}
		if !definition.enabled {
			if definition.minimum != 0 {
				return EffectivePasswordParameters{}, nil, ErrInvalidParameters
			}
			continue
		}

		alphabet := []byte(definition.alphabet)
		if effective.ExcludeAmbiguous {
			alphabet = excludeAmbiguous(alphabet)
		}
		if len(alphabet) == 0 {
			return EffectivePasswordParameters{}, nil, ErrInvalidParameters
		}
		classes = append(classes, passwordClass{alphabet: alphabet, minimum: definition.minimum})
		minimumTotal += definition.minimum
	}
	if len(classes) == 0 || minimumTotal > effective.Length {
		return EffectivePasswordParameters{}, nil, ErrInvalidParameters
	}
	return effective, classes, nil
}

func intOrDefault(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func boolOrDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func minimumOrDefault(value *int, enabled bool) int {
	if value != nil {
		return *value
	}
	if enabled {
		return 1
	}
	return 0
}

func excludeAmbiguous(alphabet []byte) []byte {
	filtered := make([]byte, 0, len(alphabet))
	for _, character := range alphabet {
		ambiguous := false
		for index := 0; index < len(ambiguousAlphabet); index++ {
			if character == ambiguousAlphabet[index] {
				ambiguous = true
				break
			}
		}
		if !ambiguous {
			filtered = append(filtered, character)
		}
	}
	return filtered
}

// passwordCounter counts accepted strings by assigning each class a number of
// positions. It avoids a state for every possible per-class count tuple: the
// memoized recurrence has O(classes*length) states and O(classes*length^2)
// terms.
type passwordCounter struct {
	length        int
	classes       []passwordClass
	suffixMinimum []int
	powers        [][]*big.Int
	memo          [][]*big.Int
}

func newPasswordCounter(length int, classes []passwordClass) *passwordCounter {
	counter := &passwordCounter{
		length:        length,
		classes:       classes,
		suffixMinimum: make([]int, len(classes)+1),
		powers:        make([][]*big.Int, len(classes)),
		memo:          make([][]*big.Int, len(classes)+1),
	}
	for index := len(classes) - 1; index >= 0; index-- {
		counter.suffixMinimum[index] = counter.suffixMinimum[index+1] + classes[index].minimum
	}
	for classIndex, class := range classes {
		counter.powers[classIndex] = make([]*big.Int, length+1)
		counter.powers[classIndex][0] = big.NewInt(1)
		alphabetSize := big.NewInt(int64(len(class.alphabet)))
		for count := 1; count <= length; count++ {
			counter.powers[classIndex][count] = new(big.Int).Mul(counter.powers[classIndex][count-1], alphabetSize)
		}
	}
	for index := range counter.memo {
		counter.memo[index] = make([]*big.Int, length+1)
	}
	return counter
}

func (c *passwordCounter) total() *big.Int {
	return c.count(0, c.length)
}

func (c *passwordCounter) count(classIndex, slots int) *big.Int {
	if cached := c.memo[classIndex][slots]; cached != nil {
		return cached
	}
	if classIndex == len(c.classes) {
		if slots == 0 {
			c.memo[classIndex][slots] = big.NewInt(1)
		} else {
			c.memo[classIndex][slots] = new(big.Int)
		}
		return c.memo[classIndex][slots]
	}

	total := new(big.Int)
	maximum := slots - c.suffixMinimum[classIndex+1]
	for classCount := c.classes[classIndex].minimum; classCount <= maximum; classCount++ {
		total.Add(total, c.countWeight(classIndex, slots, classCount))
	}
	c.memo[classIndex][slots] = total
	return total
}

func (c *passwordCounter) countWeight(classIndex, slots, classCount int) *big.Int {
	positions := new(big.Int).Binomial(int64(slots), int64(classCount))
	weight := new(big.Int).Mul(positions, c.powers[classIndex][classCount])
	return weight.Mul(weight, c.count(classIndex+1, slots-classCount))
}

func (c *passwordCounter) sampleClassCounts(random io.Reader) ([]int, error) {
	counts := make([]int, len(c.classes))
	remaining := c.length
	for classIndex := 0; classIndex < len(c.classes)-1; classIndex++ {
		minimum := c.classes[classIndex].minimum
		maximum := remaining - c.suffixMinimum[classIndex+1]
		if minimum == maximum {
			counts[classIndex] = minimum
			remaining -= minimum
			continue
		}

		rank, err := cryptorand.Int(random, c.count(classIndex, remaining))
		if err != nil {
			return nil, err
		}
		selected := c.classCountForRank(classIndex, remaining, rank)
		if selected < 0 {
			return nil, ErrGenerationFailed
		}
		counts[classIndex] = selected
		remaining -= selected
	}
	counts[len(counts)-1] = remaining
	return counts, nil
}

func (c *passwordCounter) classCountForRank(classIndex, slots int, rank *big.Int) int {
	if rank == nil || rank.Sign() < 0 || rank.Cmp(c.count(classIndex, slots)) >= 0 {
		return -1
	}
	remainingRank := new(big.Int).Set(rank)
	maximum := slots - c.suffixMinimum[classIndex+1]
	for classCount := c.classes[classIndex].minimum; classCount <= maximum; classCount++ {
		weight := c.countWeight(classIndex, slots, classCount)
		if remainingRank.Cmp(weight) < 0 {
			return classCount
		}
		remainingRank.Sub(remainingRank, weight)
	}
	return -1
}

func samplePasswordCharacters(random io.Reader, length int, classes []passwordClass, counts []int) ([]byte, error) {
	remainingCounts := append([]int(nil), counts...)
	password := make([]byte, length)
	remaining := length
	for position := range password {
		classIndex, err := selectRemainingClass(random, remainingCounts, remaining)
		if err != nil {
			return password, err
		}
		characterIndex, err := randomIndex(random, len(classes[classIndex].alphabet))
		if err != nil {
			return password, err
		}
		password[position] = classes[classIndex].alphabet[characterIndex]
		remainingCounts[classIndex]--
		remaining--
	}
	return password, nil
}

func selectRemainingClass(random io.Reader, counts []int, total int) (int, error) {
	nonEmpty := -1
	for index, count := range counts {
		if count == 0 {
			continue
		}
		if nonEmpty >= 0 {
			nonEmpty = -2
			break
		}
		nonEmpty = index
	}
	if nonEmpty >= 0 {
		return nonEmpty, nil
	}

	choice, err := randomIndex(random, total)
	if err != nil {
		return 0, err
	}
	for index, count := range counts {
		if choice < count {
			return index, nil
		}
		choice -= count
	}
	return 0, ErrGenerationFailed
}

func randomIndex(random io.Reader, limit int) (int, error) {
	if limit <= 0 {
		return 0, ErrGenerationFailed
	}
	if limit == 1 {
		return 0, nil
	}
	value, err := cryptorand.Int(random, big.NewInt(int64(limit)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}
