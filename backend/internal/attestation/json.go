package attestation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"
)

type jsonKind uint8

const (
	jsonInvalid jsonKind = iota
	jsonObject
	jsonArray
	jsonString
	jsonNumber
	jsonBoolean
	jsonNull
)

type jsonValue struct {
	kind    jsonKind
	string  string
	number  string
	boolean bool
	object  []jsonMember
	array   []jsonValue
}

type jsonMember struct {
	name  string
	value jsonValue
}

var errStrictJSON = errors.New("invalid JSON")

// parseStrictJSON parses the JSON grammar without the duplicate-member and
// Unicode-scalar ambiguity of encoding/json. Callers still validate the
// resulting value against their protocol schema.
func parseStrictJSON(data []byte) (jsonValue, error) {
	if !utf8.Valid(data) {
		return jsonValue{}, errStrictJSON
	}
	parser := strictJSONParser{data: data}
	parser.skipWhitespace()
	value, err := parser.parseValue()
	if err != nil {
		return jsonValue{}, errStrictJSON
	}
	parser.skipWhitespace()
	if parser.pos != len(parser.data) {
		return jsonValue{}, errStrictJSON
	}
	return value, nil
}

type strictJSONParser struct {
	data []byte
	pos  int
}

func (p *strictJSONParser) parseValue() (jsonValue, error) {
	if p.pos >= len(p.data) {
		return jsonValue{}, errStrictJSON
	}
	switch p.data[p.pos] {
	case '{':
		return p.parseObject()
	case '[':
		return p.parseArray()
	case '"':
		value, err := p.parseString()
		if err != nil {
			return jsonValue{}, err
		}
		return jsonValue{kind: jsonString, string: value}, nil
	case 't':
		if p.consumeLiteral("true") {
			return jsonValue{kind: jsonBoolean, boolean: true}, nil
		}
	case 'f':
		if p.consumeLiteral("false") {
			return jsonValue{kind: jsonBoolean}, nil
		}
	case 'n':
		if p.consumeLiteral("null") {
			return jsonValue{kind: jsonNull}, nil
		}
	default:
		if p.data[p.pos] == '-' || (p.data[p.pos] >= '0' && p.data[p.pos] <= '9') {
			number, err := p.parseNumber()
			if err != nil {
				return jsonValue{}, err
			}
			return jsonValue{kind: jsonNumber, number: number}, nil
		}
	}
	return jsonValue{}, errStrictJSON
}

func (p *strictJSONParser) parseObject() (jsonValue, error) {
	p.pos++ // {
	p.skipWhitespace()
	members := make([]jsonMember, 0, 4)
	seen := make(map[string]struct{})
	if p.consume('}') {
		return jsonValue{kind: jsonObject, object: members}, nil
	}
	for {
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return jsonValue{}, errStrictJSON
		}
		name, err := p.parseString()
		if err != nil {
			return jsonValue{}, err
		}
		if _, exists := seen[name]; exists {
			return jsonValue{}, errStrictJSON
		}
		seen[name] = struct{}{}
		p.skipWhitespace()
		if !p.consume(':') {
			return jsonValue{}, errStrictJSON
		}
		p.skipWhitespace()
		value, err := p.parseValue()
		if err != nil {
			return jsonValue{}, err
		}
		members = append(members, jsonMember{name: name, value: value})
		p.skipWhitespace()
		if p.consume('}') {
			return jsonValue{kind: jsonObject, object: members}, nil
		}
		if !p.consume(',') {
			return jsonValue{}, errStrictJSON
		}
		p.skipWhitespace()
	}
}

func (p *strictJSONParser) parseArray() (jsonValue, error) {
	p.pos++ // [
	p.skipWhitespace()
	values := make([]jsonValue, 0, 4)
	if p.consume(']') {
		return jsonValue{kind: jsonArray, array: values}, nil
	}
	for {
		value, err := p.parseValue()
		if err != nil {
			return jsonValue{}, err
		}
		values = append(values, value)
		p.skipWhitespace()
		if p.consume(']') {
			return jsonValue{kind: jsonArray, array: values}, nil
		}
		if !p.consume(',') {
			return jsonValue{}, errStrictJSON
		}
		p.skipWhitespace()
	}
}

func (p *strictJSONParser) parseString() (string, error) {
	if !p.consume('"') {
		return "", errStrictJSON
	}
	var result strings.Builder
	for p.pos < len(p.data) {
		current := p.data[p.pos]
		switch current {
		case '"':
			p.pos++
			return result.String(), nil
		case '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", errStrictJSON
			}
			escape := p.data[p.pos]
			p.pos++
			switch escape {
			case '"', '\\', '/':
				result.WriteByte(escape)
			case 'b':
				result.WriteByte('\b')
			case 'f':
				result.WriteByte('\f')
			case 'n':
				result.WriteByte('\n')
			case 'r':
				result.WriteByte('\r')
			case 't':
				result.WriteByte('\t')
			case 'u':
				codePoint, err := p.parseUnicodeEscape()
				if err != nil {
					return "", err
				}
				var encoded [utf8.UTFMax]byte
				n := utf8.EncodeRune(encoded[:], codePoint)
				result.Write(encoded[:n])
			default:
				return "", errStrictJSON
			}
		case 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f:
			return "", errStrictJSON
		default:
			runeValue, size := utf8.DecodeRune(p.data[p.pos:])
			if runeValue == utf8.RuneError && size == 1 {
				return "", errStrictJSON
			}
			result.Write(p.data[p.pos : p.pos+size])
			p.pos += size
		}
	}
	return "", errStrictJSON
}

func (p *strictJSONParser) parseUnicodeEscape() (rune, error) {
	if p.pos+4 > len(p.data) {
		return 0, errStrictJSON
	}
	var codeBytes [2]byte
	if _, err := hex.Decode(codeBytes[:], p.data[p.pos:p.pos+4]); err != nil {
		return 0, errStrictJSON
	}
	codePoint := rune(codeBytes[0])<<8 | rune(codeBytes[1])
	p.pos += 4
	if codePoint >= 0xd800 && codePoint <= 0xdbff {
		if p.pos+6 > len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
			return 0, errStrictJSON
		}
		p.pos += 2
		if p.pos+4 > len(p.data) {
			return 0, errStrictJSON
		}
		if _, err := hex.Decode(codeBytes[:], p.data[p.pos:p.pos+4]); err != nil {
			return 0, errStrictJSON
		}
		low := rune(codeBytes[0])<<8 | rune(codeBytes[1])
		if low < 0xdc00 || low > 0xdfff {
			return 0, errStrictJSON
		}
		p.pos += 4
		return 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00), nil
	}
	if codePoint >= 0xdc00 && codePoint <= 0xdfff {
		return 0, errStrictJSON
	}
	return codePoint, nil
}

func (p *strictJSONParser) parseNumber() (string, error) {
	start := p.pos
	if p.consume('-') {
		if p.pos >= len(p.data) {
			return "", errStrictJSON
		}
	}
	if p.consume('0') {
		if p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			return "", errStrictJSON
		}
	} else {
		if p.pos >= len(p.data) || p.data[p.pos] < '1' || p.data[p.pos] > '9' {
			return "", errStrictJSON
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.consume('.') {
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return "", errStrictJSON
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.data) || p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return "", errStrictJSON
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	return string(p.data[start:p.pos]), nil
}

func (p *strictJSONParser) consume(expected byte) bool {
	if p.pos >= len(p.data) || p.data[p.pos] != expected {
		return false
	}
	p.pos++
	return true
}

func (p *strictJSONParser) consumeLiteral(literal string) bool {
	if !bytes.HasPrefix(p.data[p.pos:], []byte(literal)) {
		return false
	}
	p.pos += len(literal)
	return true
}

func (p *strictJSONParser) skipWhitespace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (v jsonValue) member(name string) (jsonValue, bool) {
	if v.kind != jsonObject {
		return jsonValue{}, false
	}
	for _, member := range v.object {
		if member.name == name {
			return member.value, true
		}
	}
	return jsonValue{}, false
}

func (v jsonValue) hasOnlyMembers(allowed map[string]struct{}) bool {
	if v.kind != jsonObject {
		return false
	}
	for _, member := range v.object {
		if _, ok := allowed[member.name]; !ok {
			return false
		}
	}
	return true
}
