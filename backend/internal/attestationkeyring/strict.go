package attestationkeyring

import (
	"bytes"
	"encoding/json"
	"io"
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
	object  map[string]jsonValue
	array   []jsonValue
}

const maxJSONDepth = 32

// parseStrictJSON rejects duplicate object members and trailing JSON values.
// encoding/json is used only as a grammar tokenizer; schema validation below
// rejects all non-ASCII keyring values and therefore does not accept its
// replacement behavior for malformed Unicode strings.
func parseStrictJSON(data []byte) (jsonValue, error) {
	if len(data) == 0 || !utf8.Valid(data) {
		return jsonValue{}, ErrInvalidKeyring
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := parseJSONValue(decoder, 0)
	if err != nil {
		return jsonValue{}, ErrInvalidKeyring
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return jsonValue{}, ErrInvalidKeyring
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder, depth int) (jsonValue, error) {
	if depth > maxJSONDepth {
		return jsonValue{}, ErrInvalidKeyring
	}
	token, err := decoder.Token()
	if err != nil {
		return jsonValue{}, ErrInvalidKeyring
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]jsonValue)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return jsonValue{}, ErrInvalidKeyring
				}
				key, ok := keyToken.(string)
				if !ok {
					return jsonValue{}, ErrInvalidKeyring
				}
				if _, exists := object[key]; exists {
					return jsonValue{}, ErrInvalidKeyring
				}
				child, err := parseJSONValue(decoder, depth+1)
				if err != nil {
					return jsonValue{}, err
				}
				object[key] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return jsonValue{}, ErrInvalidKeyring
			}
			return jsonValue{kind: jsonObject, object: object}, nil
		case '[':
			array := make([]jsonValue, 0)
			for decoder.More() {
				child, err := parseJSONValue(decoder, depth+1)
				if err != nil {
					return jsonValue{}, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return jsonValue{}, ErrInvalidKeyring
			}
			return jsonValue{kind: jsonArray, array: array}, nil
		default:
			return jsonValue{}, ErrInvalidKeyring
		}
	case string:
		if !utf8.ValidString(value) {
			return jsonValue{}, ErrInvalidKeyring
		}
		return jsonValue{kind: jsonString, string: value}, nil
	case json.Number:
		return jsonValue{kind: jsonNumber, number: value.String()}, nil
	case bool:
		return jsonValue{kind: jsonBoolean, boolean: value}, nil
	case nil:
		return jsonValue{kind: jsonNull}, nil
	default:
		return jsonValue{}, ErrInvalidKeyring
	}
}

func (value jsonValue) member(name string) (jsonValue, bool) {
	if value.kind != jsonObject {
		return jsonValue{}, false
	}
	member, ok := value.object[name]
	return member, ok
}

func (value jsonValue) hasOnlyMembers(allowed map[string]struct{}) bool {
	if value.kind != jsonObject {
		return false
	}
	for name := range value.object {
		if _, ok := allowed[name]; !ok {
			return false
		}
	}
	return true
}

func requiredString(value jsonValue, name string) (string, error) {
	member, ok := value.member(name)
	if !ok || member.kind != jsonString || member.string == "" {
		return "", ErrInvalidKeyring
	}
	return member.string, nil
}
