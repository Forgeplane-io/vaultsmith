package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

type document struct {
	OpenAPI    string              `yaml:"openapi"`
	Info       info                `yaml:"info"`
	Servers    []server            `yaml:"servers"`
	Paths      map[string]pathItem `yaml:"paths"`
	Components components          `yaml:"components"`
}

type info struct {
	Title       string `yaml:"title"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
}

type server struct {
	URL         string `yaml:"url"`
	Description string `yaml:"description"`
}

type pathItem struct {
	Parameters []parameter `yaml:"parameters"`
	Get        *operation  `yaml:"get"`
	Post       *operation  `yaml:"post"`
	Put        *operation  `yaml:"put"`
	Patch      *operation  `yaml:"patch"`
	Delete     *operation  `yaml:"delete"`
	Options    *operation  `yaml:"options"`
	Head       *operation  `yaml:"head"`
}

type operation struct {
	OperationID         string                `yaml:"operationId"`
	Summary             string                `yaml:"summary"`
	Description         string                `yaml:"description"`
	Deprecated          bool                  `yaml:"deprecated"`
	Tags                []string              `yaml:"tags"`
	Security            []map[string][]string `yaml:"security"`
	RequiredBearerScope string                `yaml:"x-required-bearer-scope"`
	DeadlineSeconds     int                   `yaml:"x-request-deadline-seconds"`
	MaxBodyBytes        int                   `yaml:"x-max-body-bytes"`
	NoAutomaticRetry    bool                  `yaml:"x-no-automatic-retry"`
	Parameters          []parameter           `yaml:"parameters"`
	RequestBody         requestBody           `yaml:"requestBody"`
	Responses           map[string]response   `yaml:"responses"`
}

type parameter struct {
	Ref         string `yaml:"$ref"`
	Name        string `yaml:"name"`
	In          string `yaml:"in"`
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
	Schema      schema `yaml:"schema"`
}

type requestBody struct {
	Ref         string               `yaml:"$ref"`
	Description string               `yaml:"description"`
	Required    bool                 `yaml:"required"`
	Content     map[string]mediaType `yaml:"content"`
}

type mediaType struct {
	Schema  schema `yaml:"schema"`
	Example any    `yaml:"example"`
}

type response struct {
	Ref         string               `yaml:"$ref"`
	Description string               `yaml:"description"`
	Content     map[string]mediaType `yaml:"content"`
}

type components struct {
	Schemas         map[string]schema         `yaml:"schemas"`
	Responses       map[string]response       `yaml:"responses"`
	Parameters      map[string]parameter      `yaml:"parameters"`
	RequestBodies   map[string]requestBody    `yaml:"requestBodies"`
	SecuritySchemes map[string]securityScheme `yaml:"securitySchemes"`
}

type securityScheme struct {
	Type         string `yaml:"type"`
	Scheme       string `yaml:"scheme"`
	BearerFormat string `yaml:"bearerFormat"`
	In           string `yaml:"in"`
	Name         string `yaml:"name"`
	Description  string `yaml:"description"`
}

type schema struct {
	Ref                  string            `yaml:"$ref"`
	Type                 string            `yaml:"type"`
	Format               string            `yaml:"format"`
	Description          string            `yaml:"description"`
	Enum                 []any             `yaml:"enum"`
	Required             []string          `yaml:"required"`
	Properties           map[string]schema `yaml:"properties"`
	Items                *schema           `yaml:"items"`
	OneOf                []schema          `yaml:"oneOf"`
	AnyOf                []schema          `yaml:"anyOf"`
	MinLength            *int              `yaml:"minLength"`
	MaxLength            *int              `yaml:"maxLength"`
	Minimum              *float64          `yaml:"minimum"`
	Maximum              *float64          `yaml:"maximum"`
	AdditionalProperties any               `yaml:"additionalProperties"`
}

type endpoint struct {
	Path      string
	Method    string
	Operation *operation
	Common    []parameter
}

func main() {
	input := flag.String("input", "openapi.yaml", "OpenAPI input file")
	output := flag.String("output", "../docs/api-reference.md", "Markdown output file")
	flag.Parse()

	raw, err := os.ReadFile(*input)
	if err != nil {
		fatal(err)
	}
	reference, err := generateReference(raw)
	if err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*output, reference, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "generate API reference:", err)
	os.Exit(1)
}

func generateReference(raw []byte) ([]byte, error) {
	var doc document
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode contract: %w", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.1.") {
		return nil, errors.New("contract must use OpenAPI 3.1")
	}
	if strings.TrimSpace(doc.Info.Title) == "" || strings.TrimSpace(doc.Info.Version) == "" {
		return nil, errors.New("contract title and version are required")
	}

	var out strings.Builder
	line(&out, "<!-- Code generated from api/openapi.yaml by api/cmd/reference. DO NOT EDIT. -->")
	line(&out, "")
	line(&out, "# "+doc.Info.Title+" reference")
	line(&out, "")
	line(&out, "**Contract version:** `"+escapeInline(doc.Info.Version)+"`")
	line(&out, "")
	paragraph(&out, doc.Info.Description)
	line(&out, "This is the static reference for the released REST contract. The canonical source is [`api/openapi.yaml`](../api/openapi.yaml). MCP is documented separately because it is not part of OpenAPI.")
	line(&out, "")

	if len(doc.Servers) > 0 {
		line(&out, "## Servers")
		line(&out, "")
		for _, item := range doc.Servers {
			entry := "- `" + escapeInline(item.URL) + "`"
			if item.Description != "" {
				entry += " — " + clean(item.Description)
			}
			line(&out, entry)
		}
		line(&out, "")
	}

	writeSecuritySchemes(&out, doc.Components.SecuritySchemes)

	line(&out, "# Operations")
	line(&out, "")
	for _, item := range endpoints(doc.Paths) {
		writeOperation(&out, doc, item)
	}

	if len(doc.Components.Schemas) > 0 {
		line(&out, "# Schemas")
		line(&out, "")
		for _, name := range sortedKeys(doc.Components.Schemas) {
			writeSchema(&out, name, doc.Components.Schemas[name])
		}
	}

	if len(doc.Components.Responses) > 0 {
		line(&out, "# Reusable responses")
		line(&out, "")
		for _, name := range sortedKeys(doc.Components.Responses) {
			writeReusableResponse(&out, name, doc.Components.Responses[name])
		}
	}
	return []byte(strings.TrimRight(out.String(), "\n") + "\n"), nil
}

func writeSecuritySchemes(out *strings.Builder, schemes map[string]securityScheme) {
	if len(schemes) == 0 {
		return
	}
	line(out, "## Security schemes")
	line(out, "")
	line(out, "| Name | Type | Location | Description |")
	line(out, "| --- | --- | --- | --- |")
	for _, name := range sortedKeys(schemes) {
		scheme := schemes[name]
		typeText := scheme.Type
		if scheme.Scheme != "" {
			typeText += " / " + scheme.Scheme
		}
		if scheme.BearerFormat != "" {
			typeText += " (`" + scheme.BearerFormat + "`)"
		}
		location := scheme.In
		if scheme.Name != "" {
			location = scheme.In + " `" + scheme.Name + "`"
		}
		line(out, fmt.Sprintf("| `%s` | %s | %s | %s |", escapeTable(name), escapeTable(typeText), escapeTable(location), escapeTable(clean(scheme.Description))))
	}
	line(out, "")
}

func writeOperation(out *strings.Builder, doc document, item endpoint) {
	op := item.Operation
	line(out, "## `"+item.Method+" "+item.Path+"`")
	line(out, "")
	if op.Summary != "" {
		line(out, "**"+clean(op.Summary)+"**")
		line(out, "")
	}
	if op.OperationID != "" {
		line(out, "**Operation ID:** `"+escapeInline(op.OperationID)+"`")
		line(out, "")
	}
	if op.Deprecated {
		line(out, "**Deprecated:** Yes")
		line(out, "")
	}
	paragraph(out, op.Description)

	if len(op.Security) > 0 {
		line(out, "**Authentication:** "+securityText(op.Security))
		line(out, "")
	}
	if op.RequiredBearerScope != "" {
		line(out, "**Required Bearer scope:** `"+escapeInline(op.RequiredBearerScope)+"`")
		line(out, "")
	}
	if op.DeadlineSeconds > 0 {
		line(out, fmt.Sprintf("**Application deadline:** %d seconds", op.DeadlineSeconds))
		line(out, "")
	}
	if op.MaxBodyBytes > 0 {
		line(out, fmt.Sprintf("**Maximum HTTP body:** %d bytes (%s)", op.MaxBodyBytes, formatBytes(op.MaxBodyBytes)))
		line(out, "")
	}
	if op.NoAutomaticRetry {
		line(out, "**Automatic retry:** Prohibited")
		line(out, "")
	}

	parameters := append(append([]parameter{}, item.Common...), op.Parameters...)
	if len(parameters) > 0 {
		line(out, "### Parameters")
		line(out, "")
		line(out, "| Name | In | Type | Required | Description |")
		line(out, "| --- | --- | --- | --- | --- |")
		for _, parameter := range parameters {
			parameter = resolveParameter(doc, parameter)
			line(out, fmt.Sprintf("| `%s` | %s | %s | %s | %s |", escapeTable(parameter.Name), escapeTable(parameter.In), schemaText(parameter.Schema), yesNo(parameter.Required), escapeTable(clean(parameter.Description))))
		}
		line(out, "")
	}

	request := resolveRequestBody(doc, op.RequestBody)
	if request.Ref != "" || request.Description != "" || len(request.Content) > 0 {
		line(out, "### Request body")
		line(out, "")
		line(out, "**Required:** "+yesNo(request.Required))
		line(out, "")
		paragraph(out, request.Description)
		for _, media := range sortedKeys(request.Content) {
			line(out, "- `"+escapeInline(media)+"`: "+schemaText(request.Content[media].Schema))
		}
		line(out, "")
	}

	if len(op.Responses) > 0 {
		line(out, "### Responses")
		line(out, "")
		line(out, "| Status | Meaning | Body |")
		line(out, "| --- | --- | --- |")
		for _, status := range sortedResponseCodes(op.Responses) {
			response := op.Responses[status]
			meaning := clean(response.Description)
			body := responseContent(response)
			if response.Ref != "" {
				name := refName(response.Ref)
				body = link(name, "response-"+name)
				if reusable, ok := doc.Components.Responses[name]; ok {
					meaning = clean(reusable.Description)
				}
			}
			line(out, fmt.Sprintf("| `%s` | %s | %s |", escapeTable(status), escapeTable(meaning), body))
		}
		line(out, "")
	}
}

func writeSchema(out *strings.Builder, name string, value schema) {
	line(out, "## Schema `"+name+"`")
	line(out, "")
	paragraph(out, value.Description)
	line(out, "**Type:** "+schemaText(value))
	line(out, "")
	if len(value.OneOf) > 0 || len(value.AnyOf) > 0 {
		variants := value.OneOf
		label := "One of"
		if len(variants) == 0 {
			variants = value.AnyOf
			label = "Any of"
		}
		parts := make([]string, 0, len(variants))
		for _, variant := range variants {
			parts = append(parts, schemaText(variant))
		}
		line(out, "**"+label+":** "+strings.Join(parts, ", "))
		line(out, "")
	}
	if len(value.Properties) == 0 {
		return
	}
	required := stringSet(value.Required)
	line(out, "| Property | Type and limits | Required | Description |")
	line(out, "| --- | --- | --- | --- |")
	for _, property := range sortedKeys(value.Properties) {
		definition := value.Properties[property]
		line(out, fmt.Sprintf("| `%s` | %s | %s | %s |", escapeTable(property), schemaText(definition), yesNo(required[property]), escapeTable(clean(definition.Description))))
	}
	line(out, "")
}

func writeReusableResponse(out *strings.Builder, name string, value response) {
	line(out, "## Response `"+name+"`")
	line(out, "")
	paragraph(out, value.Description)
	if len(value.Content) == 0 {
		line(out, "No response body is defined.")
		line(out, "")
		return
	}
	for _, media := range sortedKeys(value.Content) {
		line(out, "- `"+escapeInline(media)+"`: "+schemaText(value.Content[media].Schema))
	}
	line(out, "")
}

func endpoints(paths map[string]pathItem) []endpoint {
	items := make([]endpoint, 0, len(paths)*2)
	for path, item := range paths {
		for _, candidate := range []struct {
			method string
			op     *operation
		}{
			{"GET", item.Get}, {"POST", item.Post}, {"PUT", item.Put}, {"PATCH", item.Patch},
			{"DELETE", item.Delete}, {"OPTIONS", item.Options}, {"HEAD", item.Head},
		} {
			if candidate.op != nil {
				items = append(items, endpoint{Path: path, Method: candidate.method, Operation: candidate.op, Common: item.Parameters})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].Method < items[j].Method
	})
	return items
}

func resolveParameter(doc document, value parameter) parameter {
	if value.Ref == "" {
		return value
	}
	if resolved, ok := doc.Components.Parameters[refName(value.Ref)]; ok {
		return resolved
	}
	return value
}

func resolveRequestBody(doc document, value requestBody) requestBody {
	if value.Ref == "" {
		return value
	}
	if resolved, ok := doc.Components.RequestBodies[refName(value.Ref)]; ok {
		return resolved
	}
	return value
}

func responseContent(value response) string {
	if len(value.Content) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(value.Content))
	for _, media := range sortedKeys(value.Content) {
		parts = append(parts, "`"+escapeInline(media)+"` "+schemaText(value.Content[media].Schema))
	}
	return strings.Join(parts, "<br>")
}

func schemaText(value schema) string {
	if value.Ref != "" {
		name := refName(value.Ref)
		return link(name, "schema-"+name)
	}
	typeName := value.Type
	if typeName == "" {
		switch {
		case len(value.OneOf) > 0:
			typeName = "one of " + schemaList(value.OneOf)
		case len(value.AnyOf) > 0:
			typeName = "any of " + schemaList(value.AnyOf)
		default:
			typeName = "value"
		}
	}
	if value.Items != nil {
		typeName += " of " + schemaText(*value.Items)
	}
	if value.Format != "" {
		typeName += " (`" + escapeInline(value.Format) + "`)"
	}
	limits := make([]string, 0, 5)
	if value.MinLength != nil {
		limits = append(limits, "min length "+strconv.Itoa(*value.MinLength))
	}
	if value.MaxLength != nil {
		limits = append(limits, "max length "+strconv.Itoa(*value.MaxLength))
	}
	if value.Minimum != nil {
		limits = append(limits, "minimum "+formatNumber(*value.Minimum))
	}
	if value.Maximum != nil {
		limits = append(limits, "maximum "+formatNumber(*value.Maximum))
	}
	if len(value.Enum) > 0 {
		values := make([]string, 0, len(value.Enum))
		for _, item := range value.Enum {
			values = append(values, "`"+escapeInline(fmt.Sprint(item))+"`")
		}
		limits = append(limits, "values "+strings.Join(values, ", "))
	}
	if len(limits) > 0 {
		typeName += "; " + strings.Join(limits, "; ")
	}
	return typeName
}

func schemaList(values []schema) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, schemaText(value))
	}
	return strings.Join(parts, ", ")
}

func securityText(requirements []map[string][]string) string {
	alternatives := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		parts := make([]string, 0, len(requirement))
		for _, name := range sortedKeys(requirement) {
			text := "`" + escapeInline(name) + "`"
			if len(requirement[name]) > 0 {
				scopes := make([]string, 0, len(requirement[name]))
				for _, scope := range requirement[name] {
					scopes = append(scopes, "`"+escapeInline(scope)+"`")
				}
				text += " (" + strings.Join(scopes, ", ") + ")"
			}
			parts = append(parts, text)
		}
		alternatives = append(alternatives, strings.Join(parts, " + "))
	}
	return strings.Join(alternatives, " or ")
}

func sortedResponseCodes(values map[string]response) []string {
	keys := sortedKeys(values)
	sort.SliceStable(keys, func(i, j int) bool {
		left, leftErr := strconv.Atoi(keys[i])
		right, rightErr := strconv.Atoi(keys[j])
		if leftErr == nil && rightErr == nil {
			return left < right
		}
		if leftErr == nil {
			return true
		}
		if rightErr == nil {
			return false
		}
		return keys[i] < keys[j]
	})
	return keys
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func refName(ref string) string {
	parts := strings.Split(ref, "/")
	return parts[len(parts)-1]
}

func link(label, anchor string) string {
	return "[" + label + "](#" + strings.ToLower(anchor) + ")"
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func formatNumber(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func formatBytes(value int) string {
	const mebibyte = 1024 * 1024
	if value%mebibyte == 0 {
		return strconv.Itoa(value/mebibyte) + " MiB"
	}
	return strconv.Itoa(value) + " bytes"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func paragraph(out *strings.Builder, value string) {
	value = clean(value)
	if value == "" {
		return
	}
	line(out, value)
	line(out, "")
}

func clean(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func escapeInline(value string) string {
	return strings.ReplaceAll(value, "`", "\\`")
}

func escapeTable(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	return strings.ReplaceAll(value, "\n", " ")
}

func line(out *strings.Builder, value string) {
	out.WriteString(value)
	out.WriteByte('\n')
}
