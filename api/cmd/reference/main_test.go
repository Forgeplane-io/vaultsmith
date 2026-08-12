package main

import (
	"bytes"
	"strings"
	"testing"
)

const referenceFixture = `openapi: 3.1.0
info:
  title: Synthetic API
  version: 1.2.3
  description: Synthetic contract.
servers:
  - url: https://service.example.test
paths:
  /items/{itemId}:
    parameters:
      - name: itemId
        in: path
        required: true
        schema:
          type: string
    post:
      operationId: updateItem
      summary: Update an item
      description: Does not retry automatically.
      deprecated: true
      security:
        - BearerAuth: [items.write]
      x-required-bearer-scope: items.write
      x-request-deadline-seconds: 30
      x-max-body-bytes: 8388608
      x-no-automatic-retry: true
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateItemRequest'
      responses:
        "200":
          description: Updated.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Item'
        "400":
          $ref: '#/components/responses/BadRequest'
components:
  schemas:
    UpdateItemRequest:
      type: object
      additionalProperties: false
      required: [value]
      properties:
        value:
          type: string
          maxLength: 16
          description: Synthetic value.
    Item:
      type: object
      required: [value]
      properties:
        value:
          type: string
  responses:
    BadRequest:
      description: Invalid request.
`

func TestGenerateReferenceIncludesContractDetailsDeterministically(t *testing.T) {
	first, err := generateReference([]byte(referenceFixture))
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateReference([]byte(referenceFixture))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("reference output is not deterministic")
	}
	if bytes.HasSuffix(first, []byte("\n\n")) || !bytes.HasSuffix(first, []byte("\n")) {
		t.Fatalf("reference must end with exactly one newline: %q", first[len(first)-2:])
	}
	for _, want := range []string{
		"# Synthetic API reference",
		"**Contract version:** `1.2.3`",
		"## `POST /items/{itemId}`",
		"**Operation ID:** `updateItem`",
		"**Deprecated:** Yes",
		"`BearerAuth` (`items.write`)",
		"**Required Bearer scope:** `items.write`",
		"**Application deadline:** 30 seconds",
		"**Maximum HTTP body:** 8388608 bytes (8 MiB)",
		"**Automatic retry:** Prohibited",
		"`itemId` | path | string | yes",
		"[UpdateItemRequest](#schema-updateitemrequest)",
		"`200` | Updated. | `application/json` [Item](#schema-item)",
		"[BadRequest](#response-badrequest)",
		"## Schema `UpdateItemRequest`",
		"`value` | string; max length 16 | yes | Synthetic value.",
		"## Response `BadRequest`",
	} {
		if !strings.Contains(string(first), want) {
			t.Fatalf("reference missing %q:\n%s", want, first)
		}
	}
}

func TestGenerateReferenceRejectsNonOpenAPI31(t *testing.T) {
	_, err := generateReference([]byte("openapi: 3.0.3\ninfo: {title: Old, version: 1}\npaths: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "OpenAPI 3.1") {
		t.Fatalf("error = %v, want OpenAPI 3.1 error", err)
	}
}
