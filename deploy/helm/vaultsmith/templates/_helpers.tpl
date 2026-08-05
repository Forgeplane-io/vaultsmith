{{- define "vaultsmith.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "vaultsmith.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "vaultsmith.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "vaultsmith.labels" -}}
helm.sh/chart: {{ include "vaultsmith.chart" . }}
{{ include "vaultsmith.selectorLabels" . }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "vaultsmith.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vaultsmith.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "vaultsmith.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vaultsmith.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "vaultsmith.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{- define "vaultsmith.validate" -}}
{{- $seenIDs := dict -}}
{{- $seenEnvs := dict -}}
{{- range .Values.profiles }}
{{- if hasKey $seenIDs .id }}{{ fail (printf "profiles contains duplicate id %q" .id) }}{{ end }}
{{- $_ := set $seenIDs .id true }}
{{- if hasKey $seenEnvs .passwordEnv }}{{ fail (printf "profiles contains duplicate passwordEnv %q" .passwordEnv) }}{{ end }}
{{- $_ := set $seenEnvs .passwordEnv true }}
{{- if or (eq .passwordEnv "VAULT_PROFILES_JSON") (eq .passwordEnv "HTTP_ADDR") }}{{ fail (printf "profiles passwordEnv %q is reserved" .passwordEnv) }}{{ end }}
{{- end }}
{{- if gt (len .Values.profiles) 0 }}
{{- $_ := required "secret.existingSecret is required when profiles are configured" .Values.secret.existingSecret }}
{{- end }}
{{- if and .Values.networkPolicy.enabled .Values.networkPolicy.denyAllIngress .Values.networkPolicy.allowedIngress }}{{ fail "networkPolicy.denyAllIngress cannot be combined with allowedIngress" }}{{ end }}
{{- if .Values.networkPolicy.enabled }}
{{- range .Values.networkPolicy.allowedIngress }}
{{- if and (not .namespaceSelector) (not .podSelector) }}{{ fail "networkPolicy.allowedIngress rules need namespaceSelector or podSelector" }}{{ end }}
{{- end }}
{{- end }}
{{- end }}
