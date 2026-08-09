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
{{- $reservedEnvs := list "VAULT_PROFILES_JSON" "HTTP_ADDR" "AUTH_MODE" "CSRF_SECRET" "OIDC_ISSUER_URL" "OIDC_CLIENT_ID" "OIDC_CLIENT_SECRET" "OIDC_CA_FILE" "OIDC_REDIRECT_URL" "PUBLIC_BASE_URL" "OIDC_GROUPS_CLAIM" "OIDC_SCOPES" "AUTHZ_POLICY_FILE" "REDIS_ADDR" "REDIS_USERNAME" "REDIS_PASSWORD" "REDIS_DB" "REDIS_TLS" "REDIS_CONNECT_TIMEOUT" "REDIS_READ_TIMEOUT" "REDIS_WRITE_TIMEOUT" "REDIS_POOL_SIZE" "REDIS_REFRESH_LOCK_TTL" "REDIS_REFRESH_LOCK_WAIT" "REDIS_REFRESH_LOCK_RETRY" "REDIS_PROVIDER_TIMEOUT" "REDIS_KEY_PREFIX" "COOKIE_SECURE" "COOKIE_SAME_SITE" "SESSION_ABSOLUTE_LIFETIME" "SESSION_IDLE_LIFETIME" "CORS_ALLOWED_ORIGINS" -}}
{{- range .Values.profiles }}
{{- if hasKey $seenIDs .id }}{{ fail (printf "profiles contains duplicate id %q" .id) }}{{ end }}
{{- $_ := set $seenIDs .id true }}
{{- if hasKey $seenEnvs .passwordEnv }}{{ fail (printf "profiles contains duplicate passwordEnv %q" .passwordEnv) }}{{ end }}
{{- $_ := set $seenEnvs .passwordEnv true }}
{{- if has .passwordEnv $reservedEnvs }}{{ fail (printf "profiles passwordEnv %q is reserved" .passwordEnv) }}{{ end }}
{{- end }}
{{- if gt (len .Values.profiles) 0 }}
{{- $_ := required "secret.existingSecret is required when profiles are configured" .Values.secret.existingSecret }}
{{- end }}
{{- $mode := required "auth.mode must be explicitly set to native or off" .Values.auth.mode -}}
{{- if not (has $mode (list "off" "native")) }}{{ fail (printf "auth.mode must be off or native, got %q" $mode) }}{{ end }}
{{- if and .Values.auth.policy.data .Values.auth.policy.existingConfigMap }}{{ fail "auth.policy.data and auth.policy.existingConfigMap are mutually exclusive" }}{{ end }}
{{- if eq $mode "native" }}
{{- $_ := required "auth.csrf.existingSecret is required in native mode" .Values.auth.csrf.existingSecret }}
{{- $_ := required "auth.oidc.issuerURL is required in native mode" .Values.auth.oidc.issuerURL }}
{{- $_ := required "auth.oidc.clientID is required in native mode" .Values.auth.oidc.clientID }}
{{- $_ := required "auth.oidc.clientSecret.existingSecret is required in native mode" .Values.auth.oidc.clientSecret.existingSecret }}
{{- $_ := required "auth.oidc.redirectURL is required in native mode" .Values.auth.oidc.redirectURL }}
{{- $_ := required "auth.oidc.publicBaseURL is required in native mode" .Values.auth.oidc.publicBaseURL }}
{{- $_ := required "auth.redis.address is required in native mode" .Values.auth.redis.address }}
{{- $_ := required "auth.policy.data or auth.policy.existingConfigMap is required in native mode" (default .Values.auth.policy.existingConfigMap .Values.auth.policy.data) }}
{{- if not .Values.auth.session.secure }}{{ fail "auth.session.secure must be true in native mode" }}{{ end }}
{{- if and .Values.auth.redis.username (not .Values.auth.redis.password.existingSecret) }}{{ fail "auth.redis.password.existingSecret is required when auth.redis.username is configured" }}{{ end }}
{{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.allowedEgress) }}{{ fail "networkPolicy.allowedEgress must allow OIDC and Redis egress in native mode, or disable networkPolicy explicitly" }}{{ end }}
{{- end }}
{{- if and .Values.networkPolicy.enabled .Values.networkPolicy.denyAllIngress .Values.networkPolicy.allowedIngress }}{{ fail "networkPolicy.denyAllIngress cannot be combined with allowedIngress" }}{{ end }}
{{- if .Values.networkPolicy.enabled }}
{{- range .Values.networkPolicy.allowedIngress }}
{{- if and (not .namespaceSelector) (not .podSelector) }}{{ fail "networkPolicy.allowedIngress rules need namespaceSelector or podSelector" }}{{ end }}
{{- end }}
{{- range .Values.networkPolicy.allowedEgress }}
{{- if and (not .to) (not .ports) }}{{ fail "networkPolicy.allowedEgress rules need to or ports" }}{{ end }}
{{- end }}
{{- end }}
{{- end }}
