{{/* Expand the chart name. */}}
{{- define "parsedmarc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a fully qualified app name. */}}
{{- define "parsedmarc.fullname" -}}
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

{{/* Common labels. */}}
{{- define "parsedmarc.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "parsedmarc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels. */}}
{{- define "parsedmarc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "parsedmarc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Secret names used by the workload. */}}
{{- define "parsedmarc.elasticsearchSecretName" -}}
{{- if .Values.externalSecrets.enabled }}{{ .Values.externalSecrets.elasticsearch.secretName }}{{ else }}{{ .Values.externalSecrets.elasticsearch.secretName }}{{ end }}
{{- end }}
{{- define "parsedmarc.gmailSecretName" -}}
{{- if .Values.externalSecrets.enabled }}{{ .Values.externalSecrets.gmail.secretName }}{{ else }}{{ .Values.externalSecrets.gmail.secretName }}{{ end }}
{{- end }}
{{- define "parsedmarc.kibanaSecretName" -}}
{{- if .Values.externalSecrets.enabled }}{{ .Values.externalSecrets.kibana.secretName }}{{ else }}{{ .Values.externalSecrets.kibana.secretName }}{{ end }}
{{- end }}

