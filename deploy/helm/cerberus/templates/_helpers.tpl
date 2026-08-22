{{/*
Name of the chart (without overrides).
*/}}
{{- define "cerberus.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified name of the deployment.
*/}}
{{- define "cerberus.fullname" -}}
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

{{/*
Name of the ServiceAccount.
*/}}
{{- define "cerberus.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cerberus.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "cerberus.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "cerberus.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (for Service/Deployment selector).
*/}}
{{- define "cerberus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cerberus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}