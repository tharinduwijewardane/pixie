/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pxapi

type Plugin struct {
	Name               string
	Id                 string
	Description        string
	Logo               string
	LatestVersion      string
	RetentionSupported bool
	RetentionEnabled   bool
	EnabledVersion     string
}

type RetentionPluginInfo struct {
	Configs              map[string]string
	AllowCustomExportUrl bool
	AllowInsecureTls     bool
	DefaultExportUrl     string
}

type OrgRetentionPluginConfig struct {
	Configs         map[string]string
	CustomExportUrl string
	InsecureTls     bool
}

type UpdateRetentionPluginConfigRequest struct {
	PluginId        string
	Configs         map[string]string
	Enabled         bool
	Version         string
	CustomExportUrl string
	InsecureTls     bool
	DisablePresets  bool
}

type RetentionScriptMeta struct {
	ScriptId           string
	ScriptName         string
	Description        string
	FrequencyInSeconds int64
	ClusterIds         []string
	PluginId           string
	Enabled            bool
	IsPreset           bool
}

type RetentionScript struct {
	Script    RetentionScriptMeta
	Contents  string
	ExportUrl string
}

type UpdateRetentionScriptRequest struct {
	ScriptId           string
	ScriptName         string
	Description        string
	Enabled            bool
	FrequencyInSeconds int64
	Contents           string
	ExportUrl          string
	ClusterIds         []string
}

type CreateRetentionScriptRequest struct {
	ScriptName         string
	Description        string
	FrequencyInSeconds int64
	Contents           string
	ExportUrl          string
	ClusterIds         []string
	PluginId           string
}
