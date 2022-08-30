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

import (
	"context"
	"github.com/gogo/protobuf/types"
	"px.dev/pixie/src/api/proto/uuidpb"

	"px.dev/pixie/src/api/go/pxapi/errdefs"
	"px.dev/pixie/src/api/go/pxapi/utils"
	"px.dev/pixie/src/api/proto/cloudpb"
)

// VizierStatus stores the enumeration of all vizier statuses.
type VizierStatus string

// Vizier Statuses.
const (
	VizierStatusUnknown      VizierStatus = "Unknown"
	VizierStatusHealthy      VizierStatus = "Healthy"
	VizierStatusUnhealthy    VizierStatus = "Unhealthy"
	VizierStatusDisconnected VizierStatus = "Disconnected"
	VizierStatusDegraded     VizierStatus = "Degraded"
)

// VizierInfo has information of a single Vizier.
type VizierInfo struct {
	// Name of the vizier.
	Name string
	// ID of the Vizier (uuid as a string).
	ID string
	// Status of the Vizier.
	Status VizierStatus
	// Version of the installed vizier.
	Version string
}

func clusterStatusToVizierStatus(status cloudpb.ClusterStatus) VizierStatus {
	switch status {
	case cloudpb.CS_HEALTHY:
		return VizierStatusHealthy
	case cloudpb.CS_UNHEALTHY:
		return VizierStatusUnhealthy
	case cloudpb.CS_DISCONNECTED:
		return VizierStatusDisconnected
	case cloudpb.CS_DEGRADED:
		return VizierStatusDegraded
	default:
		return VizierStatusUnknown
	}
}

// ListViziers gets a list of Viziers registered with Pixie.
func (c *Client) ListViziers(ctx context.Context) ([]*VizierInfo, error) {
	req := &cloudpb.GetClusterInfoRequest{}
	res, err := c.cmClient.GetClusterInfo(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}

	viziers := make([]*VizierInfo, 0)
	for _, v := range res.Clusters {
		viziers = append(viziers, &VizierInfo{
			Name:    v.ClusterName,
			ID:      utils.ProtoToUUIDStr(v.ID),
			Version: v.VizierVersion,
			Status:  clusterStatusToVizierStatus(v.Status),
		})
	}

	return viziers, nil
}

// GetVizierInfo gets info about the given clusterID.
func (c *Client) GetVizierInfo(ctx context.Context, clusterID string) (*VizierInfo, error) {
	req := &cloudpb.GetClusterInfoRequest{
		ID: utils.ProtoFromUUIDStrOrNil(clusterID),
	}
	res, err := c.cmClient.GetClusterInfo(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}

	if len(res.Clusters) == 0 {
		return nil, errdefs.ErrClusterNotFound
	}

	v := res.Clusters[0]

	return &VizierInfo{
		Name:    v.ClusterName,
		ID:      utils.ProtoToUUIDStr(v.ID),
		Version: v.VizierVersion,
		Status:  clusterStatusToVizierStatus(v.Status),
	}, nil
}

// CreateDeployKey creates a new deploy key, with an optional description.
func (c *Client) CreateDeployKey(ctx context.Context, desc string) (*cloudpb.DeploymentKey, error) {
	keyMgr := cloudpb.NewVizierDeploymentKeyManagerClient(c.grpcConn)
	req := &cloudpb.CreateDeploymentKeyRequest{
		Desc: desc,
	}
	dk, err := keyMgr.Create(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// CreateAPIKey creates and API key with the passed in description.
func (c *Client) CreateAPIKey(ctx context.Context, desc string) (*cloudpb.APIKey, error) {
	req := &cloudpb.CreateAPIKeyRequest{
		Desc: desc,
	}

	apiKeyMgr := cloudpb.NewAPIKeyManagerClient(c.grpcConn)
	resp, err := apiKeyMgr.Create(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// DeleteAPIKey deletes an API key by ID.
func (c *Client) DeleteAPIKey(ctx context.Context, id string) error {
	req := utils.ProtoFromUUIDStrOrNil(id)
	apiKeyMgr := cloudpb.NewAPIKeyManagerClient(c.grpcConn)
	_, err := apiKeyMgr.Delete(c.cloudCtxWithMD(ctx), req)
	return err
}

func (c *Client) GetPlugins(ctx context.Context) ([]*Plugin, error) {
	req := &cloudpb.GetPluginsRequest{}
	res, err := c.plClient.GetPlugins(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}
	var plugins []*Plugin
	for _, p := range res.GetPlugins() {
		plugins = append(plugins, &Plugin{
			Name:               p.Name,
			Id:                 p.Id,
			Description:        p.Description,
			Logo:               p.Logo,
			LatestVersion:      p.LatestVersion,
			RetentionSupported: p.RetentionSupported,
			RetentionEnabled:   p.RetentionEnabled,
			EnabledVersion:     p.EnabledVersion,
		})
	}
	return plugins, nil
}

func (c *Client) GetRetentionPluginInfo(ctx context.Context, pluginId, version string) (*RetentionPluginInfo, error) {
	req := &cloudpb.GetRetentionPluginInfoRequest{
		PluginId: pluginId,
		Version:  version,
	}
	res, err := c.plClient.GetRetentionPluginInfo(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}
	return &RetentionPluginInfo{
		Configs:              res.Configs,
		AllowCustomExportUrl: res.AllowCustomExportURL,
		AllowInsecureTls:     res.AllowInsecureTLS,
		DefaultExportUrl:     res.DefaultExportURL,
	}, nil
}

func (c *Client) GetOrgRetentionPluginConfig(ctx context.Context, pluginId string) (*OrgRetentionPluginConfig, error) {
	req := &cloudpb.GetOrgRetentionPluginConfigRequest{
		PluginId: pluginId,
	}
	res, err := c.plClient.GetOrgRetentionPluginConfig(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}
	return &OrgRetentionPluginConfig{
		Configs:         res.Configs,
		CustomExportUrl: res.CustomExportUrl,
		InsecureTls:     res.InsecureTLS,
	}, nil
}

func (c *Client) UpdateRetentionPluginConfig(ctx context.Context, req *UpdateRetentionPluginConfigRequest) error {
	r := &cloudpb.UpdateRetentionPluginConfigRequest{
		PluginId:        req.PluginId,
		Configs:         req.Configs,
		Enabled:         &types.BoolValue{Value: req.Enabled},
		Version:         &types.StringValue{Value: req.Version},
		CustomExportUrl: &types.StringValue{Value: req.CustomExportUrl},
		InsecureTLS:     &types.BoolValue{Value: req.InsecureTls},
		DisablePresets:  &types.BoolValue{Value: req.DisablePresets},
	}
	_, err := c.plClient.UpdateRetentionPluginConfig(c.cloudCtxWithMD(ctx), r)
	return err
}

func (c *Client) GetRetentionScripts(ctx context.Context) ([]*RetentionScriptMeta, error) {
	req := &cloudpb.GetRetentionScriptsRequest{}
	res, err := c.plClient.GetRetentionScripts(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}
	var retentionScript []*RetentionScriptMeta
	for _, s := range res.GetScripts() {
		retentionScript = append(retentionScript, &RetentionScriptMeta{
			ScriptId:           utils.ProtoToUUIDStr(s.ScriptID),
			ScriptName:         s.ScriptName,
			Description:        s.Description,
			FrequencyInSeconds: s.FrequencyS,
			ClusterIds: func() []string {
				var clusterIds []string
				for _, cId := range s.ClusterIDs {
					clusterIds = append(clusterIds, utils.ProtoToUUIDStr(cId))
				}
				return clusterIds
			}(),
			PluginId: s.PluginId,
			Enabled:  s.Enabled,
			IsPreset: s.IsPreset,
		})
	}
	return retentionScript, nil
}

func (c *Client) GetRetentionScript(ctx context.Context, scriptId string) (*RetentionScript, error) {
	req := &cloudpb.GetRetentionScriptRequest{
		ID: utils.ProtoFromUUIDStrOrNil(scriptId),
	}
	res, err := c.plClient.GetRetentionScript(c.cloudCtxWithMD(ctx), req)
	if err != nil {
		return nil, err
	}
	return &RetentionScript{
		Script: RetentionScriptMeta{
			ScriptId:           utils.ProtoToUUIDStr(res.Script.ScriptID),
			ScriptName:         res.Script.ScriptName,
			Description:        res.Script.Description,
			FrequencyInSeconds: res.Script.FrequencyS,
			ClusterIds: func() []string {
				var clusterIds []string
				for _, cId := range res.Script.ClusterIDs {
					clusterIds = append(clusterIds, utils.ProtoToUUIDStr(cId))
				}
				return clusterIds
			}(),
			PluginId: res.Script.PluginId,
			Enabled:  res.Script.Enabled,
			IsPreset: res.Script.IsPreset,
		},
		Contents:  res.Contents,
		ExportUrl: res.ExportURL,
	}, nil
}

func (c *Client) UpdateRetentionScript(ctx context.Context, req *UpdateRetentionScriptRequest) error {
	r := &cloudpb.UpdateRetentionScriptRequest{
		ID:          utils.ProtoFromUUIDStrOrNil(req.ScriptId),
		ScriptName:  &types.StringValue{Value: req.ScriptName},
		Description: &types.StringValue{Value: req.Description},
		Enabled:     &types.BoolValue{Value: req.Enabled},
		FrequencyS:  &types.Int64Value{Value: req.FrequencyInSeconds},
		Contents:    &types.StringValue{Value: req.Contents},
		ExportUrl:   &types.StringValue{Value: req.ExportUrl},
		ClusterIDs: func() []*uuidpb.UUID {
			var clusterIds []*uuidpb.UUID
			for _, cId := range req.ClusterIds {
				clusterIds = append(clusterIds, utils.ProtoFromUUIDStrOrNil(cId))
			}
			return clusterIds
		}(),
	}
	_, err := c.plClient.UpdateRetentionScript(c.cloudCtxWithMD(ctx), r)
	return err
}

func (c *Client) CreateRetentionScript(ctx context.Context, req *CreateRetentionScriptRequest) (string, error) {
	r := &cloudpb.CreateRetentionScriptRequest{
		ScriptName:  req.ScriptName,
		Description: req.Description,
		FrequencyS:  req.FrequencyInSeconds,
		Contents:    req.Contents,
		ExportUrl:   req.ExportUrl,
		ClusterIDs: func() []*uuidpb.UUID {
			var clusterIds []*uuidpb.UUID
			for _, cId := range req.ClusterIds {
				clusterIds = append(clusterIds, utils.ProtoFromUUIDStrOrNil(cId))
			}
			return clusterIds
		}(),
		PluginId: req.PluginId,
	}
	res, err := c.plClient.CreateRetentionScript(c.cloudCtxWithMD(ctx), r)
	if err != nil {
		return "", err
	}
	return utils.ProtoToUUIDStr(res.ID), nil
}

func (c *Client) DeleteRetentionScript(ctx context.Context, scriptId string) error {
	req := &cloudpb.DeleteRetentionScriptRequest{
		ID: utils.ProtoFromUUIDStrOrNil(scriptId),
	}
	_, err := c.plClient.DeleteRetentionScript(c.cloudCtxWithMD(ctx), req)
	return err
}
