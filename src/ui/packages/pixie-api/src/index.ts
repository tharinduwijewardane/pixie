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

export {
  PixieAPIClient, PixieAPIClientAbstract, ClusterConfig,
} from './api';

export { PixieAPIClientOptions } from './types/client-options';

export { VizierQueryErrorType, VizierQueryError, GRPCStatusCode } from './vizier';

export { CloudClient } from './cloud-gql-client';

export { containsMutation, isStreaming } from './utils/pxl';

export {
  Table as VizierTable,
  BatchDataUpdate,
  ExecutionStateUpdate,
  ExecutionEvent,
  // TODO(nick): VizierGRPCClient shouldn't be exposed; remove this line once the UI code drops its direct dependency.
  VizierGRPCClient,
  VizierQueryArg,
  VizierQueryFunc,
  VizierQueryResult,
} from './vizier-grpc-client';

// TODO(nick): Create @pixie-labs/api/testing as its own package by doing the same trick that Apollo does.
export * from './testing';

/* Generated types begin (types are generated but these exports are manually updated) */

export {
  GQLQuery,
  GQLUserInfo,
  GQLUserInvite,
  GQLOrgInfo,
  GQLUserSetting,
  GQLClusterInfo,
  GQLVizierConfig,
  GQLPodStatus,
  GQLContainerStatus,
  GQLK8sEvent,
  GQLClusterConnectionInfo,
  GQLClusterStatus,
  GQLCLIArtifact,
  GQLArtifactsInfo,
  GQLArtifact,
  GQLAutocompleteResult,
  GQLAutocompleteEntityKind,
  GQLAutocompleteEntityState,
  GQLAutocompleteActionType,
  GQLTabSuggestion,
  GQLAutocompleteSuggestion,
  GQLLiveViewMetadata,
  GQLLiveViewContents,
  GQLScriptMetadata,
  GQLScriptContents,
  GQLDeploymentKey,
  GQLAPIKey,
  GQLMutation,
  GQLResolver,
  GQLQueryTypeResolver,
  GQLUserInfoTypeResolver,
  GQLOrgInfoTypeResolver,
  GQLUserSettingTypeResolver,
  GQLClusterInfoTypeResolver,
  GQLVizierConfigTypeResolver,
  GQLPodStatusTypeResolver,
  GQLContainerStatusTypeResolver,
  GQLK8sEventTypeResolver,
  GQLClusterConnectionInfoTypeResolver,
  GQLCLIArtifactTypeResolver,
  GQLArtifactsInfoTypeResolver,
  GQLArtifactTypeResolver,
  GQLAutocompleteResultTypeResolver,
  GQLTabSuggestionTypeResolver,
  GQLAutocompleteSuggestionTypeResolver,
  GQLLiveViewMetadataTypeResolver,
  GQLLiveViewContentsTypeResolver,
  GQLScriptMetadataTypeResolver,
  GQLScriptContentsTypeResolver,
  GQLDeploymentKeyTypeResolver,
  GQLAPIKeyTypeResolver,
  GQLMutationTypeResolver,
} from './types/schema';

export {
  Axis,
  BarChart,
  Graph,
  RequestGraph,
  HistogramChart,
  VegaChart,
  TimeseriesChart,
  Vis,
  PXType,
  Table,
  Widget,
} from './types/generated/vis_pb';

export {
  BooleanColumn,
  Column,
  CompilerError,
  DataType,
  ErrorDetails,
  ExecuteScriptRequest,
  ExecuteScriptResponse,
  Float64Column,
  HealthCheckRequest,
  HealthCheckResponse,
  Int64Column,
  LifeCycleState,
  MutationInfo,
  QueryData,
  QueryExecutionStats,
  QueryMetadata,
  QueryTimingInfo,
  Relation,
  RowBatchData,
  ScalarValue,
  SemanticType,
  Status,
  StringColumn,
  Time64NSColumn,
  UInt128,
  UInt128Column,
} from './types/generated/vizierapi_pb';

export { VizierServiceClient } from './types/generated/VizierapiServiceClientPb';

/* Generated types end */
