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

package controllers_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/gogo/protobuf/types"
	bindata "github.com/golang-migrate/migrate/source/go_bindata"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"px.dev/pixie/src/api/proto/uuidpb"
	"px.dev/pixie/src/cloud/cron_script/controllers"
	"px.dev/pixie/src/cloud/cron_script/cronscriptpb"
	"px.dev/pixie/src/cloud/cron_script/schema"
	"px.dev/pixie/src/shared/services/authcontext"
	"px.dev/pixie/src/shared/services/pgtest"
	srvutils "px.dev/pixie/src/shared/services/utils"
	"px.dev/pixie/src/utils"
)

var db *sqlx.DB

func TestMain(m *testing.M) {
	err := testMain(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Got error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func testMain(m *testing.M) error {
	viper.Set("jwt_signing_key", "key0")
	s := bindata.Resource(schema.AssetNames(), schema.Asset)
	testDB, teardown, err := pgtest.SetupTestDB(s)
	if err != nil {
		return fmt.Errorf("failed to start test database: %w", err)
	}

	defer teardown()
	db = testDB

	if c := m.Run(); c != 0 {
		return fmt.Errorf("some tests failed with code: %d", c)
	}
	return nil
}

func createTestContext() context.Context {
	sCtx := authcontext.New()
	sCtx.Claims = srvutils.GenerateJWTForUser("abcdef", "223e4567-e89b-12d3-a456-426655440000", "test@test.com", time.Now(), "pixie")
	return authcontext.NewContext(context.Background(), sCtx)
}

func mustLoadTestData(db *sqlx.DB) {
	db.MustExec(`DELETE FROM cron_scripts`)

	insertScript := `INSERT INTO cron_scripts(id, org_id, script, cluster_ids, configs, enabled, frequency_s) VALUES ($1, $2, $3, $4, PGP_SYM_ENCRYPT($5, $6), $7, $8)`

	clusterIDs1 := []uuid.UUID{
		uuid.FromStringOrNil("323e4567-e89b-12d3-a456-426655440000"),
		uuid.FromStringOrNil("323e4567-e89b-12d3-a456-426655440001"),
	}
	clusterIDs2 := []uuid.UUID{
		uuid.FromStringOrNil("423e4567-e89b-12d3-a456-426655440000"),
		uuid.FromStringOrNil("423e4567-e89b-12d3-a456-426655440001"),
	}
	clusterIDs3 := []uuid.UUID{
		uuid.FromStringOrNil("323e4567-e89b-12d3-a456-426655440000"),
	}
	db.MustExec(insertScript, "123e4567-e89b-12d3-a456-426655440000", "223e4567-e89b-12d3-a456-426655440000", "px.display()", controllers.ClusterIDs(clusterIDs1), "testConfigYaml: abcd", "test", true, 5)
	db.MustExec(insertScript, "123e4567-e89b-12d3-a456-426655440002", "223e4567-e89b-12d3-a456-426655440000", "px()", controllers.ClusterIDs(clusterIDs3), "testConfigYaml: 1234", "test", false, 10)
	db.MustExec(insertScript, "123e4567-e89b-12d3-a456-426655440001", "223e4567-e89b-12d3-a456-426655440001", "px.stream()", controllers.ClusterIDs(clusterIDs2), "testConfigYaml2: efgh", "test", true, 10)
}

func TestServer_GetScript(t *testing.T) {
	mustLoadTestData(db)

	s := controllers.New(db, "test")
	resp, err := s.GetScript(createTestContext(), &cronscriptpb.GetScriptRequest{
		ID: utils.ProtoFromUUIDStrOrNil("123e4567-e89b-12d3-a456-426655440000"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, &cronscriptpb.GetScriptResponse{
		Script: &cronscriptpb.CronScript{
			ID:     utils.ProtoFromUUIDStrOrNil("123e4567-e89b-12d3-a456-426655440000"),
			OrgID:  utils.ProtoFromUUIDStrOrNil("223e4567-e89b-12d3-a456-426655440000"),
			Script: "px.display()",
			ClusterIDs: []*uuidpb.UUID{
				utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440000"),
				utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440001"),
			},
			Configs: "testConfigYaml: abcd",
			Enabled: true,
		},
	}, resp)
}

func TestServer_GetScripts(t *testing.T) {
	mustLoadTestData(db)

	s := controllers.New(db, "test")
	resp, err := s.GetScripts(createTestContext(), &cronscriptpb.GetScriptsRequest{
		IDs: []*uuidpb.UUID{
			utils.ProtoFromUUIDStrOrNil("123e4567-e89b-12d3-a456-426655440000"),
			utils.ProtoFromUUIDStrOrNil("123e4567-e89b-12d3-a456-426655440002"),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, &cronscriptpb.GetScriptsResponse{
		Scripts: []*cronscriptpb.CronScript{
			&cronscriptpb.CronScript{
				ID:     utils.ProtoFromUUIDStrOrNil("123e4567-e89b-12d3-a456-426655440000"),
				OrgID:  utils.ProtoFromUUIDStrOrNil("223e4567-e89b-12d3-a456-426655440000"),
				Script: "px.display()",
				ClusterIDs: []*uuidpb.UUID{
					utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440000"),
					utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440001"),
				},
				Configs: "testConfigYaml: abcd",
				Enabled: true,
			},
			&cronscriptpb.CronScript{
				ID:     utils.ProtoFromUUIDStrOrNil("123e4567-e89b-12d3-a456-426655440002"),
				OrgID:  utils.ProtoFromUUIDStrOrNil("223e4567-e89b-12d3-a456-426655440000"),
				Script: "px()",
				ClusterIDs: []*uuidpb.UUID{
					utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440000"),
				},
				Configs: "testConfigYaml: 1234",
				Enabled: false,
			},
		},
	}, resp)
}

func TestServer_CreateScript(t *testing.T) {
	mustLoadTestData(db)

	s := controllers.New(db, "test")

	clusterIDs := []*uuidpb.UUID{
		utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440003"),
		utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440002"),
	}
	resp, err := s.CreateScript(createTestContext(), &cronscriptpb.CreateScriptRequest{
		Script:     "px.display()",
		Configs:    "testYAML",
		FrequencyS: 11,
		ClusterIDs: clusterIDs,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	id := resp.ID

	query := `SELECT id, org_id, script, cluster_ids, PGP_SYM_DECRYPT(configs, $1::text) as configs, enabled, frequency_s FROM cron_scripts WHERE org_id=$2 AND id=$3`
	rows, err := db.Queryx(query, "test", "223e4567-e89b-12d3-a456-426655440000", utils.UUIDFromProtoOrNil(id))
	require.Nil(t, err)

	defer rows.Close()
	require.True(t, rows.Next())

	var script controllers.CronScript
	err = rows.StructScan(&script)
	require.Nil(t, err)

	assert.Equal(t, controllers.CronScript{
		ID:        utils.UUIDFromProtoOrNil(id),
		OrgID:     uuid.FromStringOrNil("223e4567-e89b-12d3-a456-426655440000"),
		Script:    "px.display()",
		ConfigStr: "testYAML",
		Enabled:   true,
		ClusterIDs: []uuid.UUID{
			uuid.FromStringOrNil("323e4567-e89b-12d3-a456-426655440003"),
			uuid.FromStringOrNil("323e4567-e89b-12d3-a456-426655440002"),
		},
		FrequencyS: 11,
	}, script)
}

func TestServer_UpdateScript(t *testing.T) {
	mustLoadTestData(db)

	s := controllers.New(db, "test")

	clusterIDs := []*uuidpb.UUID{
		utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440003"),
		utils.ProtoFromUUIDStrOrNil("323e4567-e89b-12d3-a456-426655440002"),
	}
	resp, err := s.UpdateScript(createTestContext(), &cronscriptpb.UpdateScriptRequest{
		Script:     &types.StringValue{Value: "px.updatedScript()"},
		Configs:    &types.StringValue{Value: "updatedYAML"},
		ClusterIDs: &cronscriptpb.ClusterIDs{Value: clusterIDs},
		ScriptId:   utils.ProtoFromUUIDStrOrNil("123e4567-e89b-12d3-a456-426655440002"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	query := `SELECT id, org_id, script, cluster_ids, PGP_SYM_DECRYPT(configs, $1::text) as configs, enabled, frequency_s FROM cron_scripts WHERE org_id=$2 AND id=$3`
	rows, err := db.Queryx(query, "test", "223e4567-e89b-12d3-a456-426655440000", "123e4567-e89b-12d3-a456-426655440002")
	require.Nil(t, err)

	defer rows.Close()
	require.True(t, rows.Next())

	var script controllers.CronScript
	err = rows.StructScan(&script)
	require.Nil(t, err)

	assert.Equal(t, controllers.CronScript{
		ID:        uuid.FromStringOrNil("123e4567-e89b-12d3-a456-426655440002"),
		OrgID:     uuid.FromStringOrNil("223e4567-e89b-12d3-a456-426655440000"),
		Script:    "px.updatedScript()",
		ConfigStr: "updatedYAML",
		Enabled:   false,
		ClusterIDs: []uuid.UUID{
			uuid.FromStringOrNil("323e4567-e89b-12d3-a456-426655440003"),
			uuid.FromStringOrNil("323e4567-e89b-12d3-a456-426655440002"),
		},
		FrequencyS: 10,
	}, script)
}

func TestServer_DeleteScript(t *testing.T) {
	mustLoadTestData(db)

	s := controllers.New(db, "test")

	resp, err := s.DeleteScript(createTestContext(), &cronscriptpb.DeleteScriptRequest{
		ID: utils.ProtoFromUUIDStrOrNil("123e4567-e89b-12d3-a456-426655440002"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, &cronscriptpb.DeleteScriptResponse{}, resp)

	query := `SELECT id, org_id, script, cluster_ids, PGP_SYM_DECRYPT(configs, $1::text) as configs, enabled, frequency_s FROM cron_scripts WHERE org_id=$2 AND id=$3`
	rows, err := db.Queryx(query, "test", "223e4567-e89b-12d3-a456-426655440000", "123e4567-e89b-12d3-a456-426655440002")
	require.Nil(t, err)

	defer rows.Close()
	require.False(t, rows.Next())
}