/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const diagWorkloadDump = `{
	"workloads": [
		{"name": "sleep-abc", "namespace": "default", "uid": "uid-1", "addresses": ["10.0.0.1"], "status": "Healthy"}
	],
	"services": [
		{"name": "productpage", "namespace": "default", "hostname": "productpage.default.svc.cluster.local", "vips": ["10.96.5.5"]},
		{"name": "waypointed", "namespace": "default", "vips": ["10.96.5.6"], "waypoint": {"destination": "waypoint-1"}}
	],
	"policies": [
		{"name": "allow-read", "namespace": "kube-system", "action": "ALLOW", "scope": "namespace"}
	]
}`

const diagBpfDump = `{
	"backends": [
		{"ip": "10.0.0.1", "services": ["default/productpage"]},
		{"ip": "10.0.0.2", "services": ["default/productpage"]}
	],
	"frontends": [{"upstreamId": "default/productpage"}],
	"endpoints": [{"backendUid": "uid-1"}],
	"services": [],
	"workloadPolicies": []
}`

func diagnoseStub(daemonMode string) func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
	return func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
		switch {
		case endpoint == "version":
			return []byte(`{"mode":"` + daemonMode + `"}`), nil
		case endpoint == "debug/config_dump/dual-engine":
			return []byte(diagWorkloadDump), nil
		case endpoint == "debug/config_dump/bpf/dual-engine":
			return []byte(diagBpfDump), nil
		case endpoint == "debug/config_dump/kernel-native":
			return []byte(`{"dynamicResources": {"clusterConfigs": [{"name": "outbound|80||productpage"}]}}`), nil
		}
		return nil, assert.AnError
	}
}

func runDiagnose(t *testing.T, args map[string]any, stub func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error)) map[string]any {
	t.Helper()
	h := newTestHandler(nil, nil, stub)
	res, err := h.HandleDiagnoseConnectivity(context.Background(), makeCallRequest(args))
	require.NoError(t, err)
	require.False(t, res.IsError, res.Content[0].(mcp.TextContent).Text)
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(res.Content[0].(mcp.TextContent).Text), &out))
	return out
}

func TestHandleDiagnoseConnectivity(t *testing.T) {
	ctx := context.Background()

	t.Run("source and target are required", func(t *testing.T) {
		h := newTestHandler(nil, nil, diagnoseStub("dual-engine"))
		res, err := h.HandleDiagnoseConnectivity(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.True(t, res.IsError)

		res, err = h.HandleDiagnoseConnectivity(ctx, makeCallRequest(map[string]any{"source": "sleep"}))
		require.NoError(t, err)
		assert.True(t, res.IsError)
	})

	t.Run("wired path is reachable-suspected", func(t *testing.T) {
		out := runDiagnose(t, map[string]any{"source": "sleep-abc", "target": "productpage"}, diagnoseStub("dual-engine"))
		assert.Equal(t, "dual-engine", out["mode"])
		assert.Equal(t, "reachable-suspected", out["verdict"])
		src := out["source"].(map[string]any)
		assert.Equal(t, true, src["found"])
		assert.Equal(t, "workload", src["kind"])
		dst := out["target"].(map[string]any)
		assert.Equal(t, "service", dst["kind"])
		bpf := out["bpfState"].(map[string]any)
		assert.Equal(t, float64(2), bpf["backendsForTarget"])
	})

	t.Run("unknown source gives source-not-enrolled", func(t *testing.T) {
		out := runDiagnose(t, map[string]any{"source": "ghost", "target": "productpage"}, diagnoseStub("dual-engine"))
		assert.Equal(t, "source-not-enrolled", out["verdict"])
		assert.NotEmpty(t, out["hints"])
	})

	t.Run("unknown target gives target-not-found", func(t *testing.T) {
		out := runDiagnose(t, map[string]any{"source": "sleep-abc", "target": "nowhere"}, diagnoseStub("dual-engine"))
		assert.Equal(t, "target-not-found", out["verdict"])
	})

	t.Run("service without backends gives missing-endpoints", func(t *testing.T) {
		out := runDiagnose(t, map[string]any{"source": "sleep-abc", "target": "waypointed"}, diagnoseStub("dual-engine"))
		assert.Equal(t, "missing-endpoints", out["verdict"])
	})

	t.Run("deny policy gives blocked-by-policy", func(t *testing.T) {
		stub := func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			if endpoint == "debug/config_dump/dual-engine" {
				return []byte(`{
					"workloads": [{"name": "sleep-abc", "namespace": "default", "addresses": ["10.0.0.1"]}],
					"services": [{"name": "productpage", "namespace": "default", "vips": ["10.96.5.5"]}],
					"policies": [{"name": "deny-all", "namespace": "default", "action": "DENY", "scope": "namespace"}]
				}`), nil
			}
			return diagnoseStub("dual-engine")(ctx, podName, namespace, endpoint)
		}
		out := runDiagnose(t, map[string]any{"source": "sleep-abc", "target": "productpage"}, stub)
		assert.Equal(t, "blocked-by-policy", out["verdict"])
	})

	t.Run("waypoint in path produces a hint", func(t *testing.T) {
		out := runDiagnose(t, map[string]any{"source": "sleep-abc", "target": "waypointed"}, diagnoseStub("dual-engine"))
		hints, _ := json.Marshal(out["hints"])
		assert.Contains(t, string(hints), "get_waypoint_status")
	})

	t.Run("kernel-native falls back to shallow diagnosis", func(t *testing.T) {
		out := runDiagnose(t, map[string]any{"source": "sleep", "target": "productpage"}, diagnoseStub("kernel-native"))
		assert.Equal(t, "kernel-native", out["mode"])
		assert.Equal(t, "needs-manual-inspection", out["verdict"])
		assert.True(t, strings.Contains(out["hints"].([]any)[0].(string), "get_bpf_ads_details"))
	})

	t.Run("ip address resolves a workload", func(t *testing.T) {
		out := runDiagnose(t, map[string]any{"source": "10.0.0.1", "target": "productpage"}, diagnoseStub("dual-engine"))
		src := out["source"].(map[string]any)
		assert.Equal(t, true, src["found"])
	})
}
