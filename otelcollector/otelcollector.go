// Copyright 2019 OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Program otelcollector is an extension to the OpenTelemetry Collector
// that includes additional components, some vendor-specific, contributed
// from the wider community.

package otelcollector

import (
	"context"
	"github.com/ns1labs/orb/pkg/config"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/service"
	"go.uber.org/zap"
)

type ComponentsFunc func(logger zap.Logger) (component.Factories, error)

func RunWithComponents(logger zap.Logger, svcCfg config.BaseSvcConfig, grpcCfgs []config.GRPCConfig, componentsFunc ComponentsFunc) {
	factories, err := componentsFunc(logger)
	if err != nil {
		logger.Fatal("failed to build components", zap.Error(err))
	}

	info := component.BuildInfo{
		Command:     "otelcollector",
		Description: "Otel Collector and Sinker",
		Version:     "latest",
	}

	cmd := service.NewCommand(service.CollectorSettings{
		Factories:               factories,
		BuildInfo:               info,
		DisableGracefulShutdown: false,
		ConfigProvider:          nil,
		LoggingOptions:          nil,
		SkipSettingGRPCLogger:   false,
	})

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	if err != nil {
		logger.Fatal("failed to set context", zap.Error(err))
	}
	if err := cmd.ExecuteContext(ctx); err != nil {
		logger.Fatal("failed to run command", zap.Error(err))
	}
}