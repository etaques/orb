/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package sinker

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-kit/kit/metrics"
	"github.com/go-redis/redis/v8"
	mfnats "github.com/mainflux/mainflux/pkg/messaging/nats"
	fleetpb "github.com/ns1labs/orb/fleet/pb"
	policiespb "github.com/ns1labs/orb/policies/pb"
	"github.com/ns1labs/orb/sinker/backend/pktvisor"
	"github.com/ns1labs/orb/sinker/config"
	"github.com/ns1labs/orb/sinker/prometheus"
	sinkspb "github.com/ns1labs/orb/sinks/pb"
	promexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter"
	"go.opentelemetry.io/collector/component"
	otelconfig "go.opentelemetry.io/collector/config"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/otlpreceiver"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"time"
)

const (
	BackendMetricsTopic = "be.*.m.>"
	MaxMsgPayloadSize   = 1024 * 100
)

var (
	ErrPayloadTooBig = errors.New("payload too big")
	ErrNotFound      = errors.New("non-existent entity")
)

type Service interface {
	// Start set up communication with the message bus to communicate with agents
	Start() error
	// Stop end communication with the message bus
	Stop() error
}

type sinkerService struct {
	pubSub mfnats.PubSub
	otel   bool

	sinkerCache config.ConfigRepo
	esclient    *redis.Client
	logger      *zap.Logger

	hbTicker *time.Ticker
	hbDone   chan bool

	promClient prometheus.Client

	policiesClient policiespb.PolicyServiceClient
	fleetClient    fleetpb.FleetServiceClient
	sinksClient    sinkspb.SinkServiceClient

	requestGauge   metrics.Gauge
	requestCounter metrics.Counter

	messageInputCounter metrics.Counter
}

func (svc sinkerService) Start() error {

	topic := fmt.Sprintf("channels.*.%s", BackendMetricsTopic)
	if err := svc.pubSub.Subscribe(topic, svc.handleMsgFromAgent); err != nil {
		return err
	}
	svc.logger.Info("started metrics consumer", zap.String("topic", topic))

	svc.hbTicker = time.NewTicker(CheckerFreq)
	svc.hbDone = make(chan bool)
	go svc.checkSinker()

	err := svc.startOtel()
	if err != nil {
		return err
	}

	return nil
}

func (svc sinkerService) startOtel() error {
	ctx := context.Background()
	if svc.otel {
		exporter, err := createExporter(ctx, svc.logger)
		if err != nil {
			svc.logger.Error("error during create exporter", zap.Error(err))
			return err
		}

		metricsReceiver, err := createReceiver(ctx, svc.logger)
		if err != nil {
			svc.logger.Error("error during create receiver", zap.Error(err))
			return err
		}

		err = exporter.Start(ctx, nil)
		if err != nil {
			svc.logger.Error("otel exporter startup error", zap.Error(err))
			return err
		}

		err = metricsReceiver.Start(ctx, nil)
		if err != nil {
			svc.logger.Error("otel receiver startup error", zap.Error(err))
			return err
		}
	}
	return nil
}

func (svc sinkerService) Stop() error {
	topic := fmt.Sprintf("channels.*.%s", BackendMetricsTopic)
	if err := svc.pubSub.Unsubscribe(topic); err != nil {
		return err
	}
	svc.logger.Info("unsubscribed from agent metrics")

	svc.hbTicker.Stop()
	svc.hbDone <- true

	return nil
}

// New instantiates the sinker service implementation.
func New(logger *zap.Logger,
	pubSub mfnats.PubSub,
	esclient *redis.Client,
	configRepo config.ConfigRepo,
	policiesClient policiespb.PolicyServiceClient,
	fleetClient fleetpb.FleetServiceClient,
	sinksClient sinkspb.SinkServiceClient,
	requestGauge metrics.Gauge,
	requestCounter metrics.Counter,
	inputCounter metrics.Counter,
) Service {

	pktvisor.Register(logger)
	return &sinkerService{
		logger:              logger,
		pubSub:              pubSub,
		esclient:            esclient,
		sinkerCache:         configRepo,
		policiesClient:      policiesClient,
		fleetClient:         fleetClient,
		sinksClient:         sinksClient,
		requestGauge:        requestGauge,
		requestCounter:      requestCounter,
		messageInputCounter: inputCounter,
		otel:                false,
	}
}

func createReceiver(ctx context.Context, logger *zap.Logger) (component.MetricsReceiver, error) {
	receiverFactory := otlpreceiver.NewFactory()

	set := component.ReceiverCreateSettings{
		TelemetrySettings: component.TelemetrySettings{
			Logger:         logger,
			TracerProvider: trace.NewNoopTracerProvider(),
			MeterProvider:  global.MeterProvider(),
			MetricsLevel:   configtelemetry.LevelDetailed,
		},
		BuildInfo: component.BuildInfo{},
	}
	metricsReceiver, err := receiverFactory.CreateMetricsReceiver(ctx, set,
		receiverFactory.CreateDefaultConfig(), consumertest.NewNop())
	return metricsReceiver, err
}

func createExporter(ctx context.Context, logger *zap.Logger) (component.MetricsExporter, error) {
	// 2. Create the Prometheus metrics exporter that'll receive and verify the metrics produced.
	exporterCfg := &promexporter.Config{
		ExporterSettings: otelconfig.NewExporterSettings(otelconfig.NewComponentID("pktvisor_prometheus_exporter")),
		Namespace:        "test",
		Endpoint:         ":8787",
		SendTimestamps:   true,
		MetricExpiration: 2 * time.Hour,
	}
	exporterFactory := promexporter.NewFactory()
	set := component.ExporterCreateSettings{
		TelemetrySettings: component.TelemetrySettings{
			Logger:         logger,
			TracerProvider: trace.NewNoopTracerProvider(),
			MeterProvider:  global.MeterProvider(),
		},
		BuildInfo: component.NewDefaultBuildInfo(),
	}
	exporter, err := exporterFactory.CreateMetricsExporter(ctx, set, exporterCfg)
	if err != nil {
		return nil, err
	}
	return exporter, nil
}
