/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package pktvisor

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/ns1labs/orb/agent/policies"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func (p *pktvisorBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {

	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		err := p.RemovePolicy(data)
		if err != nil {
			p.logger.Warn("policy failed to remove", zap.String("policy_id", data.ID), zap.String("policy_name", data.Name), zap.Error(err))
		}
	}

	p.logger.Debug("pktvisor policy apply", zap.String("policy_id", data.ID), zap.Any("data", data.Data))

	fullPolicy := map[string]interface{}{
		"version": "1.0",
		"visor": map[string]interface{}{
			"policies": map[string]interface{}{
				data.Name: data.Data,
			},
		},
	}

	policyYaml, err := yaml.Marshal(fullPolicy)
	if err != nil {
		p.logger.Warn("yaml policy marshal failure", zap.String("policy_id", data.ID), zap.Any("policy", fullPolicy))
		return err
	}

	var resp map[string]interface{}
	err = p.request("policies", &resp, http.MethodPost, bytes.NewBuffer(policyYaml), "application/x-yaml", ApplyPolicyTimeout)
	if err != nil {
		p.logger.Warn("yaml policy application failure", zap.String("policy_id", data.ID), zap.ByteString("policy", policyYaml))
		return err
	}

	if p.scrapeOtel {
		//set context to cancel go routine when policy was removed
		exeCtx, execCancelF := context.WithCancel(context.Background())
		p.policyContextMap[data.ID] = execCancelF
		//context enrichement
		attributeCtx := context.WithValue(exeCtx, "policy_id", data.ID)
		attributeCtx = context.WithValue(attributeCtx, "policy_name", data.Name)
		//scrape opentelemetry per policy (go func)
		p.scrapeOpenTelemetry(attributeCtx)
	}

	return nil

}

func (p *pktvisorBackend) RemovePolicy(data policies.PolicyData) error {
	p.logger.Debug("pktvisor policy remove", zap.String("policy_id", data.ID))
	var resp interface{}
	err := p.request(fmt.Sprintf("policies/%s", data.Name), &resp, http.MethodDelete, http.NoBody, "application/json", RemovePolicyTimeout)
	if err != nil {
		return err
	}
	if p.scrapeOtel {
		//cancel (scrap opentelemetry) go routine context when policy was removed
		cancelScrappingContext := p.policyContextMap[data.ID]
		if cancelScrappingContext != nil {
			cancelScrappingContext()
		}
	}
	return nil
}
