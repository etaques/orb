import { Component } from '@angular/core';

import { NotificationsService } from 'app/common/services/notifications/notifications.service';
import { ActivatedRoute, Router } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AgentPolicy } from 'app/common/interfaces/orb/agent.policy.interface';
import { AgentPoliciesService } from 'app/common/services/agents/agent.policies.service';

@Component({
  selector: 'ngx-agent-policy-add-component',
  templateUrl: './agent.policy.add.component.html',
  styleUrls: ['./agent.policy.add.component.scss'],
})
export class AgentPolicyAddComponent {

  /**
   * Forms
   * //NOTE: refactor to be all dynamic
   */
    // agent policy general information
  detailsFormGroup: FormGroup;

  // Refactor while coding :)
  backendConfigForms: { [propName: string]: FormGroup };

  availableBackends: { [propName: string]: any };

  backend: { [propName: string]: any };

  tap: { [propName: string]: any };

  input: { [propName: string]: any };

  handlers: { [propName: string]: any }[];

  agentPolicy: AgentPolicy;

  agentPolicyID: string;

  isEdit: boolean;

  isLoading = false;

  agentPolicyLoading = false;

  constructor(
    private agentPoliciesService: AgentPoliciesService,
    private notificationsService: NotificationsService,
    private router: Router,
    private route: ActivatedRoute,
    private _formBuilder: FormBuilder,
  ) {
    this.agentPolicy = this.router.getCurrentNavigation().extras.state?.agentPolicy as AgentPolicy || {
      name: '',
      description: '',
      tags: {},
      backend: 'pktvisor',
    };
    this.agentPolicyID = this.route.snapshot.paramMap.get('id');
    this.agentPolicy = this.route.snapshot.paramMap.get('agentPolicy') as AgentPolicy;

    this.isEdit = !!this.agentPolicyID;
    this.agentPolicyLoading = this.isEdit;

    !!this.agentPolicyID && agentPoliciesService.getAgentPolicyById(this.agentPolicyID).subscribe(resp => {
      this.agentPolicy = resp;
      this.agentPolicyLoading = false;
    });

    const { name, description, backend } = this.agentPolicy || { name: '', description: '', backend: '' };

    this.backendConfigForms = {};

    this.detailsFormGroup = this._formBuilder.group({
      name: [name, [Validators.required, Validators.pattern('^[a-zA-Z_:][a-zA-Z0-9_]*$')]],
      description: [description, Validators.required],
      backend: [backend, Validators.required],
    });

    this.getBackendsList();
  }

  getBackendsList() {
    this.isLoading = true;
    this.agentPoliciesService.getAvailableBackends().subscribe(backends => {
      this.availableBackends = backends;

      if (this.isEdit) {
        this.detailsFormGroup.controls.backend.disable();
        this.onBackendSelected(this.agentPolicy.backend);
      }

      this.isLoading = false;
    });
  }

  onBackendSelected(selectedBackend) {
    if (this.backend) {
      if (this.availableBackends[selectedBackend] === this.backend) {
        return;
      }
      Object.keys(this.backend.config).forEach(key => {
        Object.keys(this.backendConfigForms[key].controls).forEach(controlKey => {
          this.backendConfigForms[key].removeControl(controlKey);
        });
        delete this.backendConfigForms[key];
      });
      delete this.backend;
      delete this.handlers;
    }

    this.backend = this.availableBackends[selectedBackend];

    // reconfig dynamic forms based on backend selected
    this.backendConfigForms = Object.keys(this.availableBackends[selectedBackend])
      .reduce((formGroups, groupName, groupIndex) => {
        formGroups[groupName] = this._formBuilder.group({ [groupName]: ['', Validators.required] });
        return formGroups;
      }, {});

    this.backendConfigForms['handlers'].addControl('current', this._formBuilder.control('', []));

  }


  onTapSelected(selectedTap) {
    if (this.tap) {
      Object.keys(this.tap.config).forEach(key => {
        this.backendConfigForms['taps'].removeControl(key);
      });
      if (this.input) {
        Object.keys(this.input.config).forEach(key => {
          this.backendConfigForms['inputs'].removeControl(key);
        });
        delete this.input;
      }
      delete this.tap;
      // this.input = undefined;
      // this.tap = undefined;
    }
    this.tap = this.backend['taps'][selectedTap];
    const { taps } = this.backendConfigForms;
    Object.keys(this.tap.config).forEach(key => {
      taps.addControl(key, this._formBuilder.control('', [Validators.required]));
    });
  }

  onInputSelected(selectedInput) {
    if (this.input) {
      Object.keys(this.input.config).forEach(key => {
        this.backendConfigForms['inputs'].removeControl(key);
      });
      // this.input = undefined;
      delete this.input;
    }

    this.input = this.backend['inputs'][selectedInput];
    const { inputs } = this.backendConfigForms;
    Object.keys(this.input.config).forEach(key => {
      inputs.addControl(key, this._formBuilder.control('', [Validators.required]));
    });
  }

  onHandlerSelected(selectedHandler) {

  }

  onHandlerAdded() {

  }

  onHandlerRemoved(selectedHandler) {

  }

  goBack() {
    this.router.navigateByUrl('/pages/datasets/policies');
  }

  onFormSubmit() {
    const payload = {
      name: this.detailsFormGroup.controls.name.value,
      description: this.detailsFormGroup.controls.description.value,
      backend: this.detailsFormGroup.controls.backend.value,
      // config: this.selectedTap.reduce((accumulator, current) => {
      //   accumulator[current.prop] = this.tapFormGroup.controls[current.prop].value;
      //   return accumulator;
      // }, {}),
      validate_only: false, // Apparently this guy is required..
    };

    if (this.isEdit) {
      // updating existing sink
      this.agentPoliciesService.editAgentPolicy({ ...payload, id: this.agentPolicyID }).subscribe(() => {
        this.notificationsService.success('Agent Policy successfully updated', '');
        this.goBack();
      });
    } else {
      this.agentPoliciesService.addAgentPolicy(payload).subscribe(() => {
        this.notificationsService.success('Agent Policy successfully created', '');
        this.goBack();
      });
    }
  }
}
