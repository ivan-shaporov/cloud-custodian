# Copyright 2015-2018 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function, unicode_literals

from azure_common import BaseTest, arm_template
from c7n_azure.session import Session
from c7n.utils import local_session
from azure.mgmt.storage.models import StorageAccountUpdateParameters, DefaultAction

rg_name = 'test_storage'


class StorageTestFirewall(BaseTest):
    def tearDown(self):
        client = local_session(Session).client('azure.mgmt.storage.StorageManagementClient')
        resources = list(client.storage_accounts.list_by_resource_group(rg_name))
        self.assertEqual(len(resources), 1)
        resource = resources[0]
        resource.network_rule_set.ip_rules = []
        resource.network_rule_set.virtual_network_rules = []
        resource.network_rule_set.bypass = 'AzureServices'
        resource.network_rule_set.default_action = DefaultAction.allow
        client.storage_accounts.update(
            rg_name,
            resource.name,
            StorageAccountUpdateParameters(network_rule_set=resource.network_rule_set))

    @arm_template('storage.json')
    def test_network_ip_rules_action(self):
        p_add = self.load_policy({
            'name': 'test-azure-storage-add-ips',
            'resource': 'azure.storage',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctstorage*'}],
            'actions': [
                {'type': 'set-network-rules',
                 'default-action': 'Deny',
                 'bypass': ['Logging', 'Metrics'],
                 'ip-rules': [
                     {'ip-address-or-range': '11.12.13.14'},
                     {'ip-address-or-range': '21.22.23.24'}
                 ]}
            ]
        })

        p_add.run()

        resources = self._get_resources()
        self.assertEqual(len(resources), 1)
        ip_rules = resources[0]['properties']['networkAcls']['ipRules']
        self.assertEqual(len(ip_rules), 2)
        self.assertEqual(ip_rules[0]['value'], '11.12.13.14')
        self.assertEqual(ip_rules[1]['value'], '21.22.23.24')
        self.assertEqual(ip_rules[0]['action'], 'Allow')
        self.assertEqual(ip_rules[1]['action'], 'Allow')

    @arm_template('storage.json')
    def test_virtual_network_rules_action(self):
        p_vnet_get = self.load_policy({
            'name': 'test-azure-storage-enum',
            'resource': 'azure.vnet',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctstoragevnet*'}],
        })

        vnets = p_vnet_get.run()

        id1 = vnets[0]['properties']['subnets'][0]['id']
        id2 = vnets[1]['properties']['subnets'][0]['id']

        p_add = self.load_policy({
            'name': 'test-azure-storage-add-ips',
            'resource': 'azure.storage',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctstorage*'}],
            'actions': [
                {'type': 'set-network-rules',
                 'default-action': 'Deny',
                 'bypass': ['Logging', 'Metrics'],
                 'virtual-network-rules': [
                     {'virtual-network-resource-id': id1},
                     {'virtual-network-resource-id': id2}
                 ]}
            ]
        })

        p_add.run()

        resources = self._get_resources()
        self.assertEqual(len(resources), 1)
        rules = resources[0]['properties']['networkAcls']['virtualNetworkRules']
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]['id'], id1)
        self.assertEqual(rules[1]['id'], id2)
        self.assertEqual(rules[0]['action'], 'Allow')
        self.assertEqual(rules[1]['action'], 'Allow')

    @arm_template('storage.json')
    def test_empty_bypass_network_rules_action(self):
        p_add = self.load_policy({
            'name': 'test-azure-storage-add-ips',
            'resource': 'azure.storage',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctstorage*'}],
            'actions': [
                {'type': 'set-network-rules',
                 'default-action': 'Deny',
                 'bypass': []}
            ]
        })

        p_add.run()

        resources = self._get_resources()
        bypass = resources[0]['properties']['networkAcls']['bypass']
        self.assertEqual(bypass, 'None')

    @arm_template('storage.json')
    def test_missing_bypass_network_rules_action(self):
        p_add = self.load_policy({
            'name': 'test-azure-storage-add-ips',
            'resource': 'azure.storage',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctstorage*'}],
            'actions': [
                {'type': 'set-network-rules',
                 'default-action': 'Deny'}
            ]
        })

        p_add.run()

        resources = self._get_resources()
        bypass = resources[0]['properties']['networkAcls']['bypass']
        self.assertEqual(bypass, 'None')

    @arm_template('storage.json')
    def test_default_action_network_rules_action(self):
        p_add = self.load_policy({
            'name': 'test-azure-storage-add-ips',
            'resource': 'azure.storage',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctstorage*'}],
            'actions': [
                {'type': 'set-network-rules',
                 'default-action': 'Deny'}
            ]
        })

        p_add.run()

        resources = self._get_resources()
        action = resources[0]['properties']['networkAcls']['defaultAction']
        self.assertEqual(action, 'Deny')

    @arm_template('storage.json')
    def test_bypass_network_rules_action(self):
        p_add = self.load_policy({
            'name': 'test-azure-storage-add-ips',
            'resource': 'azure.storage',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctstorage*'}],
            'actions': [
                {'type': 'set-network-rules',
                 'default-action': 'Deny',
                 'bypass': ['Metrics']}
            ]
        })

        p_add.run()

        resources = self._get_resources()
        bypass = resources[0]['properties']['networkAcls']['bypass']
        self.assertEqual(bypass, 'Metrics')

    def _get_resources(self):
        p_get = self.load_policy({
            'name': 'test-azure-storage-enum',
            'resource': 'azure.storage',
            'filters': [
                {'type': 'value',
                 'key': 'name',
                 'op': 'glob',
                 'value_type': 'normalize',
                 'value': 'cctstorage*'}],
        })

        resources = p_get.run()

        return resources
