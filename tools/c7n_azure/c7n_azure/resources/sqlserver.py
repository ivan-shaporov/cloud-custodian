# Copyright 2018 Capital One Services, LLC
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

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager
from c7n.filters import ValueFilter
from c7n.filters.core import type_schema


@resources.register('sqlserver')
class SqlServer(ArmResourceManager):

    class resource_type(ArmResourceManager.resource_type):
        service = 'azure.mgmt.sql'
        client = 'SqlManagementClient'
        enum_spec = ('servers', 'list', None)

@SqlServer.filter_registry.register('firewall')
class SqlServerFirewallFilter(ValueFilter):
    """Filters SQL servers by the firewall rules

    :example:

    .. code-block:: yaml

            policies:
              - name: servers-without-firewall
                resource: azure.sqlserver
                filters:
                  - type: firewall
                    key: firewall_rules
                    value_type: size
                    op: eq
                    value: 0
    """

    schema = type_schema('firewall', rinherit=ValueFilter.schema)

    def process(self, resources, event=None):
        client = self.manager.get_client()

        def _query_firewall_rules(resource):
            query = client.firewall_rules.list_by_server(
                resource['resourceGroup'],
                resource['name'])

            rules = [
                {
                    'name': r.name,
                    'start_ip_address': r.start_ip_address,
                    'end_ip_address': r.end_ip_address
                }
                for r in query]

            resource['firewall_rules'] = rules

        with self.executor_factory(max_workers=2) as w:
            list(w.map(_query_firewall_rules, resources))

        return super(SqlServerFirewallFilter, self).process(resources, event)
