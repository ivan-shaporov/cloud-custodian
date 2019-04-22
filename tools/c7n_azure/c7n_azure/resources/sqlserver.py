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

from c7n_azure import constants
from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager
from c7n_azure.utils import ThreadHelper
from c7n.filters import ValueFilter
from c7n.filters.core import type_schema
import logging

log = logging.getLogger('azure.networkinterface')


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
                    key: c7n:firewall_rules
                    value_type: size
                    op: eq
                    value: 0
    """

    schema = type_schema('firewall', rinherit=ValueFilter.schema)

    def process(self, resources, event=None):
        self.client = self.manager.get_client()

        resources, _ = ThreadHelper.execute_in_parallel(
            resources=resources,
            event=event,
            execution_method=self._query_firewall_rules,
            executor_factory=self.executor_factory,
            log=log,
            max_workers=constants.DEFAULT_MAX_THREAD_WORKERS,
            chunk_size=constants.DEFAULT_CHUNK_SIZE
        )

        return super(SqlServerFirewallFilter, self).process(resources, event)

    def _query_firewall_rules(self, resources, event):
        for resource in resources:
            try:
                query = self.client.firewall_rules.list_by_server(
                    resource['resourceGroup'],
                    resource['name'])

                rules = [
                    {
                        'name': r.name,
                        'start_ip_address': r.start_ip_address,
                        'end_ip_address': r.end_ip_address
                    }
                    for r in query]

                resource['c7n:firewall_rules'] = rules
            except Exception as error:
                log.warning(error)

        return resources
    