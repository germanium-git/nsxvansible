#!/usr/bin/env python
# coding=utf-8
#
# Copyright � 2015 VMware, Inc. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
# to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions
# of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

# It's been created based on the example of nsx_ospf.py published on https://github.com/vmware/nsxansible

__author__ = 'Petr Nemec'


def get_edge(client_session, edge_name):
    """
    :param client_session: An instance of an NsxClient Session
    :param edge_name: The name of the edge searched
    :return: A tuple, with the first item being the edge or dlr id as string of the first Scope found with the
             right name and the second item being a dictionary of the logical parameters as return by the NSX API
    """
    all_edge = client_session.read_all_pages('nsxEdges', 'read')

    try:
        edge_params = [scope for scope in all_edge if scope['name'] == edge_name][0]
        edge_id = edge_params['objectId']
    except IndexError:
        return None, None

    return edge_id, edge_params


def check_bgp_state(current_config):
    """
    :param current_config:
    :return: A boolean, with indication if BGP is enabled or not
    """
    # if current_config['routing']['bgp']:
    if 'bgp' in current_config['routing'].keys():
        if current_config['routing']['bgp']['enabled'] == 'true':
            return True
        else:
            return False
    else:
        return False


def set_bgp_state(current_config):
    # if current_config['routing']['bgp']:
    if 'bgp' in current_config['routing'].keys():
        if current_config['routing']['bgp']['enabled'] == 'false':
            current_config['routing']['bgp']['enabled'] = 'true'
            return True, current_config
        else:
            return False, current_config
    else:
        current_config['routing'].update({'bgp': {'enabled': 'true'}})
        # current_config['routing']['bgp']['enabled'] = 'true'
        return True, current_config


def check_router_id(current_config, router_id):
    current_routing_cfg = current_config['routing']['routingGlobalConfig']
    current_router_id = current_routing_cfg.get('routerId', None)
    if current_router_id == router_id:
        return False, current_config
    else:
        current_config['routing']['routingGlobalConfig']['routerId'] = router_id
        return True, current_config


def check_ecmp(current_config, ecmp):
    current_ecmp_cfg = current_config['routing']['routingGlobalConfig']
    current_ecmp_state = current_ecmp_cfg.get('ecmp', None)
    if current_ecmp_state == ecmp:
        return False, current_config
    else:
        current_config['routing']['routingGlobalConfig']['ecmp'] = ecmp
        return True, current_config


def check_bgp_options(current_config, graceful_restart, default_originate, local_as):
    changed = False
    current_bgp = current_config['routing']['bgp']
    c_grst_str = current_bgp.get('gracefulRestart', 'false')
    c_dio_str = current_bgp.get('defaultOriginate', 'false')
    c_las = current_bgp.get('localAS')

    if c_grst_str == 'true':
        c_grst = True
    else:
        c_grst = False

    if c_dio_str == 'true':
        c_dio = True
    else:
        c_dio = False

    # graceful_restart ~ bool
    # graceful_restart is not configured and is desired
    if c_grst != graceful_restart and graceful_restart:
        current_config['routing']['bgp']['gracefulRestart'] = 'true'
        changed = True
    # graceful_restart is configured and is not desired
    elif c_grst != graceful_restart and not graceful_restart:
        current_config['routing']['bgp']['gracefulRestart'] = 'false'
        changed = True

    # default_originate ~ bool
    # default_originate is not configured and is desired
    if c_dio != default_originate and default_originate:
        current_config['routing']['bgp']['defaultOriginate'] = 'true'
        changed = True
    # default_originate is configured and is not desired
    elif c_dio != default_originate and not default_originate:
        current_config['routing']['bgp']['defaultOriginate'] = 'false'
        changed = True

    # local AS is not the same
    if c_las != local_as:
        current_config['routing']['bgp']['localAS'] = local_as
        changed = True

    return changed, current_config


def normalize_neighbours(neighbour_list):
    """
    :param neighbour_list: List of neighbors to be configured
    :return: It returns normalized list of neighbors checked against the errors
    """
    new_neighbour_list = []
    if neighbour_list:
        for neighbour in neighbour_list:
            if not isinstance(neighbour, dict):
                return False, 'Neighbour {} is not a valid dictionary'.format(neighbour)

            if neighbour.get('ip_address', 'missing') == 'missing':
                return False, 'One Neighbour in your list is missing the mandatory ip_address parameter'
            else:
                neighbour['ip_address'] = str(neighbour['ip_address'])

            if neighbour.get('remote_as', 'missing') == 'missing':
                return False, 'One Neighbour in your list is missing the mandatory remote_as parameter'
            else:
                neighbour['remote_as'] = str(neighbour['remote_as'])

            if neighbour.get('weight', 'none') != 'none':
                neighbour['weight'] = str(neighbour['weight'])

            if neighbour.get('hold_down_timer', 'none') != 'none':
                neighbour['hold_down_timer'] = str(neighbour['hold_down_timer'])

            if neighbour.get('weight', 'none') != 'none':
                neighbour['keep_alive_timer'] = str(neighbour['keep_alive_timer'])

            # TODO Proceed with normalizing other parameters such as filters, password etc.
            new_neighbour_list.append(neighbour)

    return True, None, new_neighbour_list


def check_neighbours(client_session, current_config, d_neighbour_list):
    changed = False
    new_neighbours = []

    if not d_neighbour_list:
        d_neighbour_list = []

    # if current_config['routing']['bgp']['bgpNeighbours']:
    if 'bgpNeighbours' in current_config['routing']['bgp'].keys():
        c_neighbour_list = client_session.normalize_list_return(
            current_config['routing']['bgp']['bgpNeighbours']['bgpNeighbour'])
    else:
        c_neighbour_list = []

    # Filter out the Neighbours that are on NSX but not in the desired list, and check if the parameters are correct
    for c_neighbour in c_neighbour_list:
        for d_neighbour in d_neighbour_list:
            if c_neighbour['ipAddress'] == str(d_neighbour['ip_address']):

                # Check if the Forwarding address is the same - applicable for DLR only
                if 'fwd_addr' in d_neighbour.keys():
                    d_fwd_addr = d_neighbour.get('fwd_addr')
                    if c_neighbour['forwardingAddress'] != d_fwd_addr:
                        c_neighbour['forwardingAddress'] = d_fwd_addr
                        changed = True

                # Check if the Protocol address is the same - applicable for DLR only
                if 'prot_addr' in d_neighbour.keys():
                    d_prot_addr = d_neighbour.get('prot_addr')
                    if c_neighbour['protocolAddress'] != d_prot_addr:
                        c_neighbour['protocolAddress'] = d_prot_addr
                        changed = True

                # Check if remote AS is the same
                d_remote_as = d_neighbour.get('remote_as')
                if c_neighbour['remoteAS'] != d_remote_as:
                    c_neighbour['remoteAS'] = d_remote_as
                    changed = True

                # Check if Weight is the same - if the desired value is not defined use default 60
                d_weight = d_neighbour.get('weight', '60')
                if c_neighbour['weight'] != d_weight:
                    c_neighbour['weight'] = d_weight
                    changed = True

                # Check if holdDownTimer is the same - if the desired value is not defined use default 180
                d_hld_timer = d_neighbour.get('hold_down_timer', '180')
                if c_neighbour['holdDownTimer'] != d_hld_timer:
                    c_neighbour['holdDownTimer'] = d_hld_timer
                    changed = True

                # Check if keepAliveTimer is the same - if the desired value is not defined use default 60
                d_keepalv_timer = d_neighbour.get('keep_alive_timer', '60')
                if c_neighbour['keepAliveTimer'] != d_keepalv_timer:
                    c_neighbour['keepAliveTimer'] = d_keepalv_timer
                    changed = True

                # Check if password is the same - it can't be checked since current psw can't be retrieved
                # If a password is defined then it's treated automatically as a change
                if 'password' in d_neighbour.keys():
                    d_pass = d_neighbour.get('password')
                    c_neighbour['password'] = d_pass
                    changed = True

                # Current filters will be kept if no filters are specified
                # Filters will be overwritten if desired filters are not the same as existing ones
                """
                If only one filter is defined than data type is dictionary
                {"bgpFilters': {'bgpFilter': {'action': 'permit', 'direction': 'in', 'network': '10.20.30.40/32'}}

                If multiple filters are defined than data type is list of dictionaries
                {"bgpFilters": {"bgpFilter": [{"action": "permit", "direction": "in", "network": "10.20.30.40/32"},
                                              {"action": "permit", "direction": "out", "network": "7.7.7.7/32"}]}
                """

                # Check if current neighbor has any filters defined
                if c_neighbour['bgpFilters']:
                    c_filters = c_neighbour['bgpFilters']['bgpFilter']
                    # If current filter consists of only one entry it results in dictionary
                    # Desired filters are always defined as list of dictionaries
                    if type(c_filters) != list:
                        c_filters = [c_filters]
                else:
                    c_filters = 'none'

                # Check if desired filters are specified
                d_filters = d_neighbour.get('filters', 'none')
                if 'd_filters' != 'none':
                    if c_filters != d_filters:
                        c_neighbour.update({'bgpFilters': {'bgpFilter': d_filters}})
                        changed = True

                new_neighbours.append(c_neighbour)
                break
        else:
            changed = True

    # Add the BGP Neighbours that are in the desired list but not in NSX
    c_neighbour_ids = [c_neighbour['ipAddress'] for c_neighbour in c_neighbour_list]
    for d_neighbour in d_neighbour_list:
        # If BGP neighbor doesn't exist
        if str(d_neighbour['ip_address']) not in c_neighbour_ids:
            d_remote_as = d_neighbour.get('remote_as')
            d_fwd_addr = d_neighbour.get('fwd_addr', 'none')
            d_prot_addr = d_neighbour.get('prot_addr', 'none')
            d_weight = d_neighbour.get('weight', '60')
            d_hld_timer = d_neighbour.get('hold_down_timer', '180')
            d_keepalv_timer = d_neighbour.get('keep_alive_timer', '60')
            d_pass = d_neighbour.get('password', 'none')
            d_filters = d_neighbour.get('filters', 'none')

            new_neighbour = {'ipAddress': d_neighbour['ip_address'],
                             'remoteAS': d_remote_as,
                             'weight': d_weight,
                             'holdDownTimer': d_hld_timer,
                             'keepAliveTimer': d_keepalv_timer,
                             'password': d_pass
                             }

            # Add password if specified
            if d_pass != 'none':
                new_neighbour.update({'password': d_pass})

            # Add protocol address and forwarding address if both are specified when a DLR is to be configured
            if d_fwd_addr != 'none' and d_prot_addr != 'none':
                new_neighbour.update({'forwardingAddress': d_fwd_addr,
                                      'protocolAddress': d_prot_addr})

            if d_filters != 'none':
                new_neighbour.update({'bgpFilters': {'bgpFilter': d_filters}})

            new_neighbours.append(new_neighbour)

            changed = True

    if changed:
        current_config['routing']['bgp']['bgpNeighbours'] = {'bgpNeighbour': new_neighbours}

    return changed, current_config


def get_current_config(client_session, edge_id):
    response = client_session.read('routingConfig', uri_parameters={'edgeId': edge_id})
    return response['body']


def update_config(client_session, current_config, edge_id):
    client_session.update('routingConfig', uri_parameters={'edgeId': edge_id},
                          request_body_dict=current_config)


def reset_config(client_session, edge_id):
    client_session.delete('routingBGP', uri_parameters={'edgeId': edge_id})


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent']),
            nsxmanager_spec=dict(required=True, no_log=True, type='dict'),
            edge_name=dict(required=True, type='str'),
            router_id=dict(required=True, type='str'),
            ecmp=dict(default='false', choices=['true', 'false']),
            graceful_restart=dict(default=True, type='bool'),
            default_originate=dict(default=False, type='bool'),
            logging=dict(default=False, type='bool'),
            log_level=dict(default='info', choices=['debug', 'info', 'notice', 'warning', 'error', 'critical',
                                                    'alert', 'emergency'], type='str'),
            neighbours=dict(type='list'),
            local_as=dict(required=True, type='str')
        ),
        supports_check_mode=False
    )

    from nsxramlclient.client import NsxClient

    client_session = NsxClient(module.params['nsxmanager_spec']['raml_file'], module.params['nsxmanager_spec']['host'],
                               module.params['nsxmanager_spec']['user'], module.params['nsxmanager_spec']['password'])

    # Check if the edge exists
    edge_id, edge_params = get_edge(client_session, module.params['edge_name'])
    if not edge_id:
        module.fail_json(msg='could not find Edge with name {}'.format(module.params['edge_name']))

    current_config = get_current_config(client_session, edge_id)

    # Test absent state -----------------------------------------------------------------
    # If BGP is enabled and it to be removed
    if module.params['state'] == 'absent' and check_bgp_state(current_config):
        reset_config(client_session, edge_id)
        module.exit_json(changed=True, current_config=None)

    # If BGP is not enabled and is to be removed than no action is needed
    elif module.params['state'] == 'absent' and not check_bgp_state(current_config):
        module.exit_json(changed=False, current_config=None)

    # Test present state -----------------------------------------------------------------
    # Check if BGP is enabled and enable it as the state must be present
    changed_state, current_config = set_bgp_state(current_config)

    # Check changes of Router ID
    changed_rtid, current_config = check_router_id(current_config, module.params['router_id'])

    # Check changes in ECMP settings
    changed_ecmp, current_config = check_ecmp(current_config, module.params['ecmp'])

    # Check changes in BGP options
    changed_opt, current_config = check_bgp_options(current_config,
                                                    module.params['graceful_restart'],
                                                    module.params['default_originate'],
                                                    module.params['local_as'])

    # Check if the specified neighbors are valid and may be configured
    valid, msg, neighbor_map = normalize_neighbours(module.params['neighbours'])
    if not valid:
        module.fail_json(msg=msg)

    # Check changes in BGP neighbors
    changed_neighbors, current_config = check_neighbours(client_session, current_config, neighbor_map)

    # If some changes are detected update routing config
    if changed_state or changed_rtid or changed_ecmp or changed_opt or changed_neighbors:
        update_config(client_session, current_config, edge_id)
        module.exit_json(changed=True, current_config=current_config)
    else:
        module.exit_json(changed=False, current_config=current_config)


from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()