#!/usr/bin/env python3
# pylint # {{{
# vim: tw=100 foldmethod=marker
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace
# }}}

import json

def aarc_g002_split(groupspec):# {{{
    '''return namespace, group, authority'''
    (namespace, tmp) = groupspec.split(':group:')
    try:
        (group_hierarchy, authority) = tmp.split('#')
    except ValueError:
        authority=None
        group_hierarchy = tmp
    return(namespace, group_hierarchy, authority)
# }}}
def aarc_g002_split_roles(groupspec):# {{{
    '''return group and roles'''
    group = None
    role  = None
    try:
        (group, role) = groupspec.split(':role=')
    except ValueError: # no roles found
        group = groupspec
    return (group, role)
# }}}
def aarc_g002_matcher(required_group, actual_group):# {{{
    ''' match if user is in subgroup, but not in supergroup
    match if Authority is different
    This should comply to https://aarc-project.eu/guidelines/aarc-g002/'''
    #pylint: disable=too-many-return-statements,consider-using-enumerate

    (act_namespace, act_group_role, act_authority) = aarc_g002_split(actual_group)
    (req_namespace, req_group_role, req_authority) = aarc_g002_split(required_group)

    # Finish the two easy cases

    if act_namespace != req_namespace:
        return False

    if act_group_role == req_group_role:
        return True

    # Interesting cases:
    (act_group, act_role) = aarc_g002_split_roles(act_group_role)
    (req_group, req_role) = aarc_g002_split_roles(req_group_role)

    if act_group == req_group:
        if req_role is None:
            return True
        if act_role is None:
            return False
        if act_role == req_role:
            return True
        if act_role != req_role:
            return False
        return 'Error, unreachable code'

    act_group_tree = act_group.split(':')
    req_group_tree = req_group.split(':')

    # print (json.dumps(locals(), sort_keys=True, indent=4, separators=(',', ': ')))
    try:
        for i in range(0,len(req_group_tree)):
            if act_group_tree[i] != req_group_tree[i]: # wrong group name
                return False
    except IndexError: # user not in subgroup:
        return False

    return True
# }}}
if __name__ == '__main__':# {{{
    required_group= 'urn:geant:h-df.de:group:aai-admin:role=member#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin:role=member#backupserver.used.for.developmt.de'
    print('\nSimple case: Different authorities, everything else same')
    print('    Required group: ' + required_group)
    print('    Actial   group: ' + actual_group)
    print(' => %s' % aarc_g002_matcher(required_group, actual_group))


    required_group= 'urn:geant:h-df.de:group:aai-admin#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin:role=member#backupserver.used.for.developmt.de'
    print('\nRole assigned but not required')
    print('    Required group: ' + required_group)
    print('    Actial   group: ' + actual_group)
    print(' => %s' % aarc_g002_matcher(required_group, actual_group))

    required_group= 'urn:geant:h-df.de:group:aai-admin:role=member#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin#backupserver.used.for.developmt.de'
    print('\nRole required but not assigned')
    print('    Required group: ' + required_group)
    print('    Actial   group: ' + actual_group)
    print(' => %s' % aarc_g002_matcher(required_group, actual_group))


    required_group= 'urn:geant:h-df.de:group:aai-admin:special-admins#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin#backupserver.used.for.developmt.de'
    print('\nSubgroup required, but not available')
    print('    Required group: ' + required_group)
    print('    Actial   group: ' + actual_group)
    print(' => %s' % aarc_g002_matcher(required_group, actual_group))

    required_group= 'urn:geant:h-df.de:group:aai-admin#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin:special-admins#backupserver.used.for.developmt.de'
    print('\nEdge case: User in subgroup, but only supergroup required')
    print('    Required group: ' + required_group)
    print('    Actial   group: ' + actual_group)
    print(' => %s' % aarc_g002_matcher(required_group, actual_group))


    #TODO: Weird combinations of these with roles
#}}}
