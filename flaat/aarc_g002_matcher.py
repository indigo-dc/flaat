'''Check entitlements according to the AARC G002 recommendation
   https://aarc-project.eu/guidelines/aarc-g002'''
# This code is distributed under the MIT License
# pylint 
# vim: tw=100
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace


verbose = 1
def aarc_g002_split(groupspec):
    '''return namespace, group, authority'''
    (namespace, tmp) = groupspec.split(':group:')
    try:
        (group_hierarchy, authority) = tmp.split('#')
    except ValueError:
        authority=None
        group_hierarchy = tmp
    return(namespace, group_hierarchy, authority)

def aarc_g002_split_roles(groupspec):
    '''return group and roles'''
    group = None
    role  = None
    try:
        (group, role) = groupspec.split(':role=')
    except ValueError: # no roles found
        group = groupspec
    return (group, role)

def vprint(x):
    if verbose:
        print(x)
def aarc_g002_matcher(required_group, actual_group):
    ''' match if user is in subgroup, but not in supergroup
    match if Authority is different
    This should comply to https://aarc-project.eu/guidelines/aarc-g002/'''
    #pylint: disable=too-many-return-statements,consider-using-enumerate

    (act_namespace, act_group_role, act_authority) = aarc_g002_split(actual_group)
    (req_namespace, req_group_role, req_authority) = aarc_g002_split(required_group)

    # Finish the two easy cases

    if act_namespace != req_namespace:
        vprint('    Different namespace')
        return False

    if act_group_role == req_group_role:
        vprint('    group and role match in this combination')
        return True

    # Interesting cases:
    (act_group, act_role) = aarc_g002_split_roles(act_group_role)
    (req_group, req_role) = aarc_g002_split_roles(req_group_role)

    if act_group == req_group: # idnentical group tree, let's look at the roles
        if req_role is None:
            vprint('    Groups match, no role required')
            return True
        if act_role is None:
            vprint('    Groups match, but user does not have role')
            return False
        if act_role == req_role:
            vprint('    Group and role match')
            return True
        if act_role != req_role:
            vprint('    Roup and role do not match')
            return False
        return 'Error, unreachable code'


    act_group_tree = act_group.split(':')
    req_group_tree = req_group.split(':')

    # now we check every single required group
    try:
        for i in range(0,len(req_group_tree)):
            if act_group_tree[i] != req_group_tree[i]: # wrong group name
                vprint('    one of the subgroups did not match')
                return False
    except IndexError: # user not in subgroup:
        vprint('    more required subgroups than assigned to the user')
        return False

    # up to this point all required groups are assigned and the role is the same
    # reformat first:
    if act_role is None and req_role is None:
        vprint('    no role required nor given, user probably in subgroup of required supergroup')
        return True
    act_role_in_subgroup = act_group[-1]+':role='+act_role

    if req_role is None and act_role is not None:
        vprint('    no role required but one given')
        return True
    req_role_in_subgroup = req_group[-1]+':role='+req_role

    if act_role_in_subgroup == req_role_in_subgroup: # this is probably never reached.
        vprint('    role in subgroup is identical')
        return True
    if act_role_in_subgroup != req_role_in_subgroup:
        vprint('    role in subgroup is not identical')
        return False

    # print (json.dumps(locals(), sort_keys=True, indent=4, separators=(',', ': ')))
    return None


if __name__ == '__main__':

    required_group= 'urn:geant:h-df.de:group:aai-admin:role=member#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin:role=member#unity.helmholtz-data-federation.de'
    print('\n1: Simple case: Different authorities, everything else same')
    print('    Required group: ' + required_group)
    print('    Actual   group: ' + actual_group)
    print('    aarc_g002_matcher: => %s' % aarc_g002_matcher(required_group, actual_group))

    required_group= 'urn:geant:h-df.de:group:aai-admin:role=member#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin:role=member#backupserver.used.for.developmt.de'

    print('\n2: Simple case: Different authorities, everything else same')
    print('    Required group: ' + required_group)
    print('    Actual   group: ' + actual_group)
    print('    aarc_g002_matcher: => %s' % aarc_g002_matcher(required_group, actual_group))

    required_group= 'urn:geant:h-df.de:group:aai-admin#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin:role=member#backupserver.used.for.developmt.de'

    print('\n3: Role assigned but not required')
    print('    Required group: ' + required_group)
    print('    Actual   group: ' + actual_group)
    print('    aarc_g002_matcher: => %s' % aarc_g002_matcher(required_group, actual_group))


    required_group= 'urn:geant:h-df.de:group:aai-admin:role=member#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin#backupserver.used.for.developmt.de'

    print('\n4: Role required but not assigned')
    print('    Required group: ' + required_group)
    print('    Actual   group: ' + actual_group)
    print('    aarc_g002_matcher: => %s' % aarc_g002_matcher(required_group, actual_group))


    required_group= 'urn:geant:h-df.de:group:aai-admin:special-admins#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin#backupserver.used.for.developmt.de'

    print('\n5: Subgroup required, but not available')
    print('    Required group: ' + required_group)
    print('    Actual   group: ' + actual_group)
    print('    aarc_g002_matcher: => %s' % aarc_g002_matcher(required_group, actual_group))

    required_group= 'urn:geant:h-df.de:group:aai-admin#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin:testgroup:special-admins#backupserver.used.for.developmt.de'

    print('\n6: Edge case: User in subgroup, but only supergroup required')
    print('    Required group: ' + required_group)
    print('    Actual   group: ' + actual_group)
    print('    aarc_g002_matcher: => %s' % aarc_g002_matcher(required_group, actual_group))


    required_group= 'urn:geant:h-df.de:group:aai-admin:role=admin#unity.helmholtz-data-federation.de'
    actual_group  = 'urn:geant:h-df.de:group:aai-admin:special-admins:role=admin#backupserver.used.for.developmt.de'

    print('\n7: role required for supergroup but only assigned for subgroup')
    print('    Required group: ' + required_group)
    print('    Actual   group: ' + actual_group)
    print('    aarc_g002_matcher: => %s' % aarc_g002_matcher(required_group, actual_group))

    #TODO: Weird combinations of these with roles
