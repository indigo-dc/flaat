# pylint: disable=bad-whitespace, invalid-name, missing-docstring
import unittest
from flaat import aarc_g002_matcher

class Aarc_g002(unittest.TestCase):
    def test_simple(self):
        required_group= 'urn:geant:h-df.de:group:aai-admin:role=member#unity.helmholtz-data-federation.de'
        actual_group  = 'urn:geant:h-df.de:group:aai-admin:role=member#backupserver.used.for.developmt.de'
        self.assertEqual(aarc_g002_matcher.aarc_g002_matcher(required_group, actual_group), True)

    def test_role_not_required(self):
        required_group= 'urn:geant:h-df.de:group:aai-admin#unity.helmholtz-data-federation.de'
        actual_group  = 'urn:geant:h-df.de:group:aai-admin:role=member#backupserver.used.for.developmt.de'
        self.assertEqual(aarc_g002_matcher.aarc_g002_matcher(required_group, actual_group), True)

    def test_role_required(self):
        required_group= 'urn:geant:h-df.de:group:aai-admin:role=member#unity.helmholtz-data-federation.de'
        actual_group  = 'urn:geant:h-df.de:group:aai-admin#backupserver.used.for.developmt.de'
        self.assertEqual(aarc_g002_matcher.aarc_g002_matcher(required_group, actual_group), False)

    def test_subgroup_required(self):
        required_group= 'urn:geant:h-df.de:group:aai-admin:special-admins#unity.helmholtz-data-federation.de'
        actual_group  = 'urn:geant:h-df.de:group:aai-admin#backupserver.used.for.developmt.de'
        self.assertEqual(aarc_g002_matcher.aarc_g002_matcher(required_group, actual_group), False)

    def test_user_in_subgroup(self):
        required_group= 'urn:geant:h-df.de:group:aai-admin#unity.helmholtz-data-federation.de'
        actual_group  = 'urn:geant:h-df.de:group:aai-admin:special-admins#backupserver.used.for.developmt.de'
        self.assertEqual(aarc_g002_matcher.aarc_g002_matcher(required_group, actual_group), True)

    def test_role_required_for_supergroup(self):
        required_group= 'urn:geant:h-df.de:group:aai-admin:role=admin#unity.helmholtz-data-federation.de'
        actual_group  = 'urn:geant:h-df.de:group:aai-admin:special-admins:role=admin#backupserver.used.for.developmt.de'
        self.assertEqual(aarc_g002_matcher.aarc_g002_matcher(required_group, actual_group), False)
    #
    # def test_(self):
    #     required_group= ''
    #     actual_group  = ''
    #     self.assertEqual(aarc_g002_matcher.aarc_g002_matcher(required_group, actual_group), True)

if __name__ == '__main__':
    unittest.main()
