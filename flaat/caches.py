'''FLAsk support for OIDC Access Tokens -- FLAAT. A set of decorators for authorising
access to OIDC authenticated REST APIs.'''
# This code is distributed under the MIT License
# pylint
# vim: tw=100 foldmethod=indent
# pylint: disable=invalid-name, superfluous-parens
# pylint: disable=logging-not-lazy, logging-format-interpolation, logging-fstring-interpolation
# pylint: disable=wrong-import-position, no-self-use, line-too-long

import logging
import logsetup
logger = logging.getLogger(__name__)

class Issuer_config_cache():
    '''Caching of issuer configs'''
    def __init__(self):
        self.entries = {} # maps 'iss' to the whole issuer config
        self.n = 0
    def add_config(self, iss, issuer_config):
        '''add entry'''
        # if self.get(iss) is not None:
        #     logger.info(F"updating: {iss}")
        # else:
        #     logger.info(F"adding: {iss}")
        self.entries[issuer_config['issuer']] = issuer_config
    def add_list(self, issuer_configs):
        '''add entry'''
        for issuer_config in issuer_configs:
            self.add_config(issuer_config['issuer'], issuer_config)
    def get(self, iss):
        '''get entry'''
        try:
            return (self.entries[iss])
        except KeyError:
            # logger.warning(F"cannot return issuer config for {iss}")
            return None
    def remove(self, iss):
        '''remove entry'''
        del self.entries[iss]
    def dump_to_log(self):
        '''display cache'''
        logger.info("Issuer Cache:")
        for iss in self.entries:
            logger.info(F"  {self.entries[iss]['issuer']:30} -> {self.entries[iss]['userinfo_endpoint']}")

    def __iter__(self):
        self.n = 0
        return self

    def __next__(self):
        my_length = len(self.entries.keys())
        if self.n < my_length:
            retval = self.entries[list(self.entries.keys())[self.n]]
            self.n += 1
            return retval
        raise StopIteration

    def __len__(self):
        '''return length'''
        return len(self.entries.keys())

    def has(self, iss):
        '''do we have an entry'''
        if iss in self.entries.keys():
            return True
        return False


if __name__ == '__main__':
    ic = Issuer_config_cache()
    print (F"is none: {ic is None}")
    ic.add_config('first_issuer1', {'issuer': 'first issuer1', 'userinfo_endpoint': 'userinfo1'})
    ic.add_config('sencodnd issuer2', {'issuer': 'sencodnd issuer2', 'userinfo_endpoint': 'userinfo2'})

    print ('--')
    print (F"test: {ic.get('test2')}")
    print ('--')

    # ic.dump_to_log()

    for x in ic:
        print(F"iterating: {x}")

    print(F"length: {len(ic)}")

    print(F"testing in")
    if ic.has('first issuer1'):
        print ("Yes")
    else:
        print ("NOPE")

