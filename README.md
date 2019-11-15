# FLAsk support for handling oidc Access Tokens - FLAAT
Now with support for AIOHTTP (>= v0.5.0)

# Installation

Actually the code should just run straight from github. Python
dependencies include requests, flask, json and functools. Most of which
are pretty standard.

Just *source* install.sh to get a pyve with the dependencies installed:

`pip install flaat`

# TL;DR

FLAAT is here to provide the simplest way to verify OIDC Access Tokens.
The goal is that FLAAT is a tool that can be used to very easily make
access decisions or not.  Priority is on ease of use, which comes with a
few potential drawbacks.

# Documentation

First off there's examples that demonstrate the functionality 
(example-flask.py and example-aio.py) 
They  provide an API that is protected
with `flaat`.

`flaat` allows protecting REST interfaces with simple decorators like:
```
@flaat.login_required()
```
`flaat` also supports complex group membership checking. To match two of
the given groups, use:
```
@flaat.group_required(group=['admins@kit.edu', 'employee@kit.edu', 'member@kit.edu'],
        claim='eduperson_scoped_affiliation', match=2)
```
The claim parameter allows selecting the OIDC claim in which to look for
group membership.

Once started you can test calls to the example like this:

```
curl http://localhost:8080/valid_user -H "Authorization: Bearer `oidc-token deep`"
```
or
```
http localhost:8080/group_test_hdf "Authorization: Bearer `oidc-token unity`"
```
or

Please find details for usage in the examples and in the respective
docstrings.

Your Bearer token can be any OIDC Access Token.

## Examples

FLAAT comes with two examples:
- `example-flask.py` / `example-aio.py`, rhat uses the three
  decorators provided by FLAAT:
  -  login_required
  -  group_required
  That protect the functions they decorate
    You can run it like
    ``python3 ./example-flask.py`
    ``python3 ./example-aio.py`
    You can run queries against it like:
```
http localhost:8080/info "Authorization: Bearer $OIDC"
http localhost:8080/valid_user "Authorization: Bearer $OIDC"
http localhost:8080/valid_user "Authorization: Bearer `oidc-token unity`"
curl localhost:8080/valid_user -H "Authorization: Bearer `oidc-token egi`"
http localhost:8080/group_test_iam "Authorization: Bearer `oidc-token google`"
```

- `get_userinfo.py` is a commandline application for testing. It uses
  FLAAT in a similar way as the examples
Examples:
```
./get_userinfo.py `oidc-token indigo-iam`
```

## What does FLAAT do?

FLAAT tries to get as much information out of the AT to determine whether
or not the function it protects should be called or not.

FLAAT only operates on the OIDC Access Token, called AT.

-  FLAAT firstly analyses the AT to see if the AT is a json web token
   (JWT). In that case there may be an `exp` claim, which is used.

   In case the AT is JWT, FLAAT will also query the userinfo endpoint of
   the OP found in the `iss` claim.

-  For cases in which the OP cannot be determined, FLAAT offers several
   ways to determine the issuing OP. You can provide a list of trusted
   OPs, a file that cointains a list of trusted OPs, or a single OP.
   In the case of lists, an OP_hint can be specified, which is used to
   filter the available list of trusted OPs.

   Based on list and OP_hint, FLAAT queries all provided OPs for their
   config and then for their userinfo endpoint, to evaluate whether the AT
   is possibly provided by them.

   Note: For being nice to OPs that are known to issue JWTs, these are
   excluded from the search.

-  In case the user provides a valid client_id and client_secret, the
   token introspection endpoint of the given OP is queried.

## Issues

FLAAT works under the assumption that ATs cannot be used to access the
userinfo endpoint after the AT expired.  This does not seem to be the
case. If you need to be strict on lifetime checking, please obtain a
client_id and client_secret from the OPs that you work with.


## Compatibility
Tested OIDC Providers are
- IAM of the [Deep Hybrid Datacloud](https://deep-hybrid-datacloud.eu) project -- https://iam.deep-hybrid-datacloud.eu/
- EGI -- https://aai.egi.eu/oidc/
- Unity / B2Access as used in the Helmholtz-Data-Federation -- https://unity.helmholtz-data-federation.de/oauth2/
- KIT's Shibboleth installation -- https://oidc.scc.kit.edu/auth/realms/kit/
- Google -- https://accounts.google.com/
- EduTEAMS -- https://proxy.demo.eduteams.org


# Recommendation

For obtaining OIDC access tokens on  the commandline you might want to use
[oidc-agent](https://github.com/indigo-dc/oidc-agent) 


# License
FLAAT is provided under the [MIT License](https://opensource.org/licenses/MIT)
