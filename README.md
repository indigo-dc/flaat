# FLAsk support for handling oidc Access Tokens - FLAAT



Tested OIDC Providers are
- IAM of the [Deep Hybrid Datacloud](https://deep-hybrid-datacloud.eu) project.
- EGI
- Unity / B2Access as used in the Helmholtz-Data-Federation
- KIT's Shibboleth installation
- Google


For using the API you will need a valid OIDC access token. For the
commandline you might want to use
[oidc-agent](https://github.com/indigo-dc/oidc-agent) for that.

# License
FLAAT is provided under the [MIT License](https://opensource.org/licenses/MIT)

# Installation

Actually the code should just run straight from github. Python
dependencies include requests, flask, json and functools. Most of which
are pretty standard.

Just *source* install.sh to get a pyve with the dependencies installed:

`  . install.sh`

# Documentation

First off there's a pretty neat example.py that you can find all the
examples inside. example.py provides an API via flask that is protected
with `flaat` (FLAsk support for Access Tokens).

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

Please find details for usage in example.py and in the respective
docstrings.

Your Bearer token can be any OIDC Access Token.


# Tested OPs:
- https://iam.deep-hybrid-datacloud.eu/
- https://unity.helmholtz-data-federation.de/oauth2/
- https://accounts.google.com/
- https://oidc.scc.kit.edu/auth/realms/kit/

# Open Issues / Roadmap:
- Offline verification: Check the signature, in case token is a jwt
- Fix aarc-g002 handling

