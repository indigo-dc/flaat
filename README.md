# Example for using flask with OIDC.

Tested OIDC Providers are
- IAM of the [Deep Hybrid Datacloud](https://deep-hybrid-datacloud.eu) project.
- Unity / B2Access as used in the Helmholtz-Data-Federation
- KIT's Shibboleth installation
- Google


For using the API you will need a valid OIDC access token. For the
commandline you might want to use
[oidc-agent](https://github.com/indigo-dc/oidc-agent) for that .


# Installation

Actually the code should just run straight from github. Python
dependencies include requests, flask, json and functools. Most of which
are pretty standard.

Just *source* install.sh to get a pyve with the dependencies installed:

`  . install.sh`

# Documentation

First off there's a pretty neat example.py that you can find all the
examples inside. example.py provides an API via flask that is protected
with `floidau` (FLask OIDc AUthentication and authorisation).

`floidau` allows protecting REST interfaces with simple decorators like:
```
@floidau.login_required()
```

Once started you can test calls to the example like this:

```
http localhost:8080/group_test_iam "Authorization: Bearer `oidc-token deep`"
```
or
```
curl http://localhost:8080/valid_user -H "Authorization: Bearer `oidc-token deep`"
```


Your Bearer token can be any OIDC Access Token.

I'm probably colliding with the OIDC spec, but it worked quite neatly with
all OPs tried.

Tested OPs:
- https://iam.deep-hybrid-datacloud.eu/
- https://unity.helmholtz-data-federation.de/oauth2/
- https://accounts.google.com/
- https://oidc.scc.kit.edu/auth/realms/kit/


