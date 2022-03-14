On the CLI: flaat-userinfo
==========================

Installation
------------
:program:`flaat-userinfo` is included with the :doc:`flaat installation <./installation>`.

Description
-----------

:program:`flaat-userinfo` is a simple tool to gather all oidc user info based on access tokens.

The tool can be used in multiple ways:

- Directly pass an access token.
- Name an `oidc-agent` account, which is used to retrieve an access token.
- Use an access token from environment variables (e.g. `ACCESS_TOKEN`).

Options
-------
.. code-block:: bash

    usage: flaat-userinfo [-h] [--my-config MY_CONFIG] [--client_id CLIENT_ID] [--client_secret CLIENT_SECRET] [--oidc-agent-account OIDC_AGENT_ACCOUNT] [--issuer ISSUER] [--audience AUDIENCE]
                          [--skip_tls_verify] [--skip_jwt_verify] [--accesstoken] [--userinfo] [--introspection] [--all] [--quiet] [--verbose] [--machine-readable]
                          [access_token ...]

    flaat-userinfo

    positional arguments:
      access_token          An access token (without 'Bearer ')

    options:
      -h, --help            show this help message and exit
      --my-config MY_CONFIG, -c MY_CONFIG
                            config file path
      --client_id CLIENT_ID
                            Specify the client_id of an oidc client. This is needed for token introspection.
      --client_secret CLIENT_SECRET
                            Specify the client_secret of an oidc client. This is may be needed for token introspection.
      --oidc-agent-account OIDC_AGENT_ACCOUNT, -o OIDC_AGENT_ACCOUNT
                            Name of oidc-agent account for access token retrieval
      --issuer ISSUER, -i ISSUER
                            Specify issuer (OIDC Provider)
      --audience AUDIENCE, --aud AUDIENCE
                            Specify an intended audience for the requested access
                            token. Multiple audiences can be provided as a space
                            separated list. Only used when token is retrieved via
                            the oidc-agent. Ignored if OP does not support
                            audience setting.
      --skip_tls_verify     Disable TLS verification
      --skip_jwt_verify     Disable JWT verification
      --accesstoken, -at    Show access token info (default)
      --userinfo, -ui       Show user info (default)
      --introspection, -in  Show introspection info (default)
      --all, -a
      --quiet, -q           Enable quiet mode. This will only show requested information, no explanatory text
      --verbose, -v         Enable verbose mode. This will also print debug messages.
      --machine-readable, -m
                            Make stdout machine readable

Quick examples
--------------

To use a raw access token with :program:`flaat-userinfo`, just pass it as an argument:

.. code-block:: bash

   flaat-userinfo eyJraWQ...

If you have a loaded `oidc-agent` account called "foo", you can use :program:`flaat-userinfo` using:

.. code-block:: bash

   flaat-userinfo -o foo
