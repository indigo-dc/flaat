flaat-get-userinfo.py
=====================

Synopsis
--------

:program:`get_userinfo` [options]

Description
-----------

:program:`get_userinfo` is a simple tool to gather all info based on a given OIDC Access Token.

Options
-------

usage: get_userinfo.py [-h] [-c MY_CONFIG] [--verbose] [--client_id CLIENT_ID] [--client_secret CLIENT_SECRET] [--verify_tls]
                       [--accesstoken] [--userinfo] [--introspection] [--all] [--quiet] [--issuersconf ISSUERSCONF] [--issuer ISSUER]  access_token

positional arguments:
  access_token          An Access Token

optional arguments:
  -h, --help          show this help message and exit

  -c MY_CONFIG, --my-config         MY_CONFIG config file path

  --verbose, -v         Verbosity

  --client_id            CLIENT_ID

  --client_secret        CLIENT_SECRET

  --verify_tls          disable verify

  --accesstoken, -at    Access Token

  --userinfo, -ui       Show info from userinfo endpoint 

  --introspection, -in   Show results from introspection endpoint

  --all, -a             Show all info

  --quiet, -q           Quiet operation 

  --issuersconf ISSUERSCONF         issuer.config, e.g. from oidc-agent

  --issuer ISSUER, --iss ISSUER, -i         ISSUER Specify issuer (OIDC Provider)



Reporting Bugs
--------------

Bugs are managed at `github <https://github.com/indigo-dc/flaat>`__

