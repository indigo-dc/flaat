FLAAT
=====

Release v\ |version|. (:ref:`Installation <installation>`)

FLAsk/aiohttp support for Access Tokens (FLAAT) provides a few decorators to allow
authentication and authorisation using OpenID Connect (OIDC) in Flask and
aiohttp.

Compatibility
-------------

Flaat works with Python 2.7+ and Python 3.

Documentation
-------------

If you want to protect a REST interface, that is used with OpenID Connect
(OIDC), this documentation is what you are looking for.

Flaat supports to limit access to any REST endpoint you have. We do
support this by making use of decorators.  Three different decorators are
currently supported:

- ``login_required``: Requires a valid user from one of the supported OpenID
  Connect Providers (OPs)
- ``group_required``: Requires membership in a given group.
- ``aarc_g002_group_required``: Same as ``group required`` but facilitating the
  [AARC_G002]_ 

.. toctree::
   :maxdepth: 1

   installation
   configuration/index
   configuration/sample-aio
   configuration/sample-flask
   cli/flaat-userinfo

API reference
-------------

If you are looking for information on a specific function, class or
method, this part of the documentation is for you.

.. toctree::
   :maxdepth: 2

   api


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


.. [AARC_G002] Guidelines on Expressing group membership and role
  information https://aarc-project.eu/guidelines/aarc-g002

