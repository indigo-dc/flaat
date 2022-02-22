.. _development:

Development
===========

Repository
----------

Clone the repository to start developing:

.. code-block:: bash

   git clone https://github.com/indigo-dc/flaat
   cd ./flaat

Testing
-------
We need access token(s) to run tests.
We use `oidc-agent <https://github.com/indigo-dc/oidc-agent>`_ for handling access tokens.
The test suite uses environment variables for configuration.
You can configure the test suite using a dotenv file:

.. code-block:: bash

    cp .env-template .env   # use the template
    <editor> .env           # set the correct values in the dotenv file

You should preferably configure two oidc agent accounts: One for an OIDC provider that issues
JWTs and one that does not. The following file is the environment template. You will almost
certainly need to change `OIDC_AGENT_ACCOUNT` and `NON_JWT_OIDC_AGENT_ACCOUNT`:

.. literalinclude:: ../../../.env-template
   :language: bash

Tox
---
We use tox to run the tests for supported python versions, lint the code using pylint and build this beautiful documentation:


.. code-block:: bash

   tox              # Do everything
   tox -e docs      # Only build the docs
   tox -e pylint    # Only lint the code
   tox -e py310     # Run a test for a specific python version


Code conventions
----------------
We use `pyright <https://github.com/microsoft/pyright>`_ for static type checking. Code is formatted using `black <https://github.com/psf/black>`_.

Override auth using environment variables
-----------------------------------------

.. important::

    Be careful with these variables and never use them in production.

You may find setting the following environment variable useful:

- `export DISABLE_AUTHORIZATION_AND_ASSUME_AUTHORIZED_USER=YES`
    Bypasses user authorization done by the decorators.
- `export DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER=YES`
    Bypasses user authentication done by the decorators. This also bypasses the authorization.


Releasing to PyPI
-----------------
To build a new version use:

.. code-block:: bash

    git tag <new version>   # Tag the release version
    git push                # Push the tag

    make dist               # build the release
    make upload             # upload it to PyPI (needs a valid PyPI account configured in ~/.pypirc)


*Read the Docs* will automatically update the documentation for the git tag.
