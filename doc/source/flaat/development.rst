.. _development:

Development
===========

Tox
---

We use tox to run the tests for supported python versions, lint the code using pylint and build this beautiful documentation:


.. code-block:: console

   cd <..>/flaat    # in the project root

   tox              # Do everything
   tox -e docs      # Only build the docs
   tox -e pylint    # Only lint the code


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
