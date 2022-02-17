.. _development:

Development
===========


Override authentication using environment variables
---------------------------------------------------
You may find setting the following environment variable useful:

- `DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER=YES`: Assumes a valid user
- `DISABLE_AUTHENTICATION_AND_ASSUME_SATISFIED=YES`: Assumes all group membership requriements to be true
- `DISABLE_AUTHENTICATION_AND_ASSUME_CLAIM=<string of json list>`: Assumes the user in question to be member of the groups specified.

Example for the json list:

.. code-block:: json

    [
      "urn:geant:h-df.de:group:m-team:feudal-developers",
      "urn:geant:h-df.de:group:MyExampleColab#unity.helmholtz.de"
    ]

