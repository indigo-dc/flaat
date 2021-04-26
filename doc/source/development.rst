.. _development:

Development
===========

You may find setting the following environment variable useful:

- `DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER=YES`: Assumes a valid user
- `DISABLE_AUTHENTICATION_AND_ASSUME_VALID_GROUPS=YES`: Assumes all group membership requriements to be true
- `DISABLE_AUTHENTICATION_AND_ASSUME_GROUPS=<json list>`: Assumes the user in question to be member of the groups specified.

Please note that this changes the prevriously undocumented behaviour of 
`DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER=YES` in that now,
setting it will not assume the groups to be valid anymore.

Example for the json list:

.. code-block:: json

    [
      "urn:geant:h-df.de:group:m-team:feudal-developers",
      "urn:geant:h-df.de:group:MyExampleColab#unity.helmholtz.de"
    ]

