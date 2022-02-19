Example: aiohttp
================

The following is an example of using flaat with **aiohttp**.
Using flaat with Flask or fastapi is basically the same.
You can use the example using:

.. code-block:: bash

    # run the server:
    python ./examples/example_aio.py


    # Do the following commands in a different shell

    # With oidc agent:
    curl http://localhost:8080/info -H "Authorization:Bearer $(oidc-token <account name>)"

    # With access token:
    curl http://localhost:8080/info -H "Authorization:Bearer eyJraWQ..."

.. literalinclude:: ../../../../examples/example_aio.py
