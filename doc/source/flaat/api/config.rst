Configuration Options
=====================

Flaat instances are configured like :class:`FlaatConfig` below.


.. autoclass:: flaat.config.FlaatConfig
   :members:

.. autoclass:: flaat.config.AccessLevel
   :members:

Additional configuration
------------------------

OP specific configuration can be loaded from a config file. Config locations, by priority:

- $FLAAT_CONFIG
- ./flaat.conf
- ~/.config/flaat/flaat.conf
- /etc/flaat/flaat.conf

The config file is a simple ini file with sections and key-value pairs. Currently, the following options can be configured in an [ops] section:

- **ops_that_support_jwt**: List of additional OPs that support JWTs, in case you are not using a well-known OP. A list of default OPs is already included in the code.
- **ops_that_support_audience**: List of additional OPs that support the audience parameter. A list of default OPs is already included in the code.

Example config file (this is just an example, these OPs are already included in the code):

.. code-block:: yaml
  :linenos:

   [ops]
   ops_that_support_jwt = [
      "https://aai-demo.egi.eu/auth/realms/egi"
      ]
   ops_that_support_audience = [
      "https://wlcg.cloud.cnaf.infn.it"
      ]
