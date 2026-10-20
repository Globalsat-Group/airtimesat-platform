"""SITEST port of the IWS gateway: the recorder's only entry point into the gateway.

Will hold the ``SitestPort`` protocol and its in-process implementation over the SITEST
signer core, and the loader of the generated field map. It reaches the two SITEST endpoints
only, never Beta or production, and never imports ``gateway.api``. Built in stage S2
(design ``docs/design/s2-recorder-masker.md`` §7.1, §7.2); empty until then.
"""
