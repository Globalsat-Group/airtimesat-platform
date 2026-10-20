"""IWS gateway: the only code allowed to talk to IWS.

Owns SOAP signing, the two concurrency permits, the operation registry and the WSDL
snapshots with their generated bindings. Other packages use it only through
``airtimesat_platform.gateway.api``. Built in stage S3; empty until then.
"""
