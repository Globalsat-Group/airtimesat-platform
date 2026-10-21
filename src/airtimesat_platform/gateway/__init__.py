"""IWS gateway: the only code allowed to talk to IWS.

Owns SOAP signing, the two concurrency permits, the operation registry and the WSDL
snapshots with their generated bindings. The console uses it only through
``airtimesat_platform.gateway.api``; the recorder only through
``airtimesat_platform.gateway.sitest_port``. Stage S2 builds the SITEST signer core; stage
S3 grows the rest. Empty until then.
"""
