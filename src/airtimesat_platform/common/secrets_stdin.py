"""Secrets read once from standard input.

Will hold ``StdinSecretsProvider``, which reads named secrets piped by the Keeper CLI into
``SecretValue`` objects for one recorder run: no file, no environment variable, no AWS.
Built in stage S2 (design ``docs/design/s2-recorder-masker.md`` §6.2, §7.2); empty until
then.
"""
