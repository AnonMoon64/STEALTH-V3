STEALTH tests
===============

This folder contains small sample payloads used for integration testing with the packer and stub.

Safety first
-----------
- Always test inside an isolated VM or sandbox.
- Do not run tests on your host machine.

Using the test harness
----------------------
- `run_test_payload.ps1` is a helper script that runs a dry-run flow by default. It will only execute real commands if you pass `-Run` to confirm you want to run them.
- Example (dry-run):

```powershell
cd "c:\Users\atomi\Downloads\STEALTH"
.\tests\run_test_payload.ps1
```

- Example (actually run, only in safe isolated VM):

```powershell
cd "c:\Users\atomi\Downloads\STEALTH"
.\tests\run_test_payload.ps1 -Run
```

The script expects `stealth_cryptor.exe` to be present in the repository root. If it is not present, the script shows the command it would run.
