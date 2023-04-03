# Spooler
Local and remote MS-RPRN abuse.
## Usage
```
$ Spooler.exe --help
Local and remote MS-RPRN abuse

  local     Local MS-RPRN abuse using SeImpersonatePrivilege.
  remote    Remote MS-RPRN abuse.
  help      Display more information on a specific command.

$ Spooler.exe local --help
Local and remote MS-RPRN abuse

  -c, --check      (Default: false) Check abuse possibility.
  -x, --command    Command to execute.
  -a, --args       Command arguments.
  -s, --show       (Default: false) Show window.
  --help           Display this help screen.

$ Spooler.exe remote --help
Local and remote MS-RPRN abuse

  -f, --find       Find if a remote server has Print Spooler enabled. Accepts
                    comma-separated list of addresses.
  -t, --target     Target host with enabled Print Spooler service.
  -c, --capture    Capture host.
  --help           Display this help screen.
```