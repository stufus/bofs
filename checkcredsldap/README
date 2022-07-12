# CheckCredsLDAP

This is a beacon object file which will attempt an LDAP bind to a domain controller using
the credentials passed to it. This is useful where credentials are recovered, for example
from a file on a share, and you want to verify whether the domain credentials are valid or
not, bearing in mind that you may not know at this point what they can be used to access.

## Syntax
 checkcredsldap <domain>\<username> <password>

## Output
Once run, it will attempt the LDAP bind and will either return a string stating that the 
connection was made successfully, or it will return the error code and the string representation
of the error code. It will display the credentials that it tried, with the domain controller
that the credentials were tested against.

## Compiling
```
$ make
i686-w64-mingw32-gcc -Wall -o checkcredsldap.x86.o -c checkcredsldap.c 
x86_64-w64-mingw32-gcc -Wall -o checkcredsldap.x64.o -c checkcredsldap.c
```

I have included the compiled BOFs for ease, but feel free to modify and rebuild as you see fit.

## Usage
Load checkcredsldap.cna as a script in Cobalt Strike, and make sure that the two object files
are in the same directory as the cna file.

## Example
```
beacon> checkcredsldap STUFUS\domainuser domainpassword
[+] host called home, sent: 1592 bytes
[-] LDAP Connection Failed: 49 (Invalid Credentials).
  Username: STUFUS\domainuser
  Password: domainpassword
  DC: W2K8DC.stufus.int

beacon> checkcredsldap STUFUS\domainuser F3ll0W
[+] host called home, sent: 1587 bytes
[+] received output:
LDAP Connection Successful (Valid credentials).
  Username: STUFUS\domainuser
  Password: F3ll0W
  DC: W2K8DC.stufus.int
```
