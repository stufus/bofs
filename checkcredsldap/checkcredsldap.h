/*
 * CheckCredsLDAP: Beacon Object File
 * @ukstufus (https://github.com/stufus)
 * Stuart Morgan <stuart.morgan@mwrinfosecurity.com> 
 *
 * This is a beacon object file which attempts to bind to the LDAP server on
 * any current domain controller.
 */

#include <windows.h>
#include <dsgetdc.h>
#include <winldap.h>
#include "../beacon.h"

// Sort out the imports that are needed for Beacon
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);
DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_init(PSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_simple_bind_s(LDAP *ld, const PSTR un, const PSTR pw);
DECLSPEC_IMPORT ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT PCHAR LDAPAPI WLDAP32$ldap_err2string(ULONG err);

