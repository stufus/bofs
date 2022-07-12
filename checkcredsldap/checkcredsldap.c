/*
 * CheckCredsLDAP: Beacon Object File
 * @ukstufus (https://github.com/stufus)
 * Stuart Morgan <stuart.morgan@mwrinfosecurity.com> 
 *
 * This is a beacon object file which attempts to bind to the LDAP server on
 * any current domain controller.
 */

#include "checkcredsldap.h"

void checkcredsldap(char * args, int length) {

    datap beaconArguments;
    char *username;
    char *password;
    char *targetdc;
    HMODULE libLDAP = NULL;
    ULONG uLDAPBindResult = 0;
    PDOMAIN_CONTROLLER_INFO dcInfo = NULL;
    LDAP* pLDAP = NULL;

    // Parse the username and password arguments
    BeaconDataParse(&beaconArguments, args, length);
    username = BeaconDataExtract(&beaconArguments, NULL);
    password = BeaconDataExtract(&beaconArguments, NULL);

    if (strlen(password) < 1 || strlen(username) < 1) {
       BeaconPrintf(CALLBACK_ERROR, "checkcredsldap: A username and password are both required.");
       return;
    }

    // Find a DC
    if (NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &dcInfo) == ERROR_SUCCESS) {
       targetdc = dcInfo->DomainControllerName + 2;
    } else {
       BeaconPrintf(CALLBACK_ERROR, "checkcredsldap: Unable to obtain domain controller name automatically.\n");
       return;
    }

    // Load the LDAP API
    libLDAP = LoadLibrary("wldap32");
    if (libLDAP == NULL) {
      BeaconPrintf(CALLBACK_ERROR, "checkcredsldap: Unable to load LDAP library\n"); 
      return;
    }

    // Connect to the DC
    pLDAP = WLDAP32$ldap_init(targetdc, 389);
    if (pLDAP == NULL) {
      BeaconPrintf(CALLBACK_ERROR, "checkcredsldap: Failed to establish LDAP connection to %s:389\n", targetdc);
      return;
    }

    // Try the credentials
    uLDAPBindResult = WLDAP32$ldap_simple_bind_s(pLDAP, username, password);
    if(uLDAPBindResult != LDAP_SUCCESS) {
      char *errstring = WLDAP32$ldap_err2string(uLDAPBindResult);
      BeaconPrintf(CALLBACK_ERROR, "checkcredsldap: LDAP Connection Failed: %lu (%s).\n  Username: %s\n  Password: %s\n  DC: %s", uLDAPBindResult, errstring, username, password, targetdc);
    } else {
      BeaconPrintf(CALLBACK_OUTPUT, "checkcredsldap: LDAP Connection Successful (Valid credentials).\n  Username: %s\n  Password: %s\n  DC: %s", username, password, targetdc);
    }

    // Clean up afterwards, avoid memory leaks
    if (dcInfo) { 
      NETAPI32$NetApiBufferFree(dcInfo);
      dcInfo = NULL;
    }
    if (pLDAP) { 
      WLDAP32$ldap_unbind(pLDAP);
      pLDAP = NULL;
    }
    if (libLDAP) { 
      FreeLibrary(libLDAP);
      libLDAP = NULL;
    }

    return;
}
