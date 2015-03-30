# -*- coding: utf-8 -*-
# pylint: disable=C0325
# pylint: disable=C0103
# pylint: disable=C0302
"""
Application Security and Development Checklist

http://iase.disa.mil/stigs/Documents/U_Application_Security_and_Development_V3R10_STIG.zip



"""
from textwrap import TextWrapper
indent = 4
width = 76


wrapper = TextWrapper(initial_indent=''.join([' '*indent, '| ', ' '*indent]),
                      subsequent_indent=' '*indent+'| '+' '*indent,
                      width=width)
line_break = ''.join([' '*(indent), '+', '-'*(width-indent), '+'])


def print_response(response):
    """ """
    response = wrapper.wrap(response.replace('\n    ', ' '))
    margin_limit = indent + width - 2 - 1
    response_seq = ['    | Response:'.ljust(margin_limit) +'|'] + \
        [line.ljust(margin_limit) + '|' for line in response]
    print('\n'.join(response_seq))
    print line_break    




def SV21828r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-19687                                             [HIGH] |
    |    Rule ID: SV-21828r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure web servers are on logically separate          |
    |     network segments from the application and database servers if      |
    |     it is a tiered application.                                        |
    |                                                                        |
    | Description:                                                           |
    |     Web servers should be on logically separated network segments      |
    |     from the application and database servers in order to provide      |
    |     different levels and types of defenses for each type of            |
    |     server.  Failure to comply would result in an immediate loss       |
    |     of confidentiality.  This requirement to this STIG was added       |
    |     at the request of the DoD DMZ PM.  The goal is to ensure this      |
    |     requirement is addressed as the application is being               |
    |     developed.  This requirement and severity was previously           |
    |     approved by the DSAWG in the Internet-NIPRNet DoD DMZ              |
    |     Inrecrement 1, Phase 1 STIG.    Any vulnerability associated       |
    |     with a DoD Information system or system enclave, the               |
    |     exploitation of which, by a risk factor, will directly and         |
    |     immediately result in loss of Confidentiality, Availability or     |
    |     Integrity of the system associated data.                           |
    +------------------------------------------------------------------------+
    """
    response = """<RESPONSE>
    """
    print(SV21828r1.__doc__.rstrip())
    print_response(response)



def SV21829r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-19688                                             [HIGH] |
    |    Rule ID: SV-21829r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer and the IAO will ensure physical operating system     |
    |     separation and physical application separation is employed         |
    |     between servers of different data types in the web tier of         |
    |     Increment 1/Phase 1 deployment of the DoD DMZ for Internet-        |
    |     facing applications.                                               |
    |                                                                        |
    | Description:                                                           |
    |     Restricted and unrestricted data residing on the same server       |
    |     may allow unauthorized access which would result in a loss of      |
    |     integrity and possibly the availability of the data.   This        |
    |     requirement to this STIG was added at the request of the DoD       |
    |     DMZ PM.  The goal is to ensure this requirement is addressed       |
    |     as the application is being developed.  This requirement and       |
    |     severity was previously approved by the DSAWG in the Internet-     |
    |     NIPRNet DoD DMZ Increment 1, Phase 1 STIG.  *This requirement      |
    |     does not apply to SIPRNet DMZs.                                    |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV21829r1.__doc__.rstrip())
    print(response)


def SV17837r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16837                                             [HIGH] |
    |    Rule ID: SV-17837r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure the application is decommissioned when         |
    |     maintenance or support is no longer available.                     |
    |                                                                        |
    | Description:                                                           |
    |     When maintenance no longer exists for an application, there        |
    |     are no individuals responsible for providing security updates.     |
    |     The application is no longer supported, and should be              |
    |     decommissioned.                                                    |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17837r1.__doc__.rstrip())
    print(response)


def SV17809r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16809                                             [HIGH] |
    |    Rule ID: SV-17809r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not contain          |
    |     format string vulnerabilities.                                     |
    |                                                                        |
    | Description:                                                           |
    |     Format string vulnerabilities usually occur when unvalidated       |
    |     input is entered and is directly written into  the format          |
    |     string used to format data in the print style family of C/C++      |
    |     functions. If an attacker can manipulate a format string, this     |
    |     may result in a buffer overflow causing a denial of service        |
    |     for the application. Format string vulnerabilities may lead to     |
    |     information disclosure vulnerabilities. Format string              |
    |     vulnerabilities may be used to execute arbitrary code.             |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17809r1.__doc__.rstrip())
    print(response)


def SV17808r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16808                                             [HIGH] |
    |    Rule ID: SV-17808r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application is not vulnerable to      |
    |     integer arithmetic issues.                                         |
    |                                                                        |
    | Description:                                                           |
    |     Integer overflows occur when an integer has not been properly      |
    |     checked and is used in memory allocation, copying, and             |
    |     concatenation.  Also, when incrementing integers past their        |
    |     maximum possible value, it could potentially become a very         |
    |     small or negative number. Integer overflows can lead to            |
    |     infinite looping when loop index variables are compromised and     |
    |     cause a denial of service.  If the integer is used in data         |
    |     references, the data can become corrupt. Also, using the           |
    |     integer in memory allocation can cause buffer overflows, and a     |
    |     denial of service.  Integers used in access control mechanisms     |
    |     can potentially trigger buffer overflows, which can be used to     |
    |     execute arbitrary code.                                            |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17808r1.__doc__.rstrip())
    print(response)


def SV17800r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16800                                             [HIGH] |
    |    Rule ID: SV-17800r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure users’ accounts are locked after          |
    |     three consecutive unsuccessful logon attempts within one hour.     |
    |                                                                        |
    | Description:                                                           |
    |     If user accounts are not locked after a set number of              |
    |     unsuccessful logins, attackers can infinitely retry user           |
    |     password combinations providing immediate access to the            |
    |     application.                                                       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17800r1.__doc__.rstrip())
    print(response)


def SV17804r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16804                                             [HIGH] |
    |    Rule ID: SV-17804r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not rely solely      |
    |     on a resource name to control access to a resource.                |
    |                                                                        |
    | Description:                                                           |
    |     Application access control decisions should be based on            |
    |     authentication of users. Resource names alone can be spoofed       |
    |     allowing access control mechanisms to be bypassed giving           |
    |     immediate access to the application.                               |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17804r1.__doc__.rstrip())
    print(response)


def SV17807r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16807                                             [HIGH] |
    |    Rule ID: SV-17807r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application is not vulnerable to      |
    |     SQL Injection, uses prepared or parameterized statements, does     |
    |     not use concatenation or replacement to build SQL queries, and     |
    |     does not directly access the tables in a database.                 |
    |                                                                        |
    | Description:                                                           |
    |     SQL Injection can be used to bypass user login to gain             |
    |     immediate access to the application and can also be used to        |
    |     elevate privileges with an existing user account.                  |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17807r1.__doc__.rstrip())
    print(response)


def SV17813r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16813                                             [HIGH] |
    |    Rule ID: SV-17813r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not use hidden       |
    |     fields to control user access privileges or as a part of a         |
    |     security mechanism.                                                |
    |                                                                        |
    | Description:                                                           |
    |     Using hidden fields to pass data in forms is very common.          |
    |     However, hidden fields can be easily manipulated by users.         |
    |     Hidden fields used to control access decisions can lead to a       |
    |     complete compromise of access control  mechanism allowing          |
    |     immediate anonymous user access.                                   |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17813r1.__doc__.rstrip())
    print(response)


def SV17810r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16810                                             [HIGH] |
    |    Rule ID: SV-17810r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not allow            |
    |     command injection.                                                 |
    |                                                                        |
    | Description:                                                           |
    |     A command injection attack, is an attack on a vulnerable           |
    |     application where improperly validated input is passed to a        |
    |     command shell setup in the application. A command injection        |
    |     allows an attacker to execute their own commands with the same     |
    |     privileges as the application executing. Command injection         |
    |     allows immediate access to the system where the application is     |
    |     executing.                                                         |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17810r1.__doc__.rstrip())
    print(response)


def SV17811r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16811                                             [HIGH] |
    |    Rule ID: SV-17811r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not have cross       |
    |     site scripting (XSS) vulnerabilities.                              |
    |                                                                        |
    | Description:                                                           |
    |     XSS vulnerabilities exist when an attacker uses a trusted          |
    |     website to inject malicious scripts into applications with         |
    |     improperly validated input.                                        |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17811r1.__doc__.rstrip())
    print(response)


def SV17787r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16787                                             [HIGH] |
    |    Rule ID: SV-17787r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application follows the secure        |
    |     failure design principle.                                          |
    |                                                                        |
    | Description:                                                           |
    |     The secure design principle ensures the application follows a      |
    |     secure predictable path in the application code. If all            |
    |     possible code paths are not accounted for, the application may     |
    |     allow access to unauthorized users. Applications should            |
    |     perform checks on the validity of data, user permissions, and      |
    |     resource existence before performing a function. Secure            |
    |     failure is defined if a check fails for any reason, the            |
    |     application remains in a secure state.                             |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17787r1.__doc__.rstrip())
    print(response)


def SV6129r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6129                                              [HIGH] |
    |    Rule ID: SV-6129r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application using PKI validates       |
    |     certificates for expiration, confirms origin is from a DoD         |
    |     authorized CA, and verifies the certificate has not been           |
    |     revoked by CRL or OCSP, and CRL cache (if used) is updated at      |
    |     least daily.                                                       |
    |                                                                        |
    | Description:                                                           |
    |     The application should not provide access to users or other        |
    |     entities using expired, revoked or improperly signed               |
    |     certificates because the identity cannot be verified.              |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6129r1.__doc__.rstrip())
    print(response)


def SV21844r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-19703                                             [HIGH] |
    |    Rule ID: SV-21844r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure validity periods are verified on all      |
    |     messages using WS-Security or SAML assertions.                     |
    |                                                                        |
    | Description:                                                           |
    |     When using WS-Security in SOAP messages, the application           |
    |     should check the validity of the timestamps with creation and      |
    |     expiration times. Unvalidated timestamps may lead to a replay      |
    |     event and provide immediate unauthorized access of the             |
    |     application.  Unauthorized access results in an immediate loss     |
    |     of confidentiality.   Any vulnerability associated with a DoD      |
    |     Information system or system enclave, the exploitation of          |
    |     which, by a risk factor, will directly and immediately result      |
    |     in loss of Confidentiality, Availability or Integrity of the       |
    |     system associated data.                                            |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV21844r1.__doc__.rstrip())
    print(response)


def SV21843r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-19702                                             [HIGH] |
    |    Rule ID: SV-21843r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure when using WS-Security, messages use      |
    |     timestamps with creation and expiration times.                     |
    |                                                                        |
    | Description:                                                           |
    |     The lack of timestamps could lead to the eventual replay of        |
    |     the message, leaving the application susceptible to replay         |
    |     events which may result in an immediate loss of                    |
    |     confidentiality.   Any vulnerability associated with a DoD         |
    |     Information system or system enclave, the exploitation of          |
    |     which, by a risk factor, will directly and immediately result      |
    |     in loss of Confidentiality, Availability or Integrity of the       |
    |     system associated data.                                            |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV21843r1.__doc__.rstrip())
    print(response)


def SV17795r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16795                                             [HIGH] |
    |    Rule ID: SV-17795r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not display          |
    |     account passwords as clear text.                                   |
    |                                                                        |
    | Description:                                                           |
    |     Passwords being displayed in clear text can be easily seen by      |
    |     casual observers. Password masking should be employed so any       |
    |     casual observers cannot see passwords on the screen as they        |
    |     are being typed.                                                   |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17795r1.__doc__.rstrip())
    print(response)


def SV17797r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16797                                             [HIGH] |
    |    Rule ID: SV-17797r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application stores account            |
    |     passwords in an approved encrypted format.                         |
    |                                                                        |
    | Description:                                                           |
    |     Passwords stored without encryption or with weak, unapproved,      |
    |     encryption can easily be read and unencrypted. These passwords     |
    |     can then be used for immediate access to the application.          |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17797r1.__doc__.rstrip())
    print(response)


def SV17796r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16796                                             [HIGH] |
    |    Rule ID: SV-17796r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application transmits account         |
    |     passwords in an approved encrypted format.                         |
    |                                                                        |
    | Description:                                                           |
    |     Passwords transmitted in clear text or with an unapproved          |
    |     format are vulnerable to network protocol analyzers. These         |
    |     passwords acquired with the network protocol analyzers can be      |
    |     used to immediately access the application.                        |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17796r1.__doc__.rstrip())
    print(response)


def SV23682r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-21498                                             [HIGH] |
    |    Rule ID: SV-23682r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application is not vulnerable to      |
    |     XML Injection.                                                     |
    |                                                                        |
    | Description:                                                           |
    |     XML injection results in an immediate loss of “integrity” of       |
    |     the data.  Any vulnerability associated with a DoD Information     |
    |     system or system enclave, the exploitation of which, by a risk     |
    |     factor, will directly and immediately result in loss of            |
    |     Confidentiality, Availability or Integrity of the system           |
    |     associated data.                                                   |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV23682r1.__doc__.rstrip())
    print(response)


def SV6136r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6136                                              [HIGH] |
    |    Rule ID: SV-6136r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure data transmitted through a commercial     |
    |     or wireless network is protected using an appropriate form of      |
    |     cryptography.                                                      |
    |                                                                        |
    | Description:                                                           |
    |     Unencrypted sensitive application data could be intercepted in     |
    |     transit.                                                           |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6136r1.__doc__.rstrip())
    print(response)


def SV6134r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6134                                              [HIGH] |
    |    Rule ID: SV-6134r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure default passwords are changed.                 |
    |                                                                        |
    | Description:                                                           |
    |     Default passwords can easily be compromised by attackers           |
    |     allowing immediate access to the applications.                     |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6134r1.__doc__.rstrip())
    print(response)


def SV21830r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-19689                                           [MEDIUM] |
    |    Rule ID: SV-21830r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure web services are designed and             |
    |     implemented to recognize and react to the attack patterns          |
    |     associated with application-level DoS attacks.                     |
    |                                                                        |
    | Description:                                                           |
    |     Because of potential denial of service, web services should be     |
    |     designed to recognize potential attack patterns.                   |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV21830r1.__doc__.rstrip())
    print(response)


def SV17839r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16839                                           [MEDIUM] |
    |    Rule ID: SV-17839r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure protections against DoS attacks are            |
    |     implemented.                                                       |
    |                                                                        |
    | Description:                                                           |
    |     Known threats documented in the threat model should be             |
    |     mitigated, to prevent DoS type attacks.                            |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17839r1.__doc__.rstrip())
    print(response)


def SV17834r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16834                                           [MEDIUM] |
    |    Rule ID: SV-17834r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO shall ensure if a DoD STIG or NSA guide is not             |
    |     available, a third-party product will be configured by the         |
    |     following in descending order as available: 1) commercially        |
    |     accepted practices, (2) independent testing results, or (3)        |
    |     vendor literature.                                                 |
    |                                                                        |
    | Description:                                                           |
    |     Not all COTS products are covered by a STIG.  Those products       |
    |     not covered by a STIG, should be minimally configured to           |
    |     vendors recommendation guidelines.                                 |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17834r1.__doc__.rstrip())
    print(response)


def SV17835r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16835                                           [MEDIUM] |
    |    Rule ID: SV-17835r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure at least one application administrator has     |
    |     registered to receive update notifications, or security            |
    |     alerts, when automated alerts are available.                       |
    |                                                                        |
    | Description:                                                           |
    |     Administrators should register for updates to all COTS and         |
    |     custom developed software, so when security flaws are              |
    |     identified, they can be tracked for testing and updates of the     |
    |     application can be applied.                                        |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17835r1.__doc__.rstrip())
    print(response)


def SV17836r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16836                                           [MEDIUM] |
    |    Rule ID: SV-17836r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure the system and installed applications have     |
    |     current patches, security updates, and configuration settings.     |
    |                                                                        |
    | Description:                                                           |
    |     Due to viruses, worms, Trojans, and other malicious software,      |
    |     in addition to inevitable weaknesses in code, the necessity to     |
    |     patch critical vulnerabilities is paramount. As part of the        |
    |     general practice of performing application or system               |
    |     administration, it is imperative that security vulnerabilities     |
    |     from the vendor are monitored and patches are tested and           |
    |     applied.                                                           |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17836r1.__doc__.rstrip())
    print(response)


def SV17830r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16830                                           [MEDIUM] |
    |    Rule ID: SV-17830r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Test Manager will ensure flaws found during a code review      |
    |     are tracked in a defect tracking system.                           |
    |                                                                        |
    | Description:                                                           |
    |     If flaws are not tracked they may possibly be forgotten to be      |
    |     included in a release.  Tracking flaws in the configuration        |
    |     management repository will help identify code elements to be       |
    |     changed, as well as the requested change.                          |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17830r1.__doc__.rstrip())
    print(response)


def SV55789r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16831                                           [MEDIUM] |
    |    Rule ID: SV-55789r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure active vulnerability testing is performed.     |
    |                                                                        |
    | Description:                                                           |
    |     Use of automated scanning tools accompanied with manual            |
    |     testing/validation which confirms or expands on the automated      |
    |     test results is an accepted best practice when performing          |
    |     application security testing.  Automated scanning tools            |
    |     expedite and help to standardize security testing, they can        |
    |     incorporate known attack methods and procedures, test for          |
    |     libraries and other software modules known to be vulnerable to     |
    |     attack and utilize a test method known as "fuzz testing".          |
    |     Fuzz testing is a testing process where the application is         |
    |     provided invalid, unexpected, or random data. Poorly designed      |
    |     and coded applications will become unstable or crash. Properly     |
    |     designed and coded applications will reject improper and           |
    |     unexpected data input from application clients and remain          |
    |     stable.     Many vulnerability scanning tools provide              |
    |     automated fuzz testing capabilities for the testing of web         |
    |     applications.  All of these tools help to identify a wide          |
    |     range of application vulnerabilities including, but not            |
    |     limited to; buffer overflows, cross-site scripting flaws,          |
    |     denial of service format bugs and SQL injection, all of which      |
    |     can lead to a successful compromise of the system or result in     |
    |     a denial of service.    Due to changes in the production           |
    |     environment, it is a good practice to schedule periodic active     |
    |     testing of production web applications.  Ideally, this will        |
    |     occur prior to deployment and after updates or changes to the      |
    |     application production environment.   It is imperative that        |
    |     automated scanning tools are configured properly to ensure         |
    |     that all of the application components that can be tested are      |
    |     tested.  In the case of web applications, some of the              |
    |     application code base may be accessible on the web site and        |
    |     could potentially be corrected by a knowledgeable system           |
    |     administrator.  Active testing is different from code review       |
    |     testing in that active testing does not require access to the      |
    |     application source code base. A code review requires complete      |
    |     code base access and is normally performed by the development      |
    |     team.  If vulnerability testing is not conducted, there is the     |
    |     distinct potential that security vulnerabilities could be          |
    |     unknowingly introduced into the application environment.  The      |
    |     following website provides an overview of fuzz testing and         |
    |     examples:  http://www.owasp.org/index.php/Fuzzing  The             |
    |     following website provides information on web application          |
    |     vulnerability scanner tools.  Reference the “Related Links”        |
    |     section at the bottom of the page for a list of available          |
    |     commercial and open source tools.    http://samate.nist.gov/in     |
    |     dex.php/Web_Application_Vulnerability_Scanners.html Please         |
    |     note that reference to these tools does not imply that they        |
    |     have been tested and approved for use by DISA.                     |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV55789r1.__doc__.rstrip())
    print(response)


def SV17832r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16832                                           [MEDIUM] |
    |    Rule ID: SV-17832r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Test Manager will ensure security flaws are fixed or           |
    |     addressed in the project plan.                                     |
    |                                                                        |
    | Description:                                                           |
    |     If security flaws are not tracked, they may possibly be            |
    |     forgotten to be included in a release.  Tracking flaws in the      |
    |     project plan will help identify code elements to be changed as     |
    |     well as the requested change.                                      |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17832r1.__doc__.rstrip())
    print(response)


def SV17833r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16833                                           [MEDIUM] |
    |    Rule ID: SV-17833r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure if an application is designated critical,      |
    |     the application is not hosted on a general purpose machine.        |
    |                                                                        |
    | Description:                                                           |
    |     Critical applications should not be hosted on a multi-purpose      |
    |     server with other applications. Applications that share            |
    |     resources are susceptible to the other shared application          |
    |     security defects.  Even if the critical application is             |
    |     designed and deployed securely, an application that is not         |
    |     designed and deployed securely, can cause resource issues and      |
    |     possibly crash effecting the critical application.                 |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17833r1.__doc__.rstrip())
    print(response)


def SV23685r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-21500                                           [MEDIUM] |
    |    Rule ID: SV-23685r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not have CSRF        |
    |     vulnerabilities.                                                   |
    |                                                                        |
    | Description:                                                           |
    |     Cross Site Request Forgery (CSRF) is an attack where an end        |
    |     user is previously authenticated to a specific website and the     |
    |     user through social engineering (e.g., e-mail or chat)             |
    |     launches a hyperlink which executes unwanted actions on a          |
    |     website. A CSRF attack may execute any web site request on         |
    |     behalf of the user leading to compromise of the user’s data.       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV23685r1.__doc__.rstrip())
    print(response)


def SV6198r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6198                                            [MEDIUM] |
    |    Rule ID: SV-6198r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager and IAO will ensure development systems,       |
    |     build systems, test systems, and all components comply with        |
    |     all appropriate DoD STIGs, NSA guides, and all applicable DoD      |
    |     policies.  The Test Manager will ensure both client and server     |
    |     machines are STIG compliant.                                       |
    |                                                                        |
    | Description:                                                           |
    |     Applications developed on a non STIG compliant platform may        |
    |     not function when deployed to a STIG compliant platform, and       |
    |     therefore cause a potential denial of service to the users and     |
    |     the application, or require lessening security requirements on     |
    |     the client side of the application.                                |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6198r1.__doc__.rstrip())
    print(response)


def SV6197r2():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6197                                            [MEDIUM] |
    |    Rule ID: SV-6197r2_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager will ensure a System Security Plan (SSP)       |
    |     is established to describe the technical, administrative, and      |
    |     procedural IA program and policies governing the DoD               |
    |     information system, and identifying all IA personnel and           |
    |     specific IA requirements and objectives.                           |
    |                                                                        |
    | Description:                                                           |
    |     If the DAA, IAM, or IAO are not performing assigned functions      |
    |     in accordance with DoD requirements, it could impact the           |
    |     overall security of the facility, personnel, systems, and          |
    |     data, which could lead to degraded security. If the DAA and        |
    |     the IAM/IAO are not appointed in writing, there will be no way     |
    |     to ensure they understand the responsibilities of the position     |
    |     and the appointment criteria. The lack of a complete System        |
    |     Security Plan (SSP) could lead to ineffective secure               |
    |     operations and impede accreditation.  A System Identification      |
    |     Profile (SIP) and the DIACAP Implementation Plan (DIP) may be      |
    |     considered as sufficient proof of compliance as long as the        |
    |     documentation provides all of the information that is needed       |
    |     to meet the requirement.                                           |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6197r2.__doc__.rstrip())
    print(response)


def SV17801r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16801                                           [MEDIUM] |
    |    Rule ID: SV-17801r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure locked users’ accounts can only be        |
    |     unlocked by the application administrator.                         |
    |                                                                        |
    | Description:                                                           |
    |     User accounts should only be unlocked by the user contacting       |
    |     an administrator, and making a formal request to have the          |
    |     account reset.  Accounts that are automatically unlocked after     |
    |     a set time limit, allow potential attackers to retry possible      |
    |     user password combinations without knowledge of the user or        |
    |     the administrator.                                                 |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17801r1.__doc__.rstrip())
    print(response)


def SV17803r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16803                                           [MEDIUM] |
    |    Rule ID: SV-17803r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer and IAO will ensure application resources are         |
    |     protected with permission sets which allow only an application     |
    |     administrator to modify application resource configuration         |
    |     files.                                                             |
    |                                                                        |
    | Description:                                                           |
    |     If application resources are not protected with permission         |
    |     sets that allow only an application administrator to modify        |
    |     application resource configuration files, unauthorized users       |
    |     can modify configuration files allowing these users to capture     |
    |     data within the application, or turn off encryption, or change     |
    |     any configurable option in the application.                        |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17803r1.__doc__.rstrip())
    print(response)


def SV17802r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16802                                           [MEDIUM] |
    |    Rule ID: SV-17802r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application provides a capability     |
    |     to automatically terminate a session and log out after a           |
    |     system defined session idle time limit is exceeded.                |
    |                                                                        |
    | Description:                                                           |
    |     In the event a user does not log out of the application, the       |
    |     application should automatically terminate the session and log     |
    |     out; otherwise, subsequent users of a shared system could          |
    |     continue to use the previous user's session to the                 |
    |     application.                                                       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17802r1.__doc__.rstrip())
    print(response)


def SV17806r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16806                                           [MEDIUM] |
    |    Rule ID: SV-17806r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the web application assigns the           |
    |     character set on all web pages.                                    |
    |                                                                        |
    | Description:                                                           |
    |     For web applications, setting the character set on the web         |
    |     page reduces the possibility of receiving unexpected input         |
    |     that uses other character set encodings by the web                 |
    |     application.                                                       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17806r1.__doc__.rstrip())
    print(response)


def SV17816r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16816                                           [MEDIUM] |
    |    Rule ID: SV-17816r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application supports the creation     |
    |     of transaction logs for access and changes to the data.            |
    |                                                                        |
    | Description:                                                           |
    |     Without required logging and access control, security issues       |
    |     related to data changes will not be identified. This could         |
    |     lead to security compromises such as data misuse, unauthorized     |
    |     changes, or unauthorized access.                                   |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17816r1.__doc__.rstrip())
    print(response)


def SV17814r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16814                                           [MEDIUM] |
    |    Rule ID: SV-17814r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not disclose         |
    |     unnecessary information to users.                                  |
    |                                                                        |
    | Description:                                                           |
    |     Applications should not disclose information not required for      |
    |     the transaction.  (e.g., a web application should not divulge      |
    |     the fact there is a SQL server database and/or its version)        |
    |     This provides attackers additional information which they can      |
    |     use to find other attack avenues, or tailor specific attacks,      |
    |     on the application.                                                |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17814r1.__doc__.rstrip())
    print(response)


def SV17815r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16815                                           [MEDIUM] |
    |    Rule ID: SV-17815r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application is not vulnerable to      |
    |     race conditions.                                                   |
    |                                                                        |
    | Description:                                                           |
    |     A race condition occurs when an application receives two or        |
    |     more actions on the same resource in an unanticipated order        |
    |     which causes a conflict. Sometimes, the resource is locked by      |
    |     different users or functions within the application creating a     |
    |     deadlock situation.                                                |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17815r1.__doc__.rstrip())
    print(response)


def SV17812r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16812                                           [MEDIUM] |
    |    Rule ID: SV-17812r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application has no canonical          |
    |     representation vulnerabilities.                                    |
    |                                                                        |
    | Description:                                                           |
    |     Canonical representation issues arise when the name of a           |
    |     resource is used to control resource access.  There are            |
    |     multiple methods of representing resource names on a computer      |
    |     system.  An application relying solely on a resource name to       |
    |     control access may incorrectly make an access control decision     |
    |     if the name is specified in an unrecognized format.                |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17812r1.__doc__.rstrip())
    print(response)


def SV17818r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16818                                           [MEDIUM] |
    |    Rule ID: SV-17818r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application has a capability to       |
    |     display the user’s time and date of the last change in data        |
    |     content.                                                           |
    |                                                                        |
    | Description:                                                           |
    |     Without access control mechanisms in place, the data is not        |
    |     secure. The time and date display of data content change           |
    |     provides an indication that the data may have been accessed by     |
    |     unauthorized persons, and It may have been compromised,            |
    |     misused, or changed.                                               |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17818r1.__doc__.rstrip())
    print(response)


def SV17838r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16838                                              [LOW] |
    |    Rule ID: SV-17838r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     Procedures are not in place to notify users when an                |
    |     application is decommissioned.                                     |
    |                                                                        |
    | Description:                                                           |
    |     When maintenance no longer exists for an application, there        |
    |     are no individuals responsible for making security updates.        |
    |     The application should maintain procedures for                     |
    |     decommissioning.                                                   |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17838r1.__doc__.rstrip())
    print(response)


def SV17843r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16843                                              [LOW] |
    |    Rule ID: SV-17843r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure, for classified systems, application audit     |
    |     trails are continuously and automatically monitored, and           |
    |     alerts are provided immediately when unusual or inappropriate      |
    |     activity is detected.                                              |
    |                                                                        |
    | Description:                                                           |
    |     For critical and classified systems, an automated, continuous      |
    |     on-line monitoring and audit trail creation capability must be     |
    |     deployed with the capability to immediately alert personnel of     |
    |     any unusual or inappropriate activity with potential IA            |
    |     implications, and with a user configurable capability to           |
    |     automatically disable the system if serious IA violations are      |
    |     detected. This protects the system from serious data               |
    |     compromises.                                                       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17843r1.__doc__.rstrip())
    print(response)


def SV17817r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16817                                              [LOW] |
    |    Rule ID: SV-17817r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application has a capability to       |
    |     notify the user of important login information.                    |
    |                                                                        |
    | Description:                                                           |
    |     Attempted logons must be controlled to prevent password            |
    |     guessing exploits and unauthorized access attempts.                |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17817r1.__doc__.rstrip())
    print(response)


def SV17791r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16791                                              [LOW] |
    |    Rule ID: SV-17791r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure transaction based applications            |
    |     implement transaction rollback and transaction journaling.         |
    |                                                                        |
    | Description:                                                           |
    |     Transaction based systems must have transaction rollback and       |
    |     transaction journaling, or technical equivalents implemented       |
    |     to ensure the system can recover from an attack or faulty          |
    |     transaction data. Otherwise,  a denial of service condition        |
    |     could result.                                                      |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17791r1.__doc__.rstrip())
    print(response)


def SV6139r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6139                                               [LOW] |
    |    Rule ID: SV-6139r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application has a capability to       |
    |     notify an administrator when audit logs are nearing capacity       |
    |     as specified in the system documentation.                          |
    |                                                                        |
    | Description:                                                           |
    |     If an application audit log reaches capacity without warning,      |
    |     it will stop logging important system and security events.         |
    |     It could also open the system up for a type of denial of           |
    |     service attack, if an application halts with a full log.           |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6139r1.__doc__.rstrip())
    print(response)


def SV6132r2():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6132                                               [LOW] |
    |    Rule ID: SV-6132r2_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure all user accounts are disabled which are       |
    |     authorized to have access to the application but have not          |
    |     authenticated within the past 35 days.                             |
    |                                                                        |
    | Description:                                                           |
    |     Disabling inactive userids ensures access and privilege are        |
    |     available to only those who need it.                               |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6132r2.__doc__.rstrip())
    print(response)


def SV17841r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16841                                              [LOW] |
    |    Rule ID: SV-17841r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will review audit trails periodically based on system      |
    |     documentation recommendations or immediately upon system           |
    |     security events.                                                   |
    |                                                                        |
    | Description:                                                           |
    |     Without access control the data is not secure. It can be           |
    |     compromised, misused, or changed by unauthorized access at any     |
    |     time.                                                              |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17841r1.__doc__.rstrip())
    print(response)


def SV17840r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16840                                              [LOW] |
    |    Rule ID: SV-17840r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure the system alerts an administrator when        |
    |     low resource conditions are encountered.                           |
    |                                                                        |
    | Description:                                                           |
    |     In order to prevent DoS type attacks, applications should be       |
    |     monitored when resource conditions reach a predefined              |
    |     threshold indicating there may be attack occurring.                |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17840r1.__doc__.rstrip())
    print(response)


def SV17824r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16824                                              [LOW] |
    |    Rule ID: SV-17824r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Test Manager will ensure at least one tester is designated     |
    |     to test for security flaws in addition to functional testing.      |
    |                                                                        |
    | Description:                                                           |
    |     If there is no person designated to test for security flaws,       |
    |     vulnerabilities can potentially be missed during testing.          |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17824r1.__doc__.rstrip())
    print(response)


def SV17820r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16820                                              [LOW] |
    |    Rule ID: SV-17820r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Release Manager will ensure the access privileges to the       |
    |     configuration management (CM) repository are reviewed every 3      |
    |     months.                                                            |
    |                                                                        |
    | Description:                                                           |
    |     Incorrect access privileges to the CM repository can lead to       |
    |     malicious code or unintentional code being introduced into the     |
    |     application.                                                       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17820r1.__doc__.rstrip())
    print(response)


def SV6170r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6170                                               [LOW] |
    |    Rule ID: SV-6170r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager and designer will ensure any IA, or IA         |
    |     enabled, products used by the application are NIAP approved or     |
    |     in the NIAP approval process.                                      |
    |                                                                        |
    | Description:                                                           |
    |     IA or IA enabled products that have not been evaluated by NIAP     |
    |     may degrade the security posture of the enclave, if they do        |
    |     not operate as expected, be configured incorrectly, or have        |
    |     hidden security flaws.                                             |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6170r1.__doc__.rstrip())
    print(response)


def SV17828r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16828                                              [LOW] |
    |    Rule ID: SV-17828r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Test Manager will ensure code coverage statistics are          |
    |     maintained for each release of the application.                    |
    |                                                                        |
    | Description:                                                           |
    |     Code coverage statistics describes the how much of the source      |
    |     code has been executed based on the test procedures.               |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17828r1.__doc__.rstrip())
    print(response)


