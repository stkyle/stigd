# -*- coding: utf-8 -*-
"""
Created on Sat Mar 28 10:36:28 2015
pip install pyopenssl ndg-httpsclient pyasn1
http://iase.disa.mil/stigs/Documents/U_Application_Security_and_Development_V3R10_STIG.zip

print_findings('HIGH')
print_findings('MEDIUM')
print_findings('LOW')
https://urllib3.readthedocs.org/en/latest/security.html
"""
PATH_TO_STIG_XML = './3R10/U_Application_Security_and_Development_V3R10_Manual-xccdf.xml'
PATH_TO_STIG_JSON = './stig.json'
import json
from textwrap import wrap
#import OpenSSL
#import ndg_httpsclient
#import pyasn1

IA_CODE = {}
IA_CODE['DCPA-1'] = 'Partitioning the Application'


stig = json.load(open(PATH_TO_STIG_JSON))['stig']['findings']
table_width = 74


def func_names(lvl='HIGH'):
    for s in stig:
        if stig[s]['severity'].upper() == lvl.upper():
            func_name = stig[s]['ruleID'].replace('-', '').replace('_rule', '')
            print('%s()' % func_name)

# func_names(lvl='HIGH')
# func_names(lvl='medium')
# func_names(lvl='low')


def print_line():
    print('+' + (table_width - 2) * '-' + '+')


def print_finding(finding_dict, header=True):

    h_fields = ('id', 'version', 'ruleID')
    severity = finding_dict['severity'].upper()
    finding_id, version, rule = map(finding_dict.get, h_fields)

    l1 = '+' + (table_width - 2) * '-' + '+'  # 79 character line break
    l2 = '| Finding ID: %s' % (finding_id)
    l2 = l2 + ((table_width - 2) - len(l2) - len(severity) - 2) * \
        ' ' + ('[%s] |' % severity)
    l3 = '|    Rule ID: %*s' % (8, rule)
    l3 = l3 + ' ' * ((table_width - 1) - len(l3)) + '|'
    l4 = '|%*s|\n| Description:%s' % ((table_width - 2),
                                      ' ',
                                      ' ' * (table_width - 15) + '|')
    l5 = '|     ' + \
        '\n|     '.join(wrap(finding_dict['description'].rstrip(), width=58))
    ll = l5.split('\n')
    l5_new = []
    for li in ll:
        cat_str = ((table_width - 2) - len(li)) * ' '
        l5_new += [li + cat_str]
    l5 = ' |\n'.join(l5_new) + ' |'
    lines = [l1, l2, l3, l4, l5]
    for l in lines:
        print l


def print_findings(lvl=None):
    if not lvl:
        for k, v in stig.iteritems():
            print_finding(v, header=False)
            print_line()
    else:
        for k, v in stig.iteritems():
            if v['severity'].upper() == lvl.upper():
                print_finding(v, header=False)
                print_line()


def generate_funcs(lvl=None, N=99):
    n = 0
    if not lvl:
        for k, v in stig.iteritems():
            write_skeleton_code(v)
            n += 1
    else:
        for k, v in stig.iteritems():
            if n > N:
                break
            if v['severity'].upper() == lvl.upper():
                write_skeleton_code(v)
                n += 1


def write_skeleton_code(finding_dict):
    h_fields = ('id', 'version', 'ruleID', 'title')
    severity = finding_dict['severity'].upper()
    finding_id, version, rule, title = map(finding_dict.get, h_fields)

    func_name = rule.replace('-', '').replace('_rule', '')
    print r'def %s():' % func_name
    print r'    """'

    # 79 character line break
    l1 = 4 * ' ' + '+' + (table_width - 2) * '-' + '+'
    l2 = 4 * ' ' + '| Finding ID: %s' % (finding_id)
    l2 = l2 + ((table_width - 2 + 4) - len(l2) - len(severity) - 2) * \
        ' ' + ('[%s] |' % severity)
    l3 = '|    Rule ID: %*s' % (8, rule)
    l3 = 4 * ' ' + l3 + ' ' * ((table_width - 1) - len(l3)) + '|'

    lt3_1 = 4 * ' ' + \
        '|%*s|\n    | Title:%s' % ((table_width - 2), ' ', ' ' * (table_width - 9) + '|')
    lt3_2 = 4 * ' ' + '|     ' + \
        '\n    |     '.join(wrap(title.rstrip(), width=62))

    lt3_3 = []
    for entry in lt3_2.split('\n'):
        entry = entry + (3 + table_width - len(entry)) * ' ' + '|'
        lt3_3 += [entry]
    lt3_2 = '\n'.join(lt3_3)
    l4 = 4 * ' ' + \
        '|%*s|\n    | Description:%s' % ((table_width - 2), ' ', ' ' * (table_width - 15) + '|')
    l5 = 4 * ' ' + '|     ' + \
        '\n    |     '.join(wrap(finding_dict['description'].rstrip(), width=62))
    ll = l5.split('\n')
    l5_new = []
    for li in ll:
        cat_str = ((table_width - 2 + 4) - len(li)) * ' '
        l5_new += [li + cat_str]
    l5 = ' |\n'.join(l5_new) + ' |'
    lines = [l1, l2, l3, lt3_1, lt3_2, l4, l5]
    for l in lines:
        print l
    print l1
    print r'    """'
    print u'    response = \'\''
    print r'    print(%s.__doc__.rstrip())' % func_name
    print r'    print(response)'
    print '\n'


def audit():
    SV21828r1()
    SV21829r1()
    SV17837r1()
    SV17809r1()
    SV17808r1()
    SV17800r1()
    SV17804r1()
    SV17807r1()
    SV17813r1()
    SV17810r1()
    SV17811r1()
    SV17787r1()
    SV6129r1()
    SV21844r1()
    SV21843r1()
    SV17795r1()
    SV17797r1()
    SV17796r1()
    SV23682r1()
    SV6136r1()
    SV6134r1()
    SV6141r1()
    SV6146r1()
    SV25354r1()
    SV25355r1()
    SV17848r1()
    SV6153r1()
    SV6156r1()
    SV17785r1()
    SV6164r1()
    SV6165r1()
    SV21836r1()
    SV23731r1()


#print_findings('HIGH')
#generate_funcs('HIGH', 20)


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
    response = ''
    print(SV21828r1.__doc__.rstrip())
    print(response)


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


def SV6141r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6141                                              [HIGH] |
    |    Rule ID: SV-6141r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure access control mechanisms exist to        |
    |     ensure data is accessed and changed only by authorized             |
    |     personnel.                                                         |
    |                                                                        |
    | Description:                                                           |
    |     If access control mechanisms are not in place, anonymous users     |
    |     could potentially make unauthorized read and modification          |
    |     requests to the application data which is an immediate loss of     |
    |     the integrity of the data.  Any vulnerability associated with      |
    |     a DoD Information system or system enclave, the exploitation       |
    |     of which, by a risk factor, will directly and immediately          |
    |     result in loss of Confidentiality, Availability or Integrity       |
    |     of the system associated data.                                     |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6141r1.__doc__.rstrip())
    print(response)


def SV6146r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6146                                              [HIGH] |
    |    Rule ID: SV-6146r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application has the capability to     |
    |     mark sensitive/classified output when required.                    |
    |                                                                        |
    | Description:                                                           |
    |     Failure to properly mark output could result in a disclosure       |
    |     of sensitive or classified data which is an immediate loss in      |
    |     confidentiality.  Any vulnerability associated with a DoD          |
    |     Information system or system enclave, the exploitation of          |
    |     which, by a risk factor, will directly and immediately result      |
    |     in loss of Confidentiality, Availability or Integrity of the       |
    |     system associated data.                                            |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6146r1.__doc__.rstrip())
    print(response)


def SV25354r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-22028                                             [HIGH] |
    |    Rule ID: SV-25354r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer shall use the NotOnOrAfter property when using        |
    |     the <SubjectConfirmation> element in a SAML assertion.             |
    |                                                                        |
    | Description:                                                           |
    |     When a SAML assertion is used with a <SubjectConfirmation>         |
    |     element, a begin and end time for the <SubjectConfirmation>        |
    |     should be set to prevent reuse of the message at a later time.     |
    |     Not setting a specific time period for the                         |
    |     <SubjectConfirmation>, may grant immediate access to an            |
    |     attacker and results in an immediate loss of confidentiality.      |
    |     Any vulnerability associated with a DoD Information system or      |
    |     system enclave, the exploitation of which, by a risk factor,       |
    |     will directly and immediately result in loss of                    |
    |     Confidentiality, Availability or Integrity of the system           |
    |     associated data.                                                   |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV25354r1.__doc__.rstrip())
    print(response)


def SV25355r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-22029                                             [HIGH] |
    |    Rule ID: SV-25355r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer shall use both the <NotBefore> and <NotOnOrAfter>     |
    |     elements or <OneTimeUse> element when using the <Conditions>       |
    |     element in a SAML assertion.                                       |
    |                                                                        |
    | Description:                                                           |
    |     When a SAML assertion is used with a <Conditions> element, a       |
    |     begin and end time for the <Conditions> element should be set      |
    |     to prevent reuse of the message at a later time. Not setting a     |
    |     specific time period for the <Conditions> element, the             |
    |     possibility exists of granting immediate access or elevated        |
    |     privileges to an attacker which result in an immediate loss of     |
    |     confidentiality.  Any vulnerability associated with a DoD          |
    |     Information system or system enclave, the exploitation of          |
    |     which, by a risk factor, will directly and immediately result      |
    |     in loss of Confidentiality, Availability or Integrity of the       |
    |     system associated data.                                            |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV25355r1.__doc__.rstrip())
    print(response)


def SV17848r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16848                                             [HIGH] |
    |    Rule ID: SV-17848r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure passwords generated for users are not          |
    |     predictable and comply with the organization's password            |
    |     policy.                                                            |
    |                                                                        |
    | Description:                                                           |
    |     Predictable passwords may allow an attacker to gain immediate      |
    |     access to new user accounts which would result in a loss of        |
    |     integrity.  Any vulnerability associated with a DoD                |
    |     Information system or system enclave, the exploitation of          |
    |     which, by a risk factor, will directly and immediately result      |
    |     in loss of Confidentiality, Availability or Integrity of the       |
    |     system associated data.                                            |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17848r1.__doc__.rstrip())
    print(response)


def SV6153r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6153                                              [HIGH] |
    |    Rule ID: SV-6153r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application removes                   |
    |     authentication credentials on client computers after a session     |
    |     terminates.                                                        |
    |                                                                        |
    | Description:                                                           |
    |     Leaving authentication credentials stored at the client level      |
    |     allows potential access to session information that can be         |
    |     used by subsequent users of a shared workstation and could         |
    |     also be exported and used on other workstation providing           |
    |     immediate unauthorized access to the application.                  |
    +------------------------------------------------------------------------+
    """
    response = 'N/A'
    print(SV6153r1.__doc__.rstrip())
    print(response)


def SV6156r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6156                                              [HIGH] |
    |    Rule ID: SV-6156r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not contain          |
    |     embedded authentication data.                                      |
    |                                                                        |
    | Description:                                                           |
    |     Authentication data stored in code could potentially be read       |
    |     and used by anonymous users to gain access to a backend            |
    |     database or application server. This could lead to immediate       |
    |     access to a backend server.                                        |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV6156r1.__doc__.rstrip())
    print(response)


def SV17785r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16785                                             [HIGH] |
    |    Rule ID: SV-17785r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application supports detection        |
    |     and/or prevention of communication session hijacking.              |
    |                                                                        |
    | Description:                                                           |
    |     Session tokens can be compromised by various methods. Using        |
    |     predictable session tokens can allow an attacker to hijack a       |
    |     session in progress. Session sniffing can be used to capture a     |
    |     valid session token or session id, and the attacker uses this      |
    |     session information to gain immediate unauthorized access to       |
    |     the server which is a loss of confidentially and potentially a     |
    |     loss of integrity. Also, the Man-in-the-Middle (MITM) attack       |
    |     can be accomplished over an TLS connection with a session in       |
    |     progress.  Any vulnerability associated with a DoD Information     |
    |     system or system enclave, the exploitation of which, by a risk     |
    |     factor, will directly and immediately result in loss of            |
    |     Confidentiality, Availability or Integrity of the system           |
    |     associated data.                                                   |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV17785r1.__doc__.rstrip())
    print(response)


def SV6164r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6164                                              [HIGH] |
    |    Rule ID: SV-6164r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application validates all input.      |
    |                                                                        |
    | Description:                                                           |
    |     Absence of input validation opens an application to improper       |
    |     manipulation of data. The lack of input validation can lead        |
    |     immediate access of application, denial of service, and            |
    |     corruption of data.                                                |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV6164r1.__doc__.rstrip())
    print(response)


def SV6165r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6165                                              [HIGH] |
    |    Rule ID: SV-6165r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application does not have buffer      |
    |     overflows, use functions known to be vulnerable to buffer          |
    |     overflows, and does not use signed values for memory               |
    |     allocation where permitted by the programming language.            |
    |                                                                        |
    | Description:                                                           |
    |     Buffer overflow attacks occur when improperly validated input      |
    |     is passed to an application overwriting of memory. Usually,        |
    |     buffer overflow errors stop execution of the application           |
    |     causing a minimum of denial of service and possibly a system       |
    |     call to a command shell giving the attacker access to the          |
    |     underlying operating system.                                       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6165r1.__doc__.rstrip())
    print(response)


def SV21836r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-19695                                             [HIGH] |
    |    Rule ID: SV-21836r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure web services provide a mechanism for      |
    |     detecting resubmitted SOAP messages.                               |
    |                                                                        |
    | Description:                                                           |
    |     SOAP messages should be designed so duplicate messages are         |
    |     detected.  Replay attacks may lead to a loss of                    |
    |     confidentiality and potentially a loss of availability  Any        |
    |     vulnerability associated with a DoD Information system or          |
    |     system enclave, the exploitation of which, by a risk factor,       |
    |     will directly and immediately result in loss of                    |
    |     Confidentiality, Availability or Integrity of the system           |
    |     associated data.                                                   |
    +------------------------------------------------------------------------+
    """
    response = 'N/A'
    print(SV21836r1.__doc__.rstrip())
    print(response)


def SV23731r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-21519                                             [HIGH] |
    |    Rule ID: SV-23731r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager will ensure all products are supported by      |
    |     the vendor or the development team.                                |
    |                                                                        |
    | Description:                                                           |
    |     Unsupported software products should not be used because of        |
    |     the unknown potential vulnerabilities.  Any vulnerability          |
    |     associated with a DoD Information system or system enclave,        |
    |     the exploitation of which, by a risk factor, will directly and     |
    |     immediately result in loss of Confidentiality, Availability or     |
    |     Integrity of the system associated data.   Unsupported             |
    |     software where there is no documented acceptance of DAA risk.      |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV23731r1.__doc__.rstrip())
    print(response)

# Cat I: High
# SV21828r1()
# SV21829r1()
# SV17837r1()
# SV17809r1()
# SV17808r1()
# SV17800r1()
# SV17804r1()
# SV17807r1()
# SV17813r1()
# SV17810r1()
# SV17811r1()
# SV17787r1()
# SV6129r1()
# SV21844r1()
# SV21843r1()
# SV17795r1()
# SV17797r1()
# SV17796r1()
# SV23682r1()
# SV6136r1()
# SV6134r1()
# SV6141r1()
# SV6146r1()
# SV25354r1()
# SV25355r1()
# SV17848r1()
# SV6153r1()
# SV6156r1()
# SV17785r1()
# SV6164r1()
# SV6165r1()
# SV21836r1()
# SV23731r1()


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


def SV17783r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16783                                           [MEDIUM] |
    |    Rule ID: SV-17783r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager will ensure procedures are implemented to      |
    |     assure physical handling and storage of information is in          |
    |     accordance with the data’s sensitivity.                            |
    |                                                                        |
    | Description:                                                           |
    |     Failure to have proper workplace security procedures can lead      |
    |     to the loss or compromise of classified or sensitive               |
    |     information.                                                       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17783r1.__doc__.rstrip())
    print(response)


def SV17780r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16780                                           [MEDIUM] |
    |    Rule ID: SV-17780r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager will ensure all levels of program              |
    |     management, designers, developers, and testers receive the         |
    |     appropriate security training pertaining to their job              |
    |     function.                                                          |
    |                                                                        |
    | Description:                                                           |
    |     Well trained IT personnel are the first line of defense            |
    |     against attacks or disruptions to the information system. Lack     |
    |     of sufficient training can lead to security oversights             |
    |     thereby, leading to compromise or failure to take necessary        |
    |     actions to prevent disruptions to operations.                      |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17780r1.__doc__.rstrip())
    print(response)


def SV21831r2():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-19690                                           [MEDIUM] |
    |    Rule ID: SV-21831r2_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the web service design includes           |
    |     redundancy of critical functions.                                  |
    |                                                                        |
    | Description:                                                           |
    |     Because of potential denial of service, web services should be     |
    |     designed to be redundant.                                          |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV21831r2.__doc__.rstrip())
    print(response)


def SV17825r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16825                                           [MEDIUM] |
    |    Rule ID: SV-17825r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Test Manager will ensure the changes to the application        |
    |     are assessed for IA and accreditation impact prior to              |
    |     implementation.                                                    |
    |                                                                        |
    | Description:                                                           |
    |     IA assessment of proposed changes is necessary to ensure           |
    |     security integrity is maintained within the application.           |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17825r1.__doc__.rstrip())
    print(response)


def SV17788r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16788                                           [MEDIUM] |
    |    Rule ID: SV-17788r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application uses encryption to        |
    |     implement key exchange and authenticate endpoints prior to         |
    |     establishing a communication channel for key exchange.             |
    |                                                                        |
    | Description:                                                           |
    |     If the application does not use encryption and authenticate        |
    |     endpoints prior to establishing a communication channel and        |
    |     prior to transmitting encryption keys, these keys may be           |
    |     intercepted, and could be used to decrypt the traffic of the       |
    |     current session, leading to potential loss or compromise of        |
    |     DoD data.                                                          |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV17788r1.__doc__.rstrip())
    print(response)


def SV17789r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16789                                           [MEDIUM] |
    |    Rule ID: SV-17789r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure private keys are accessible only to       |
    |     administrative users.                                              |
    |                                                                        |
    | Description:                                                           |
    |     If private keys are accessible to non-administrative users,        |
    |     these users could potentially read and use the private keys to     |
    |     unencrypt stored or transmitted sensitive data used by the         |
    |     application.                                                       |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17789r1.__doc__.rstrip())
    print(response)


def SV17777r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16777                                           [MEDIUM] |
    |    Rule ID: SV-17777r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager will ensure COTS IA and IA enabled             |
    |     products, comply with NIAP/NSA endorsed  protection profiles.      |
    |                                                                        |
    | Description:                                                           |
    |     The security posture of the enclave could be compromised if        |
    |     applications are not at the approved NIAP/NSA protection           |
    |     profile.  GOTS, or COTS IA and IA enabled IT products, must be     |
    |     in compliance with NIAP/NSA protection profiles in order to        |
    |     protect classified information when the information transits       |
    |     networks which are at a lower classification level than the        |
    |     information being transported.                                     |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17777r1.__doc__.rstrip())
    print(response)


def SV17823r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16823                                           [MEDIUM] |
    |    Rule ID: SV-17823r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Release Manager will establish a Configuration Control         |
    |     Board (CCB), that meets at least every release cycle, for          |
    |     managing the CM process.                                           |
    |                                                                        |
    | Description:                                                           |
    |     Software Configuration Management (SCM) is very important in       |
    |     tracking code releases, baselines, and managing access to the      |
    |     configuration management repository. The SCM plan identifies       |
    |     what should be under configuration management control. Without     |
    |     an SCM plan code, and a CCB, releases can be tracked and           |
    |     vulnerabilities can be inserted intentionally or                   |
    |     unintentionally into the code base of the application.             |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17823r1.__doc__.rstrip())
    print(response)


def SV21835r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-19694                                           [MEDIUM] |
    |    Rule ID: SV-21835r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure an XML firewall is deployed to protect web     |
    |     services.                                                          |
    |                                                                        |
    | Description:                                                           |
    |     Web Services are vulnerable to many types of attacks.  XML         |
    |     based firewalls can be used to prevent common attacks.             |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV21835r1.__doc__.rstrip())
    print(response)


def SV6166r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6166                                            [MEDIUM] |
    |    Rule ID: SV-6166r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure the application is not subject to         |
    |     error handling vulnerabilities.                                    |
    |                                                                        |
    | Description:                                                           |
    |     Unhandled exceptions leaves users with no means to properly        |
    |     respond to errors.  Mishandled exceptions can transmit             |
    |     information that can be used in future security breaches.          |
    |     Properly handled errors allow applications to follow security      |
    |     procedures and guidelines in an informed manner.  If too much      |
    |     information is revealed in the error message, it can be used       |
    |     as the basis for an attack.                                        |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6166r1.__doc__.rstrip())
    print(response)


def SV6167r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6167                                            [MEDIUM] |
    |    Rule ID: SV-6167r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure application initialization, shutdown,     |
    |     and aborts are designed to keep the application in a secure        |
    |     state.                                                             |
    |                                                                        |
    | Description:                                                           |
    |     An application could be compromised, providing an attack           |
    |     vector into the enclave if application initialization,             |
    |     shutdown, and aborts are not designed to keep the application      |
    |     in a secure state.   If an application fails without closing       |
    |     or shutting down processes or open sessions; authentication        |
    |     and validation mechanisms are in doubt.   Responsible              |
    |     application development practices must be applied to ensure        |
    |     the failed application is handled gracefully to prevent            |
    |     creation of security risks.                                        |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6167r1.__doc__.rstrip())
    print(response)


def SV6160r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6160                                            [MEDIUM] |
    |    Rule ID: SV-6160r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure unsigned Category 2 mobile code           |
    |     executing in a constrained environment has no access to local      |
    |     system and network resources.                                      |
    |                                                                        |
    | Description:                                                           |
    |     Mobile code cannot conform to traditional installation and         |
    |     configuration safeguards, therefore, the use of local              |
    |     operating system resources and spawning of network connections     |
    |     introduce harmful and uncertain effects.                           |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6160r1.__doc__.rstrip())
    print(response)


def SV6161r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6161                                            [MEDIUM] |
    |    Rule ID: SV-6161r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure signed Category 1A and Category 2         |
    |     mobile code signature is validated before executing.               |
    |                                                                        |
    | Description:                                                           |
    |     Untrusted mobile code may contain malware or malicious code        |
    |     and digital signatures provide a source of the content which       |
    |     is crucial to authentication and trust of the data.                |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6161r1.__doc__.rstrip())
    print(response)


def SV6162r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6162                                            [MEDIUM] |
    |    Rule ID: SV-6162r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure uncategorized or emerging mobile code     |
    |     is not used in applications.                                       |
    |                                                                        |
    | Description:                                                           |
    |     Mobile code does not require any traditional software              |
    |     acceptance testing or security validation.  Mobile code needs      |
    |     to follow sound policy to maintain a reasonable level of           |
    |     trust.  Mobile code that does not fall into existing policy        |
    |     cannot be trusted.                                                 |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6162r1.__doc__.rstrip())
    print(response)


def SV6163r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6163                                            [MEDIUM] |
    |    Rule ID: SV-6163r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The Designer will ensure the application removes temporary         |
    |     storage of files and cookies when the application is               |
    |     terminated.                                                        |
    |                                                                        |
    | Description:                                                           |
    |     If the application does not remove temporary data (e.g.,           |
    |     authentication data, temporary files containing sensitive          |
    |     data, etc.) this temporary data could be used to re-               |
    |     authenticate the user or allow unauthorized access to              |
    |     sensitive data.                                                    |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV6163r1.__doc__.rstrip())
    print(response)


def SV17850r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16850                                           [MEDIUM] |
    |    Rule ID: SV-17850r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure connections between the DoD enclave and        |
    |     the Internet or other public or commercial wide area networks      |
    |     require a DMZ.                                                     |
    |                                                                        |
    | Description:                                                           |
    |     In order to protect DoD data and systems, all remote access to     |
    |     DoD information systems must be mediated through a managed         |
    |     access control point, such as a remote access server in a DMZ.     |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV17850r1.__doc__.rstrip())
    print(response)


def SV6168r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6168                                            [MEDIUM] |
    |    Rule ID: SV-6168r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The designer will ensure applications requiring server             |
    |     authentication are PK-enabled.                                     |
    |                                                                        |
    | Description:                                                           |
    |     Applications not using PKI are at risk of containing many          |
    |     password vulnerabilities. PKI is the preferred method of           |
    |     authentication.                                                    |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV6168r1.__doc__.rstrip())
    print(response)


def SV6169r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6169                                            [MEDIUM] |
    |    Rule ID: SV-6169r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager and designer will ensure the application       |
    |     design complies with the DoD Ports and Protocols guidance.         |
    |                                                                        |
    | Description:                                                           |
    |     Failure to comply with DoD Ports, Protocols, and Services          |
    |     (PPS) Vulnerability Analysis and associated PPS mitigations        |
    |     may result in compromise of enclave boundary protections           |
    |     and/or functionality of the application.                           |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6169r1.__doc__.rstrip())
    print(response)


def SV17776r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-16776                                           [MEDIUM] |
    |    Rule ID: SV-17776r1_rule                                            |
    |                                                                        |
    | Title:                                                                 |
    |     The Program Manager will ensure the development team follows a     |
    |     set of coding standards.                                           |
    |                                                                        |
    | Description:                                                           |
    |     Implementing coding standards provides many benefits to the        |
    |     development process.  These benefits include readability,          |
    |     consistency, and ease of integration.    Code conforming to a      |
    |     standard format is easier to read, especially if someone other     |
    |     than the original developer is examining the code.  In             |
    |     addition, formatted code can be debugged and corrected faster      |
    |     than unformatted code.  Introducing coding standards can help      |
    |     increase the consistency, reliability, and security of the         |
    |     application by ensuring common programming structures and          |
    |     tasks are handled by similar methods, as well as, reducing the     |
    |     occurrence of common logic errors.  Coding standards also          |
    |     allow developers to quickly adapt to code which has been           |
    |     developed by various members of a development team.  Coding        |
    |     standards are useful in the code review process as well as in      |
    |     situations where a team member leaves and duties must then be      |
    |     assigned to another team member.  Coding standards often cover     |
    |     the use of white space characters, variable naming                 |
    |     conventions, function naming conventions, and comment styles.      |
    +------------------------------------------------------------------------+
    """
    response = 'APPLICABLE'
    print(SV17776r1.__doc__.rstrip())
    print(response)


def SV6173r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6173                                            [MEDIUM] |
    | Rule ID:    SV-6173r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure application audit trails are retained for      |
    |     at least 1 year for applications without SAMI data, and 5          |
    |     years for applications including SAMI data.                        |
    |                                                                        |
    | Description:                                                           |
    |     Log files are a requirement to trace intruder activity or to       |
    |     audit user activity.                                               |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6173r1.__doc__.rstrip())
    print(response)


def SV6172r1():
    """
    +------------------------------------------------------------------------+
    | Finding ID: V-6172                                            [MEDIUM] |
    |    Rule ID: SV-6172r1_rule                                             |
    |                                                                        |
    | Title:                                                                 |
    |     The IAO will ensure data backup is performed at required           |
    |     intervals in accordance with DoD policy.                           |
    |                                                                        |
    | Description:                                                           |
    |     Without proper backups, the application is not protected from      |
    |     the loss of data or the operating environment in the event of      |
    |     hardware or software failure.                                      |
    +------------------------------------------------------------------------+
    """
    response = ''
    print(SV6172r1.__doc__.rstrip())
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


#SV21830r1()
#SV17839r1()
#SV17834r1()
#SV17835r1()
#SV17836r1()
#SV17783r1()
#SV17780r1()
#SV21831r2()
#SV17825r1()
#SV17788r1()
#SV17789r1()
#SV17777r1()
#SV17823r1()
#SV21835r1()
#SV6166r1()
#SV6167r1()
#SV6160r1()
#SV6161r1()
#SV6162r1()
#SV6163r1()
#SV17850r1()
#SV6168r1()
#SV6169r1()
#SV17776r1()
#SV6173r1()
#SV6172r1()
