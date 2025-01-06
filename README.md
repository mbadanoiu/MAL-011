# MAL-011: Log4J Misconfiguration Allows Malicious JavaScript in Red Hat AMQ

The Log4J component of the Redhat A-MQ application is misconfigured to allow the execution of arbitrary “Script” attributes in the Log4J config. If an attacker finds a way to modify the Log4J config used by A-MQ (e.g. via “setConfigText”), the insertion of malicious JavaScript scripts that will result in Remote Code Execution (RCE).

**Note:** For exploiting Red Hat AMQ versions > 7.10.2 and < 7.12 refer to [CVE-2023-50780: Dangerous MBeans Accessible via Jolokia API in Apache ActiveMQ Artemis](https://github.com/mbadanoiu/CVE-2023-50780).

### Vendor Disclosure:

Vendor did not care ¯\\\_(ツ)\_/¯.

### Requirements:

This vulnerability requires:
<br/>
- Valid credentials for user with "admin" role (if authentication is required)

**Note:** If the server is set with "--allow-anonymous", then any non-null user-password combination can be used to authenticate.

### Proof Of Concept:

More details and the exploitation process can be found in this [PDF](https://github.com/mbadanoiu/MAL-011/blob/main/Redhat%20A-MQ%20-%20MAL-011.pdf).

### Additional Resources:

[Code for exploiting Log4J over Jolokia (a.k.a log4jolokia)](https://github.com/mbadanoiu/log4jolokia)

[CVE-2023-50780: Dangerous MBeans Accessible via Jolokia API in Apache ActiveMQ Artemis](https://github.com/mbadanoiu/CVE-2023-50780)

