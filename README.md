# **tlsscan**

## Passive SSL/TLS HTTPS server analyzer. 

tlsscan is a framework which provide basic analysis of a server SSL/TLS implementation, thus including a final report with suggestions and conclusions. The aim is to point out server failures and/or server important flaws concerning SSL/TLS parameters and server HTTPS configuration.

tlsscan is built upon [Scapy-SSL/TLS](https://github.com/tintinweb/scapy-ssl_tls) which is <cite>an offensive stack for SSLv2, SSLv3 (TLS), TLS, DTLS </cite> and is using Python 2.7.

### **Features**
 * Server supported protocol
 * SSL2, SSL3, TLS1.0, TLS1.1, TLS1.2
 * Certificate (and chain) analysis
 * Certificate CRL/OCSP manual validation, **soon**
 * TLS compression support
 * TLS secure renegotiation support
 * Server cipher suite accepted and ordered by server preference
 * OCSP stapling support
 * Incorrect Server Name Indication
 * TLS Heartbeat extension and Heartbleed vulnerability
 * TLS session ticket support
 * POODLE attack vulnerability
 * BEAST attack vulnerability
 * RC4 cipher support
 * EXPORT cipher support
 * Using TOR network for scanning anonymously
 * Write report to file
 * Save full packet capture of the test to .pcap file
 * Timing scan available
 * HTTP Strict Transport Security status


### **Installation**
**pip - download latest release from the python package index**

Use pip2 for python2 packages.
```bash
$ pip2 install -r requirements.txt
```

**TOR Network**

If you decide di route traffic through TOR infrastructure the script will use a local TOR SOCKS5 proxy set on 127.0.0.0 on port 9050.

If you don't have, you need to install tor on your own. I will add later, if necessary, support for using external-managed TOR SOCKS5 proxy.

### **Example**
```
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
|                                             |
|   ############  ###         #############   |
|   ############  ###         #############   | Scan a website and analyze 
|       ###       ###         ###             | HTTPS configurations and 
|       ###       ###         #############   | certificates.
|       ###       ###         #############   |
|       ###       ###                   ###   |
|       ###       ###                   ###   | Find misconfigurations
|       ###       ##########  #############   | which could lead to 
|       ###       ##########  #############   | potential attacks.
|                                             |
| and SSL for HTTPS  Passive Security Scanner |
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


TARGET: www.example.com resolved to 95.345.123.123:443
Date of the test: 2017-11-10 12:23:53.151923



Starting SSL/TLS test on www.example.com --> 95.345.123.123:443
TYPE SCAN:  FULLSCAN


scanning for supported protocol...                      done. in --- 0.2211 seconds ---
loading certificate chain...                            done. in --- 0.0078 seconds ---
scanning for compression support...                     done. in --- 0.0253 seconds ---
scanning for secure renegotiation extension..           done. in --- 0.1173 seconds ---
ordering cipher suites based on server preference...    done. in --- 1.8655 seconds ---
checking ocsp response..                                done. in --- 0.0883 seconds ---
checking bad sni response...                            done. in --- 0.0977 seconds ---
checking TLS heartbeat extension...                     done. in --- 0.0971 seconds ---
checking TLS heartbleed...                              done. in --- 1.0229 seconds ---
checking TLS session ticket support..                   done. in --- 0.0999 seconds ---
looking for HSTS header...                              done. in --- 0.2277 seconds ---

 ---------- SCAN FINISHED ----------


###########  PRINTING RESULTS  ###########

[*]INFO:  TLSRecord version: TLS_1_0 Handshake version: TLS_1_2 supported
[*]INFO:  TLSRecord version: TLS_1_0 Handshake version: TLS_1_1 supported
[*]INFO:  TLSRecord version: TLS_1_0 Handshake version: TLS_1_0 not supported
[*]INFO:  TLSRecord version: TLS_1_0 Handshake version: SSL_3_0 not supported
[*]INFO:  TLSRecord version: TLS_1_0 Handshake version: SSL_2_0 not supported

Total number of certificates received:  2

################# CERTIFICATE INFORMATION for www.example.com #################

Signature Algorithm:    sha256_rsa
[*]Is certificate EXPIRED?  NO, valid until 2018-01-10 13:16:20
[*]Hostname match CN or SUBJECT_ALTERNATIVE_NAME? YES
(Requested)  www.example.com  (Certificate) www.example.com
[*]Hostname matches with alternative name:  www.example.com
[*]Is a CA certificate? NO
[*]Is a self-signed certificate?  NO

################# CERTIFICATE INFORMATION for Let's Encrypt Authority X3 #################

Signature Algorithm:    sha256_rsa
[*]Is certificate EXPIRED?  NO, valid until 2021-03-17 16:40:46
(Requested)  www.example.com  (Certificate) Let's Encrypt Authority X3
[*]Is a CA certificate? YES
[*]Is a self-signed certificate?  NO

################# PROTOCOLS SUPPORTED #################

SUPPORTED PROTOCOLS FOR HANDSHAKE:  TLS_1_2 TLS_1_1 

################## CIPHER SUITES #################


Accepted cipher-suites ( 20 / 333 ) Ordered by server preference.

TLS_1_1 supports 6 cipher suites.

Protocol: TLS_1_1 -> ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014) supported. FS
Protocol: TLS_1_1 -> RSA_WITH_AES_256_CBC_SHA (0x35) supported. non FS
Protocol: TLS_1_1 -> RSA_WITH_CAMELLIA_256_CBC_SHA (0x84) supported. non FS
Protocol: TLS_1_1 -> ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013) supported. FS
Protocol: TLS_1_1 -> RSA_WITH_AES_128_CBC_SHA (0x2f) supported. non FS
Protocol: TLS_1_1 -> RSA_WITH_CAMELLIA_128_CBC_SHA (0x41) supported. non FS
[*]ALERT:  SHA could be upgraded to SHA-2 (even though used in case does not pose a real threat) 

TLS_1_2 supports 14 cipher suites.

Protocol: TLS_1_2 -> ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030) supported. FS
Protocol: TLS_1_2 -> ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028) supported. FS
Protocol: TLS_1_2 -> ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014) supported. FS
Protocol: TLS_1_2 -> RSA_WITH_AES_256_GCM_SHA384 (0x9d) supported. non FS
Protocol: TLS_1_2 -> RSA_WITH_AES_256_CBC_SHA256 (0x3d) supported. non FS
Protocol: TLS_1_2 -> RSA_WITH_AES_256_CBC_SHA (0x35) supported. non FS
Protocol: TLS_1_2 -> RSA_WITH_CAMELLIA_256_CBC_SHA (0x84) supported. non FS
Protocol: TLS_1_2 -> ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f) supported. FS
Protocol: TLS_1_2 -> ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027) supported. FS
Protocol: TLS_1_2 -> ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013) supported. FS
Protocol: TLS_1_2 -> RSA_WITH_AES_128_GCM_SHA256 (0x9c) supported. non FS
Protocol: TLS_1_2 -> RSA_WITH_AES_128_CBC_SHA256 (0x3c) supported. non FS
Protocol: TLS_1_2 -> RSA_WITH_AES_128_CBC_SHA (0x2f) supported. non FS
Protocol: TLS_1_2 -> RSA_WITH_CAMELLIA_128_CBC_SHA (0x41) supported. non FS
[*]ALERT:  SHA could be upgraded to SHA-2 (even though used in case does not pose a real threat) 

        FS = Forward Secrecy (should use only cipher suite with it)


################## SECURITY OPTIONS #################

[*]TLS_FALLBACK_SCSV supported?  True

[*]TLS COMPRESSION enabled?  False

[*]SECURE RENEGOTIATION supported? True

[*]TLS Heartbeat extension supported? Yes

[*]OCSP stapling supported? No

[*]HTTP Strict Transport Security enabled on https://www.example.com ?  YES
        Header:  max-age=31536000; includeSubdomains; preload
        Include subdomains?  YES
        Preloaded?  YES

[*]Incorrect Server Name Indication alert?  NO

[*]TLS session tickets resumption?  YES


################## ATTACKS #################

[*]POODLE attack (SSLv3):  not vulnerable, SSLv3 disabled and/or TLS downgrade protection supported.

[*]BEAST attack?  NO

[*]EXPORT ciphers enabled?  NO

[*]Heartbleed vulnerable? NO

[*]RC4 supported?  NO




Finished in --- 4.15645909309 seconds ---
```

### Other modules used to make this:

 * [requests](https://pypi.python.org/pypi/requests) for HTTP/HTTPS simplified requests
 * [futures](https://pythonhosted.org/futures/) for asynchronous and parallel computation
 * [asn1crypto](https://pypi.python.org/pypi/asn1crypto/0.22.0) ASN.1 parser
 * [pysocks](https://pypi.python.org/pypi/PySocks) for SOCKS proxy functionality
