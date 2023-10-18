# cLDAP (Connectionless Lightweight Directory Access Protocol) UDP 389

---



### protocol flaw


Lightweight Directory Access Protocol (LDAP) is defined in RFC2251 ([LDAPv3](https://tools.ietf.org/html/rfc2251)) and it uses TCP as it's transmission mechanism. Connection-less Lightweight Directory Access Protocol [CLDAP RFC1798](https://datatracker.ietf.org/doc/html/rfc1798) was published in 1995 as a Proposed Standard.  The protocol uses UDP Port 389 and was targeted at applications which require lookup of small amounts of information held in the directory.The protocol avoids the overhead of establishing (and closing) a connection and the session bind and unbind operations needed in connection-oriented directory access protocols.


However [RFC3352](https://datatracker.ietf.org/doc/html/rfc3352) made the previous RFC1798 Obsolete and moved it into Historic status and explained that this protocol is not widely used because of limited functionality (read-only, anonymous only), Insufficient security capabilities (no integrity protection, no confidentiality protection), etc.


There are three operations provided in cLDAP: `searchRequest`, `searchResponse` (contains searchResEntry and searchResDone), and `abandonRequest`. The client uses UDP Protocol to send the request (searchRequest), it doesn't require authentication as it is not supported in the protocol. Since in the response of the client searchRequest, the server will return two response messages (searchResEntry and searchResDone) and responses of an LDAP directory search usually contain larger messages than the query itself, this flaw is then exploited for reflection amplification DDoS attacks (amplification factor 0f 50-70x).

LDAP is a binary protocol, which helps make it compact and efficient to parse. The particular binary encoding that it uses is based on ASN.1 [Abstract Syntax Notation One](https://en.wikipedia.org/wiki/ASN.1), which is a framework for representing structured data. ASN.1 is actually a family of encodings that each have their own pros and cons for different situations. For example, you might use the Packed Encoding Rules (PER) if you want to make sure that the encoded representation is as small as possible, or you might use the Octet Encoding Rules (OER) if you favor encode/decode performance over size. LDAP uses the Basic Encoding Rules (BER), which finds a good middle ground between the two.

### payload Info

As mentioned in the protocol section, cLDAP uses [ASN.1](https://datatracker.ietf.org/doc/html/rfc1798#section-4) to structure it's messages. to be able to successfully identify a cLDAP message we should have access to the Schema of LDAP messages so we can identify fields and map the encoded data to them. [Here](docker/ldap-v3.asn) is an ASN.1 Schema that we can use to decoded our messages.

Here is an example of Binary cLDAP request used to to check vulnerable servers: <pre> "\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00</pre>

to successfully decode this we can either use online ASN.1 decoders available or use Python [asn1tools](https://pypi.org/project/asn1tools/) package.

With the LDAP ASN.1 Schema if we decode the binary payload it will be look like this:
<pre>
{'messageID': 1, 'protocolOp': ('searchRequest', {'baseObject': b'', 'scope': 'baseObject', 'derefAliases': 'neverDerefAliases', 'sizeLimit': 0, 'timeLimit': 0, 'typesOnly': False, 'filter': ('present', b'objectclass'), 'attributes': []})}
</pre>
Since it is decoded, it is clear that is just a search request for all objects in the directory of LDAP (baseObject is empty string which means the search starts from the root of the directory). this is actually the cause of amplification in DDoS attacks in the protocol. In other words, the returned result are usually much larger than the query itself.

An example of cLDAP packets captured from a DDoS attack is available [here](amp.cldap.pcap).


### Example response

<pre>
0\84\00\00\0b\0e\02\01\07d\84\00\00\0b\05\04\000\84\00\00\n\fd0\84\00\00\00&\04\0bcurrentTime1\84\00\00\00\13\04\1120190922100706.0Z0\84\00\00\00R\04\11subschemaSubentry1\84\00\00\009\047CN=Aggregate,CN=Schema,CN=Configuration,DC=Mogambo,DC=D0\84\00\00\00\82\04\rdsServiceName1\84\00\00\00m\04kCN=NTDS Settings,CN=RC81230,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=Mogambo,DC=D0\84\00\00\00\bb\04\0enamingContexts1\84\00\00\00\a5\04\0fDC=Mogambo,DC=D\04 CN=Configuration,DC=Mogambo,DC=D\04*CN=Schema,CN=Configuration,DC=Mogambo,DC=D\04!DC=DomainDnsZones,DC=Mogambo,DC=D\04!DC=ForestDnsZones,DC=Mogambo,DC=D0\84\00\00\00-\04\14defaultNamingContext1\84\00\00\00\11\04\0fDC=Mogambo,DC=D0\84\00\00\00G\04\13schemaNamingContext1\84\00\00\00,\04*CN=Schema,CN=Configuration,DC=Mogambo,DC=D0\84\00\00\00D\04\1aconfigurationNamingContext1\84\00\00\00"\04 CN=Configuration,DC=Mogambo,DC=D0\84\00\00\000\04\17rootDomainNamingContext1\84\00\00\00\11\04\0fDC=Mogambo,DC=D0\84\00\00\03\a9\04\10supportedControl1\84\00\00\03\91\04\161.2.840.113556.1.4.319\04\161.2.840.113556.1.4.801\04\161.2.840.113556.1.4.473\04\161.2.840.113556.1.4.528\04\161.2.840.113556.1.4.417\04\161.2.840.113556.1.4.619\04\161.2.840.113556.1.4.841\04\161.2.840.113556.1.4.529\04\161.2.840.113556.1.4.805\04\161.2.840.113556.1.4.521\04\161.2.840.113556.1.4.970\04\171.2.840.113556.1.4.1338\04\161.2.840.113556.1.4.474\04\171.2.840.113556.1.4.1339\04\171.2.840.113556.1.4.1340\04\171.2.840.113556.1.4.1413\04\172.16.840.1.113730.3.4.9\04\182.16.840.1.113730.3.4.10\04\171.2.840.113556.1.4.1504\04\171.2.840.113556.1.4.1852\04\161.2.840.113556.1.4.802\04\171.2.840.113556.1.4.1907\04\171.2.840.113556.1.4.1948\04\171.2.840.113556.1.4.1974\04\171.2.840.113556.1.4.1341\04\171.2.840.113556.1.4.2026\04\171.2.840.113556.1.4.2064\04\171.2.840.113556.1.4.2065\04\171.2.840.113556.1.4.2066\04\171.2.840.113556.1.4.2090\04\171.2.840.113556.1.4.2205\04\171.2.840.113556.1.4.2204\04\171.2.840.113556.1.4.2206\04\171.2.840.113556.1.4.2211\04\171.2.840.113556.1.4.2239\04\171.2.840.113556.1.4.2255\04\171.2.840.113556.1.4.22560\84\00\00\00"\04\14supportedLDAPVersion1\84\00\00\00\06\04\013\04\0120\84\00\00\01\86\04\15supportedLDAPPolicies1\84\00\00\01i\04\0eMaxPoolThreads\04\19MaxPercentDirSyncRequests\04\0fMaxDatagramRecv\04\10MaxReceiveBuffer\04\0fInitRecvTimeout\04\0eMaxConnections\04\0fMaxConnIdleTime\04\0bMaxPageSize\04\16MaxBatchReturnMessages\04\10MaxQueryDuration\04\10MaxTempTableSize\04\10MaxResultSetSize\04\rMinResultSets\04\14MaxResultSetsPerConn\04\16MaxNotificationPerConn\04\0bMaxValRange\04\15MaxValRangeTransitive\04\11ThreadMemoryLimit\04\18SystemMemoryLimitPercent0\84\00\00\00%\04\13highestCommittedUSN1\84\00\00\00\n\04\08224379550\84\00\00\00I\04\17supportedSASLMechanisms1\84\00\00\00*\04\06GSSAPI\04\nGSS-SPNEGO\04\08EXTERNAL\04\nDIGEST-MD50\84\00\00\00&\04\0bdnsHostName1\84\00\00\00\13\04\11rc81230.Mogambo.D0\84\00\00\005\04\0fldapServiceName1\84\00\00\00\1e\04\1cMogambo.D:rc81230$@MOGAMBO.D0\84\00\00\00n\04\nserverName1\84\00\00\00\\\04ZCN=RC81230,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=Mogambo,DC=D0\84\00\00\00\b2\04\15supportedCapabilities1\84\00\00\00\95\04\161.2.840.113556.1.4.800\04\171.2.840.113556.1.4.1670\04\171.2.840.113556.1.4.1791\04\171.2.840.113556.1.4.1935\04\171.2.840.113556.1.4.2080\04\171.2.840.113556.1.4.22370\84\00\00\00\1c\04\0eisSynchronized1\84\00\00\00\06\04\04TRUE0\84\00\00\00"\04\14isGlobalCatalogReady1\84\00\00\00\06\04\04TRUE0\84\00\00\00\1e\04\13domainFunctionality1\84\00\00\00\03\04\0160\84\00\00\00\1e\04\13forestFunctionality1\84\00\00\00\03\04\0160\84\00\00\00(\04\1ddomainControllerFunctionality1\84\00\00\00\03\04\0160\84\00\00\00\10\02\01\07e\84\00\00\00\07\n\01\00\04\00\04\00</pre>


#### References
1) L.F. Haaijer, DDoS Packet Capture Collection, (2022). Available from https://github.com/StopDDoS/packet-captures
2) Involved in the 2.3Tbps attack on AWS infrastructure in February 2020. <https://aws-shield-tlr.s3.amazonaws.com/2020-Q1_AWS_Shield_TLR.pdf>.
3) https://www.exploit-db.com/exploits/40703
4) https://www.trendmicro.com/en_vn/research/19/l/ddos-attacks-and-iot-exploits-new-activity-from-momentum-botnet.html

