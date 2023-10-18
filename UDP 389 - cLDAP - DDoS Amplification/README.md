# cLDAP (Connectionless Lightweight Directory Access Protocol) UDP 389

---



### protocol flaw


Lightweight Directory Access Protocol (LDAP) is defined in RFC2251 ([LDAPv3](https://tools.ietf.org/html/rfc2251)) and it uses TCP as its transmission mechanism. Connection-less Lightweight Directory Access Protocol [CLDAP RFC1798](https://datatracker.ietf.org/doc/html/rfc1798) was published in 1995 as a Proposed Standard.  The protocol uses UDP Port 389 and was targeted at applications which require the lookup of small amounts of information held in the directory.The protocol avoids the overhead of establishing (and closing) a connection and the session bind and unbind operations needed in connection-oriented directory access protocols.


However [RFC3352](https://datatracker.ietf.org/doc/html/rfc3352) made the previous RFC1798 Obsolete and moved it into Historic status and explained that this protocol is not widely used because of limited functionality (read-only, anonymous only), Insufficient security capabilities (no integrity protection, no confidentiality protection), etc.


There are three operations provided in cLDAP: `searchRequest`, `searchResponse` (contains searchResEntry and searchResDone), and `abandonRequest`. The client uses UDP Protocol to send the request (searchRequest), it doesn't require authentication as it is not supported in the protocol. Since in the response of the client searchRequest, the server will return two response messages (searchResEntry and searchResDone) and responses of an LDAP directory search usually contain larger messages than the query itself, this flaw is then exploited for reflection amplification DDoS attacks (amplification factor 0f 50-70x).

LDAP is a binary protocol, which helps make it compact and efficient to parse. The particular binary encoding that it uses is based on ASN.1 [Abstract Syntax Notation One](https://en.wikipedia.org/wiki/ASN.1), which is a framework for representing structured data. ASN.1 is actually a family of encodings that each have their own pros and cons for different situations. For example, you might use the Packed Encoding Rules (PER) if you want to make sure that the encoded representation is as small as possible, or you might use the Octet Encoding Rules (OER) if you favour encode/decode performance over size. LDAP uses the Basic Encoding Rules (BER), which finds a good middle ground between the two.

### payload Info

As mentioned in the protocol section, cLDAP uses [ASN.1](https://datatracker.ietf.org/doc/html/rfc1798#section-4) to structure its messages. to be able to successfully identify a cLDAP message we should have access to the Schema of LDAP messages so we can identify fields and map the encoded data to them. [Here](docker/ldap-v3.asn) is an ASN.1 Schema that we can use to decode our messages.

Here is an example of a binary cLDAP request used to to check vulnerable servers: <pre> "\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00</pre>

to successfully decode this, we can use online ASN.1 decoders available or Python [asn1tools](https://pypi.org/project/asn1tools/) package.
With the LDAP ASN.1 Schema if we decode the binary payload it will look like this:
<pre>
{'messageID': 1, 'protocolOp': ('searchRequest', {'baseObject': b'', 'scope': 'baseObject', 'derefAliases': 'neverDerefAliases', 'sizeLimit': 0, 'timeLimit': 0, 'typesOnly': False, 'filter': ('present', b'objectclass'), 'attributes': []})}
</pre>
Since it is decoded, it is clear that is just a search request for all objects in the directory of LDAP (baseObject is an empty string which means the search starts from the root of the directory). this is actually the cause of amplification in DDoS attacks in the protocol. In other words, the returned result is usually much larger than the query itself.

An example of cLDAP packets captured from a DDoS attack is available [here](amp.cldap.pcap). we can we how large the responses are.




#### References
1) L.F. Haaijer, DDoS Packet Capture Collection, (2022). Available from https://github.com/StopDDoS/packet-captures
2) Involved in the 2.3Tbps attack on AWS infrastructure in February 2020. <https://aws-shield-tlr.s3.amazonaws.com/2020-Q1_AWS_Shield_TLR.pdf>.
3) https://www.exploit-db.com/exploits/40703
4) https://www.trendmicro.com/en_vn/research/19/l/ddos-attacks-and-iot-exploits-new-activity-from-momentum-botnet.html

