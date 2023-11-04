# SLP (Service Location Protocol) UDP 427

### protocol flaw

The Service Location Protocol ([SLP](https://en.wikipedia.org/wiki/Service_Location_Protocol)) [RFC 2165](https://www.rfc-editor.org/rfc/rfc2165.html) is a legacy "service discovery" protocol that dates back to 1997 and was meant to be used on local networks for automated service discovery and dynamic configuration between applications. The SLP daemon on a system will maintain a directory of available services such as printers, file servers, and other network resources. It will listen to requests on UDP port 427.
SLP is a relatively obsolete protocol and has mostly been supplanted by more modern alternatives like UPnP, mDNS/Zeroconf, and WS-Discovery. Nevertheless, many commercial products still offer support for SLP. Since SLP has no method for authentication, it should never be exposed to the public Internet.

It should be mentioned that the SLP protocols uses both UDP and TCP for the transmission of data (most packets are transmitted using UDP, but TCP can also be used for the transmission of longer packets). Researchers have discovered that the UDP version of this protocol has an amplification factor of up to 2,200x.

As specified in the protocol [RFC](https://www.rfc-editor.org/rfc/rfc2165.html#page-56) it has three main components:

#### User-Agents (UA) - Clients:
- Description: User-Agents are the clients or end-user applications that utilize SLP to discover and access services available on the network.
- Functionality: UAs send service requests to the network in order to find specific services, such as printers, file servers, or other resources.
- Example: A web browser acting as a User-Agent can use SLP to locate available web servers on the network.

#### Service Agents (SA) - Register/DeRegister Services:
- Description: Service Agents are responsible for registering services on the network and informing the Directory Agents of their availability.
- Functionality: SAs announce their services to the network so that User-Agents can locate them when needed. They also handle the process of unregistering services when they become unavailable.
- Example: A printer with an SLP-enabled component can register itself on the network, allowing User-Agents to discover and print documents.

#### Directory Agents (DA) - Advertise Services:
- Description: Directory Agents maintain a directory of available services within a network domain.
- Functionality: DAs collect and store service advertisements from Service Agents. They respond to service requests from User-Agents by providing information about available services.
- Example: A Directory Agent can maintain a list of all the printers, file servers, and other services available in a local network and respond to User-Agent queries with this information.

Malicious actors may craft User-Agent requests with victim's IP address that trigger excessive responses from Directory Agents. This amplifies the traffic directed at the victim, making the attack more potent.


The protocol has two main versions.The original version of SLP (Version 1), defined in [RFC 2165](https://www.rfc-editor.org/rfc/rfc2165.html). It was published in June 1997. SLPv2 is an enhanced and more widely adopted version of the protocol. It addressed some of the limitations of SLPv1 and introduced additional features. SLPv2 is defined in [RFC 2608](https://www.ietf.org/rfc/rfc2608.txt) (published in June 1999) and later updated by [RFC 3111](https://datatracker.ietf.org/doc/html/rfc3111) for IPv6 (published in May 2001).

SLPv2 is the version most commonly used in practice due to its improved capabilities and broader support in networking environments


### payload Info

SLP defines its own custom message format with specific fields, as outlined in the SLP RFC documents (such as page 17 of [RFC 2608](https://www.ietf.org/rfc/rfc2608.txt) for SLPv2).

Here are general structure of the SLP requests:
<pre>

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |  Function-ID  |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Length, contd.|O|F|R|       reserved          |Next Ext Offset|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Extension Offset, contd.|              XID              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Language Tag Length      |         Language Tag          \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Version (1 byte): Indicates the version of the SLP protocol being used. For SLPv2, this field will have a value of 2.
Function ID (1 byte): Specifies the function or operation of the request (e.g., Service Request, Attribute Request, Service Type Request, etc.).
Reserved (2 bytes): These bytes are reserved for future use and are typically set to 0x0000 (zero).
Length (2 bytes): Specifies the total length of the request message, including the header.
Language Code (2 bytes): Indicates the natural language in which the request is made.
Stateless Boot Timestamp (4 bytes): Used in stateless mode to aid in the synchronization of time between the client and responder.
XID (4 bytes): Transaction Identifier. A unique value assigned to each request-response pair to match them up.
Encoding (1 byte): Specifies the encoding of the message (e.g., UTF-8).
Scope List (variable length): A list of scopes that restrict the search space for service responses. Each scope is represented as a length byte followed by the scope string.
Predicate (variable length): Specifies the search criteria for the request. This can include service type, attributes, and other filters.
Authentication Blocks (variable length): Contains authentication information if security is enabled.
SLP SPI List (variable length): List of Service Provider Interfaces (SPIs) that can process the request.
</pre>

Here is an example of a binary SLP request used to to check vulnerable servers: <pre>\x02\t\x00\x00\x1d\x00\x00\x00\x00\x00s_\x00\x02en\x00\x00\xff\xff\x00\x07default</pre>

To successfully decode this, we can use custom parsers to decode the binary protocol based on the specification available in the SLP RFCs:
<pre>
{'version': 2, 'function_id': 9, 'length': 29, 'xid': 29535, 'language_tag_length': 2, 'language_tag': 'en'}
</pre>
The decoded payload shows it is a SLP version two packet which contains a `Service Type Request (SrvTypeRqst)` as the `function_id` field. the `xid` contain the transaction ID which will be the same for the response of this request. `Service Type Request (SrvTypeRqst)` allows a User-Agent (Could be Malicious Actor) to discover all types of service on a network. This is useful for general purpose service browsers. as a note `function_id` of 1 for `Service Request (SrvRqst)` will only be used to get specific services that matches the type specified in the request, hence it covers smaller scope of services and usually it has smaller responses.

for testing purposes, we can send the payload to a SLP server and check the size of the response via wireshark or tcpdump:
<pre>echo "\x02\t\x00\x00\x1d\x00\x00\x00\x00\x00s_\x00\x02en\x00\x00\xff\xff\x00\x07default" | nc -4u -w1 SERVER-ADDRESS-HERE 427</pre>







#### References
1) CVE-2023-29552 Service Location Protocol-Denial of Service Amplification Attack:
    - https://curesec.com/blog/article/CVE-2023-29552-Service-Location-Protocol-Denial-of-Service-Amplification-Attack-212.html
    - https://www.bitsight.com/blog/new-high-severity-vulnerability-cve-2023-29552-discovered-service-location-protocol-slp

