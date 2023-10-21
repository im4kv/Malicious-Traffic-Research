import sys
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.python import log
import asn1tools
import binascii


log.startLogging(sys.stdout)
ldap_message = asn1tools.compile_files('ldap-v3.asn')

class MockCLDAP(DatagramProtocol):
    decoded_request = ''
    def datagramReceived(self, datagram, addr):
        log.msg(f"Recieved datagram from address: {addr} Raw Message (hex representation): " \
                f"{binascii.b2a_hex(datagram, b' ')}")
        try:
            self.decoded_request = ldap_message.decode('LDAPMessage',data=datagram)
        except Exception as err:
            self.decoded_request = str(err)
        log.msg(f"Decoded Request {addr}: {self.decoded_request}")


reactor.listenUDP(389, MockCLDAP())
reactor.run()
