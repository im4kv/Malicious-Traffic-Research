import sys
from twisted.internet import reactor, task
from twisted.internet.protocol import DatagramProtocol
from twisted.python import log
import binascii
import parse
import creator
from collections import defaultdict


APP_NAME = 'udp-slp'
RATE_LIMITING_THRESHOLD = 3

class MockSLP(DatagramProtocol):
    rate_limit_counter = defaultdict(int)
    def _service_request_response(self,datagram,addr):
        '''Handling function ID 1: Service Request (SrvRqst) and 9: Service Type Request (SrvTypeRqst)'''
        header, _ = parse.parse_header(datagram)
        response = creator.create_reply(
            xid=header['xid'],
            url_entries=self.url_entries
        )
        self.transport.write(response, addr)

    def _service_reg_response(self,datagram,addr):

        ''' Service Registration (SrvReg)
            We are not accepting any service registration requests, let's just create fake acknowledgement response
        '''
        try:
            header, url_entries, msg = parse.parse_registration(datagram)
            log.msg(f"app:{APP_NAME} source_ip:{addr[0]} source_port:{addr[1]} decoded_header:{header} url_entries:{url_entries}, msg:{msg}")
            response = creator.create_acknowledge(xid=header['xid'])
            self.transport.write(response, addr)
        except Exception as err:
            log.err(f"app:{APP_NAME} source_ip:{addr[0]} source_port:{addr[1]} payload_parse_error: {err}")
            return None
    def _default_request_hanlder(self,datagram,addr):
        ''' Unsupported function IDs will not be processed'''
        log.msg(f"app:{APP_NAME} source_ip:{addr[0]} source_port:{addr[1]} msg: Unsupported function ID")
        return None



    def __init__(self) -> None:
        super().__init__()
        self.url_entries = [dict(
                        url='service:VMwareInfrastructure://10.10.125.10:427/MyVMwareService',
                        lifetime=15
                        ),
                        dict(
                        url='service:api:https://10.10.125.11',
                        lifetime=15
                        ),
                        ]
        self.function_handlers = {
            1 : self._service_request_response,
            3: self._service_reg_response,
            9: self._service_request_response
        }

    def reset_rate_limit_counter():
        MockSLP.rate_limit_counter = defaultdict(int)

    def datagramReceived(self, datagram, addr):
        source_ip = addr[0]
        source_port =  addr[1]
        MockSLP.rate_limit_counter[source_ip] += 1
        log.msg(f"app:{APP_NAME} source_ip:{source_ip} source_port:{source_port} raw_message_hex:" + \
                f"{binascii.b2a_hex(datagram, b' ')}")
        try:
            header, _ = parse.parse_header(datagram)
            log.msg(f"app:{APP_NAME} source_ip:{addr[0]} source_port:{addr[1]} decoded_header:{header}")
        except Exception as err:
            log.err(f"app:{APP_NAME} source_ip:{addr[0]} source_port:{addr[1]} payload_parse_error: {err}")
            return None

        function_id_handler = self.function_handlers.get(header['function_id'], self._default_request_hanlder)
        if MockSLP.rate_limit_counter[source_ip] < RATE_LIMITING_THRESHOLD:
            function_id_handler(datagram,addr)
        else:
            log.msg(f"app:{APP_NAME} source_ip:{addr[0]} source_port:{addr[1]} msg:rate limit exceeded { self.rate_limit_counter[source_ip]} requests received")



def main():
    log.startLogging(sys.stdout)
    # Schedule reset_counter to be called every 24 hours
    rate_limit_reset_task = task.LoopingCall(MockSLP.reset_rate_limit_counter)
    rate_limit_reset_task.start(24 * 60 * 60)  # 24 hours in seconds

    reactor.listenUDP(427, MockSLP())
    reactor.run()

if __name__ == '__main__':
    main()

