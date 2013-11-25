#!/opt/local/bin/ruby

require 'test/unit'
require '/Users/administrator/Programing/MTP/ptp_test/ptp_ip_packet.rb'


class PTP_IP_packet_test < Test::Unit::TestCase

    def setup
    end
    
    def teardown
    end
    
    def test_init_cmd_req_pkt_001
        data = [58,0,0,0,
                1,0,0,0,
                49,35,245,42,24,60,65,45,150,50,152,19,196,0,65,50,
                77,0,97,0,99,0,66,0,111,0,111,0,107,0,45,0,65,0,105,0,114,0,45,
                    0,105,0,55,0,0,0,
                0,0,1,0]
    
        packet = PTP_IP_packet.new(data)
        
        assert_equal(Fixnum, packet.length.class)
        assert_equal(58, packet.length)
        
        payload = packet.payload
        
        assert_equal(Fixnum, payload.type.class)
        assert_equal(1, payload.type)
            
        assert_equal(Array, payload.guid.class)
        assert_equal([49,35,245,42,24,60,65,45,
            150,50,152,19,196,0,65,50], payload.guid)
            
        assert_equal(String, payload.friendly_name.class)
        assert_equal("MacBook-Air-i7\000", payload.friendly_name)
            
        assert_equal(Fixnum, payload.protocol_version.class)
        assert_equal(65536, payload.protocol_version)
    end
    
    
    RESPONDER_GUID = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    RESPONDER_FRIENDLY_NAME = "Ruby-PTP-Responder"
    RESPONDER_PROTOCOL_VERSION = 65536

    def test_init_cmd_req_ack_001
    
        connection_number = 1
        
        payload = PTP_IP_payload_INIT_CMD_ACK.new()
        
        payload.conn_number = connection_number
        payload.guid = RESPONDER_GUID
        payload.friendly_name = RESPONDER_FRIENDLY_NAME
        payload.protocol_version = RESPONDER_PROTOCOL_VERSION
        
        payload_check_data = [1, 0, 0, 0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            82, 0, 117, 0, 98, 0, 121, 0, 45, 0, 80, 0, 84, 0, 80, 0, 45, 0,
                82, 0, 101, 0, 115, 0, 112, 0, 111, 0, 110, 0, 100, 0, 101, 0,
                114, 0, 0, 0,
            0, 0, 1, 0]
        
        assert_equal(payload_check_data, payload.to_data)
        
        packet = PTP_IP_packet.create(payload)
        
        packet_check_data = [70, 0, 0, 0,
            2, 0, 0, 0,
            1, 0, 0, 0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            82, 0, 117, 0, 98, 0, 121, 0, 45, 0, 80, 0, 84, 0, 80, 0, 45, 0, 
                82, 0, 101, 0, 115, 0, 112, 0, 111, 0, 110, 0, 100, 0, 101, 0,
                114, 0, 0, 0,
            0, 0, 1, 0]
            
        assert_equal(packet_check_data, packet.to_data)
        
    end

end