require 'socket'

class PtpIpInitiator
 
  attr_reader :transaction_id

  def initialize addr='127.0.0.1', port=15740, guid='', name='', protocol_version=65536
    @addr = addr
    @port = port
    @guid = guid
    @name = name
    @protocol_version = protocol_version
    @transaction_id = 1
  end

  def wait_event
    recv_pkt  = read_packet @event_sock
    raise "Invalid Event Packet. Packet Type: 0x#{recv_pkt.type.to_s(16)}" unless recv_pkt.type == PTPIP_PT_EventPacket
    return recv_pkt
  end

  def data_operation(operation_code, parameters = [])
 
    transaction_id = @transaction_id
    @transaction_id += 1
 
    op_payload = PTPIP_payload_OPERATION_REQ_PKT.new()
    op_payload.data_phase_info = PTPIP_payload_OPERATION_REQ_PKT::NO_DATA_OR_DATA_IN_PHASE
    op_payload.operation_code = operation_code
    op_payload.transaction_id = transaction_id
    op_payload.parameters = parameters
    op_pkt = PTPIP_packet.create(op_payload)
    write_packet(@command_sock, op_pkt)
 
    data = recv_data(@command_sock, transaction_id)
    recv_pkt = read_packet(@command_sock)

    raise "Data Operation Failed. code: 0x#{operation_code.to_s(16)}, response_code: #{recv_pkt.payload.response_code}" if recv_pkt.payload.response_code != PTP_RC_OK

    return recv_pkt, data
  end
 
  def simple_operation(operation_code, parameters = [])
 
    transaction_id = @transaction_id
    @transaction_id += 1
 
    op_payload = PTPIP_payload_OPERATION_REQ_PKT.new()
    op_payload.data_phase_info = PTPIP_payload_OPERATION_REQ_PKT::NO_DATA_OR_DATA_IN_PHASE
    op_payload.operation_code = operation_code
    op_payload.transaction_id = transaction_id
    op_payload.parameters = parameters
    op_pkt = PTPIP_packet.create(op_payload)
    write_packet(@command_sock, op_pkt)
 
    recv_pkt = read_packet(@command_sock)

    raise "Simple Operation Failed. code: 0x#{operation_code.to_s(16)}, response_code: #{recv_pkt.payload.response_code}" if recv_pkt.payload.response_code != PTP_RC_OK

    return recv_pkt
  end
 
  def open(session_id = 1)
 
    TCPSocket.open(@addr, @port) do |s|
 
      @command_sock = s
 
      # Command Connection
      recv_pkt = init_command
      raise "Initialization Failed (Command) #{recv_pkt.payload.reason}" if recv_pkt.type == PTPIP_PT_InitFailPacket
      p @conn_number = recv_pkt.payload.conn_number
      p @guid = recv_pkt.payload.guid
      p @name = recv_pkt.payload.friendly_name
      p @protocol_version = recv_pkt.payload.protocol_version
   
      TCPSocket.open(@addr, @port) do |es|
 
        @event_sock = es
 
        # Event Connection
        recv_pkt = init_event
        raise "Initialization Failed (Event) #{recv_pkt.payload.reason}" if recv_pkt.type == PTPIP_PT_InitFailPacket
        print "Command/Event Connections are established.\n"
 
        # Open Session
        recv_pkt = simple_operation(PTP_OC_OpenSession, [session_id])
        raise "Open Session Failed #{recv_pkt.payload.response_code}" if recv_pkt.payload.response_code != PTP_RC_OK

        yield self
 
        # Close Session
        recv_pkt = simple_operation(PTP_OC_CloseSession)
        raise "Close Session Failed #{recv_pkt.payload.response_code}" if recv_pkt.payload.response_code != PTP_RC_OK

      end
 
    end

  end


  private

    def str2guid(str)
      hexes = str.scan /([a-fA-F0-9]{2})-*/
      hexes.flatten!
      raise "Invalid GUID" if hexes.length != 16
      hexes.map do |s|
        s.hex
      end
    end
   
    def write_packet(sock, pkt)
      sock.send(pkt.to_data.pack("C*"), 0)
    end
   
    def read_packet(sock)
      data = []
      data += sock.read(PTPIP_packet::MIN_PACKET_SIZE).unpack("C*")
      len = PTPIP_packet.parse_length(data)
      data += sock.read(len-PTPIP_packet::MIN_PACKET_SIZE).unpack("C*")
      PTPIP_packet.new(data)
    end
   
    def recv_data(sock, transaction_id)
      recv_pkt = read_packet(sock)
      raise "Invalid Packet : #{recv_pkt.to_s}" if recv_pkt.type != PTPIP_PT_StartDataPacket
      raise "Invalid Transaction ID" if recv_pkt.payload.transaction_id != transaction_id
      data_len = recv_pkt.payload.total_data_length_low
      data = []
      while recv_pkt.type != PTPIP_PT_EndDataPacket
          recv_pkt = read_packet(sock)
          raise "Invalid Packet : #{recv_pkt.to_s}" if recv_pkt.type != PTPIP_PT_DataPacket && recv_pkt.type != PTPIP_PT_EndDataPacket
          raise "Invalid Transaction ID" if recv_pkt.payload.transaction_id != transaction_id
          data += recv_pkt.payload.data_payload
      end
      raise "Invalid Data Size" unless data_len == data.length
      return data
    end
   
    def init_command
      init_command_payload = PTPIP_payload_INIT_CMD_PKT.new()
      init_command_payload.guid = str2guid(@guid)
      init_command_payload.friendly_name = @name
      init_command_payload.protocol_version = @protocol_version
      init_command = PTPIP_packet.create(init_command_payload)
   
      write_packet(@command_sock, init_command)
      read_packet(@command_sock)#ACK
    end
   
    def init_event
      init_event_payload = PTPIP_payload_INIT_EVENT_REQ_PKT.new()
      init_event_payload.conn_number = @conn_number
      init_event = PTPIP_packet.create(init_event_payload);
   
      write_packet(@event_sock, init_event)
      read_packet(@event_sock)
    end

end

