require 'socket'
require_relative 'ptp.rb'
require_relative 'ptp_code.rb'
require_relative 'ptp_ip.rb'

class PtpIpInitiator
 
  include PtpCode

  attr_reader :current_transaction_id, :response_data, :response_packet

  def initialize addr='127.0.0.1', port=15740, guid='', name='', protocol_version=65536
    @addr, @port, @guid, @name, @protocol_version, @transaction_id = addr, port, guid, name, protocol_version, 1
  end

  def next_transaction_id
    @transaction_id
  end

  # You can set Event Code Name like this, 'ObjectAdded' or :ObjectAdded or 0x4002
  def wait_event expected_code_name = nil
    recv_pkt  = read_packet @event_sock
    raise "Invalid Event Packet. Packet Type: 0x#{recv_pkt.type.to_s(16)}" unless recv_pkt.type == PTPIP_PT_EventPacket
    expected_code = event_code expected_code_name if expected_code_name
    payload = recv_pkt.payload
    raise "Unexpected Event Code. Event Code: (Expect) #{expected_code.to_s}[0x#{expected_code.to_s(16)}], (Received) 0x#{payload.event_code.to_s(16)}" if !expected_code_name.nil? and expected_code.to_i != payload.event_code.to_i
    response = {
      event_code: payload.event_code,
      parameters: payload.parameters,
      transaction_id: payload.transaction_id
    }
    return response
  end

  # You can set Operation Code Name like this, 'GetDeviceInfo' or :GetDeviceInfo or 0x1001
  def operation(operation_code_name, parameters = [])

    oc = operation_code operation_code_name
    operation_impl oc, parameters
 
    recv_pkt = read_packet @command_sock
    if recv_pkt.type == PTPIP_PT_StartDataPacket
      @response_data = recv_data @command_sock, @current_transaction_id, recv_pkt
      @response_packet = read_packet @command_sock
    else
      @response_data = nil
      @response_packet = recv_pkt
    end

    payload = @response_packet.payload
    raise "Operation Failed. code: #{operation_code_name.to_s}[0x#{operation_code.to_s(16)}], response_code: #{payload.response_code}" if payload.response_code != PTP_RC_OK
    response = {
      code: payload.response_code,
      parameters: payload.parameters,
      transaction_id: payload.transaction_id
    }
    response[:data] = @response_data if @response_data
    return response

  end
 
  def open(session_id = 1)
 
    @session_id = session_id

    puts "Theta Session Open. session_id: #{session_id.to_s}, addr: #{@addr.to_s}, port: #{@port.to_s}"

    if block_given?
      TCPSocket.open(@addr, @port) do |s|
        @command_sock = s
        initialize_command_connection
        TCPSocket.open(@addr, @port) do |es|
          @event_sock = es
          initialize_event_connection
          open_session
          yield self
          close_session
        end
      end
    else
      @command_sock = TCPSocket.open(@addr, @port)
      initialize_command_connection
      @event_sock = TCPSocket.open(@addr, @port)
      initialize_event_connection
      open_session
      return self
    end

  end

  def close
    close_session
    @event_sock.close
    @command_sock.close
  end

  private

    def initialize_command_connection
      puts "Initialization Start (Command Connection)"
      recv_pkt = init_command
      raise "Initialization Failed (Command Connection) #{recv_pkt.payload.reason}" if recv_pkt.type == PTPIP_PT_InitFailPacket
      @conn_number = recv_pkt.payload.conn_number
      @guid = recv_pkt.payload.guid
      @name = recv_pkt.payload.friendly_name
      @protocol_version = recv_pkt.payload.protocol_version
      puts "Initialize Success (Command Connection)\n  Response: #{recv_pkt.payload.to_hash.inspect}"
    end

    def initialize_event_connection
      puts "Initialize Start (Event Connection)"
      recv_pkt = init_event
      raise "Initialization Failed (Event) #{recv_pkt.payload.reason}" if recv_pkt.type == PTPIP_PT_InitFailPacket
      puts "Initialization Success (Event Connection)"
    end

    def open_session
      puts "Operation (OpenSession)"
      response = operation(:OpenSession, [@session_id])
      raise "Open Session Failed #{response[:code]}" if response[:code] != PTP_RC_OK
      puts "Operation Success (OpenSession)"
    end

    def close_session
      puts "Operation (CloseSession)"
      response = operation(:CloseSession)
      raise "Close Session Failed #{response[:code]}" if response[:code] != PTP_RC_OK
      puts "Operation Success (CloseSession)"
    end

    def operation_impl operation_code, parameters = []
      transaction_id = @current_transaction_id = @transaction_id
      @transaction_id += 1

      op_payload = PTPIP_payload_OPERATION_REQ_PKT.new()
      op_payload.data_phase_info = PTPIP_payload_OPERATION_REQ_PKT::NO_DATA_OR_DATA_IN_PHASE
      op_payload.operation_code = operation_code
      op_payload.transaction_id = transaction_id
      op_payload.parameters = parameters
      op_pkt = PTPIP_packet.create(op_payload)
      write_packet(@command_sock, op_pkt)
    end

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
   
    def recv_data(sock, transaction_id, start_data_packet)
      raise "Invalid Packet : #{recv_pkt.to_s}" if start_data_packet.type != PTPIP_PT_StartDataPacket
      raise "Invalid Transaction ID" if start_data_packet.payload.transaction_id != transaction_id
      data_len = start_data_packet.payload.total_data_length_low
      data = []
      recv_pkt = start_data_packet
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

