require_relative 'ptp.rb'

def create_ptp_code_hash prefix_regex
  Object.constants.inject(Hash.new) do |hash, c|
    hash[Object.const_get(c)] = c.to_s.gsub(prefix_regex,'') if c.to_s =~ prefix_regex
    hash
  end
end

# Translate from code_name into code(ptp code constants in ptp.rb).
#   ex. event_code(:ObjectAdded) => EventCode: PTP_EC_ObjectAdded(0x4002)
module PtpCode

  EVENTS = create_ptp_code_hash /^PTP_EC_/
  def event_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_EC_#{name.to_s}"
  end
  def event_name code
    EVENTS[code]
  end

  OPERATIONS = create_ptp_code_hash /^PTP_OC_/
  def operation_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_OC_#{name.to_s}"
  end
  def operation_name code
    OPERATIONS[code]
  end

  OPERATION_RESPONSES = create_ptp_code_hash /^PTP_RC_/
  def operation_response_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_RC_#{name.to_s}"
  end
  def operation_response_name code
    OPERATION_RESPONSES[code]
  end

  DEVICE_PROPERTIES = create_ptp_code_hash(/^PTP_DPC_/).inject(Hash.new) do |hash,(code,name)|
    hash[code] = (name == 'WiteBalance') ? 'WhiteBalance' : name
    hash
  end
  def device_property_code name
    return name unless is_a_code_name? name
    name = 'WiteBalance' if name.to_s == 'WhiteBalance'
    Object.const_get "PTP_DPC_#{name.to_s}"
  end
  def device_property_name code
    DEVICE_PROPERTIES[code]
  end

  OBJECT_FORMATS = create_ptp_code_hash /^PTP_OFC_/
  def object_format_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_OFC_#{name.to_s}"
  end
  def object_format_name code
    OBJECT_FORMATS[code]
  end

  WHITE_BALANCES = create_ptp_code_hash /^PTP_WB_/
  def white_balance_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_WB_#{name.to_s}"
  end
  def white_balance_name code
    WHITE_BALANCES[code]
  end

  DATA_TYPES = create_ptp_code_hash /^PTP_DT_/
  def data_type_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_DT_#{name.to_s}"
  end
  def data_type_name code
    DATA_TYPES[code]
  end

  private

  def is_a_code_name? name
    name.is_a? String or name.is_a? Symbol
  end

end
