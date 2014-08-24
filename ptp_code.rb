require_relative 'ptp.rb'

# Translate from code_name into code(ptp code constants in ptp.rb).
#   ex. event_code(:ObjectAdded) => EventCode: PTP_EC_ObjectAdded(0x4002)
module PtpCode

  def event_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_EC_#{name.to_s}"
  end

  def operation_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_OC_#{name.to_s}"
  end

  def operation_respense_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_RC_#{name.to_s}"
  end

  def device_property_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_DPC_#{name.to_s}"
  end

  def object_format_code name
    return name unless is_a_code_name? name
    Object.const_get "PTP_OFC_#{name.to_s}"
  end

  private

  def is_a_code_name? name
    name.is_a? String or name.is_a? Symbol
  end

end
