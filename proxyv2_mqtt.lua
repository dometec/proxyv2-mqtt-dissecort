local proxy_mqtt = Proto("proxyv2_mqtt", "PROXYv2 + MQTT")

local f_signature = ProtoField.bytes("proxyv2.signature", "Signature")
local f_version   = ProtoField.uint8("proxyv2.version_cmd", "Version/Command", base.HEX)
local f_family    = ProtoField.uint8("proxyv2.family_proto", "Family/Protocol", base.HEX)
local f_length    = ProtoField.uint16("proxyv2.len", "Header Length", base.DEC)

local f_src_ip    = ProtoField.ipv4("proxyv2.src_ip", "Source IP")
local f_dst_ip    = ProtoField.ipv4("proxyv2.dst_ip", "Destination IP")
local f_src_port  = ProtoField.uint16("proxyv2.src_port", "Source Port", base.DEC)
local f_dst_port  = ProtoField.uint16("proxyv2.dst_port", "Destination Port", base.DEC)

local f_tlv_type  = ProtoField.uint8("proxyv2.tlv.type", "TLV Type", base.HEX)
local f_tlv_len   = ProtoField.uint16("proxyv2.tlv.len", "TLV Length", base.DEC)
local f_ssl_cn    = ProtoField.string("proxyv2.ssl.cn", "SSL Common Name")

proxy_mqtt.fields = {
    f_signature, f_version, f_family, f_length,
    f_src_ip, f_dst_ip, f_src_port, f_dst_port,
    f_tlv_type, f_tlv_len, f_ssl_cn
}

local mqtt_dissector = Dissector.get("mqtt")
local proxy_signature = ByteArray.new("0D0A0D0A000D0A515549540A")

function proxy_mqtt.dissector(buffer, pinfo, tree)

    -- Mimic v15 logic: simple length check to avoid errors on tiny packets
    if buffer:len() < 16 then
        return 0
    end

    local sig = buffer(0,12):bytes()
    
    if sig ~= proxy_signature then
        -- Not a proxy packet, pass to MQTT
        mqtt_dissector:call(buffer, pinfo, tree)
        return buffer:len()
    end

    -- Proxy Protocol v2 detected!
    pinfo.cols.protocol = "PROXYv2+MQTT"
    
    -- We need to read the length from the header (bytes 14-15) to know how much to read
    local addr_len = buffer(14,2):uint()
    local total_header = 16 + addr_len

    -- If we don't have the full header + addresses yet, wait for more data.
    if buffer:len() < total_header then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return 0
    end
    
    -- Create subtree only for the Proxy Protocol header (not including MQTT payload)
    local subtree = tree:add(proxy_mqtt, buffer(0, total_header), "PROXY Protocol v2")

    subtree:add(f_signature, buffer(0,12))
    subtree:add(f_version, buffer(12,1))
    
    local family = buffer(13,1):uint()
    subtree:add(f_family, buffer(13,1))
    subtree:add(f_length, buffer(14,2))

    local offset = 16

    -- IPv4 TCP
    if family == 0x11 then
        subtree:add(f_src_ip, buffer(offset,4))
        subtree:add(f_dst_ip, buffer(offset+4,4))
        subtree:add(f_src_port, buffer(offset+8,2))
        subtree:add(f_dst_port, buffer(offset+10,2))
        offset = offset + 12
    end
    
    -- TLV Parsing
    while offset + 3 <= total_header do
        local tlv_type = buffer(offset,1):uint()
        local tlv_len  = buffer(offset+1,2):uint()

        if offset + 3 + tlv_len > total_header then
            break
        end

        local tlv_tree = subtree:add(buffer(offset,3+tlv_len),"TLV")
        tlv_tree:add(f_tlv_type, buffer(offset,1))
        tlv_tree:add(f_tlv_len, buffer(offset+1,2))

        if tlv_type == 0x20 then -- PP2_TYPE_SSL
            local nested_offset = offset + 3 + 5 -- Skip type, len, client, verify, reserved? Check spec. 
            -- Actually spec says: 
            -- struct pp2_tlv_ssl {
            --   uint8_t  client;
            --   uint32_t verify;
            --   struct pp2_tlv sub_tlv[0];
            -- };
            -- So header is 1+4 = 5 bytes.

            while nested_offset + 3 <= offset + 3 + tlv_len do
                local sub_type = buffer(nested_offset,1):uint()
                local sub_len  = buffer(nested_offset+1,2):uint()

                if sub_type == 0x22 then -- PP2_SUBTYPE_SSL_CN
                     -- Ensure we don't read past buffer
                     if nested_offset + 3 + sub_len <= offset + 3 + tlv_len then
                        tlv_tree:add(f_ssl_cn, buffer(nested_offset+3, sub_len):string())
                     end
                end

                nested_offset = nested_offset + 3 + sub_len
            end
        end

        offset = offset + 3 + tlv_len
    end

    -- Pass MQTT payload to dissector (using v15 proven method)
    if buffer:len() > total_header then
        -- Convert TvbRange -> ByteArray -> Tvb (safe conversion from v15)
        local mqtt_range = buffer(total_header, buffer:len() - total_header)
        local ba = mqtt_range:bytes()
        local mqtt_tvb = ba:tvb("MQTT")
        
        -- Call MQTT dissector
        mqtt_dissector:call(mqtt_tvb, pinfo, tree)
    end
    
    -- Always return the full buffer length - we handle everything
    return buffer:len()
end

DissectorTable.get("tcp.port"):add(1884, proxy_mqtt)
