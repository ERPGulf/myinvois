import binascii
import base64


def get_tlv_for_value(tag_num, tag_value):
    """Get the TLV data value for the QR code."""
    try:
        tag_num_buf = bytes([tag_num])
        if tag_value is None:
            raise ValueError(f"Error: Tag value for tag number {tag_num} is None")

        if isinstance(tag_value, str):
            tag_value = tag_value.encode("utf-8")
            tag_length = len(tag_value)
            if tag_length < 256:
                tag_value_len_buf = bytes([tag_length])
            else:
                tag_value_len_buf = bytes(
                    [0xFF, (tag_length >> 8) & 0xFF, tag_length & 0xFF]
                )
        elif isinstance(tag_value, bytes):
            tag_length = len(tag_value)
            if tag_length < 256:
                tag_value_len_buf = bytes([tag_length])
            else:
                tag_value_len_buf = bytes(
                    [0xFF, (tag_length >> 8) & 0xFF, tag_length & 0xFF]
                )
        else:
            raise ValueError("Unsupported tag value type.")

        return tag_num_buf + tag_value_len_buf + tag_value
    except Exception as e:
        raise ValueError(f"Error in getting the TLV data value: {str(e)}")


def generate_tlv_qrcode(tags):
    """Generate the TLV QR code data."""
    tagsbufsarray = []

    for tag_num, tag_value in tags.items():
        try:
            tlv_data = get_tlv_for_value(tag_num, tag_value)
            # Print HEX representation of individual tag
            tlv_hex = binascii.hexlify(tlv_data).decode("utf-8")
            print(f"Tag {tag_num} HEX: {tlv_hex}")
            tagsbufsarray.append(tlv_data)
        except ValueError as e:
            print(f"Error processing tag {tag_num}: {e}")

    # Concatenate all TLV buffers
    qrcodebuf = b"".join(tagsbufsarray)

    # Print HEX representation of the concatenated buffer
    qrcode_hex = binascii.hexlify(qrcodebuf).decode("utf-8")
    print("Concatenated TLV HEX:", qrcode_hex)

    # Encode to Base64
    qrcodeb64 = base64.b64encode(qrcodebuf).decode("utf-8")

    return qrcodeb64, qrcode_hex


# Example usage
tags = {
    1: "ZLD",
    2: "2323232323",
    3: "2025-01-08T06:20:00",
    4: "135.00",
    5: "15.00",
    6: "4f7VjEwtAemcKnKjkAfYaSFWqgkY59W4XL6WHg/2Gn8w=",
    7: "6MEYCIQDi+OR5DOthtbaeZeRxgPkRLrFuEMtPdIMrbOOca3f82gIhALcLR9VIf4x74ppP6VquwaDor8OQgfbIM4e5xFxcFyd0",
    8: b"-----BEGIN PUBLIC KEY-----\nMII...END PUBLIC KEY-----",  # Binary example
    9: b"signature_binary_data",  # Binary example
}

# Generate QR code Base64 and HEX
qrcode_b64, qrcode_hex = generate_tlv_qrcode(tags)

print("QR Code Base64:", qrcode_b64)


import binascii
import base64

# Hexadecimal string
hex_data = "01035A4C440210323332333233323332330319323032352D30312D30385430363A32303A303004063133352E3030050531352E303006446637566A45777441656D634B6E4B6A6B4166596153465771676B5935395734584C365748672F32476E38773D082324C5330744C5331435255644A5469425156554A4D53554D675330565A4C5330744C53304B54555A5A643056425755684C6231704A656D6F775130465257555A4C4E455646515546765246466E515555325344564651304A3654473175656D4A7964474979624441354C3064335932464465455A785132524D6177707954576450636A5A6D61484A6E527A56304B3252754E58464B646B7446553342696333686E5A6D3532545752786233426F54564255656A5250597974445455396F5330526C4E46453950516F744C5330744C55564F5243425156554A4D53554D675330565A4C5330744C53304B09144333034363032323130306532663865343739306365623631623562363965363565343731383066393131326562313665313063623466373438333262366365333963366237376663646130323231303062373062343764353438376638633762653239613466653935616165633161306538616663333930383166366338333338376239633435633563313732373734"

# Decode the hex string to bytes
byte_data = binascii.unhexlify(hex_data)

# Encode the bytes to Base64
base64_data = base64.b64encode(byte_data).decode("utf-8")

print(base64_data)
