# The SCF_parser is an application made for the class project for CSE 202
# TODO More description

# Created by Tyler Lennen,
# Last updated: 4/19/2020

# type is always 1 bytes
# Length is always 2 bytes
def parse_read(file_name):
    with open(file_name, "rb") as file:
        bytes_pages = []
        byte_char = file.read(1)
        while byte_char:
            bytes_pages.append(byte_char)
            byte_char = file.read(1)
    print("Bytes_pages: ", bytes_pages)
    parse_header(bytes_pages)


# type is always 1 bytes
# Length is always 2 bytes
def parse_header(bytes_pages):
    print("Length of Bytes_pages: ", len(bytes_pages))
    if len(bytes_pages) < 5:
        return None
    SCF_header = {}
    # Required Values
    if bytes_pages[0] != b'\x01':
        return None
    if bytes_pages[1] != b'\x00' or bytes_pages[2] != b'\x02':
        return None
    SCF_header["Rev-major"] = to_int(bytes_pages[3])
    SCF_header["Rev-minor"] = to_int(bytes_pages[4])

    # Optional below
    count = 5
    while count < len(bytes_pages):
        if bytes_pages[count] == b'\x0D':
            print("Header is done")
            print("SCF_Header: ", SCF_header)
            return SCF_header
        elif "header_length" not in SCF_header and bytes_pages[count] == b'\x02' and bytes_pages[count + 1] == b'\x00' and bytes_pages[count + 2] == b'\x02':
            SCF_header["header_length"] = to_int(bytes_pages[count + 3] + bytes_pages[count + 4])
            count = count + 4
        elif "signer_identity_length" not in SCF_header and bytes_pages[count] == b'\x03':
            SCF_header["signer_identity_length"] = to_int(bytes_pages[count + 1] + bytes_pages[count + 2])
            count = count + 2
        elif "signer_name" not in SCF_header and bytes_pages[count] == b'\x04':
            SCF_header, pos = read_tlv(SCF_header, bytes_pages, "signer_name", count)
        elif "cert_sn" not in SCF_header and bytes_pages[count] == b'\x05':
            SCF_header, pos = read_tlv(SCF_header, bytes_pages, "cert_sn", count)
        elif "ca_name" not in SCF_header and bytes_pages[count] == b'\x06':
            SCF_header, pos = read_tlv(SCF_header, bytes_pages, "ca_name", count)
        #TODO TLV file has flag 0x07 then 0x0f, ASSUMING TLV file is correct. Not sure what this flag is for.
        elif bytes_pages[count] == b'\x07' and bytes_pages[count+1] == b'\x00' and bytes_pages[count+2] == b'\x0f':
            print(bytes_pages[count:count+10])
            print("Flag 7 is here.")
            count = count+2
        elif "dig_alg" not in SCF_header and bytes_pages[count] == b'\x08' and bytes_pages[count + 1] == b'\x00' and bytes_pages[count + 2] == b'\x01':
            SCF_header["dig_alg"] = bytes_pages[count + 3]
            count = count+3
        # TODO TLV file has flag 0x07 then 0x0f, ASSUMING TLV file is correct. Not sure what this flag is for.
        elif bytes_pages[count] == b'\x09' and bytes_pages[count + 1] == b'\x00' and bytes_pages[count + 2] == b'\x08':
            print(bytes_pages[count:count + 10])
            print("Flag 9 is here.")
            count = count+2
        #TODO \n instead of 0A
        elif "sig_alg" not in SCF_header and bytes_pages[count]==b'\n' and bytes_pages[count+1]==b'\x00' and bytes_pages[count+2]==b'\x01':
            SCF_header["sig_alg"] = bytes_pages[count + 3]
            count = count + 3
        elif "mod_size" not in SCF_header and bytes_pages[count] == b'\x0b' and bytes_pages[count + 1] == b'\x00' and bytes_pages[count + 2] == b'\x01':
            SCF_header["mod_size"] = bytes_pages[count + 3]
            count = count + 3
        elif "signature" not in SCF_header and bytes_pages[count] == b'\x0c':
            SCF_header, pos = read_tlv(SCF_header, bytes_pages, "signature", count)
        elif "file_name" not in SCF_header and bytes_pages[count] == b'\x0e':
            SCF_header, pos = read_tlv(SCF_header, bytes_pages, "file_name", count)
        #elif "file_name_and_extension" not in SCF_header and
        count = count + 1
    # SCF_header["signer_identity_length"] = to_int(bytes_pages[10] + bytes_pages[11])
    # SCF_header, pos = read_tlv(SCF_header, bytes_pages, "signer_identity_length", 4, 12)
    # SCF_header, pos = read_tlv(SCF_header, bytes_pages, "cert_sn_length", 5, pos)
    # SCF_header, pos = read_tlv(SCF_header, bytes_pages, "ca_name_length", 6, pos)
    # if to_int(bytes_pages[pos]) != 7:
    #     return None
    # # TODO Wrong flag here?!?!
    # if to_int(bytes_pages[pos + 1] + bytes_pages[pos + 2]) != b'0b':
    #     pass
    # if to_int(bytes_pages[pos + 3]) != 8:
    #     return None
    # if to_int(bytes_pages[pos + 4] + bytes_pages[pos + 5]) != 1:
    #     return None
    # SCF_header["dig_alg"] = to_int(bytes_pages[pos + 6])
    # if to_int(bytes_pages[pos + 7]) != 9:
    #     return None
    # # TODO Flag is not working
    # if to_int(bytes_pages[pos + 8] + bytes_pages[pos + 9]) != 6:
    #     pass
    # # Stopped before Sig alg on header page
    # print(bytes_pages[310:330])


def to_int(bytes):
    return int.from_bytes(bytes, 'big')


def read_tlv(SCF_header, bytes_pages, name, pos):
    print(bytes_pages[pos])
    length = to_int(bytes_pages[pos + 1] + bytes_pages[pos + 2])
    hold = b""
    for x in bytes_pages[pos+3:pos+3+length]:
        if(name =="cert_sn"):
            print(x)
        hold = hold + x
    SCF_header[name] = hold
    pos = pos+3+length
    return SCF_header, pos


if __name__ == "__main__":
    parse_read("SCFFile.tlv")
