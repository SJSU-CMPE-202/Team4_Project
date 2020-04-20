# The SCF_parser is an application made for the class project for CSE 202
# TODO More description

# Created by Tyler Lennen,
# Last updated: 4/19/2020

# type is always 1 bytes
# Length is always 2 bytes
def parse_read(file_name):
    bytes_pages = []
    with open(file_name, "rb") as file:
        byte = file.read(1)
        while byte != b"":
            # Do stuff with byte.
            byte = file.read(1)
            bytes_pages.append(byte)
    parse_header(bytes_pages)
    print("Bytes_pages: ", bytes_pages)


# type is always 1 bytes
# Length is always 2 bytes
def parse_header(bytes_pages):
    print("Length of Bytes_pages: ", len(bytes_pages))
    SCF_header = {}
    count = 0
    # TODO First 8 bytes are wrong or different
    SCF_header["Rev-major"] = to_int(bytes_pages[2])
    SCF_header["Rev-minor"] = to_int(bytes_pages[3])
    if to_int(bytes_pages[4]) != 2 and to_int(bytes_pages[5] + bytes_pages[6]) != 2:
        return None
    SCF_header["header_length"] = to_int(bytes_pages[7] + bytes_pages[8])
    if to_int(bytes_pages[9]) != 3:
        return None
    SCF_header["signer_identity_length"] = to_int(bytes_pages[10] + bytes_pages[11])
    SCF_header, pos = read_tlv(SCF_header, bytes_pages, "signer_identity_length", 4, 12)
    SCF_header, pos = read_tlv(SCF_header, bytes_pages, "cert_sn_length", 5, pos)
    SCF_header, pos = read_tlv(SCF_header, bytes_pages, "ca_name_length", 6, pos)
    if to_int(bytes_pages[pos]) != 7:
        return None
    # TODO Wrong flag here?!?!
    if to_int(bytes_pages[pos + 1] + bytes_pages[pos + 2]) != b'0b':
        pass
    if to_int(bytes_pages[pos + 3]) != 8:
        return None
    if to_int(bytes_pages[pos + 4] + bytes_pages[pos + 5]) != 1:
        return None
    SCF_header["dig_alg"] = to_int(bytes_pages[pos + 6])
    if to_int(bytes_pages[pos + 7]) != 9:
        return None
    # TODO Flag is not working
    if to_int(bytes_pages[pos + 8] + bytes_pages[pos + 9]) != 6:
        pass
    # Stopped before Sig alg on header page
    print(bytes_pages[pos + 10:pos + 10 + 10])
    print("SCF_Header: ", SCF_header)


def to_int(bytes):
    return int.from_bytes(bytes, 'big')


def read_tlv(SCF_header, bytes_pages, name, flag, pos):
    if to_int(bytes_pages[pos]) != flag:
        print("FAIL")
        return None
    SCF_header[name] = to_int(bytes_pages[pos + 1] + bytes_pages[pos + 2])
    byte_hold = b""
    for x in range(0, SCF_header[name]):
        byte_hold += bytes_pages[pos + 3 + x]
    pos = SCF_header[name] + pos + 3
    return SCF_header, pos


if __name__ == "__main__":
    parse_read("SCFFile.tlv")
