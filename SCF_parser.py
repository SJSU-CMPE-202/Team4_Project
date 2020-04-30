# The SCF_parser is an application made for the class project for CSE 202
# TODO More description

# Created by Tyler Lennen,
# Last updated: 4/19/2020

# type is always 1 bytes
# Length is always 2 bytes

import os

def parse_read(file_name):
    with open(file_name, "rb") as file:
        bytes_pages = []
        byte_char = file.read(1)
        while byte_char:
            bytes_pages.append(byte_char)
            byte_char = file.read(1)
    # print("Bytes_pages: ", bytes_pages)
    SCF_header, position = parse_header(bytes_pages)
    while position < len(bytes_pages) - 1:
        SCF_body, position = parse_body(bytes_pages, position)
        print(position)


# type is always 1 bytes
# Length is always 2 bytes
def parse_header(bytes_pages):
    print('Length of Bytes_pages:' + str(len(bytes_pages)))
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
    while count < len(bytes_pages) or count > 10000000:
        if bytes_pages[count] == b'\x0D':
            print("Header is done")
            print("SCF_Header: ", SCF_header)
            return SCF_header, count + 1
        elif "header_length" not in SCF_header and bytes_pages[count] == b'\x02' and bytes_pages[
            count + 1] == b'\x00' and bytes_pages[count + 2] == b'\x02':
            SCF_header["header_length"] = to_int(bytes_pages[count + 3] + bytes_pages[count + 4])
            count = count + 4
        elif "signer_identity_length" not in SCF_header and bytes_pages[count] == b'\x03':
            SCF_header["signer_identity_length"] = to_int(bytes_pages[count + 1] + bytes_pages[count + 2])
            count = count + 2
        elif "signer_name" not in SCF_header and bytes_pages[count] == b'\x04':
            SCF_header, count = read_tlv(SCF_header, bytes_pages, "signer_name", count)
        elif "cert_sn" not in SCF_header and bytes_pages[count] == b'\x05':
            SCF_header, count = read_tlv(SCF_header, bytes_pages, "cert_sn", count)
        elif "ca_name" not in SCF_header and bytes_pages[count] == b'\x06':
            SCF_header, count = read_tlv(SCF_header, bytes_pages, "ca_name", count)
        # TODO TLV file has flag 0x07 then 0x0f, ASSUMING TLV file is correct. Not sure what this flag is for.
        elif bytes_pages[count] == b'\x07' and bytes_pages[count + 1] == b'\x00' and bytes_pages[count + 2] == b'\x0f':
            print(bytes_pages[count:count + 10])
            print("Flag 7 is here.")
            count = count + 2
        elif "dig_alg" not in SCF_header and bytes_pages[count] == b'\x08' and bytes_pages[count + 1] == b'\x00' and \
                bytes_pages[count + 2] == b'\x01':
            SCF_header["dig_alg"] = bytes_pages[count + 3]
            count = count + 3
        # TODO TLV file has flag 0x07 then 0x0f, ASSUMING TLV file is correct. Not sure what this flag is for.
        elif bytes_pages[count] == b'\x09' and bytes_pages[count + 1] == b'\x00' and bytes_pages[count + 2] == b'\x08':
            print(bytes_pages[count:count + 10])
            print("Flag 9 is here.")
            count = count + 2
        # TODO \n instead of 0A
        elif "sig_alg" not in SCF_header and bytes_pages[count] == b'\n' and bytes_pages[count + 1] == b'\x00' and \
                bytes_pages[count + 2] == b'\x01':
            SCF_header["sig_alg"] = bytes_pages[count + 3]
            count = count + 3
        elif "mod_size" not in SCF_header and bytes_pages[count] == b'\x0b' and bytes_pages[count + 1] == b'\x00' and \
                bytes_pages[count + 2] == b'\x01':
            SCF_header["mod_size"] = bytes_pages[count + 3]
            count = count + 3
        elif "signature" not in SCF_header and bytes_pages[count] == b'\x0c':
            SCF_header, pos = read_tlv(SCF_header, bytes_pages, "signature", count)
        elif "file_name" not in SCF_header and bytes_pages[count] == b'\x0e':
            SCF_header, pos = read_tlv(SCF_header, bytes_pages, "file_name", count)
        # elif "file_name_and_extension" not in SCF_header and
        count = count + 1


def parse_body(bytes_pages, start_pos):
    print("Body begins: ", bytes_pages[start_pos:start_pos + 10])
    print("Length of Body: ", len(bytes_pages[start_pos:]))
    scf_body = {}
    if len(bytes_pages) < 5:
        return None
    if bytes_pages[start_pos] != b'\x01':
        return None
    if bytes_pages[start_pos + 1] != b'\x00' or bytes_pages[start_pos + 2] != b'\x02':
        return None
    scf_body["record_length"] = to_int(bytes_pages[start_pos + 3] + bytes_pages[start_pos + 4])
    print("HEY STOP", bytes_pages[start_pos + scf_body["record_length"] - 20:start_pos + scf_body["record_length"] + 6])
    count = start_pos + 5
    while count < scf_body["record_length"] + start_pos:
        if bytes_pages[count] == b'\x0C':
            print(count)
            print("Body is done")
            print("SCF_Body: ", scf_body)
            return scf_body
        elif "subject_dns_name" not in scf_body and bytes_pages[count] == b'\x02':
            scf_body, count = read_tlv(scf_body, bytes_pages, "subject_dns_name", count)
            print("Flag 02:", bytes_pages[count:count + 10])
            print(count)
        elif "subject_name" not in scf_body and bytes_pages[count] == b'\x03':
            scf_body, count = read_tlv(scf_body, bytes_pages, "subject_name", count)
            print("Flag 03:", bytes_pages[count:count + 10])
            print(count)
        elif "subject_role" not in scf_body and bytes_pages[count] == b'\x04':
            scf_body, count = read_tlv(scf_body, bytes_pages, "subject_role", count)
            print("Flag 04:", bytes_pages[count:count + 10])
            print(count)
        elif "subject_certificate_issuer" not in scf_body and bytes_pages[count] == b'\x05':
            scf_body, count = read_tlv(scf_body, bytes_pages, "subject_certificate_issuer", count)
            print("Flag 05:", bytes_pages[count:count + 10])
            print(count)
        elif "cert_serial_number" not in scf_body and bytes_pages[count] == b'\x06':
            scf_body, count = read_tlv(scf_body, bytes_pages, "cert_serial_number", count)
            print("Flag 06:", bytes_pages[count:count + 10])
            print(count)
        elif "public_key" not in scf_body and bytes_pages[count] == b'\x07':
            scf_body, count = read_tlv(scf_body, bytes_pages, "public_key", count)
            print("Flag 07:", bytes_pages[count:count + 10])
            print(count)
        elif "subject_cert_signature" not in scf_body and bytes_pages[count] == b'\x08':
            scf_body, count = read_tlv(scf_body, bytes_pages, "subject_cert_signature", count)
            print("Flag 08:", bytes_pages[count:count + 10])
            print(count)
        elif "subject_509_Cert" not in scf_body and bytes_pages[count] == b'\t':
            scf_body, count = read_tlv(scf_body, bytes_pages, "subject_509_Cert", count)
            print("Flag 09:", bytes_pages[count:count + 10])
            print(count)
        elif "hash_cert" not in scf_body and bytes_pages[
            count] == b'\n':  # these flags are the same for some reason, I have no clue why
            scf_body, count = read_tlv(scf_body, bytes_pages, "hash_cert", count)
            print("Flag n:", bytes_pages[count:count + 10])
            print(count)
        elif "hash_algorithm" not in scf_body and bytes_pages[count] == b'\x0c':
            scf_body, count = read_tlv(scf_body, bytes_pages, "hash_algorithm", count)
            print("Flag 0c:", bytes_pages[count:count + 10])
            print(count)
        count = count + 1
    print(scf_body)
    return scf_body, count


def to_int(bytes):
    return int.from_bytes(bytes, 'big')


def read_tlv(SCF_header, bytes_pages, name, pos):
    length = to_int(bytes_pages[pos + 1] + bytes_pages[pos + 2])
    hold = b""
    for x in bytes_pages[pos + 3:pos + 3 + length]:
        hold = hold + x
    SCF_header[name] = hold
    pos = pos + 3 + length - 1
    # Breaks if I don't have -1
    return SCF_header, pos


if __name__ == "__main__":
    parse_read("SCFFile.tlv")
