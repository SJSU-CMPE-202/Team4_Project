def read_out(filename):
    with open(filename, "rb") as file:
        bytes_pages = []
        byte_char = file.read(1)
        while byte_char:
            bytes_pages.append(byte_char)
            byte_char = file.read(1)
    print(bytes_pages)

    # 14 and 15 are signer length of the header
    bytes_pages[14] = b'FF'
    bytes_pages[15] = b'FF'
    print(bytes_pages)
    with open("modifiedSCF.tlv", "wb")as file:
        for x in bytes_pages:
            file.write(x)


if __name__ == "__main__":
    read_out("SCFFile.tlv")
