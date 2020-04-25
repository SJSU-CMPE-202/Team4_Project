def to_int(bytes):
    return int.from_bytes(bytes, 'big')

if b'\n' == b'\x09':
    print("YAY")