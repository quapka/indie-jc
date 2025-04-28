#!/usr/bin/env python3

import string
import secrets
import random

from base64 import urlsafe_b64encode

alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"

sig = '{"alg":"ES256"}'
token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
_, body, _ = token.split(".")

# b_sig = sig.encode("ascii")


# exp_encoded = urlsafe_b64encode(b_sig).decode("ascii")
encoded = "eyJhbGciOiJFUzI1NiJ9"


def bencode(data: bytes) -> str:
    result = []
    for ind in range(0, len(data), 3):
        group = data[ind : ind + 3]

        # smaller_group = len(group) % 3
        # pad_len = 0
        # if smaller_group:
        #     pad_len = 3 - smaller_group
        # group += b"\x00" * pad_len
        base = int.from_bytes(group, "big")
        pad_len = 0
        shifts = [3, 2, 1, 0]

        remainder = len(group) % 3
        # group has 8 bits, 4 zeroes are missing
        if remainder == 1:
            base <<= 4
            pad_len = 2
            shifts = [1, 0]
        # group has 16 bits, 2 are missing
        elif remainder == 2:
            base <<= 2
            pad_len = 1
            shifts = [2, 1, 0]

        for x in shifts:
            char = alphabet[base >> (x * 6) & 0x3F]
            result.append(char)

        result.extend("=" * pad_len)

    return "".join(result)


def bedcode(data):
    out = b""

    for i in range(0, len(data), 4):
        group = 0
        for j, char in enumerate(data[i : i + 4]):
            try:
                ind = alphabet.index(char)
            except ValueError:
                ind = 0
            print(char, ind)
            # FIXME what if ind is None, because of =
            group += ind << ((3 - j) * 6)

        out += group.to_bytes(3, "big")

    # print(out)
    return out.decode("ascii")


# print(out, exp_encoded)

# assert out == exp_encoded

print(bedcode(body))
print(len(body) % 3)

# print(bedcode(encoded))
# x = bedcode(bencode((sig + "11").encode()))
# print(f'"{x}"')

# while True:
#     x = random.randint(0, 1024)
#     data = secrets.token_bytes(x)
#     assert bencode(data) == urlsafe_b64encode(data).decode("ascii")
