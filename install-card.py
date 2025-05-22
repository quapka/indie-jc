#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p python312Packages.pyscard

import argparse
import configparser
import smartcard

from smartcard.System import readers

# Example installation command:
# $ opensc-tool -s 80b800000d0cF276A288BCFBA69D34F3100100


def load_jcardsim_configuration():
    config = configparser.ConfigParser()
    config.read("./jcardsim_indie.cfg")
    return config


def main():
    config = load_jcardsim_configuration()
    install_apdu = [0x80, 0xB8]
    p1 = 0x00
    p2 = 0x00
    install_apdu.extend([p1, p2])

    AID = list(
        bytearray(
            bytes.fromhex(
                config.get("jcardsim", "com.licel.jcardsim.card.applet.0.AID")
            )
        )
    )
    # NOTE the aid_length is expected to be one byte
    aid_length = len(AID)
    install_apdu.extend([aid_length + 1, aid_length] + AID)

    r = readers()
    connection = r[0].createConnection()
    connection.connect()

    data, sw1, sw2 = connection.transmit([0x00, 0xA4, 0x04, 0x00])
    status = f"0x{sw1:02x}{sw2:02x}"

    print(f"Install APDU SW: {status}")


if __name__ == "__main__":
    main()
