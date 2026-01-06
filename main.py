#!/usr/bin/env python3


import configparser
import json
import requests

from typing import Tuple

# import smartcard

from requests.auth import HTTPBasicAuth


def get_credentials() -> Tuple[str, str]:
    config = configparser.ConfigParser()
    config.read("config.ini")
    btc = config["bitcoin-node"]
    return btc.get("user"), btc.get("password")


def get_connection_string() -> str:
    config = configparser.ConfigParser()
    config.read("config.ini")
    btc = config["bitcoin-node"]

    schema = btc.get("schema")
    domain = btc.get("domain")
    port = btc.get("port")

    return f"{schema}://{domain}:{port}"


def get_sixth_past_hash():
    user, password = get_credentials()
    basic = HTTPBasicAuth(user, password)
    con_string = get_connection_string()

    headers = {"Content-Type": "application/json"}
    payload = json.dumps(
        {
            "jsonrpc": "1.0",
            "id": "indie",
            "method": "getblockcount",
            "params": [],
        }
    )
    resp = requests.post(con_string, auth=basic, data=payload, headers=headers)
    blockcount = resp.json()["result"]
    payload = json.dumps(
        {
            "jsonrpc": "1.0",
            "id": "indie",
            "method": "getblockhash",
            "params": [blockcount],
        }
    )
    resp = requests.post(con_string, auth=basic, data=payload, headers=headers)
    return resp.json()["result"]


def main():
    btc_sixth_hash = get_sixth_past_hash()
    print(btc_sixth_hash)


if __name__ == "__main__":
    main()
