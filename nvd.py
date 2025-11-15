#!/usr/bin/env python3

import requests
import json
from rich import print_json


def get_result(software):
    params = {"keywordSearch": software}
    base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    r = requests.get(url=base_url, params=params)

    if r.status_code != 200:
        print(f"{r.status_code}")
        return None

    dados = r.json()
    for item in dados["vulnerabilities"]:
        print_json(data=item["cve"]["id"])
    return dados


while True:
    user_input = input("Buscar por ->").lower()

    try:
        dados = get_result(user_input)

        second_input = input("another search ? y/n ").lower()
        if second_input != "y":
            break
    except:
        print(f"error")
        break
