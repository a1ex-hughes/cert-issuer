"""
Atomic — Blockcerts Certificate Worker
Runs as a daily batch job on Railway.
Fetches pending certs from Supabase, issues via cert-issuer CLI, reports back.
"""

import os
import json
import shutil
import subprocess
import tempfile
import requests
from datetime import datetime, timezone
from lds_merkle_proof_2019.merkle_proof_2019 import MerkleProof2019

SUPABASE_FUNCTIONS_URL = os.environ["SUPABASE_FUNCTIONS_URL"]
CERT_WORKER_SECRET = os.environ["CERT_WORKER_SECRET"]
ETHEREUM_PRIVATE_KEY = os.environ["ETHEREUM_PRIVATE_KEY"]
NETWORK = os.environ.get("NETWORK", "sepolia")
ISSUING_ADDRESS = "0x993dc9D20EbfE5797B538Abcb9D9BF53653858Bb"

HEADERS = {
    "Authorization": f"Bearer {CERT_WORKER_SECRET}",
    "Content-Type": "application/json",
}

CERT_ISSUER_CONF = "/etc/cert-issuer/conf.ini"
PRIVATE_KEY_FILE = "/etc/cert-issuer/pk.txt"


def setup_conf():
    os.makedirs("/etc/cert-issuer", exist_ok=True)
    with open(PRIVATE_KEY_FILE, "w") as f:
        f.write(ETHEREUM_PRIVATE_KEY.removeprefix("0x"))
    chain = f"ethereum_{NETWORK}"
    conf = (
        f"issuing_address = {ISSUING_ADDRESS}\n"
        f"chain = {chain}\n"
        "usb_name = /etc/cert-issuer\n"
        "key_file = pk.txt\n"
        "no_safe_mode\n"
    )
    with open(CERT_ISSUER_CONF, "w") as f:
        f.write(conf)


def fetch_pending():
    r = requests.get(f"{SUPABASE_FUNCTIONS_URL}/cert-queue", headers=HEADERS)
    r.raise_for_status()
    return r.json().get("certificates", [])


def report_anchored(certificate_id, tx_id, blockcert_json):
    r = requests.post(
        f"{SUPABASE_FUNCTIONS_URL}/cert-anchored",
        headers=HEADERS,
        json={
            "certificate_id": certificate_id,
            "blockchain_tx_id": tx_id,
            "blockcert_json": blockcert_json,
        },
    )
    r.raise_for_status()


def report_failed(certificate_id):
    r = requests.post(
        f"{SUPABASE_FUNCTIONS_URL}/cert-anchored",
        headers=HEADERS,
        json={"certificate_id": certificate_id, "status": "failed"},
    )
    r.raise_for_status()


def build_unsigned_cert(cert):
    """
    Build a Blockcerts v2 unsigned certificate JSON.
    cert dict contains: certificate_id, recipient_name, recipient_email, pathway_title (from queue endpoint).
    """
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/blockcerts/schema/3.0/context.json",
        ],
        "type": ["VerifiableCredential", "BlockcertsCredential"],
        "id": f"urn:uuid:{cert['id']}",
        "issuer": "https://atomic-labs.io",
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        "credentialSubject": {
            "id": f"mailto:{cert['recipient_email']}",
        },
    }


def extract_tx_id(blockcert):
    """Extract the blockchain tx hash from a Blockcerts v3 issued certificate.

    The tx is embedded in proof.proofValue as a CBOR+multibase encoded MerkleProof2019.
    The anchor string looks like 'blink:eth:sepolia:0xabc123...'
    """
    proof = blockcert.get("proof", {})
    if isinstance(proof, list):
        proof = next((p for p in proof if p.get("cryptosuite") == "merkle-proof-2019"), {})
    proof_value = proof.get("proofValue")
    if not proof_value:
        return None
    try:
        decoded = MerkleProof2019().decode(proof_value)
        anchors = decoded.get("anchors", [])
        if anchors:
            # anchor format: "blink:eth:sepolia:0xTXHASH"
            return anchors[0].split(":")[-1]
    except Exception as e:
        print(f"Failed to decode proofValue: {e}")
    return None


def issue_certificate(cert):
    work_dir = tempfile.mkdtemp()
    try:
        unsigned_dir = os.path.join(work_dir, "unsigned")
        blockchain_dir = os.path.join(work_dir, "blockchain")
        os.makedirs(unsigned_dir)
        os.makedirs(blockchain_dir)

        cert_id = cert["id"]
        unsigned_cert = build_unsigned_cert(cert)

        unsigned_path = os.path.join(unsigned_dir, f"{cert_id}.json")
        with open(unsigned_path, "w") as f:
            json.dump(unsigned_cert, f)

        # Write a per-cert conf that includes the temp dirs
        conf_path = os.path.join(work_dir, "conf.ini")
        chain = f"ethereum_{NETWORK}"
        with open(conf_path, "w") as f:
            f.write(
                f"issuing_address = {ISSUING_ADDRESS}\n"
                f"chain = {chain}\n"
                "usb_name = /etc/cert-issuer\n"
                "key_file = pk.txt\n"
                "no_safe_mode\n"
                f"unsigned_certificates_dir = {unsigned_dir}\n"
                f"blockchain_certificates_dir = {blockchain_dir}\n"
                "sepolia_rpc_url = https://ethereum-sepolia-rpc.publicnode.com\n"
            )

        result = subprocess.run(
            ["cert-issuer", "-c", conf_path],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            print(f"[{cert_id}] cert-issuer failed:\n{result.stderr}")
            return None, None

        issued_path = os.path.join(blockchain_dir, f"{cert_id}.json")
        with open(issued_path) as f:
            blockcert = json.load(f)

        tx_id = extract_tx_id(blockcert)

        return tx_id, blockcert

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main():
    print(f"[{datetime.now().isoformat()}] cert_worker starting")
    setup_conf()
    pending = fetch_pending()
    print(f"Found {len(pending)} pending certificate(s)")

    for cert in pending:
        cert_id = cert["id"]
        print(f"Processing {cert_id} — {cert.get('recipient_name')} / {cert.get('pathway_title')}")
        try:
            tx_id, blockcert = issue_certificate(cert)
            if tx_id and blockcert:
                report_anchored(cert_id, tx_id, blockcert)
                print(f"[{cert_id}] anchored — tx: {tx_id}")
            else:
                report_failed(cert_id)
                print(f"[{cert_id}] failed — reported to Supabase")
        except Exception as e:
            print(f"[{cert_id}] exception: {e}")
            report_failed(cert_id)

    print("Done.")


if __name__ == "__main__":
    main()
