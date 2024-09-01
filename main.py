import argparse
import requests
import time
import base64
import json
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion
from my_crypto import extract_public_key, verify_binary_signature

def consistency(prev_checkpoint, debug=False):
    try:
        current_checkpoint = get_latest_checkpoint()

        size1 = prev_checkpoint["treeSize"]
        size2 = current_checkpoint["treeSize"]

        if (size1 == size2):
            print("both checkpoints are the same")
            return

        root1 = prev_checkpoint["rootHash"]
        root2 = current_checkpoint["rootHash"]

        if (prev_checkpoint["treeID"] == current_checkpoint["treeID"]):
            treeID = prev_checkpoint["treeID"]
        else:
            print("bad tree id")
            return

        resp = requests.get(f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={size1}&lastSize={size2}&treeID={treeID}")
        if resp.status_code != 200:
            print("error getting consistency proof", resp.url)
            return

        proof = resp.json()["hashes"]
        if debug:
            print("obtained consistency proof", proof)

        # verify consistency of checkpoints
        verify_consistency(DefaultHasher, size1, size2, proof, root1, root2)
        print("Consistency verification successful.")

    except Exception as e:
        print(f"Consistency verification failed: {str(e)}")


def get_verification_proof(log_index, debug=False):
    proof = {}
    resp = requests.get(f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}")
    if resp.status_code != 200:
        print("error getting verification proof")
    response_json = resp.json()
    for key, value in response_json.items():
        # key contains uuid
        # uuid is 16 byte string + entry hash
        proof["leaf_hash"] = key[16:]
        proof["index"] = value["verification"]["inclusionProof"]["logIndex"]
        proof["root_hash"] = value["verification"]["inclusionProof"]["rootHash"]
        proof["tree_size"] = value["verification"]["inclusionProof"]["treeSize"]
        proof["hashes"] = value["verification"]["inclusionProof"]["hashes"]

    if debug:
        print(proof)
        print("writing to file")
        with open("proof.json", 'w') as f:
            f.write(json.dumps(proof, indent=4))
    return proof


def get_latest_checkpoint(debug=False):
    checkpoint = {}
    # NOTE: rekor-monitor uses stable=true and a 5 minute gap between checkpoints by default
    # more info about stable flag: https://github.com/sigstore/rekor/issues/1566
    resp = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=false")
    if resp.status_code != 200:
        print("error getting checkpoint")
    else:
        checkpoint = resp.json()
    if debug:
        print("fetched checkpoint:")
        print(json.dumps(checkpoint, indent=4))
        print("writing to file")
        with open("checkpoint.json", 'w') as f:
            f.write(json.dumps(checkpoint, indent=4))
    return checkpoint

def main():
    # print(art.text2art("rekor verifier"))
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        get_latest_checkpoint(debug)
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

def inclusion(log_index, artifact_filepath, debug=False):
    # sanity
    if (log_index <= 0):
        print("log index is incorrect:,", log_index)
        return
    print("checking inclusion for log index", log_index)
    url = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=" + str(log_index)
    response = requests.get(url)
    if response.status_code != 200:
        print("error getting log entry", log_index)
        return

    response_json = response.json()
    for key, value in response_json.items():
        print("for uuid:", key)
        hashes = value["verification"]["inclusionProof"]["hashes"]
        body = json.loads(base64.b64decode(value["body"]))
        # print(json.dumps(body, indent=4))
        sig_b64 = body["spec"]["signature"]["content"]
        cert_b64 = body["spec"]["signature"]["publicKey"]["content"]

        # base64 decode signature and public key
        sig = base64.b64decode(sig_b64)
        cert = base64.b64decode(cert_b64)
        public_key = extract_public_key(cert)
        # store them in files if debug mode enabled

        if debug:
            print("base64 signature", sig_b64)
            print("base64 cert", cert_b64)
            with open("signing_cert.pem", "wb") as f:
                f.write(cert)
            with open("artifact.sig", "wb") as f:
                f.write(sig)
            with open("public_key.pem", "wb") as f:
                f.write(public_key)

            print(public_key.decode("utf8"))
        verify_binary_signature(sig, public_key, artifact_filepath)

    try:
        proof = get_verification_proof(log_index, debug)
        verify_inclusion(DefaultHasher, proof["index"], proof["tree_size"],
                         proof["leaf_hash"], proof["hashes"], proof["root_hash"])
    except Exception as e:
        print(f"Inclusion verification failed: {str(e)}")

if __name__ == "__main__":
    main()
