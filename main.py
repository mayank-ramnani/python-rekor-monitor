import argparse
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion
import requests
import time
import base64
import json
from my_crypto import extract_public_key, verify_binary_signature

def consistency():
    try:
        checkpoint1 = {}
        checkpoint2 = {}
        # NOTE: rekor-monitor uses stable=true and a 5 minute gap between checkpoints by default
        # more info about stable flag: https://github.com/sigstore/rekor/issues/1566
        resp = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=false")
        if resp.status_code != 200:
            print("error getting checkpoint1")
        else:
            checkpoint1 = resp.json()
            print("fetched checkpoint1:", checkpoint1)

        # wait for data in the rekor log to update
        # time.sleep(30)
        resp = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=false")
        if resp.status_code != 200:
            print("error getting checkpoint2")
        else:
            checkpoint2 = resp.json()
            print("fetched checkpoint2:", checkpoint2)

        size1 = checkpoint1["treeSize"]
        size2 = checkpoint2["treeSize"]

        if (size1 == size2):
            print("both checkpoints are the same")
            # return

        root1 = checkpoint1["rootHash"]
        root2 = checkpoint2["rootHash"]

        if (checkpoint1["treeID"] == checkpoint2["treeID"]):
            treeID = checkpoint1["treeID"]
        else:
            print("bad tree id")
            return

        # get proof
        size1 = 2665690
        size2 = 2665696
        treeID = 1193050959916656506
        root1 = "e66004eadd7085da9077cfe6a636223f03f8484c0fbdda5515dc34c93072f378"
        root2 = "1d16c60946261d659c516af834a840b0f754fdd6319d6a193af4cdeec4c6eff7"
        resp = requests.get(f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={size1}&lastSize={size2}&treeID={treeID}")
        if resp.status_code != 200:
            print("error getting proof", resp.url)
            return

        proof = resp.json()["hashes"]
        print("obtained proof", proof)

        # verify consistency of checkpoints
        # verify_consistency(DefaultHasher, size1, size2, proof, root1, root2)
        verify_consistency(DefaultHasher, size1, size2, proof, root1, root2)
        print("Consistency verification successful")
        # verify_inclusion(DefaultHasher, index, size, leaf_hash, proof, root)

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
    resp = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=false")
    if resp.status_code != 200:
        print("error getting checkpoint")
    else:
        checkpoint = resp.json()
        print("fetched checkpoint:")
        print(json.dumps(checkpoint, indent=4))
    if debug:
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
                        checkpoint with the latest checkpoint. Usage: \
                        --consistency \'{"treeID": "abcd", "rootHash": "asdf",\
                                        treeSize: "123123"}\'',
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
        consistency()

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

    # TODO: also need to call the merkle proof verify inclusion from here
    # figure out what args you need and how to get them here and then call it
    # take inspiration from inclusion.py
    try:
        proof = get_verification_proof(log_index, debug)
        verify_inclusion(DefaultHasher, proof["index"], proof["tree_size"],
                         proof["leaf_hash"], proof["hashes"], proof["root_hash"])
    except Exception as e:
        print(f"Inclusion verification failed: {str(e)}")

if __name__ == "__main__":
    main()
