from merkle_proof import DefaultHasher, verify_consistency
import requests
import time

# TODO: make the api call and fetch two checkpoints with a hardcoded interval
# TODO: add functionality to store and retrieve old checkpoint
# TODO: low prio: add signing verification functionality by getting the public key from 
# the api and using that to verify
# TODO: new feature: inclusion proof check
# TODO: future feature: track an identity

def main():
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
        time.sleep(30)
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
            return

        root1 = checkpoint1["rootHash"]
        root2 = checkpoint2["rootHash"]

        if (checkpoint1["treeID"] == checkpoint2["treeID"]):
            treeID = checkpoint1["treeID"]
        else:
            print("bad tree id")
            return

        # get proof
        resp = requests.get(f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={size1}&lastSize={size2}&treeID={treeID}")
        if resp.status_code != 200:
            print("error getting proof", resp.url)
            return
       
        proof = resp.json()["hashes"]
        print("obtained proof", proof)
        
        # verify consistency of checkpoints
        verify_consistency(DefaultHasher, size1, size2, proof, root1, root2)
        print("Consistency verification successful")

    except Exception as e:
        print(f"Consistency verification failed: {str(e)}")

if __name__ == "__main__":
    main()
