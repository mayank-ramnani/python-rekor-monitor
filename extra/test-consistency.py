
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
