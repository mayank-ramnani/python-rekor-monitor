## Goals
1. Add an artifact to the Rekor transparency log using the cosign tool.
    Verify that the entry was successfully included in the transparency log.
2. Verify the consistency of the rekor transparency log, i.e that the new
    entry that was append only to the log.

## Steps
1. Create an artifact (binary) that will be signed with entry being stored in
    the rekor log.
2. Use the `cosign` tool to sign the artifact using your email id and store
    the signature and certificate that was used to sign it. (bundle command)
3. Get checkpoint of the rekor public instance transparency log.
    "--checkpoint"
4.  a. Verify that the artifact is in the transparency log by getting a merkle proof
    and verifying it offline (use `merkle_proof` api)
    "--inclusion <logIndex>"
    b. Verify that the artifact signature is correct (use `crypto` api)
5. At any point in time, can verify that the consistency of the checkpoint which had our entry added and the latest checkpoint by verifying the consistency proof.
    Just need the old checkpoint details.
    `--consistency '{"treeID": "abcd", "rootHash": "asdf", treeSize: "123123"}'`
    Verifying consistency of a checkpoint till the latest checkpoint.


## Required data
- For consistency verification, you need the old and new checkpoint details (treeSize, rootHash, treeID) and the hashes to generate a merkle proof to show that the old checkpoint exists in the new checkpoint.
- For inclusion verification, you need the

### Global Flags
- `--debug` to dump intermediate files and print verbose output
