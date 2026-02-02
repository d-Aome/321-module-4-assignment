import json
import math
import os

# to time functions
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

import bcrypt
import nltk
from nltk.corpus import words

nltk.download("words")
# Filter the words for the words we may actually find
word_list = [w.lower() for w in words.words() if 6 <= len(w) <= 10]

hash_list = [
    "Bilbo:$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq",
    "Gandalf:$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC",
    "Thorin:$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q",
    "Fili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm",
    "Kili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im",
    "Balin:$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom",
    "Dwalin:$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be",
    "Oin:$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK",
    "Gloin:$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q",
    "Dori:$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq",
    "Nori:$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12",
    "Ori:$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O",
    "Bifur:$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK",
    "Bofur:$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O",
    "Durin:$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay",
]


# return the salt and hash seperately
def get_salt_and_hash(salt_hash_combined):
    salt = salt_hash_combined[:22]
    hash_val = salt_hash_combined[22:]
    return salt, hash_val


def preproces_hash_list():
    cleaned_hashes = []
    for entry in hash_list:
        full_hash = entry.split(":")[1]
        hash_parts = full_hash.split("$")
        work_factor = hash_parts[2]
        salt, h = get_salt_and_hash(hash_parts[3])
        cleaned_hashes.append(
            {
                "work_factor": work_factor,
                "salt": salt,
                "hash": h,
                "full_hash": full_hash,
            }
        )
    return cleaned_hashes


def check_chunk(chunk, targets, global_start, worker_id):
    found = []
    checkpoint_file = (
        "cracked_passwords.log"  # Log file for if i stop prgogram by Accident
    )

    for i, word in enumerate(chunk):
        word_bytes = word.encode("utf-8")
        for target in targets:
            # convert word to bytes and check it with hashes
            if bcrypt.checkpw(word_bytes, target["full_hash"].encode("utf-8")):
                crack_time = time.perf_counter() - global_start

                result = {
                    "work_factor": target["work_factor"],
                    "password": word,
                    "time": crack_time,
                    "hash": target["hash"],
                }

                with open(checkpoint_file, "a") as f:
                    f.write(json.dumps(result) + "\n")
                # Notify me when we have found a password
                print(f"\n[!] SAVED TO LOG: {word}")
                found.append(result)
    return found


def main():
    clean_hashes = preproces_hash_list()
    total_to_find = len(clean_hashes)
    workers_count = os.cpu_count()

    chunk_size = math.ceil(len(word_list) / workers_count)
    chunks = [
        word_list[i : i + chunk_size] for i in range(0, len(word_list), chunk_size)
    ]

    global_start = time.perf_counter()
    all_found = []

    print(f"Cracking on {workers_count} cores. Goal: {total_to_find} hashes.")
    print("--- Starting Attack ---")

    # Multi Thread so that program goes by faster, also ran this on cloud vm
    # for even more cores/threads.
    with ProcessPoolExecutor(max_workers=workers_count) as executor:
        futures = [
            executor.submit(check_chunk, c, clean_hashes, global_start, i + 1)
            for i, c in enumerate(chunks)
        ]

        try:
            for future in as_completed(futures):
                chunk_results = future.result()
                if chunk_results:
                    for res in chunk_results:
                        all_found.append(res)
        except KeyboardInterrupt:
            print("\nAborting...")

    all_found.sort(key=lambda x: x["time"])
    print(f"\n{'WF':<4} | {'Salt':<23} | {'Password':<12} | {'Time':<8}")
    print("-" * 65)
    for res in all_found:
        print(
            f"{res['work_factor']:<4} | {res['salt']:<23} | {res['password']:<12} | {res['time']:.2f}s"
        )


if __name__ == "__main__":
    main()
