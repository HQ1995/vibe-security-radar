#!/usr/bin/env python3
import os
import subprocess

ROOT = "/home/hanqing/.cache/ghsa200-sweep-fetch"
TARGETS = {
    "documenso/documenso": [
        "0d65693d5570b7106d60740d37d03d22d60d740a",
        "4babe9b1920ad886130cfa0c041ff67218631d80",
        "7ea664214ab25e064443c6eed31016fafdd78147",
        "93137c63966e472ecaa3c153cf21a0af458bf918",
    ],
    "ModelEngine-Group/nexent": [
        "420c2ac395882c43980ecbd3f611fee4a3abf4e0",
        "66a571806245fe42e1330f5c1d75a72898e71735",
        "98a95098645696888a8198f9f1a59136d7c6162c",
    ],
    "themactep/thingino-firmware": ["1cef36616fe6268eb3b5bf56da4d7c4c5d191018"],
    "xpp3901/CVE_APPLY": [
        "73e56f2584caded944e727a910d7948eeec1b57b",
        "ab8284fc1dc1f58cdf8f18d602147f4d12b20479",
        "b46851245c45f9c331129f27a4624070fd5b292a",
        "d48271437b79126f319268d04c63d4e585409b81",
        "e64c983bbe48254649b7ca7598bb7e6a8cdbb5aa",
    ],
    "huangjunsen0406/xiaozhi-mcphub": [
        "81c3091a5c4071d082a79233f2aa006ec8f9bc0b",
        "83cbd16821939c31b68e3c68b6d8f0b6f3be62ed",
        "976e90679df07d8f2c91cc9eae566aa5fb2aeb03",
    ],
    "kubev2v/migration-planner-ui-app": ["da0182724a58db760a71391abb244190822e134a"],
    "TwiN/gatus": [
        "2be0bd717db9298cfbe71364fffffe34bd846336",
        "42b51f5da58af5ad67bfe04ae5a24a695fce04f3",
        "4566e746f35cb02145bbf191bf6b4afad5800c1c",
    ],
}


def main():
    for repo, shas in TARGETS.items():
        key = repo.replace("/", "__")
        path = ROOT + "/" + key
        url = "https://github.com/" + repo + ".git"
        if not os.path.isdir(path):
            subprocess.run(["git", "--no-optional-locks", "init", "-q", "--bare", path],
                           capture_output=True)
        r = subprocess.run(
            ["git", "--no-optional-locks", "-C", path, "fetch", "-q",
             "--filter=blob:none", "--depth", "1", url] + shas,
            capture_output=True, text=True, timeout=300)
        print(repo, "rc", r.returncode, r.stderr.strip()[:120])
        for s in shas:
            chk = subprocess.run(["git", "-C", path, "cat-file", "-e", s + "^{commit}"],
                                 capture_output=True)
            print("  ", s[:10], "present" if chk.returncode == 0 else "MISSING")


if __name__ == "__main__":
    main()
