# Scripts to maintain RVD

### Import issues from sanitizer's result (e.g. ASan/TSan, etc.)

Fetch a token for your account and set it up in an env. variable. E.g.:
```bash
export GITHUB_TOKEN=11b0d091869e647e3db4baa4d71dcb5c3c6a18938 # exemplary token, don't expect it to work, generate your own
cd scripts/ # head to the scripts folder
python3 import_asan.py files/issues_moveit2.csv
```

### Produce summary
This script will re-generate README.md and make the corresponding changes automatically.
```bash
export GITHUB_TOKEN=11b0d091869e647e3db4baa4d71dcb5c3c6a18938 # exemplary token, don't expect it to work, generate your own
cd scripts/ # head to the scripts folder
python3 summary.py
```
