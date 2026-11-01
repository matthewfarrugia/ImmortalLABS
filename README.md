# ImmortalLABS

Python package to salvage the *free* LABS plugins I have downloaded on one computer and move them over to my other studio mac and continue using there.

## Prerequists

1. Have LABS version `1.5.1` or `3.7.29` installed and registered
2. Find the `Presets` and `Patches` folders for the instruments you want to move and note the path to these files
3. Needs `pip install mpmath`

## Steps

Generate the `machine-key.key` file needed. This key is the encryption key that the plug-in uses to encrypt the .zmulti / .zpreset / .zconfig files.
LABS will error when trying to parse these files on init if they are not encrypted with the same key as is derived from the machine's mac address + other identifiers.

```
./build_and_capture.sh
```

Decrypt your current LABS files, ensure you back up your original files, or use the --output parameter to ensure the original files remain as they are

```
python decrypt.py "path/to/LABS Content" --output "path/to/export"
```

Move the outputted raw files over to the new machine. Then on the new machine run `./build_and_capture.sh` again to generate _it's_ `machine-key.key` file.
And encrypt the raw files to the format the plug-in expects:

```
python encrypt.py "path/to/RAW Content" --output "path/to/export"
```

Note: You may need to add the content file paths to Spitfire.properties if not already registered.
