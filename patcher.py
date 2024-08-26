import argparse
import shutil

from pathlib import Path
from trainzutil import TrainzError, TrainzUtil

SPEEDTREE_LIB_KUID = "kuid:401543:1077"


class SignatureException(Exception):
    pass


def find_pattern(data, signature, mask=None, start=None, maxit=None):
    sig_len = len(signature)

    if start is None:
        start = 0

    stop = len(data) - len(signature)

    if maxit is not None:
        stop = start + maxit

    if mask:
        assert sig_len == len(mask), "mask must be as long as the signature!"

        for i in range(sig_len):
            signature[i] &= mask[i]

    for i in range(start, stop):
        matches = 0

        while signature[matches] is None or signature[matches] == (data[i + matches] & (mask[matches] if mask else 0xFF)):
            matches += 1

            if matches == sig_len:
                return i

    raise SignatureException("Pattern not found!")


def patch_trainz_exe(trainz_path: Path):
    input_file = trainz_path / "bin" / "trainz.exe"
    backup_file = input_file.with_suffix(input_file.suffix + ".bak")

    # restore the backup if it exists
    if backup_file.exists():
        backup_file.replace(input_file)

    # create a backup of the original file
    shutil.copy(input_file, backup_file)

    with open(input_file, "r+b") as f:
        data = bytearray(f.read())

        # find the pattern "C2 08 00 6A 08", offset by 3 and replace the following 14 bytes with NOPs
        sig = [0xC2, 0x08, 0x00, 0x6A, 0x08]
        offset = find_pattern(data, sig) + 3
        data[offset:offset + 14] = [0x90] * 14

        # save the patched file
        f.seek(0)
        f.write(data)


def patch_tni_dll(trainz_path: Path):
    input_file = trainz_path / "bin" / "trainznativeinterface.dll"
    backup_file = input_file.with_suffix(input_file.suffix + ".bak")

    # restore the backup if it exists
    if backup_file.exists():
        backup_file.replace(input_file)

    # create a backup of the original file
    shutil.copy(input_file, backup_file)

    with open(input_file, "r+b") as f:
        data = bytearray(f.read())
        
        # find the pattern "8B 44 24 04 8B 40 1C 85 C0 75", offset by 7
        sig = [0x8b, 0x44, 0x24, 0x04, 0x8b, 0x40, 0x1c, 0x85, 0xc0, 0x75]
        offset = find_pattern(data, sig) + 7
        data[offset:offset + 4] = [0xb0, 0x01, 0xc3, 0x90]

        # save the patched file
        f.seek(0)
        f.write(data)


def copy_speedtree_dll(trainz_path: Path):
    speedtree_dll = Path("TNISpeedTree.dll")

    # check if the SpeedTree DLL exists
    if not speedtree_dll.exists():
        print("SpeedTree DLL not found at:", speedtree_dll)
        return

    shutil.copy(speedtree_dll, trainz_path / "bin" / "plugins" / speedtree_dll.name)


def main(trainz_path: Path, accept_license: bool):
    trainzutil: TrainzUtil

    try:
        trainzutil = TrainzUtil(trainz_path)
    except FileNotFoundError:
        print("TrainzUtil.exe not found at:", trainz_path)
        return

    if not accept_license:
        print("You must accept the license agreement before running this patcher!")
        print("Do you accept the license agreement? (Y/n)")

        if input() != "Y":
            return

    patch_trainz_exe(trainz_path)
    patch_tni_dll(trainz_path)

    if not (trainz_path / "bin" / "plugins" / "TNISpeedTree.dll").exists():
        try:
            copy_speedtree_dll(trainz_path)
        except Exception as e:
            print("Failed to copy SpeedTree DLL:", e)
            return

    trainzutil.delete_asset(SPEEDTREE_LIB_KUID)

    try:
        trainzutil.install_cdp(Path("SpeedTreeLibrary.cdp").absolute())
        trainzutil.commit_asset(SPEEDTREE_LIB_KUID)
    except TrainzError as e:
        print("Failed to commit SpeedTree library:", e)
        return

    print("Patching complete!")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Patches Trainz to allow the SpeedTree plugin to work")
    parser.add_argument("trainz_path", type=Path, help="path to the Trainz installation directory")
    parser.add_argument("--accept-license", action="store_true", help="skip the license agreement prompt")

    args = parser.parse_args()

    try:
        main(args.trainz_path, args.accept_license)
    except KeyboardInterrupt:
        pass
