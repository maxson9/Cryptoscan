import pyewf
import pytsk3


def open_image(image_path):
    if image_path.endswith('.E01'):
        return open_e01(image_path)
    elif image_path.endswith('.001'):
        return open_raw(image_path)
    else:
        raise ValueError("Unsupported image format")

def open_raw(raw_image_path):
    try:
        image = pytsk3.Img_Info(raw_image_path)
        return image
    except Exception as e:
        raise IOError(f"Error opening raw image: {e}")

def open_e01(e01_image_path):
    try:
        filenames = pyewf.glob(e01_image_path)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames, "r")
        return EWFImgInfo(ewf_handle)
    except Exception as e:
        raise IOError(f"Error opening E01 image: {e}")

class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()

# Replace this with the path to your image file (either .E01 or .raw)
image_path = "USB.001"

# Open the image
image = open_image(image_path)
print(image)

try:
    vs = pytsk3.Volume_Info(image)
except IOError:
    print("No volume system found")
    vs = None

def process_directory(directory, parent_path, depth=0, max_depth=10):
    if depth > max_depth:
        return

    for entry in directory:
        if entry.info.name.name in [".", ".."]:
            continue

        file_path = f"{parent_path}/{entry.info.name.name}"

        try:
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                sub_directory = entry.as_directory()
                path = f"{parent_path}/{entry.info.name.name}"
                process_directory(sub_directory, path, depth + 1, max_depth)
            else:
                # Read and process file data
                file_data = entry.read()
                # Do something with the file_data (e.g., save it to a file)
                print(f"Found file: {file_path}")
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

if vs is not None:
    for volume in vs:
        print(f"Processing volume: {volume.addr}")
        try:
            fs = pytsk3.FS_Info(image, offset=volume.start * vs.info.block_size)
            root_dir = fs.open_dir(path="/")
            process_directory(root_dir, f"Volume {volume.addr}", 0)
        except IOError as e:
            print(f"Unable to open FS on volume {volume.addr}: {e}")

else:
    try:
        fs = pytsk3.FS_Info(image)
        root_dir = fs.open_dir(path="/")
        process_directory(root_dir, "/", 0)
    except IOError as e:
        print(f"Unable to open filesystem: {e}")

# Close the image handle
if hasattr(image, "close"):
    image.close()