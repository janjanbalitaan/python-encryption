import os

class Generic:

    def save_bytes_to_file(
        self,
        file_bytes: bytes,
        file_path: str,
        file_name: str,
    ):
        f = open(os.path.join(file_path, file_name), 'wb')
        f.write(file_bytes)
        f.close()