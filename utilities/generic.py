import base64
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

    def b64_encode(
        self,
        data: bytes,
    ) -> bytes:
        return base64.b64encode(data)

    def b64_decode(
        self,
        data: bytes,
    ) -> bytes:
        return base64.b64decode(data)