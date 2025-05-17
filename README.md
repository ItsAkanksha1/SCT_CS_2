##Image_Encryption

````markdown
# Image Encryptor - Tkinter Application

A simple GUI-based **Image Encryptor** and **Decryptor** built with Python's Tkinter and cryptography libraries. This application allows you to encrypt and decrypt image files (`.png`, `.jpg`, `.jpeg`) using AES encryption implemented with the `cryptography.fernet` module.

---

## Features

- **Encrypt images** with a user-provided key or a generated AES key.
- **Decrypt encrypted images** back to their original form.
- **Key Strength Indicator**: Shows if your encryption key is weak, medium, or strong based on length and character variety.
- **Theme toggle** between dark and light modes for better user experience.
- Easy file selection via a file dialog.
- Shows status updates for selected files and encryption/decryption results.

---

## Requirements

- Python 3.6+
- Libraries:
  - `tkinter` (usually comes pre-installed with Python)
  - `cryptography`
  - `Pillow`

Install dependencies with pip:

```bash
pip install cryptography Pillow
````

---

## Usage

1. Run the script:

```bash
python image_encryptor.py
```

2. Enter an encryption key or click **Generate Key** to create a strong key automatically.
3. Choose an image file (`.png`, `.jpg`, `.jpeg`) by clicking **Choose Image**.
4. Click **Encrypt** to encrypt the selected image. The encrypted file will be saved in the same directory with `.enc` appended.
5. To decrypt, select the `.enc` file, enter the correct key, and click **Decrypt**. The decrypted image will be saved with `_decrypted.png` suffix.
6. Use the **Toggle Theme** checkbox to switch between dark and light modes.

---

## Notes

* The encryption key must be the exact key used for encryption to successfully decrypt the file.
* The key strength validation is a simple heuristic:

  * Weak: Less than 8 characters.
  * Medium: Contains uppercase or digits but not special characters.
  * Strong: Contains uppercase letters, digits, and special characters.
* Only PNG, JPG, and JPEG images are supported.

---
## License

This project is licensed under the MIT License.

---

## Author

*Akanksha*
*akjha4754@gmail.com*

---

Feel free to contribute or open issues for suggestions and bug reports!
