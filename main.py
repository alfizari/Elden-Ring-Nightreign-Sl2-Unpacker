## ALL THIS SCRIPT IS FROM JTESTA AT GITHUB: https://github.com/jtesta/souls_givifier. A MODFIED VERSION OF THE SCRIPT TO HANDE DECRYPT AND ENCRYPT OF THE DS2 SL2 FILES.
#ALL THE CREDIT GOES TO JTESTA and Nordgaren: https://github.com/Nordgaren/ArmoredCore6SaveTransferTool


import os
import sys
import struct
import hashlib
from tkinter import ttk, filedialog, messagebox
import tkinter as tk
from typing import Optional, Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Optional



window = tk.Tk()
window.title("ER Nightreign Sl2 unpacker")
window.geometry("300x200")
window.resizable(True, True)

#nightreign sl2 key
DS2_KEY = b'\x18\xF6\x32\x66\x05\xBD\x17\x8A\x55\x24\x52\x3A\xC0\xA0\xC6\x09'
DEBUG_MODE = False
input_file = None

def bytes_to_intstr(byte_array: bytes) -> str:
    ret = ''
    for _, i in enumerate(byte_array):
        ret += "%u," % i
    return ret[0:-1]


def debug(msg: str = '') -> None:
    if DEBUG_MODE:
        print(msg)


def calculate_md5(data: bytes) -> bytes:

    return hashlib.md5(data).digest()

IV_SIZE = 0x10
PADDING_SIZE = 0xC
START_OF_CHECKSUM_DATA = 4  # sizeof(int)
END_OF_CHECKSUM_DATA = PADDING_SIZE + 16  # 0xC + MD5 hash size (16 bytes) = 28

class BND4Entry:
    def __init__(self, raw_data: bytes, index: int, output_folder: str, size: int, offset: int, name_offset: int, footer_length: int, data_offset: int):
        self.index = index
        self._index = index
        self.size = size
        self.data_offset = data_offset
        self.footer_length = footer_length
        self._raw_data = raw_data
        self._encrypted_data = raw_data[offset:offset + size]
        self._decrypted_slot_path = output_folder
        self._name = f"USERDATA_{index:02d}"
        self._clean_data = b''
        
        # Extract IV from beginning of encrypted data
        self._iv = self._encrypted_data[:IV_SIZE]
        self._encrypted_payload = self._encrypted_data[IV_SIZE:]
    
    def decrypt(self) -> None:
        try:
            decryptor = Cipher(algorithms.AES(DS2_KEY), modes.CBC(self._iv)).decryptor()
            decrypted_raw = decryptor.update(self._encrypted_payload) + decryptor.finalize()
            
            self._clean_data = decrypted_raw 
            print(f"Entry {self._index}: Decrypted {len(decrypted_raw)} bytes")
            
            if self._decrypted_slot_path:
                os.makedirs(self._decrypted_slot_path, exist_ok=True)
                output_path = os.path.join(self._decrypted_slot_path, self._name)
                with open(output_path, 'wb') as f:
                    f.write(self._clean_data)
            self.decrypted = True
            
        except Exception as e:
            print(f"Error decrypting entry {self._index}: {str(e)}")
            raise
    
    def patch_checksum(self):
        checksum = self.calculate_checksum()
        checksum_end = len(self._clean_data) - END_OF_CHECKSUM_DATA
        
        # Replace checksum at the calculated position
        self._clean_data = (
            self._clean_data[:checksum_end] +
            checksum +
            self._clean_data[checksum_end + 16:]
        )
    
    def calculate_checksum(self) -> bytes:
        checksum_end = len(self._clean_data) - END_OF_CHECKSUM_DATA
        data_for_hash = self._clean_data[START_OF_CHECKSUM_DATA:checksum_end]
        return hashlib.md5(data_for_hash).digest()
    
    def encrypt_sl2_data(self) -> bytes:
        encryptor = Cipher(algorithms.AES(DS2_KEY), modes.CBC(self._iv)).encryptor()
        encrypted_payload = encryptor.update(self._clean_data) + encryptor.finalize()
        return self._iv + encrypted_payload
    

def process_entries_in_order(entries):
        sorted_entries = sorted(entries, key=lambda e: e.index)
        debug(f"Processing {len(sorted_entries)} entries in index order")
        
        for entry in sorted_entries:
            debug(f"Processing entry {entry.index}: {entry._name}")
            entry.decrypt()
        
        return sorted_entries

def get_input() -> Optional[str]:
    return filedialog.askopenfilename(
        title="Select Encrypted SL2 File",
        filetypes=[("SL2 Files", "*.sl2"), ("All Files", "*.*")]
    )


def decrypt_ds2_sl2(log_callback=None) -> Dict[int, str]:
    global original_sl2_path
    global input_decrypted_path
    global bnd4_entries
    global input_file
    global raw 
    
    if not input_file:
        input_file = get_input()

    if not input_file:
        return None

    original_sl2_path = input_file

    def log(message):
        if log_callback:
            log_callback(message)
        debug(message)

    try:
        with open(input_file, 'rb') as f:
            raw = f.read()
    except Exception as e:
        log(f"ERROR: Could not read input file: {e}")
        return {}
    
    log(f"Read {len(raw)} bytes from {input_file}.")
    if raw[0:4] != b'BND4':
        log("ERROR: 'BND4' header not found! This doesn't appear to be a valid SL2 file.")
        return {}
    else:
        log("Found BND4 header.")

    num_bnd4_entries = struct.unpack("<i", raw[12:16])[0]
    log(f"Number of BND4 entries: {num_bnd4_entries}")

    unicode_flag = (raw[48] == 1)
    log(f"Unicode flag: {unicode_flag}")
    log("")

    BND4_HEADER_LEN = 64
    BND4_ENTRY_HEADER_LEN = 32

    slot_occupancy = {}
    bnd4_entries = []
    successful_decryptions = 0

    # Process all BND4 entries
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_folder = filedialog.askdirectory(title='Select were to save the decrypted files')
    input_decrypted_path = output_folder
    
    for i in range(num_bnd4_entries):
        pos = BND4_HEADER_LEN + (BND4_ENTRY_HEADER_LEN * i)
        
        if pos + BND4_ENTRY_HEADER_LEN > len(raw):
            log(f"Warning: File too small to read entry #{i} header")
            break
            
        entry_header = raw[pos:pos + BND4_ENTRY_HEADER_LEN]

        if entry_header[0:8] != b'\x40\x00\x00\x00\xff\xff\xff\xff':
            log(f"Warning: Entry header #{i} does not match expected magic value - skipping")
            continue

        entry_size = struct.unpack("<i", entry_header[8:12])[0]
        entry_data_offset = struct.unpack("<i", entry_header[16:20])[0]
        entry_name_offset = struct.unpack("<i", entry_header[20:24])[0]
        entry_footer_length = struct.unpack("<i", entry_header[24:28])[0]
        
        # Validity checks
        if entry_size <= 0 or entry_size > 1000000000:  # Sanity check for size
            log(f"Warning: Entry #{i} has invalid size: {entry_size} - skipping")
            continue
            
        if entry_data_offset <= 0 or entry_data_offset + entry_size > len(raw):
            log(f"Warning: Entry #{i} has invalid data offset: {entry_data_offset} - skipping")
            continue
            
        if entry_name_offset <= 0 or entry_name_offset >= len(raw):
            log(f"Warning: Entry #{i} has invalid name offset: {entry_name_offset} - skipping")
            continue

        log(f"Processing Entry #{i} (Size: {entry_size}, Offset: {entry_data_offset})")

        try:
            entry = BND4Entry(
                raw_data=raw, 
                index=i, 
                output_folder=output_folder, 
                size=entry_size, 
                offset=entry_data_offset,
                name_offset=entry_name_offset, 
                footer_length=entry_footer_length, 
                data_offset=entry_data_offset  
            )
            
            try:
                entry.decrypt()
                bnd4_entries.append(entry)
                successful_decryptions += 1
                log(f"Successfully decrypted entry #{i}: {entry._name}")
            except Exception as e:
                log(f"Error decrypting entry #{i}: {str(e)}")
                continue
                    
        except Exception as e:
            log(f"Error processing entry #{i}: {str(e)}")
            continue
    messagebox.showinfo("Success", "Files have been decrypted.")    
    log(f"\nDONE! Successfully decrypted {successful_decryptions} of {num_bnd4_entries} entries.")

    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypted_output")




    
    
def get_output() -> Optional[str]:
    filename = filedialog.asksaveasfilename(
        title="Save Encrypted SL2 File As",
        filetypes=[("SL2 Files", "*.sl2"), ("All Files", "*.*")],
        defaultextension=".sl2",
        initialfile="NR0000.sl2"
    )
    if filename:
        print(f"Selected output SL2 file: {filename}") 
        return filename
    return None

raw = b''
def read_input():
    global input_file, raw

    if not input_file:
        print("ERROR: input_file is not set. Call decrypt_ds2_sl2() first.")
        sys.exit(1)

    original_sl2_path = input_file

    with open(original_sl2_path, 'rb') as f:
        raw = f.read()

    debug("Read %u bytes from %s." % (len(raw), original_sl2_path))

    if raw[0:4] != b'BND4':
        print("ERROR: 'BND4' header not found!")
        sys.exit(-1)
    else:
        debug("Found BND4 header.")

    num_bnd4_entries = struct.unpack("<i", raw[12:16])[0]
    debug("Number of BND4 entries: %u" % num_bnd4_entries)

    unicode_flag = (raw[48] == 1)
    debug("Unicode flag: %r" % unicode_flag)
    debug()

    return raw, num_bnd4_entries, unicode_flag


slot_occupancy = {}
bnd4_entries = []
BND4_HEADER_LEN = 64
BND4_ENTRY_HEADER_LEN = 32


def encrypt_modified_files():
    global raw, bnd4_entries, original_sl2_path
    
    # Load original SL2 file
    with open(original_sl2_path, 'rb') as f:
        original_data = f.read()
    print(f"Original file size: {len(original_data)} bytes")
    
    new_data = bytearray(original_data)
    output_folder = filedialog.askdirectory(title="Choose the decrypted output folder")
    
    for entry in bnd4_entries:
        filename = f"USERDATA_{entry.index:02d}"
        file_path = os.path.join(output_folder, filename)
        
        if not os.path.exists(file_path):
            continue
        
        print(f"\nProcessing {filename}:")
        
        # Load the modified decrypted data
        with open(file_path, 'rb') as f:
            modified_data = f.read()
        print(f"  Modified data size: {len(modified_data)} bytes")
        
        # Update the entry's clean data with the modified data
        entry._clean_data = bytearray(modified_data)
        #Checksum on the data
        entry.patch_checksum()
        print(f"  New checksum calculated and patched")
        

        encrypted_entry_data = entry.encrypt_sl2_data()
        print(f"  Encrypted data size: {len(encrypted_entry_data)} bytes")
        

        if len(encrypted_entry_data) != entry.size:
            print(f"  WARNING: Size mismatch! Expected {entry.size}, got {len(encrypted_entry_data)}")
            continue
        
        data_start = entry.data_offset
        new_data[data_start:data_start + len(encrypted_entry_data)] = encrypted_entry_data
        
        print(f"Successfully processed {filename}")
    output_sl2_file= get_output()
    with open(output_sl2_file, 'wb') as f:
        f.write(new_data)
    messagebox.showinfo("Success", "Files have been Encrypted.")    
    
    print(f"\n=== Final Result ===")
    print(f"Original size: {len(original_data)} bytes")
    print(f"New size: {len(new_data)} bytes")
    print(f"Saved to: {output_sl2_file}")
    if len(new_data) == len(original_data):
        print("Perfect size match!")
    else:
        print("Size difference")
#UI
window.columnconfigure(0, weight=1)
window.rowconfigure(0, weight=1)

# Create main frame with padding
main_frame = ttk.Frame(window, padding=10)
main_frame.grid(row=0, column=0, sticky="nsew")

# Allow content in main_frame to expand
main_frame.columnconfigure(0, weight=1)
main_frame.rowconfigure(0, weight=1)

# Styling constants
button_width = 20
button_padding_y = 15
button_padding_x = 20

# Add buttons using grid
decrypt_button = ttk.Button(main_frame, text="Decrypt File", width=button_width, command=decrypt_ds2_sl2)
decrypt_button.grid(row=0, column=0, pady=button_padding_y, padx=button_padding_x)

encrypt_button = ttk.Button(main_frame, text="Encrypt Files", width=button_width, command=encrypt_modified_files)
encrypt_button.grid(row=1, column=0, pady=button_padding_y, padx=button_padding_x)

# Run the application
window.mainloop()
