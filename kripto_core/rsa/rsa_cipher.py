import sys
import struct


# IMPORTANT: The block size MUST be less than or equal to the key size!
# (Note: The block size is in bytes, the key size is in bits. There
# are 8 bits in 1 byte.)
DEFAULT_BLOCK_SIZE = 128  # 128 bytes
BYTE_SIZE = 256  # One byte has 256 different values.


def get_blocks_from_text(message, block_size=DEFAULT_BLOCK_SIZE):
    # konversi message (string) ke sebuah list berisi blok-blok
    # integer, setiap integer merepresentasikan 128 (sesuai dgn
    # ukuran blok) karakter string.

    block_ints = []
    for block_start in range(0, len(message), block_size):
        # Proses blok integer untuk blok teks ini
        block_int = 0
        for i in range(block_start, min(block_start + block_size, len(message))):
            # block_int += ord(message[i]) * (BYTE_SIZE ** (i % block_size))  # ini utk python 2.7
            block_int += message[i] * (BYTE_SIZE ** (i % block_size)) # ini utk python 3.X
        block_ints.append(block_int)
    return block_ints


def get_text_from_blocks(block_ints, message_length, block_size=DEFAULT_BLOCK_SIZE):
    # Konversi list berisi blok-blok integer menjadi original message
    # Ukuran original message diperlukan agar bisa mendekripsi blok integer terakhir dengan benar
    # message = []
    message = bytearray()
    for block_int in block_ints:
        # block_message = []
        block_message = bytearray()
        for i in range(block_size - 1, -1, -1):
            if len(message) + i < message_length:
                # Decode message string yang merupakan 128 (atau tergantung blocksize) blok karakter
                # dari blok integer ini.
                ascii_number = block_int // (BYTE_SIZE ** i)
                block_int = block_int % (BYTE_SIZE ** i)    # ini utk python 3.X
                # block_message.insert(0, chr(ascii_number))    # ini utk python 2.7
                block_message.insert(0, ascii_number)    # ini utk python 2.7
        # message.extend(block_message)
        message.extend(block_message)
    # return ''.join(message)
    return bytes(message)


def encrypt_message(message, key, block_size=DEFAULT_BLOCK_SIZE):
    # Konversi message (string) ke sebuah list berisi blok-blok integer, lalu enkripsi setiap blok integer.
    encrypted_blocks = []
    n, e_or_d = key
    for block in get_blocks_from_text(message, block_size):
        # ciphertext = plaintext ^ e mod n
        encrypted_blocks.append(pow(block, e_or_d, n))
    return encrypted_blocks


def decrypt_message(encrypted_blocks, message_length, key, block_size=DEFAULT_BLOCK_SIZE):
    # Dekripsi list berisi blok-blok integer menjadi original message.
    # Ukuran original message diperlukan agar bisa mendekripsi blok integer terakhir dengan benar
    decrypted_blocks = []
    n, e_or_d = key
    for block in encrypted_blocks:
        decrypted_blocks.append(pow(block, e_or_d, n))
    return get_text_from_blocks(decrypted_blocks, message_length, block_size)


def read_key_file(key_file):
    # Given the filename of a file that contains a public or private key,
    # return the key as a (n,e) or (n,d) tuple value.
    fo = open(key_file)
    content = fo.read()
    fo.close()
    key_size, n, e_or_d = content.split(',')
    return int(key_size), int(n), int(e_or_d)


##############################################################################
# buat se generik mungkin
def read_string_key(str_key):
    key_size, n, e_or_d = str_key.split(',')
    
    return {'key_size': int(key_size), 'n': int(n), 'e_or_d': int(e_or_d)}
##############################################################################


def encrypt(key, message, block_size=DEFAULT_BLOCK_SIZE):
    key_size, n, e_or_d = key  # unpack key (key bertipe tuple)

    # Periksa ukuran key
    if key_size < block_size * 8:  # * 8 to convert bytes to bits
        # sys.exit('ERROR: Cipher RSA mengharuskan ukuran blok lebih besar atau sama dengan ukuran kunci. Coba kurangi ukuran blok atau ubah ukuran kunci.' % (block_size * 8, key_size))
        sys.exit('ERROR: Ukuran blok adalah %s bit dan ukuran kunci %s bit. Cipher RSA mengharuskan ukuran blok lebih kecil atau sama dengan ukuran kunci. Coba tingkatkan ukuran blok atau ubah ukuran kunci.' % (block_size * 8, key_size))

    # Enkripsi message
    encrypted_blocks = encrypt_message(message=message, key=(n, e_or_d), block_size=block_size)

    '''
    # Convert the large int values to one string value.
    # for i in range(len(encrypted_blocks)):
    #     encrypted_blocks[i] = str(encrypted_blocks[i])
    #
    # encrypted_content = ''
    # # jika isi blok di dlm encryptedBlocks lebih dari 1
    # if len(encrypted_blocks) > 1:
    #     # bikin encryptedContent dengan memecah blok-blok menggunakan ','
    #     encrypted_content += ','.join(encrypted_blocks)
    # # tapi jika blok isinya hanya 1, tidak pakai ','
    # encrypted_content += encrypted_blocks[0]
    #
    # Write out the encrypted string to the output file.
    # output = '%s_%s_%s' % (len(message), block_size, encrypted_content)
    '''

    for i in range(len(encrypted_blocks)):
        encrypted_blocks[i] = str(encrypted_blocks[i])
    encrypted_content = ','.join(encrypted_blocks)

    # output adalah ciphertext/cipherfile
    output = '%s_%s_%s' % (len(message), block_size, encrypted_content)

    return output


digital_signature = encrypt


def decrypt(key, message):
    # Pakai kunci dari hasil baca file atau langsung dari argmumen
    # Baca encrypted message dari file kemudian dekripsi.
    # Mengembalikan decrypted message string
    key_size, n, e_or_d = key

    # ekstrak message
    message_length, block_size, encrypted_message = message.split('_')
    message_length = int(message_length)
    block_size = int(block_size)

    # Periksa ukuran key
    if key_size < block_size * 8:  # * 8 to convert bytes to bits
        sys.exit('ERROR: Ukuran blok adalah %s bit dan ukuran kunci %s bit. Cipher RSA mengharuskan ukuran blok lebih besar atau sama dengan ukuran kunci. Coba periksa apakah kunci dan pesan terenkripsi yang dimasukan benar!.' % (blockSize * 8, keySize))

    # Konversi encrypted message, dari blok-blok string menjadi blok-blok integer berukuran besar.
    encrypted_blocks = []

    '''
    # jika isi blok di dlm encryptedMessage lebih dari 1 (> 1)
    if len(encrypted_message) > 1:
        # ambil blok-blok dengan memisahkannya dari tanda ','
        for block in encrypted_message.split(','):
            encrypted_blocks.append(int(block))
    # isi blok kurang dari 1, langsung aja isi
    encrypted_blocks.append(int(block)) ######################################################### FIX THIS
    '''

    for block in encrypted_message.split(','):
        encrypted_blocks.append(int(block))

    # Dekripsi blok-blok integer
    return decrypt_message(encrypted_blocks=encrypted_blocks,
                           message_length=message_length, key=(n, e_or_d), block_size=block_size)


decrypt_signature = decrypt
