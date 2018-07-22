from make_rsa_keys import *
from rsa_cipher import *
import sys
import os
import time
import timeit
import datetime
import random
from hurry.filesize import size, alternative


# lokasi_hasil_test = '/hasil_test_rsa/'
lokasi_hasil_test = os.path.join(os.getcwd(), 'hasil_test_rsa')
# buat lokasi hasil test
if not os.path.exists(lokasi_hasil_test):
    os.mkdir(lokasi_hasil_test)


def main():
    jumlah_iterasi = int(sys.argv[1])

    for i in range(jumlah_iterasi):
        message_size = random.randrange(10241, 1024001)  # antara 10KB dan 1000KB
        message = os.urandom(message_size)
        keysize = 1024

        keygen_start = time.time()
        pubkey, privkey = generate_key(keysize, silent=True)
        keygen_end = time.time()
        keygen_time = keygen_end - keygen_start

        pubkey = keysize, pubkey[0], pubkey[1]
        privkey = keysize, privkey[0], privkey[1]
        encrypted_message = ''
        try:
            enc_start = time.time()
            encrypted_message += encrypt(pubkey, message, 128)
            enc_end = time.time()
            enc_time = enc_end - enc_start

            dec_start = time.time()
            decrypted_message = decrypt(privkey, encrypted_message)
            dec_end = time.time()
            dec_time = dec_end - dec_start
        except:
            print('Iterasi ke-%d: (ERROR 1) Terjadi kesalahan pada proses enkripsi/dekripsi' % i)
            continue
        else:
            if decrypted_message != message:
                print('Iterasi ke-%d: (ERROR 2) message tidak sama dengan decrypted_message' % i)
                continue

            print()
            print("=" * 50)
            print("Iterasi ke-%d" % i)
            print("Waktu pembuatan kunci berukuran %d-bits: %6.4f secs" % (keysize, keygen_time))
            # print("Encrypt time: %6.4f secs, or about %dKB per sec" % (enc_time, len(message) / (enc_time * 1000)))
            # print("Decrypt time: %6.4f secs, or about %dKB per sec" % (enc_time, len(message) / (enc_time * 1000)))

            # print("Waktu enkripsi message berukuran %d: %6.4f detik per KB" % (len(decrypted_message), enc_time))
            # print("Waktu dekripsi encrypted_message berukuran %d: %6.4f detik per KB" % (len(decrypted_message), dec_time))

            print("Waktu enkripsi message berukuran %s adalah %6.4f detik atau sekitar %.2fKB per detik" % (size(len(message), system=alternative), enc_time, len(message) / (enc_time * 1024)))
            print("Waktu dekripsi encrypted_message berukuran %s adalah %6.4f detik atau sekitar %.2fKB per detik" % (size(len(encrypted_message), system=alternative), dec_time, len(encrypted_message) / (dec_time * 1024)))
            print("=" * 50)
            print()


def test_pembuatan_kunci_rsa(jumlah_iterasi=10, keysize=1024, nama_file_csv='hasil_test_pembuatan_kunci_rsa.csv'):
    print '-' * 50
    print 'Mulai test_pembuatan_kunci_rsa:', datetime.datetime.now()
    mulai_proses = timeit.default_timer()

    # periksa keberadaan lokasi output
    output_dir_path = os.path.join(lokasi_hasil_test, 'rsa_kunci')
    if not os.path.exists(output_dir_path):
        os.mkdir(output_dir_path)

    # periksa keberadaan file csv
    if os.path.exists(os.path.join(output_dir_path, nama_file_csv)):
        sys.exit('WARNING: File %s sudah ada di lokasi %s\nPakai nama yang lain atau hapus file ini kemudian jalankan ulang program.' % (nama_file_csv, output_dir_path))

    csv = open(os.path.join(output_dir_path, nama_file_csv), 'w')
    # tulis row title
    columnTitleRow = '{},{},{},{},{}\n'.format('iterasi ke', 'n', 'e', 'd', 'waktu generate')
    csv.write(columnTitleRow)

    for i in range(1, jumlah_iterasi + 1):
        keygen_start = time.time()
        pubkey, privkey = generate_key(keysize, silent=True)
        keygen_end = time.time()
        keygen_time = keygen_end - keygen_start

        n = len(str(pubkey[0]))
        e = len(str(pubkey[1]))
        d = len(str(privkey[1]))
        row = '{},{},{},{},{:6.4f}\n'.format(i, n, e, d, keygen_time)
        # print(row)
        csv.write(row)
    csv.close()

    selesai_proses = timeit.default_timer()
    waktu_keseluruhan = datetime.timedelta(seconds=selesai_proses - mulai_proses)
    print 'Selesai test_pembuatan_kunci_rsa:', datetime.datetime.now()
    print 'Waktu yg dibutuhkan test_pembuatan_kunci_rsa: %s' % waktu_keseluruhan
    print '<jumlah_iterasi>: %d' % jumlah_iterasi
    print '<keysize>: %d' % keysize
    print '<nama_file_csv>: %s' % nama_file_csv
    print 'lokasi csv disimpan: %s' % output_dir_path
    print '-' * 50


def test_enkirpsi_dekripsi_rsa_byte_acak(keysize=1024, blocksize=128, nama_file_csv='hasil_test_enkripsi_dekripsi_rsa_byte_acak.csv'):
    print '-' * 50
    print 'Mulai test_enkirpsi_dekripsi_rsa_byte_acak:', datetime.datetime.now()
    mulai_proses = timeit.default_timer()

    # periksa keberadaan lokasi output
    output_dir_path = os.path.join(lokasi_hasil_test, 'rsa_byte_acak')
    if not os.path.exists(output_dir_path):
        os.mkdir(output_dir_path)

    # periksa keberadaan file csv
    if os.path.exists(os.path.join(output_dir_path, nama_file_csv)):
        sys.exit('WARNING: File %s sudah ada di lokasi %s\nPakai nama yang lain atau hapus file ini kemudian jalankan ulang program.' % (nama_file_csv, output_dir_path))

    # ukuran_message = (32, 64, 128, 256, 512, 1024, 2048, 10240, 20480, 51200, 102400, 204800, 512000, 1048576)  # makan waktu lama
    ukuran_message = (32, 64, 128, 256, 512)  # cepat
    # ukuran_message = (32, 64, 128, 256, 512, 1024, 2048, 3072, 4096, 10240, 102400)  # gak terlalu lama

    # buat pubkey, privkey
    pubkey, privkey = generate_key(keysize, silent=True)
    pubkey = keysize, pubkey[0], pubkey[1]
    privkey = keysize, privkey[0], privkey[1]

    csv = open(os.path.join(output_dir_path, nama_file_csv), 'w')
    # tulis row title
    columnTitleRow = '{},{},{},{}\n'.format('Data ke', 'ukuran data', 'waktu enkripsi', 'waktu dekripsi')
    csv.write(columnTitleRow)

    # loop utk setiap byte acak
    for index, ukuran in enumerate(ukuran_message):
        message = os.urandom(ukuran)
        enc_start = timeit.default_timer()
        encrypted_message = encrypt(pubkey, message, blocksize)
        enc_end = timeit.default_timer()
        enc_time = enc_end - enc_start

        dec_start = timeit.default_timer()
        decrypt(privkey, encrypted_message)
        dec_end = timeit.default_timer()
        dec_time = dec_end - dec_start

        row = '{},{},{:6.4f},{:6.4f}\n'.format(index + 1, ukuran, enc_time, dec_time)
        # print row
        csv.write(row)
    csv.close()

    selesai_proses = timeit.default_timer()
    waktu_keseluruhan = datetime.timedelta(seconds=selesai_proses - mulai_proses)
    print 'Selesai test_enkirpsi_dekripsi_rsa_byte_acak:', datetime.datetime.now()
    print 'Waktu yg dibutuhkan test_enkirpsi_dekripsi_rsa_byte_acak: %s' % waktu_keseluruhan
    print '<keysize>: %d' % keysize
    print '<blocksize>: %d' % blocksize
    print '<nama_file_csv>: %s' % nama_file_csv
    print 'lokasi csv disimpan: %s' % output_dir_path
    print '-' * 50


def test_enkirpsi_dekripsi_rsa_file(input_dir_path='', keysize=1028, blocksize=128):
    print '-' * 50
    print 'Mulai test_enkirpsi_dekripsi_rsa_file:', datetime.datetime.now()
    mulai_proses = timeit.default_timer()

    # periksa keberadaan lokasi input
    if not os.path.exists(input_dir_path):
        sys.exit("WARNING: Lokasi %s tidak ditemukan!\nPeriksa kembali lokasi tersebut lalu jalankan ulang program." % input_dir_path)

    # periksa keberadaan lokasi output
    output_dir_path = os.path.join(lokasi_hasil_test, 'rsa_file')
    if os.path.exists(output_dir_path):
        sys.exit('WARNING: Folder %s sudah ada di lokasi %s\nHapus terlebih dahulu folder tersebut dan jalankan ulang program.' % ('rsa_file', lokasi_hasil_test))
    else:
        os.mkdir(output_dir_path)

    # buat lokasi report
    report_dir_path = os.path.join(output_dir_path, 'report')
    os.mkdir(report_dir_path)

    list_of_filenames = next(os.walk(input_dir_path))[2]  # hanya file saja tidak termasuk directory
    # listOfFilePaths = [os.path.join(input_dir_path, fn) for fn in listOfFileNames]
    # d = dict(zip(listOfFileNames, listOfFilePaths))

    pubkey, privkey = generate_key(keysize, silent=True)
    pubkey = keysize, pubkey[0], pubkey[1]
    privkey = keysize, privkey[0], privkey[1]

    nama_file_csv = 'hasil_test_enkripsi_dekripsi_rsa_dgn_file.csv'
    csv = open(os.path.join(report_dir_path, nama_file_csv), 'w')
    # tulis row title
    columnTitleRow = '{},{},{},{},{},{},{},{},{}\n'.format('no', 'nama file', 'tipe file', 'ukuran file', 'ukuran cipherfile', 'lama proses enkripsi', 'enkripsi data (KB/sec)', 'lama proses dekripsi', 'dekripsi data (KB/sec)')
    csv.write(columnTitleRow)

    # proses setiap file
    for index, fn in enumerate(list_of_filenames):
        input_file_path = os.path.join(input_dir_path, fn)  # fn adalah file name
        f = open(input_file_path, 'rb')
        message = f.read()
        f.close()

        file_type = os.path.splitext(fn)[1]
        file_length = len(message)

        enc_start = timeit.default_timer()
        encrypted_message = encrypt(pubkey, message, blocksize)  # byte
        enc_end = timeit.default_timer()
        enc_time = enc_end - enc_start
        enc_data_per_sec = file_length / (enc_time * 1024)
        cipherfile_length = len(encrypted_message)

        dec_start = timeit.default_timer()
        decrypted_message = decrypt(privkey, encrypted_message)
        dec_end = timeit.default_timer()
        dec_time = dec_end - dec_start
        dec_data_per_sec = file_length / (dec_time * 1024)

        # buat cipherfile
        output_file_path = os.path.join(output_dir_path, fn + '.enc')
        f = open(output_file_path, 'wb')
        f.write(encrypted_message)
        f.close()

        # buat file hasil dekripsi (file sebelum dienkripsi)
        output_file_path = os.path.join(output_dir_path, fn)
        f = open(output_file_path, 'wb')
        f.write(decrypted_message)
        f.close()

        # row = '{},{},{},{},{},{:6.4f},{:.2f},{:6.4f},{:.2f}\n'.format(index + 1, fn, file_type, file_length, cipherfile_length, enc_time, enc_data_per_sec, dec_time, dec_data_per_sec)
        row = '%d,%s,%s,%d,%d,%6.4f,%.2f,%6.4f,%.2f\n' % (index + 1, fn, file_type, file_length, cipherfile_length, enc_time, enc_data_per_sec, dec_time, dec_data_per_sec)
        # print row
        csv.write(row)
    csv.close()

    selesai_proses = timeit.default_timer()
    waktu_keseluruhan = datetime.timedelta(seconds=selesai_proses - mulai_proses)
    print 'Selesai test_enkirpsi_dekripsi_rsa_file:', datetime.datetime.now()
    print 'Waktu yg dibutuhkan test_enkirpsi_dekripsi_rsa_file: %s' % waktu_keseluruhan
    print '<input_dir_path>: %s' % input_dir_path
    print '<keysize>: %d' % keysize
    print '<blocksize>: %d' % blocksize
    print '<nama_file_csv>: %s' % nama_file_csv
    print 'lokasi csv disimpan: %s' % report_dir_path
    print '-' * 50


def test_custom_rsa():
    print '*' * 50
    print "Mulai test_custom_rsa"
    print '*' * 50
    list_nama_file_csv = ['rsa_1024_128.csv', 'rsa_2048_256.csv', 'rsa_4096_512.csv']
    keysize_blocksize = [(1024, 128), (2048, 256), (4096, 512)]

    for i in range(len(keysize_blocksize)):
        test_enkirpsi_dekripsi_rsa_byte_acak(keysize=keysize_blocksize[i][0], blocksize=keysize_blocksize[i][1], nama_file_csv=list_nama_file_csv[i])
    print '*' * 50
    print "Selesai test_custom_rsa"
    print '*' * 50


if __name__ == '__main__':
    # main()
    if sys.argv[1] == 'rsa_kunci':
        test_pembuatan_kunci_rsa(jumlah_iterasi=int(sys.argv[2]), keysize=int(sys.argv[3]))
    elif sys.argv[1] == 'rsa_byte_acak':
        test_enkirpsi_dekripsi_rsa_byte_acak(keysize=int(sys.argv[2]), blocksize=int(sys.argv[3]))
    elif sys.argv[1] == 'rsa_file':
        test_enkirpsi_dekripsi_rsa_file(input_dir_path=sys.argv[2], keysize=int(sys.argv[3]), blocksize=int(sys.argv[4]))
    elif sys.argv[1] == 'custom':
        test_custom_rsa()

    '''
    rsa_kunci: python test_rsa.py [1]rsa_kunci [2]<jumlah_iterasi> [3]<keysize>

    rsa_byte_acak: python test_rsa.py [1]rsa_byte_acak [2]<keysize> [3]<blocksize>

    rsa_file: python test_rsa.py [1]rsa_file [2]<input_dir_path> [3]<keysize> [4]<blocksize>

    custom: python test_rsa.py [1]custom
    '''
