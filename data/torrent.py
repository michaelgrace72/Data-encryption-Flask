import qbittorrentapi
import time
import os
import shutil

def download_torrent_with_qbittorrent(magnet_link):
    # Terhubung ke qBittorrent menggunakan API dengan kredensial baru
    qbt_client = qbittorrentapi.Client(host='http://127.0.0.1:8080', username='admin', password='123456')
    try:
        # Mencoba login
        qbt_client.auth_log_in()
        print("Berhasil terhubung ke qBittorrent.")
    except qbittorrentapi.LoginFailed as e:
        print(f"Login gagal: {e}")
        return

    # Tambahkan torrent menggunakan magnet link dan ambil hash-nya
    qbt_client.torrents_add(urls=magnet_link)
    print("Torrent telah ditambahkan, memulai unduhan...")

    # Tunggu beberapa detik untuk memastikan unduhan dimulai
    time.sleep(5)  # Menunggu beberapa detik agar torrent dapat terhubung ke peers

    # Ambil informasi tentang torrent yang baru ditambahkan
    torrents = qbt_client.torrents_info()
    if not torrents:
        print("Tidak ada torrent ditemukan.")
        return

    # Identifikasi torrent terbaru yang ditambahkan berdasarkan hash
    latest_torrent = None
    for torrent in torrents:
        if magnet_link in torrent.magnet_uri:
            latest_torrent = torrent
            break

    if latest_torrent is None:
        print("Torrent terbaru tidak ditemukan.")
        return

    torrent_hash = latest_torrent.hash

    # Tunggu sampai torrent selesai diunduh
    while True:
        torrent = qbt_client.torrents_info(torrent_hash=torrent_hash)[0]
        print(f"Progres unduhan: {torrent.progress * 100:.2f}%, Status: {torrent.state}")
        # Jika progres sudah 100% terlepas dari status, unduhan dianggap selesai
        if torrent.progress >= 1.0:
            print("Unduhan selesai.")
            break
        # Beri waktu jeda agar tidak terlalu sering memeriksa status
        time.sleep(5)

    # Pastikan file yang diunduh sudah ada di sistem
    files = qbt_client.torrents_files(torrent_hash)
    if files:
        for file_info in files:
            original_file = file_info.name
            download_path = os.path.expanduser('~/Downloads')  # Folder Downloads
            original_file_path = os.path.join(download_path, original_file)

            # Pastikan file benar-benar ada sebelum dipindahkan
            if os.path.exists(original_file_path):
                print(f"File ditemukan: {original_file_path}")
                # Dapatkan format file
                file_extension = os.path.splitext(original_file)[1]
                # Tentukan jalur tujuan
                folder_name = "/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file"
                os.makedirs(folder_name, exist_ok=True)
                new_file_path = get_next_available_filename(folder_name)
                # Pindahkan file yang diunduh ke folder dengan nama baru
                shutil.move(original_file_path, new_file_path + file_extension)
                print(f"File berhasil diunduh dan disimpan sebagai {new_file_path + file_extension}")
            else:
                print(f"File tidak ditemukan: {original_file_path}, menunggu unduhan selesai.")
    else:
        print("Tidak ada file ditemukan setelah pengunduhan.")

def get_next_available_filename(folder):
    """ Fungsi untuk menentukan nama file yang tersedia (file1, file2, dst.) tanpa memperhatikan format """
    counter = 1
    while True:
        new_file_name = f"file{counter}"
        new_file_path = os.path.join(folder, new_file_name)
        # Cek apakah ada file dengan nama yang sama, tanpa memperhatikan ekstensi
        if not any(f.startswith(new_file_name) for f in os.listdir(folder)):
            return new_file_path
        counter += 1

if __name__ == "__main__":
    magnet_link = input("Masukkan magnet link: ")
    download_torrent_with_qbittorrent(magnet_link)