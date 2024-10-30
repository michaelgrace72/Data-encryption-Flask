from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import csv

# Path ke Chrome WebDriver
driver_path = '/usr/bin/chromedriver'
login_url = 'http://localhost:5001/login'  # URL halaman login
encrypt_url = 'http://localhost:5001/encrypt'  # URL halaman enkripsi
decrypt_url = 'http://localhost:5001/decrypt'  # URL halaman dekripsi

# Fungsi untuk login ke aplikasi web
def login(driver, username, password):
    driver.get(login_url)
    
    # Isi form login
    username_input = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, 'email'))
    )
    username_input.send_keys(username)
    
    password_input = driver.find_element(By.NAME, 'password')
    password_input.send_keys(password)
    
    # Submit form login dengan tombol submit
    submit_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, '//button[@type="submit"]'))
    )
    submit_button.click()

# Fungsi untuk menjalankan enkripsi dan mencatat waktu
def run_encryption_test(driver, encryption_method, file_path, file_number):
    driver.get(encrypt_url)
    
    # Pilih metode enkripsi
    encryption_dropdown = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, 'encryption'))
    )
    encryption_dropdown.send_keys(encryption_method)
    
    # Upload file
    file_input = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, 'file'))
    )
    file_input.send_keys(file_path)
    
    # Start timing for encryption
    start_time = time.time()
    
    # Submit form enkripsi dengan tombol submit
    submit_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, '//button[@type="submit"]'))
    )
    submit_button.click()

    # Tunggu hingga hasil enkripsi selesai
    WebDriverWait(driver, 120).until(
        EC.presence_of_element_located((By.ID, 'alert-message'))  # Misal menunggu pesan sukses muncul
    )
    
    # End timing for encryption
    end_time = time.time()
    
    # Hitung waktu yang diperlukan
    time_taken = end_time - start_time
    
    # Simpan hasil ke file CSV
    with open('encryption_results.csv', 'a', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow([encryption_method, file_path, time_taken, f'encryption_file_{file_number}'])
    
    print(f'Encryption time for {encryption_method}, file {file_number}: {time_taken:.4f} seconds')

# Fungsi untuk menjalankan dekripsi dan mencatat waktu
# def run_decryption_test(driver, encryption_method, file_number):
#     driver.get(decrypt_url)
    
#     # Pilih file berdasarkan metode enkripsi
#     if encryption_method == 'AES':
#         table_xpath = "//h2[contains(text(),'AES Encrypted Files')]/following-sibling::div//tbody//tr"
#     elif encryption_method == 'RC4':
#         table_xpath = "//h2[contains(text(),'RC4 Encrypted Files')]/following-sibling::div//tbody//tr"
#     elif encryption_method == 'DES':
#         table_xpath = "//h2[contains(text(),'DES Encrypted Files')]/following-sibling::div//tbody//tr"
#     else:
#         raise Exception(f"Encryption method {encryption_method} not recognized")
    
#     # Pilih file dari tabel (berdasarkan nomor urutan file)
#     rows = WebDriverWait(driver, 10).until(
#         EC.presence_of_all_elements_located((By.XPATH, table_xpath))
#     )
    
#     if len(rows) < file_number:
#         raise Exception(f"File number {file_number} not found in {encryption_method} table")
    
#     selected_row = rows[file_number - 1]  # Mengambil file sesuai urutan
#     download_button = selected_row.find_element(By.XPATH, './/button[@type="submit"]')

#     # Start timing for decryption
#     start_time = time.time()
    
#     # Klik tombol download untuk mengirim form dekripsi
#     download_button.click()

#     # Tunggu hingga hasil dekripsi selesai
#     WebDriverWait(driver, 120).until(
#         EC.presence_of_element_located((By.ID, 'alert-message'))
#     )
    
#     # End timing for decryption
#     end_time = time.time()
    
#     # Hitung waktu yang diperlukan
#     time_taken = end_time - start_time
    
#     # Simpan hasil ke file CSV
#     with open('decryption_results.csv', 'a', newline='') as csvfile:
#         csvwriter = csv.writer(csvfile)
#         csvwriter.writerow([encryption_method, time_taken, f'decryption_file_{file_number}'])
    
#     print(f'Decryption time for {encryption_method}, file {file_number}: {time_taken:.4f} seconds')

# Fungsi utama untuk menjalankan proses round robin dengan file yang berbeda-beda
def run_round_robin(username, password, encryption_methods, file_paths):
    # Menggunakan Chrome Options untuk driver
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Menjalankan tanpa GUI
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    
    # Inisialisasi driver dengan opsi
    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    
    try:
        # Login sekali di awal
        login(driver, username, password)

        for file_number, (file_name, file_path) in enumerate(file_paths.items(), start=1):
            for method in encryption_methods:
                # Jalankan enkripsi untuk file ini dan metode enkripsi ini
                run_encryption_test(driver, method, file_path, file_number)
                # Jalankan dekripsi untuk file ini dan metode enkripsi ini
                # run_decryption_test(driver, method, file_number)

    finally:
        driver.quit()  # Tutup driver setelah selesai

# Daftar file paths sesuai permintaan Anda
file_paths = {
    'file1.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file1.mkv',
    'file2.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file2.mkv',
    'file3.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file3.mkv',
    'file4.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file4.mkv',
    'file5.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file5.mkv',
    'file6.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file6.cbz',
    'file7.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file7.mkv',
    'file8.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file8.mkv',
    'file9.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file9.mkv',
    'file10.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file10.mkv',
    'file11.mp4': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file11.mp4',
    'file12.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file12.mkv',
    'file13.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file13.mkv',
    'file14.cbz': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file14.cbz',
    'file15.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file15.mkv',
    'file16.mp4': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file16.mp4',
    'file17.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file17.mkv',
    'file18.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file18.mkv',
    'file19.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file19.mkv',
    'file20.mp4': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file20.mp4',
    'file21.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file21.mkv',
    'file22.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file22.mkv',
    'file23.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file23.mkv',
    'file24.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file24.mkv',
    'file25.mkv': '/home/alvn/Documents/Xinyuen/KI/fp_ets/Data-encryption-Flask/server/file/file25.mkv',
}

# Konfigurasi dan jalankan round robin
username = 'alvn@gma.com'  # Ganti dengan email untuk login
password = '12345678'  # Ganti dengan password yang benar
encryption_methods = ['AES', 'RC4', 'DES']  # Ganti sesuai metode enkripsi yang Anda punya

run_round_robin(username, password, encryption_methods, file_paths)
