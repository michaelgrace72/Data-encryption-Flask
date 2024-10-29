# Encryption Application using Flask

Mikha Gracia Sugiono
Azarel Grahandito A
Alvin Vincent Oswald Reba

---

# Project Name

Project ini adalah aplikasi Flask untuk pengelolaan file terenkripsi dan berbagi akses secara aman antar pengguna. Aplikasi ini menggunakan **Flask-Migrate** untuk mengelola migrasi database dan **SQLAlchemy** sebagai ORM (Object-Relational Mapping).

## Persyaratan Sistem

Pastikan Anda memiliki:
- **Python** versi 3.7 atau lebih baru
- **Pip** untuk mengelola paket Python
- **PostgreSQL** sebagai database
- **Virtual Environment** (opsional, tetapi direkomendasikan)

## Instalasi

1. **Clone Repository**
   ```bash
   git clone https://github.com/username/project-name.git
   cd project-name
   ```

2. **Buat Virtual Environment (opsional)**
   Membuat virtual environment direkomendasikan agar dependensi proyek terisolasi.
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Pada Windows, gunakan: venv\Scripts\activate
   ```

3. **Instal Dependensi**
   Instal semua paket yang diperlukan dengan perintah berikut:
   ```bash
   pip install -r requirements.txt
   ```
   Jika Anda belum memiliki file `requirements.txt`, berikut adalah beberapa dependensi utama yang diperlukan:
   ```bash
   pip install Flask Flask-Migrate Flask-SQLAlchemy psycopg2-binary cryptography python-dotenv
   ```

4. **Setup Database PostgreSQL**
   Pastikan PostgreSQL sudah diinstal di sistem Anda dan setup database khusus untuk aplikasi ini.
   
   - **Masuk ke PostgreSQL**:
     ```bash
     psql -U postgres
     ```
   
   - **Buat Database dan User untuk Aplikasi**:
     ```sql
     CREATE DATABASE nama_database;
     CREATE USER nama_user WITH PASSWORD 'password_user';
     ALTER ROLE nama_user SET client_encoding TO 'utf8';
     ALTER ROLE nama_user SET default_transaction_isolation TO 'read committed';
     ALTER ROLE nama_user SET timezone TO 'UTC';
     GRANT ALL PRIVILEGES ON DATABASE nama_database TO nama_user;
     ```

5. **Generate MASTER_KEY**
   Untuk menghasilkan `MASTER_KEY` secara otomatis, Anda bisa menggunakan script `master.py` yang akan menyimpan key langsung di `.bashrc`. Pastikan untuk menjalankan langkah ini sebelum melanjutkan ke migrasi database.

   ```bash
   python master.py
   ```

   Script ini akan menghasilkan key dengan panjang 64 karakter dalam format heksadesimal dan menambahkannya ke `.bashrc`. Setelah dijalankan, pastikan untuk merefresh terminal agar `MASTER_KEY` tersedia dalam environment:

   ```bash
   source ~/.bashrc
   ```

6. **Inisialisasi Database dan Migrasi**
   Untuk membuat struktur database, Anda perlu menjalankan beberapa perintah migrasi dengan Flask-Migrate.

   **Langkah-langkah untuk inisialisasi database:**
   
   - **Inisialisasi Flask-Migrate**  
     Membuat direktori migrasi yang diperlukan.
     ```bash
     flask --app server db init
     ```

   - **Membuat Migrasi Awal**  
     Membuat file migrasi untuk database, dengan pesan keterangan (misalnya, "Add public key and SymmetricKeyRequest models").
     ```bash
     flask --app server db migrate -m "Add public key and SymmetricKeyRequest models"
     ```

   - **Menerapkan Migrasi ke Database**  
     Terapkan perubahan migrasi ke database.
     ```bash
     flask --app server db upgrade
     ```

7. **Jalankan Aplikasi**
   Setelah setup selesai, Anda dapat menjalankan aplikasi dengan:
   ```bash
   flask run
   ```

   Secara default, aplikasi akan berjalan di `http://127.0.0.1:5000/`.

## Troubleshooting

- **Error `MASTER_KEY`**: Jika Anda mendapatkan error bahwa `MASTER_KEY` tidak ditemukan, pastikan Anda telah menjalankan `python master.py` dan melakukan `source ~/.bashrc`.
- **Database URI Error**: Pastikan URI yang diset dalam `SQLALCHEMY_DATABASE_URI` benar dan cocok dengan konfigurasi PostgreSQL Anda.
- **PostgreSQL Connection Error**: Jika tidak dapat terhubung ke PostgreSQL, pastikan database dan user sudah dibuat serta memiliki hak akses yang sesuai.

---
