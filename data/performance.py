import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os

# Fungsi untuk menggabungkan data duplikat berdasarkan jenis enkripsi dan ukuran file, serta menghitung rata-rata waktu
def combine_duplicate_data(df):
    # Mengelompokkan berdasarkan 'Method' dan 'File_Size_Bytes', lalu menghitung rata-rata 'Time_Taken_Seconds'
    combined_df = df.groupby(['Method', 'File_Size_Bytes'], as_index=False).agg({
        'Time_Taken_Seconds': 'mean'
    })
    return combined_df

# Fungsi normalisasi matriks TOPSIS
# Fungsi normalisasi matriks TOPSIS dengan penanganan error
def normalize_matrix(matrix):
    # Menambahkan pengecekan untuk menghindari pembagian oleh nol atau nilai invalid
    denominator = np.sqrt((matrix**2).sum())
    # Hindari pembagian jika denominator bernilai nol
    if denominator == 0:
        return np.zeros_like(matrix)
    norm_matrix = matrix / denominator
    return norm_matrix


# Fungsi TOPSIS untuk mengevaluasi performa
def topsis(df, criteria_weights):
    # Normalisasi data
    normalized_df = df.copy()
    for column in df.columns:
        normalized_df[column] = normalize_matrix(df[column])

    # Menghitung solusi ideal positif dan negatif
    ideal_positive = normalized_df.max().values
    ideal_negative = normalized_df.min().values

    # Menghitung jarak dari solusi ideal positif dan negatif
    distance_positive = np.sqrt(((normalized_df - ideal_positive) ** 2).sum(axis=1))
    distance_negative = np.sqrt(((normalized_df - ideal_negative) ** 2).sum(axis=1))

    # Menghitung skor preferensi (closer to ideal positive)
    scores = distance_negative / (distance_negative + distance_positive)

    return scores

# Fungsi untuk membaca file CSV, menggabungkan data duplikat, menyimpan data terurut, dan menggunakan TOPSIS
def evaluate_encryption_performance_with_topsis(csv_file):
    # Membaca file CSV
    df = pd.read_csv(csv_file)
    
    # Memisahkan data enkripsi dan dekripsi
    encryption_df = df[df['Operation'] == 'Encrypt'].sort_values(by='File_Size_Bytes')
    decryption_df = df[df['Operation'] == 'Decrypt'].sort_values(by='File_Size_Bytes')
    
    # Menggabungkan data duplikat dan menghitung rata-rata waktu
    encryption_df_combined = combine_duplicate_data(encryption_df)
    decryption_df_combined = combine_duplicate_data(decryption_df)
    
    # Dapatkan path folder dari file .py saat ini
    folder_path = os.path.dirname(os.path.abspath(__file__))
    
    # Simpan data terurut ke file CSV baru
    sorted_file_path = os.path.join(folder_path, 'sorted_performance_data_combined.csv')
    df_combined = pd.concat([encryption_df_combined, decryption_df_combined])
    df_combined.to_csv(sorted_file_path, index=False)
    print(f"Sorted and combined data saved to: {sorted_file_path}")
    
    # TOPSIS Evaluasi
    # Menggunakan dua kriteria: File_Size_Bytes dan Time_Taken_Seconds
    topsis_df = df_combined[['File_Size_Bytes', 'Time_Taken_Seconds']]
    criteria_weights = np.array([0.5, 0.5])  # Bobot kriteria dapat diubah sesuai kebutuhan
    
    # Melakukan evaluasi menggunakan TOPSIS
    scores = topsis(topsis_df, criteria_weights)
    
    # Menambahkan skor TOPSIS ke dalam dataframe
    df_combined['TOPSIS_Score'] = scores
    
    # Simpan hasil TOPSIS ke file CSV baru
    topsis_result_file = os.path.join(folder_path, 'topsis_performance_evaluation_combined.csv')
    df_combined.to_csv(topsis_result_file, index=False)
    print(f"TOPSIS evaluation saved to: {topsis_result_file}")
    
    # Membuat plot untuk perbandingan waktu enkripsi (terurut)
    plt.figure(figsize=(10, 6))
    methods = encryption_df_combined['Method'].unique()
    
    for method in methods:
        method_data = encryption_df_combined[encryption_df_combined['Method'] == method]
        plt.plot(method_data['File_Size_Bytes'], method_data['Time_Taken_Seconds'], marker='o', label=f'Encryption {method}')
    
    # Menambahkan judul dan label
    plt.title("Encryption Time by File Size (Sorted and Combined)", fontsize=14)
    plt.xlabel("File Size (Bytes)", fontsize=12)
    plt.ylabel("Time Taken (Seconds)", fontsize=12)
    plt.legend()
    plt.grid(True)
    
    # Simpan plot ke folder yang sama dengan file .py
    plt.savefig(os.path.join(folder_path, 'encryption_performance_sorted_combined.png'))
    plt.close()
    
    # Membuat plot untuk perbandingan waktu dekripsi (terurut)
    plt.figure(figsize=(10, 6))
    for method in methods:
        method_data = decryption_df_combined[decryption_df_combined['Method'] == method]
        plt.plot(method_data['File_Size_Bytes'], method_data['Time_Taken_Seconds'], marker='o', label=f'Decryption {method}')
    
    plt.title("Decryption Time by File Size (Sorted and Combined)", fontsize=14)
    plt.xlabel("File Size (Bytes)", fontsize=12)
    plt.ylabel("Time Taken (Seconds)", fontsize=12)
    plt.legend()
    plt.grid(True)
    
    # Simpan plot ke folder yang sama dengan file .py
    plt.savefig(os.path.join(folder_path, 'decryption_performance_sorted_combined.png'))
    plt.close()

# Contoh penggunaan fungsi
evaluate_encryption_performance_with_topsis('performance.csv')
