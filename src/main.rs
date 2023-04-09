/*This program is a command-line tool for encrypting and decrypting files
using the AES-256 block cipher in CBC mode with PKCS7 padding. The user is
prompted to provide the file path, a password, and the desired operation
mode (encrypt or decrypt). The password is used to derive a 256-bit key using
the SHA-256 hash function. The tool then reads the file content, performs
the chosen operation, and writes the result to a new file with the original
file name appended with the operation mode (e.g., "file.txt_encrypt" or "file.txt_decrypt").
 */
use aes::{Aes256, NewBlockCipher};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::str;
use std::io;
use generic_array::GenericArray;

// Replace this with your own key derivation method.
fn password_to_key(password: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..]);
    key
}

fn main() {
    // Get file path
    println!("Enter the path to the file:");
    let mut file_path_input = String::new();
    io::stdin().read_line(&mut file_path_input).expect("Failed to read line");
    let file_path = file_path_input.trim();

    // Check if file exists
    if !Path::new(file_path).exists() {
        eprintln!("File not found!");
        return;
    }

    // Get password
    println!("Enter the password:");
    let mut password_input = String::new();
    io::stdin().read_line(&mut password_input).expect("Failed to read line");
    let password = password_input.trim();

    // Derive key from password
    let key = password_to_key(password);

    // Choose mode (encrypt or decrypt)
    println!("Choose mode (encrypt/decrypt):");
    let mut mode_input = String::new();
    io::stdin().read_line(&mut mode_input).expect("Failed to read line");
    let mode = mode_input.trim();

    let iv = [0u8; 16]; // Using a fixed IV for simplicity, but it's not recommended in practice
    let key = GenericArray::from_slice(&key);
    let cipher = Aes256::new(&key);
    let iv = GenericArray::from_slice(&iv);
    let block_mode = Cbc::<Aes256, Pkcs7>::new(cipher, iv);

    // Read file content
    let mut file = File::open(file_path).expect("Failed to open file");
    let mut file_content = Vec::new();
    file.read_to_end(&mut file_content).expect("Failed to read file");

    let result = match mode {
        "encrypt" => {
            let encrypted = block_mode.encrypt_vec(&file_content);
            encrypted
        }
        "decrypt" => {
            let decrypted = block_mode.decrypt_vec(&file_content).unwrap();
            decrypted
        }
        _ => {
            eprintln!("Invalid mode!");
            return;
        }
    };

    // Write result to a new file
    let output_file_path = format!("{}_{}", file_path, mode);
    let mut output_file = File::create(&output_file_path).expect("Failed to create output file");
    output_file.write_all(&result).expect("Failed to write output file");

    println!("{}ed file saved as: {}", mode, output_file_path);
}