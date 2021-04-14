#![allow(non_snake_case)]

extern crate sha2;
extern crate hmac;
extern crate aes;
extern crate block_modes;
extern crate text_io;
extern crate serde;
extern crate serde_jsonrc;
#[macro_use]
extern crate serde_derive;

use std::fs::File;
use std::io::prelude::*;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, NewMac};
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::convert::TryInto;
use std::str;
use std::path::Path;
use std::process::exit;
use text_io::read;
use std::io;
use std::panic;
use std::env;

type HmacSha256 = Hmac<Sha256>;
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

struct BlangString {
    identifier: String,
    text: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FullBlangJsonString {
    identifier: String,
    text: String,
    modified: i64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct FullBlangJson {
    strings: Vec<FullBlangJsonString>
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BlangJsonString {
    name: String,
    text: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BlangJson {
    strings: Vec<BlangJsonString>
}

fn parse_blang(blang_bytes: Vec<u8>, is_new_format: bool) -> Vec<BlangString> {
    let mut blang_strings: Vec<BlangString> = Vec::new();

    let string_amount = i32::from_be_bytes(blang_bytes[8..12].try_into().unwrap());

    let mut pos: usize;
    if is_new_format {
        pos = 12;
    }
    else {
        pos = 4;
    }

    for _i in 0..string_amount {
        pos += 4;

        let identifier_len = i32::from_le_bytes(blang_bytes[pos..(pos + 4)].try_into().unwrap()) as usize;
        pos += 4;

        let identifier = String::from_utf8(blang_bytes[pos..(pos + identifier_len)].to_vec()).unwrap().to_string();
        pos += identifier_len;

        let text_len = i32::from_le_bytes(blang_bytes[pos..(pos + 4)].try_into().unwrap()) as usize;
        pos += 4;

        let text = String::from_utf8(blang_bytes[pos..(pos + text_len)].to_vec()).unwrap();
        pos += text_len;

        let unknown_len = i32::from_le_bytes(blang_bytes[pos..(pos + 4)].try_into().unwrap()) as usize;
        pos += 4;
        pos += unknown_len;

        let blang_string = BlangString {
            identifier: identifier,
            text: text,
        };

        blang_strings.push(blang_string);
    }

    return blang_strings;
}

fn id_crypt(file_data: Vec<u8>, internal_path: String) -> Vec<u8> {
    let key_derive_static = "swapTeam\n".to_string();
    let size = file_data.len();

    let file_salt = file_data[0..0xC].to_vec();

    let mut hasher = Sha256::new();
    hasher.update(&file_salt);
    let mut empty_byte_array = vec![0; 1];
    let mut key_derive_static_bytes = key_derive_static.as_bytes().to_vec();
    key_derive_static_bytes.append(&mut empty_byte_array);
    hasher.update(&key_derive_static_bytes);
    hasher.update(&internal_path);
    let enc_key = hasher.finalize().to_vec();

    let file_iv = file_data[0xC..(0xC + 0x10)].to_vec();

    let file_text = file_data[0x1C..(size as usize - 0x20)].to_vec();

    let file_hmac = file_data[(size as usize - 0x20)..(size as usize)].to_vec();

    let mut mac_hasher = HmacSha256::new_varkey(&enc_key).unwrap();
    mac_hasher.update(&file_salt);
    mac_hasher.update(&file_iv);
    mac_hasher.update(&file_text);
    let hmac = mac_hasher.finalize().into_bytes().to_vec();

    if &hmac[..] != &file_hmac[..] {
        return file_data;
    }

    let cipher = Aes128Cbc::new_var(&enc_key[0..0x10].to_vec(), &file_iv).unwrap();

    let crypted_text = cipher.decrypt_vec(&file_text).unwrap();

    return crypted_text;
}

fn generate_blang_json(path: String, internal_path: String, out_path: String) {
    if !Path::new(&path).exists() {
        eprintln!("ERROR: {} does not exist!", path);
        return;
    }

    let mut file = File::open(&path).expect(format!("Failed to open {} for reading.", path).as_str());
    let mut file_data: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_data).expect(format!("Failed to read from {}.", path).as_str());

    let blang_bytes = id_crypt(file_data.clone(), internal_path.to_string());

    panic::set_hook(Box::new(|_info| {}));

    let mut is_new_format = true;

    let mut result = panic::catch_unwind(|| {
        parse_blang(blang_bytes.clone(), is_new_format);
    });
    if result.is_err() {
        is_new_format = false;
        result = panic::catch_unwind(|| {
            parse_blang(blang_bytes.clone(), is_new_format);
        });
        if result.is_err() {
            eprintln!("ERROR: Failed to parse {}.", path);
            return;
        }
    }

    let _ = panic::take_hook();

    let blang_strings = parse_blang(blang_bytes, is_new_format);

    let mut strings: Vec<FullBlangJsonString> = Vec::new();

    for i in 0..blang_strings.len() {
        let blang_json_string = FullBlangJsonString {
            identifier: blang_strings[i].identifier.clone(),
            text: blang_strings[i].text.clone(),
            modified: 0,
        };

        strings.push(blang_json_string);
    }

    let blang_json = FullBlangJson {
        strings: strings,
    };

    let j = serde_jsonrc::to_string_pretty(&blang_json).unwrap_or_else(|_| {
        return "".to_string();
    });

    if j.is_empty() {
        eprintln!("ERROR: Failed to parse {}.", path);
        return;
    }

    if Path::new(&out_path).exists() {
        print!("{} already exists! Overwrite it? [y/N] ", out_path);
        io::stdout().flush().unwrap();
        let response: String = read!();
        println!("");
        if response != "y" && response != "Y" {
            return;
        }
    }

    let mut out_file = File::create(&out_path).expect(format!("Failed to open {} for writing.", out_path).as_str());
    out_file.write_all(j.as_bytes()).unwrap();

    println!("Succesfully generated blang's JSON in {}.", out_path);
}

fn generate_strings_json(path: String, out_path: String) {
    if !Path::new(&path).exists() {
        eprintln!("ERROR: {} does not exist!", path);
        return;
    }

    let mut file = File::open(&path).expect(format!("Failed to open {} for reading.", path).as_str());
    let mut blang_json_string = String::new();
    file.read_to_string(&mut blang_json_string).expect(format!("Failed to read from {}.", path).as_str());

    let blang_json: FullBlangJson = serde_jsonrc::from_str(&blang_json_string).unwrap_or_else(|_| {
        let empty_blang_json = FullBlangJson {
            strings: Vec::new(),
        };
        return empty_blang_json;
    });

    if blang_json.strings.is_empty() {
        eprintln!("ERROR: Failed to parse {}.", path);
        return;
    }

    let mut modified_strings: Vec<BlangJsonString> = Vec::new();

    for string in blang_json.strings.iter() {
        if string.modified != 0 {
            let new_string = BlangJsonString {
                name: string.identifier.clone(),
                text: string.text.clone(),
            };
            modified_strings.push(new_string);
        }
    }

    let final_json = BlangJson {
        strings: modified_strings,
    };

    let j = serde_jsonrc::to_string_pretty(&final_json).unwrap_or_else(|_| {
        return "".to_string();
    });

    if j.is_empty() {
        eprintln!("ERROR: Failed to parse {}.", path);
        return;
    }

    if Path::new(&out_path).exists() {
        print!("{} already exists! Overwrite it? [y/N] ", out_path);
        io::stdout().flush().unwrap();
        let response: String = read!();
        println!("");
        if response != "y" && response != "Y" {
            return;
        }
    }

    let mut out_file = File::create(&out_path).expect(format!("Failed to open {} for writing.", out_path).as_str());
    out_file.write_all(j.as_bytes()).unwrap();

    println!("Succesfully generated string mod JSON in {}.", out_path);
}

fn add_new_string(path: String, identifier: String) {
    if !Path::new(&path).exists() {
        eprintln!("ERROR: {} does not exist!", path);
        return;
    }

    let mut file = File::open(&path).expect(format!("Failed to open {} for reading.", path).as_str());
    let mut blang_json_string = String::new();
    file.read_to_string(&mut blang_json_string).expect(format!("Failed to read from {}.", path).as_str());

    let mut blang_json: BlangJson = serde_jsonrc::from_str(&blang_json_string).unwrap_or_else(|_| {
        let empty_blang_json = BlangJson {
            strings: Vec::new(),
        };
        return empty_blang_json;
    });

    if blang_json.strings.is_empty() {
        eprintln!("ERROR: Failed to parse {}.", path);
        return;
    }

    for string in blang_json.strings.iter() {
        if string.name == identifier {
            eprintln!("ERROR: String already exists in the JSON file!");
            return;
        }
    }

    let new_string = BlangJsonString {
        name: identifier.clone(),
        text: "".to_string(),
    };

    blang_json.strings.push(new_string);

    let j = serde_jsonrc::to_string_pretty(&blang_json).unwrap_or_else(|_| {
        return "".to_string();
    });

    if j.is_empty() {
        eprintln!("ERROR: Failed to parse {}.", path);
        return;
    }

    let mut out_file = File::create(&path).expect(format!("Failed to open {} for writing.", path).as_str());
    out_file.write_all(j.as_bytes()).expect(format!("Failed to write to {}.", path).as_str());

    println!("Succesfully added {} to {}.", identifier, path);
    exit(0);
}

fn modified_blang_to_json(modified_path: String, vanilla_path: String, internal_path: String, out_path: String) {
    if !Path::new(&modified_path).exists() {
        eprintln!("ERROR: {} does not exist!", modified_path);
        return;
    }

    if !Path::new(&vanilla_path).exists() {
        eprintln!("ERROR: {} does not exist!", vanilla_path);
        return;
    }

    let mut vanilla_file = File::open(&vanilla_path).expect(format!("Failed to open {} for reading.", vanilla_path).as_str());
    let mut vanilla_file_data: Vec<u8> = Vec::new();
    vanilla_file.read_to_end(&mut vanilla_file_data).expect(format!("Failed to read from {}.", vanilla_path).as_str());

    let vanilla_blang_bytes = id_crypt(vanilla_file_data.clone(), internal_path.to_string());

    panic::set_hook(Box::new(|_info| {}));

    let mut is_new_format = true;

    let mut result = panic::catch_unwind(|| {
        parse_blang(vanilla_blang_bytes.clone(), is_new_format);
    });
    if result.is_err() {
        is_new_format = false;
        result = panic::catch_unwind(|| {
            parse_blang(vanilla_blang_bytes.clone(), is_new_format);
        });
        if result.is_err() {
            eprintln!("ERROR: Failed to parse {}.", vanilla_path);
            return;
        }
    }

    let _ = panic::take_hook();

    let vanilla_strings = parse_blang(vanilla_blang_bytes, is_new_format);

    let mut modified_file = File::open(&modified_path).expect(format!("Failed to open {} for reading.", modified_path).as_str());
    let mut modified_file_data: Vec<u8> = Vec::new();
    modified_file.read_to_end(&mut modified_file_data).expect(format!("Failed to read from {}.", modified_path).as_str());

    let modified_blang_bytes = id_crypt(modified_file_data.clone(), internal_path.to_string());

    panic::set_hook(Box::new(|_info| {}));

    is_new_format = true;

    result = panic::catch_unwind(|| {
        parse_blang(modified_blang_bytes.clone(), is_new_format);
    });
    if result.is_err() {
        is_new_format = false;
        result = panic::catch_unwind(|| {
            parse_blang(modified_blang_bytes.clone(), is_new_format);
        });
        if result.is_err() {
            eprintln!("ERROR: Failed to parse {}.", modified_path);
            return;
        }
    }

    let _ = panic::take_hook();

    let modified_strings = parse_blang(modified_blang_bytes, is_new_format);

    let mut new_modified_strings: Vec<BlangJsonString> = Vec::new();

    for i in 0..modified_strings.len() {
        if vanilla_strings.len() > i {
            if modified_strings[i].identifier == vanilla_strings[i].identifier {
                if modified_strings[i].text != vanilla_strings[i].text {
                    let new_modified_string = BlangJsonString {
                        name: modified_strings[i].identifier.clone(),
                        text: modified_strings[i].text.clone(),
                    };

                    new_modified_strings.push(new_modified_string);
                }

                continue;
            }
        }

        let new_modified_string = BlangJsonString {
            name: modified_strings[i].identifier.clone(),
            text: modified_strings[i].text.clone(),
        };

        new_modified_strings.push(new_modified_string);
    }

    if new_modified_strings.len() == 0 {
        eprintln!("ERROR: Failed to generate JSON - all strings are equal!");
        return;
    }

    let final_json = BlangJson {
        strings: new_modified_strings,
    };

    let j = serde_jsonrc::to_string_pretty(&final_json).unwrap_or_else(|_| {
        return "".to_string();
    });

    if j.is_empty() {
        eprintln!("ERROR: Failed to parse {}.", modified_path);
        return;
    }

    if Path::new(&out_path).exists() {
        print!("{} already exists! Overwrite it? [y/N] ", out_path);
        io::stdout().flush().unwrap();
        let response: String = read!();
        println!("");
        if response != "y" && response != "Y" {
            return;
        }
    }

    let mut out_file = File::create(&out_path).expect(format!("Failed to open {} for writing.", out_path).as_str());
    out_file.write_all(j.as_bytes()).unwrap();

    println!("Succesfully generated string mod JSON in {}.", out_path);
}

fn read_line() -> String {
    let mut line: String;

    if env::consts::OS == "windows" {
        line = read!("{}\r\n");
    }
    else {
        line = read!("{}\n");
    }

    line = line.trim_matches('\"').to_string();

    return line;
}

fn main() {
    loop {
        println!("\nBlangJsonGenerator v1.1 by PowerBall253\n");
        println!("1. Generate a full blang JSON.");
        println!("2. Generate a string mod JSON using an edited full blang JSON.");
        println!("3. Add a new string to a mod JSON.");
        println!("4. Generate a string mod JSON from a modified blang file.");
        println!("5. Exit.");
    
        let mut response: String;
        loop {
            print!("\nSelect an option: ");
            io::stdout().flush().unwrap();
            response = read_line();
            if response.parse::<u32>().is_ok() && response.parse::<i32>().unwrap() <= 5 {
                break;
            }
            println!("Invalid option!");
        }

        match response.parse::<i32>().unwrap() {
            1 => {
                print!("Input the path to the .blang file: ");
                io::stdout().flush().unwrap();
                let path = read_line();
    
                print!("Input the language name: ");
                io::stdout().flush().unwrap();
                let language = read_line();
                let mut internal_path = "strings/".to_string();
                internal_path.push_str(language.as_str());
                internal_path.push_str(".blang");
    
                print!("Input the path to the output file: ");
                io::stdout().flush().unwrap();
                let out_path = read_line();
    
                println!("");
    
                generate_blang_json(path, internal_path, out_path);
            }
            2 => {
                print!("Input the path to the blang's .json file: ");
                io::stdout().flush().unwrap();
                let path = read_line();
    
                print!("Input the path to the output file: ");
                io::stdout().flush().unwrap();
                let out_path = read_line();
    
                println!("");
    
                generate_strings_json(path, out_path);
            }
            3 => {
                print!("Input the path to the mod's .json file: ");
                io::stdout().flush().unwrap();
                let path = read_line();
    
                print!("Input the name of the string you want to add: ");
                io::stdout().flush().unwrap();
                let identifier = read_line();
    
                println!("");
    
                add_new_string(path, identifier);
            }
            4 => {
                print!("Input the path to the vanilla .blang file: ");
                io::stdout().flush().unwrap();
                let vanilla_path = read_line();
    
                print!("Input the path to the modified .blang file: ");
                io::stdout().flush().unwrap();
                let modified_path = read_line();
    
                print!("Input the language name: ");
                io::stdout().flush().unwrap();
                let language = read_line();
                let mut internal_path = "strings/".to_string();
                internal_path.push_str(language.as_str());
                internal_path.push_str(".blang");
    
                print!("Input the path to the output file: ");
                io::stdout().flush().unwrap();
                let out_path = read_line();
    
                println!("");
    
                modified_blang_to_json(modified_path, vanilla_path, internal_path, out_path);
            }
            _ => {
                exit(101);
            }
        }

        println!("\nPress enter to continue...");
        let mut stdin = io::stdin();
        let _ = stdin.read(&mut [0u8]).unwrap();
    }
}