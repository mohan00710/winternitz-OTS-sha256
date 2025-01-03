
use getrandom;
use hex;
use sha2::{Sha256, Digest};


#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct Winternitz {
    pub public_key : Vec<String>,
    pub secret_key : Vec<String>,
    w : usize,
    n : usize
}


pub fn generate_random_bytes() -> Result<[u8; 32] , getrandom::Error>{
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf)?;
    Ok(buf)
}


fn sha256_hash(s: String , w: usize) -> String {
    let mut is_generation: bool = false;
    let mut is_signing: bool = false;

    if w == 0usize{
        return  s;
    }else if w> 16usize{
        is_generation = true
    }
    else if w > 16usize{
        panic!("cycle amount is high")
    }else {
        is_signing = true;
    }

    let bytes: Vec<u8> = hex::decode(s).unwrap().to_owned();
    let mut hasher = Sha256::new(); // Create a new SHA-256 hasher
    hasher.update(bytes);
    let mut hash_result = hasher.finalize().to_vec();

    let cycles = w - 1usize;

    if cycles == 0usize {
        return hex::encode_upper(&hash_result);
    }
    for _i in 0..cycles {
        let mut hasher = Sha256::new(); // Create a new SHA-256 hasher
        hasher.update(hash_result);
        hash_result = hasher.finalize().to_vec();

    }
    return hex::encode_upper(hash_result);
}



pub fn generate_winternitz_keypair() ->Winternitz {
    let w: usize = 16;
    let n: usize = 32;

    let message_size_in_bits : usize = 32 * 8 ; //error here


    let mut secret_key: Vec<String> = vec![];
    let mut private_key : Vec<String> = vec![];

    let log_2_w = f64::log(w as f64, 0.0).round() as usize;
    let total_number_of_chunks : usize = message_size_in_bits / 4;
    let checksum_value = f64::log((total_number_of_chunks * (w - 1)) as f64, 0.0).round();
    let len_2 = f64::floor(checksum_value / log_2_w as f64) as usize +1 ;

    for _i in 0..64 + len_2 {
        let secret: [u8; 32] = generate_random_bytes().unwrap();
        let secret_hex: String = hex::encode(secret);
        secret_key.push(secret_hex.clone());

        let public = sha256_hash(secret_hex, w);

        private_key.push(public)
    }

    let output = Winternitz {
        w,
        n,
        public_key ,
        secret_key,
    };

    return output;

}