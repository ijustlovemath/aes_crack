use std::vec::Vec;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;

use rand::Rng;
use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::{try_from_vec, typenum::U16, GenericArray},
};



#[derive(Clone)]
struct CrackContext {
    indices: Vec<usize>,
    partial_key: Vec<u8>,
    message: Vec<u8>,
    solution: Vec<u8>,
    soln_tx: Sender<Vec<u8>>,
  //  stop_rx: Receiver<()>,
}

fn main() {
    let mut partial_key = GenericArray::from([54u8, 16]);
    let key = GenericArray::from([54u8, 16]);
    let cipher = Aes128::new(&key);
    let mut solution = GenericArray::from([42u8, 16]);

    let mut message = GenericArray::from([42u8, 16]);

    cipher.encrypt_block(&mut message);

    // mess up the key so we have to fix it
    partial_key[0] = 255;
    partial_key[1] = 73;

    // indices we know are broken
    let mut corrupted = Vec::new();
    corrupted.push(0);
    corrupted.push(1);


    let WORKERS = 20;
    let (soln_tx, soln_rx) = channel();
    let (stop_tx, stop_rx) = channel();
    for i in 0..WORKERS {
        let work = CrackContext {
            indices: corrupted,
            partial_key: partial_key.to_vec(),
            message: message.to_vec(),
            solution: solution.to_vec(),
    //        stop_rx: stop_rx.clone(),
            soln_tx: soln_tx.clone(),
        };
        thread::spawn(move || {
            let mut work = work.clone();
            let mut rng = rand::thread_rng();

            loop {
                for j in &work.indices {
                    work.partial_key[*j] = rng.gen();
                }
                let mut workspace = try_from_vec(work.message.clone()).unwrap();
                let key = try_from_vec(work.partial_key.clone()).unwrap();
                let cipher = Aes128::new(key);
                cipher.decrypt_block(&mut workspace);
                if workspace.to_vec() == work.solution {
                    soln_tx.send(work.partial_key);
                    break;
                }

            }
        });

    }
    let solved_key = soln_rx.recv().unwrap();
    println!("solved: {solved_key:#?}");
}
