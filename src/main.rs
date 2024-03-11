use std::vec::Vec;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;

use rand::Rng;
use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::{typenum::U16, GenericArray},
};



#[derive(Clone)]
struct CrackContext {
    id: usize,
    indices: Vec<usize>,
    partial_key: GenericArray<u8, U16>,
    message: GenericArray<u8, U16>,
    solution: GenericArray<u8, U16>,
    soln_tx: Sender<(usize, GenericArray<u8, U16>)>,
  //  stop_rx: Receiver<()>,
}

fn main() {
    let mut partial_key = GenericArray::from([54u8; 16]);
    let key = GenericArray::from([54u8; 16]);
    let cipher = Aes128::new(&key);
    let mut solution = GenericArray::from([42u8; 16]);

    let mut message = GenericArray::from([42u8; 16]);

    cipher.encrypt_block(&mut message);

    // indices we want to break
    let mut corrupted = Vec::new();
    corrupted.push(0);
    corrupted.push(1);
    corrupted.push(5);
    corrupted.push(6);
    //corrupted.push(11);

    // automatically mess up the key so we have to fix it
    for i in &corrupted {
        partial_key[*i] = 0;
    }


    let WORKERS = 200;
    let (soln_tx, soln_rx) = channel();
  //  let mut stop_channels = Vec::new();

    for i in 0..WORKERS {

//        let (stop_tx, stop_rx) = channel();
        let work = CrackContext {
            id: i,
            indices: corrupted.clone(),
            partial_key: partial_key,
            message: message.clone(),
            solution: solution,
            soln_tx: soln_tx.clone(),
        };

//        stop_channels.push(stop_tx);

        thread::spawn(move || {
            let mut work = work.clone();
            let mut rng = rand::thread_rng();

            loop {
                //let mut last_j = 0;
                for j in &work.indices {
                    work.partial_key[*j] = rng.gen();
                    //last_j += j;
                }
//                if last_j == 0 {
//                    if stop_rx.try_recv().is_ok() {
//                        break;
//                    }
//                }
                // you need to clone this so you don't mess up the ciphertext every iteration
                let mut workspace = work.message.clone();
                let cipher = Aes128::new(&work.partial_key);
                cipher.decrypt_block(&mut workspace);
                if workspace == work.solution {
                    work.soln_tx.send((work.id, work.partial_key));
                }


            }
        });

    }
    let (solver, solved_key) = soln_rx.recv().unwrap();
//    for stop in stop_channels {
//        stop.send(()).expect("failed to stop everyone");
//    }
    let printable_key = solved_key.to_vec();
    println!("solved by {solver}: key={printable_key:?}");
    let mut decrypted = message.clone();
    let decryptor = Aes128::new(&solved_key);
    let ciphertext = decrypted.to_vec();
    println!("ciphertext: {ciphertext:?}");
    decryptor.decrypt_block(&mut decrypted);
    let plaintext = decrypted.to_vec();
    println!("plaintext: {plaintext:?}");
}
