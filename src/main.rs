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
    solution: Vec<u8>,
    soln_tx: Sender<(usize, Vec<u8>)>,
  //  stop_rx: Receiver<()>,
}

fn main() {
    let mut partial_key = GenericArray::from([54u8; 16]);
    let key = GenericArray::from([54u8; 16]);
    let cipher = Aes128::new(&key);
    let mut solution = GenericArray::from([42u8; 16]);

    let mut message = GenericArray::from([42u8; 16]);

    cipher.encrypt_block(&mut message);

    // mess up the key so we have to fix it
    partial_key[0] = 255;
    partial_key[1] = 73;
    partial_key[5] = 72;

    // indices we know are broken
    let mut corrupted = Vec::new();
    corrupted.push(0);
    corrupted.push(1);
    corrupted.push(5);


    let WORKERS = 20;
    let (soln_tx, soln_rx) = channel();
    let mut stop_channels = Vec::new();

    for i in 0..WORKERS {

        let (stop_tx, stop_rx) = channel();
        let work = CrackContext {
            id: i,
            indices: corrupted.clone(),
            partial_key: partial_key,
            message: message,
            solution: solution.to_vec(),
            soln_tx: soln_tx.clone(),
        };

        stop_channels.push(stop_tx);

        thread::spawn(move || {
            let mut work = work.clone();
            let mut rng = rand::thread_rng();
            let mut last_j = 0;

            loop {
                for j in &work.indices {
                    work.partial_key[*j] = rng.gen();
                    last_j += j;
                }
                if last_j == 0 {
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }
                }
                let mut workspace = work.message.clone();
                let key = work.partial_key.clone();
                let cipher = Aes128::new(&key);
                cipher.decrypt_block(&mut workspace);
                if workspace.to_vec() == work.solution {
                    work.soln_tx.send((work.id, work.partial_key.to_vec()));
                }


            }
        });

    }
    let (solver, solved_key) = soln_rx.recv().unwrap();
    for stop in stop_channels {
        stop.send(()).expect("failed to stop everyone");
    }
    println!("solved by {solver}: {solved_key:#?}");
}
