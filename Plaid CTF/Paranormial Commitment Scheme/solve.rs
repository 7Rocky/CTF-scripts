use ff_ce::Field;

use hex::FromHex;

use pairing_ce::{
    bls12_381::{Bls12, Fr, G1Affine, G2Affine, G1, G2},
    ff::PrimeField,
    Engine, GenericCurveAffine, GenericCurveProjective,
};

use serde::Deserialize;

use std::{fs::File, io::BufReader};

#[derive(Clone, Debug, Deserialize)]
struct Setup {
    g2_base: G2Affine,
}

const ALPHA: &str = "1337133713371337133713371337133713371337133713371337133713371337133713371337";

fn get_valid(com: G1Affine, values: Vec<(Fr, G1Affine)>, g2_base: G2Affine) -> (Vec<Fr>, Vec<Fr>) {
    let (mut zs, mut ys) = (vec![], vec![]);

    for (i, (y, proof)) in values.iter().enumerate() {
        let z = Fr::from_str(&i.to_string()).unwrap();

        let (g1, g2) = (G1Affine::one(), G2Affine::one());

        let mut com_y_g1_proj = G1::from(com);
        let y_g1_proj = g1.mul(*y);
        com_y_g1_proj.sub_assign(&y_g1_proj);
        let com_y_g1 = com_y_g1_proj.into_affine();

        let mut s_g2_z_g2_proj = G2::from(g2_base);
        let z_g2_proj = G2::from(g2.mul(z));
        s_g2_z_g2_proj.sub_assign(&z_g2_proj);
        let s_g2_z_g2 = s_g2_z_g2_proj.into_affine();

        if Bls12::pairing(com_y_g1, g2) == Bls12::pairing(*proof, s_g2_z_g2) {
            zs.push(z);
            ys.push(*y);
        }
    }

    (zs, ys)
}

fn interpolate(xs: Vec<Fr>, ys: Vec<Fr>, alpha: Fr) -> Fr {
    let mut result = Fr::zero();

    for i in 0..xs.len() {
        let mut term = ys[i];

        for j in 0..xs.len() {
            if j != i {
                let mut div = xs[i];
                div.sub_assign(&xs[j]);
                let mut tmp = alpha;
                tmp.sub_assign(&xs[j]);
                term.mul_assign(&tmp);
                term.mul_assign(&div.inverse().expect("zero encountered"));
            }
        }

        result.add_assign(&term);
    }

    result
}

fn main() {
    let setup_path = std::env::args().nth(1).expect("no setup file given");
    let output_path = std::env::args().nth(2).expect("no output file given");

    let setup_file = File::open(setup_path).expect("setup file not found");
    let output_file = File::open(output_path).expect("output file not found");

    let setup: Setup =
        serde_json::from_reader(BufReader::new(setup_file)).expect("failed to deserialize setup");
    let (com, values): (G1Affine, Vec<(Fr, G1Affine)>) =
        serde_json::from_reader(BufReader::new(output_file)).expect("failed to deserialize output");

    let (zs, ys) = get_valid(com, values, setup.g2_base);

    let alpha = Fr::from_str(ALPHA).unwrap();
    let flag_fr = interpolate(zs, ys, alpha);

    let mut flag_hex: String = flag_fr.to_string().chars().skip(5).collect();
    flag_hex.truncate(flag_hex.len() - 1);

    let flag: Vec<u8> = Vec::from_hex(flag_hex).expect("Error decoding hex");

    print!("{}", String::from_utf8_lossy(&flag));
}
